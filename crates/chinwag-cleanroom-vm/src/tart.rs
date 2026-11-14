// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Ephemeral Tart cleanroom VM lifecycle (`tart clone` -> background
//! `tart run --no-graphics --no-clipboard --no-audio --net-softnet --dir=...:ro` ->
//! readiness probe -> `tart exec <run-vm> -- /usr/bin/sandbox-exec -p <sbpl> -- /usr/bin/env -i ...` ->
//! `tart stop` + reap -> deterministic `defer tart delete`).
//!
//! Enforces `INV-NIX-VIRTIOFS-01` (sub-200ms read-only VirtioFS mount budget) and
//! `INV-NIX-RO-STORE-01` (hypervisor `:ro` tag enforcement + runtime guest Seatbelt).

use crate::runner_pool::NetworkEgressPolicy;
use crate::seatbelt::SeatbeltProfile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Maximum permitted VirtioFS mount latency budget in milliseconds (`INV-NIX-VIRTIOFS-01`).
pub const MAX_VIRTIOFS_MOUNT_LATENCY_MS: u64 = 200;

/// Canonical VirtioFS share tag for the immutable host `/nix/store`.
pub const NIX_STORE_TAG: &str = "nix-store";

/// Canonical VirtioFS share tag for the content-addressed host `sccache`.
pub const SCCACHE_TAG: &str = "sccache";

/// Canonical VirtioFS share tag for the read-only host repository worktree.
pub const WORKTREE_TAG: &str = "worktree";

/// Canonical VirtioFS share tag for the scoped read-only release signing lease directory.
pub const RELEASE_SIGNING_TAG: &str = "release-signing";

/// Canonical Nix store path inside host/guest filesystems.
pub const CANONICAL_NIX_STORE_PATH: &str = "/nix/store";

const MAX_VM_NAME_LEN: usize = 128;
const MAX_MOUNT_PATH_LEN: usize = 1024;
const DEFAULT_BOOT_READY_ATTEMPTS: u32 = 60;
const DEFAULT_BOOT_READY_POLL_MS: u64 = 250;
const MAX_CAPTURED_TART_STDERR_BYTES: usize = 64 * 1024;

const TRUSTED_TART_BINARY_PATHS: &[&str] = &[
    "/opt/homebrew/bin/tart",
    "/usr/local/bin/tart",
    "/usr/bin/tart",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CleanroomVmError {
    #[error(
        "invalid VM identifier `{0}`: must be 1..=128 ASCII [A-Za-z0-9._-] and not start with '-' or '.'"
    )]
    InvalidVmName(String),
    #[error("ephemeral run VM name must differ from base image `{0}`")]
    RunNameMatchesBaseImage(String),
    #[error("invalid VirtioFS share tag `{0}`")]
    InvalidShareTag(String),
    #[error(
        "invalid or unsafe VirtioFS host path `{0}`: must be normalized >=3-component non-symlink directory owned by root or current user"
    )]
    InvalidMountPath(String),
    #[error(
        "cleanroom VirtioFS share `{0}` must be mounted strictly read-only (:ro) per INV-NIX-RO-STORE-01"
    )]
    WritableMountForbidden(String),
    #[error("cleanroom Tart execution must run headless (--no-graphics)")]
    GraphicsForbidden,
    #[error("invalid CPU ({cpu_cores}) or memory ({memory_mib} MiB) bounds for ephemeral VM")]
    InvalidResourceBounds { cpu_cores: u8, memory_mib: u32 },
    #[error("invalid Softnet egress CIDR `{0}`")]
    InvalidEgressCidr(String),
    #[error(
        "VirtioFS mount latency {observed_ms}ms exceeded budget {budget_ms}ms (INV-NIX-VIRTIOFS-01)"
    )]
    MountLatencyExceeded { observed_ms: u64, budget_ms: u64 },
    #[error("cleanroom guest command cannot be empty")]
    EmptyGuestCommand,
    #[error("invalid guest command or sanitized environment entry: {0}")]
    InvalidGuestCommand(String),
    #[error("untrusted or invalid `tart` executable `{path}`: {reason}")]
    InvalidTartExecutable { path: String, reason: String },
    #[error("tart subcommand `{step}` failed: {detail}")]
    TartExecutionFailed { step: &'static str, detail: String },
}

/// VirtioFS mount permission mode. Cleanroom host cache/store mounts fail closed on `ReadWrite`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VirtioFsAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVirtioFsMount {
    tag: String,
    host_path: PathBuf,
    #[serde(default)]
    access: Option<VirtioFsAccess>,
}

/// Validated VirtioFS directory share passed to `tart run --dir=<tag>:<path>:ro`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawVirtioFsMount")]
pub struct VirtioFsMount {
    tag: String,
    host_path: PathBuf,
}

impl TryFrom<RawVirtioFsMount> for VirtioFsMount {
    type Error = CleanroomVmError;

    fn try_from(raw: RawVirtioFsMount) -> Result<Self, Self::Error> {
        Self::read_only(
            &raw.tag,
            &raw.host_path,
            raw.access.unwrap_or(VirtioFsAccess::ReadOnly),
        )
    }
}

impl VirtioFsMount {
    /// Construct a strictly read-only VirtioFS mount (`INV-NIX-VIRTIOFS-01` & `INV-NIX-RO-STORE-01`).
    pub fn read_only(
        tag: &str,
        host_path: impl AsRef<Path>,
        requested_access: VirtioFsAccess,
    ) -> Result<Self, CleanroomVmError> {
        validate_share_tag(tag)?;
        if requested_access != VirtioFsAccess::ReadOnly {
            return Err(CleanroomVmError::WritableMountForbidden(tag.to_owned()));
        }
        let validated = validate_clean_abs_path(host_path.as_ref())?;
        Ok(Self {
            tag: tag.to_owned(),
            host_path: validated,
        })
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn host_path(&self) -> &Path {
        &self.host_path
    }

    /// Formats the exact `--dir=<tag>:<path>:ro` argument with zero shell interpolation.
    pub fn to_tart_dir_arg(&self) -> String {
        format!("--dir={}:{}:ro", self.tag, self.host_path.display())
    }
}

fn default_cpu_cores() -> u8 {
    4
}

fn default_memory_mib() -> u32 {
    8192
}

fn default_no_graphics() -> bool {
    true
}

fn default_mount_budget() -> u64 {
    MAX_VIRTIOFS_MOUNT_LATENCY_MS
}

fn default_boot_attempts() -> u32 {
    DEFAULT_BOOT_READY_ATTEMPTS
}

fn default_boot_poll_ms() -> u64 {
    DEFAULT_BOOT_READY_POLL_MS
}

fn default_network_policy() -> NetworkEgressPolicy {
    NetworkEgressPolicy::RegistriesAndBinaryCacheOnly
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTartCleanroomSpec {
    base_image: String,
    run_vm_name: String,
    nix_store_mount: VirtioFsMount,
    sccache_mount: VirtioFsMount,
    #[serde(default)]
    extra_ro_mounts: Vec<VirtioFsMount>,
    #[serde(default = "default_cpu_cores")]
    cpu_cores: u8,
    #[serde(default = "default_memory_mib")]
    memory_mib: u32,
    #[serde(default = "default_no_graphics")]
    no_graphics: bool,
    #[serde(default = "default_network_policy")]
    network_policy: NetworkEgressPolicy,
    #[serde(default)]
    allowed_egress_cidrs: Vec<String>,
    #[serde(default = "default_mount_budget")]
    mount_latency_budget_ms: u64,
    #[serde(default = "default_boot_attempts")]
    boot_ready_attempts: u32,
    #[serde(default = "default_boot_poll_ms")]
    boot_ready_poll_ms: u64,
}

/// Complete validated specification for an ephemeral Tart cleanroom VM run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawTartCleanroomSpec")]
pub struct TartCleanroomSpec {
    base_image: String,
    run_vm_name: String,
    nix_store_mount: VirtioFsMount,
    sccache_mount: VirtioFsMount,
    extra_ro_mounts: Vec<VirtioFsMount>,
    cpu_cores: u8,
    memory_mib: u32,
    no_graphics: bool,
    network_policy: NetworkEgressPolicy,
    allowed_egress_cidrs: Vec<String>,
    mount_latency_budget_ms: u64,
    boot_ready_attempts: u32,
    boot_ready_poll_ms: u64,
}

impl TryFrom<RawTartCleanroomSpec> for TartCleanroomSpec {
    type Error = CleanroomVmError;

    fn try_from(raw: RawTartCleanroomSpec) -> Result<Self, Self::Error> {
        if raw.nix_store_mount.tag() != NIX_STORE_TAG {
            return Err(CleanroomVmError::InvalidShareTag(
                raw.nix_store_mount.tag().to_owned(),
            ));
        }
        if raw.sccache_mount.tag() != SCCACHE_TAG {
            return Err(CleanroomVmError::InvalidShareTag(
                raw.sccache_mount.tag().to_owned(),
            ));
        }
        let mut spec = Self::new(
            &raw.base_image,
            &raw.run_vm_name,
            raw.nix_store_mount.host_path(),
            raw.sccache_mount.host_path(),
        )?
        .with_resources(raw.cpu_cores, raw.memory_mib)?
        .with_graphics_enabled(!raw.no_graphics)?
        .with_network_egress(raw.network_policy, raw.allowed_egress_cidrs)?
        .with_boot_readiness(raw.boot_ready_attempts, raw.boot_ready_poll_ms);
        if raw.mount_latency_budget_ms == 0
            || raw.mount_latency_budget_ms > MAX_VIRTIOFS_MOUNT_LATENCY_MS
        {
            return Err(CleanroomVmError::MountLatencyExceeded {
                observed_ms: raw.mount_latency_budget_ms,
                budget_ms: MAX_VIRTIOFS_MOUNT_LATENCY_MS,
            });
        }
        spec.mount_latency_budget_ms = raw.mount_latency_budget_ms;
        for extra in raw.extra_ro_mounts {
            spec = spec.with_extra_ro_mount(extra)?;
        }
        Ok(spec)
    }
}

impl TartCleanroomSpec {
    pub fn new(
        base_image: &str,
        run_vm_name: &str,
        nix_store_host_path: impl AsRef<Path>,
        sccache_host_path: impl AsRef<Path>,
    ) -> Result<Self, CleanroomVmError> {
        validate_vm_name(base_image)?;
        validate_vm_name(run_vm_name)?;
        if base_image == run_vm_name {
            return Err(CleanroomVmError::RunNameMatchesBaseImage(
                base_image.to_owned(),
            ));
        }
        let nix_store_mount =
            VirtioFsMount::read_only(NIX_STORE_TAG, nix_store_host_path, VirtioFsAccess::ReadOnly)?;
        let sccache_mount =
            VirtioFsMount::read_only(SCCACHE_TAG, sccache_host_path, VirtioFsAccess::ReadOnly)?;
        Ok(Self {
            base_image: base_image.to_owned(),
            run_vm_name: run_vm_name.to_owned(),
            nix_store_mount,
            sccache_mount,
            extra_ro_mounts: Vec::new(),
            cpu_cores: 4,
            memory_mib: 8192,
            no_graphics: true,
            network_policy: NetworkEgressPolicy::RegistriesAndBinaryCacheOnly,
            allowed_egress_cidrs: Vec::new(),
            mount_latency_budget_ms: MAX_VIRTIOFS_MOUNT_LATENCY_MS,
            boot_ready_attempts: DEFAULT_BOOT_READY_ATTEMPTS,
            boot_ready_poll_ms: DEFAULT_BOOT_READY_POLL_MS,
        })
    }

    pub fn with_resources(
        mut self,
        cpu_cores: u8,
        memory_mib: u32,
    ) -> Result<Self, CleanroomVmError> {
        if !(1..=32).contains(&cpu_cores) || !(2048..=131_072).contains(&memory_mib) {
            return Err(CleanroomVmError::InvalidResourceBounds {
                cpu_cores,
                memory_mib,
            });
        }
        self.cpu_cores = cpu_cores;
        self.memory_mib = memory_mib;
        Ok(self)
    }

    pub fn with_network_egress(
        mut self,
        policy: NetworkEgressPolicy,
        cidrs: Vec<String>,
    ) -> Result<Self, CleanroomVmError> {
        for cidr in &cidrs {
            validate_cidr_spec(cidr)?;
        }
        self.network_policy = policy;
        self.allowed_egress_cidrs = cidrs;
        Ok(self)
    }

    pub fn with_boot_readiness(mut self, max_attempts: u32, poll_interval_ms: u64) -> Self {
        self.boot_ready_attempts = max_attempts.max(1);
        self.boot_ready_poll_ms = poll_interval_ms;
        self
    }

    pub fn with_graphics_enabled(self, enabled: bool) -> Result<Self, CleanroomVmError> {
        if enabled {
            return Err(CleanroomVmError::GraphicsForbidden);
        }
        Ok(self)
    }

    pub fn with_extra_ro_mount(mut self, mount: VirtioFsMount) -> Result<Self, CleanroomVmError> {
        if mount.tag == NIX_STORE_TAG
            || mount.tag == SCCACHE_TAG
            || self.extra_ro_mounts.iter().any(|m| m.tag == mount.tag)
        {
            return Err(CleanroomVmError::InvalidShareTag(mount.tag));
        }
        self.extra_ro_mounts.push(mount);
        Ok(self)
    }

    /// Verifies on the live host filesystem that every configured VirtioFS `host_path`
    /// traverses exclusively non-symlink directories owned by `root` (`uid 0`) or `geteuid()`.
    pub fn verify_host_mounts(&self) -> Result<(), CleanroomVmError> {
        verify_host_mount_directory(self.nix_store_mount.host_path())?;
        verify_host_mount_directory(self.sccache_mount.host_path())?;
        for extra in &self.extra_ro_mounts {
            verify_host_mount_directory(extra.host_path())?;
        }
        Ok(())
    }

    pub fn base_image(&self) -> &str {
        &self.base_image
    }

    pub fn run_vm_name(&self) -> &str {
        &self.run_vm_name
    }

    pub fn nix_store_mount(&self) -> &VirtioFsMount {
        &self.nix_store_mount
    }

    pub fn sccache_mount(&self) -> &VirtioFsMount {
        &self.sccache_mount
    }

    pub fn extra_ro_mounts(&self) -> &[VirtioFsMount] {
        &self.extra_ro_mounts
    }

    pub const fn network_policy(&self) -> NetworkEgressPolicy {
        self.network_policy
    }

    pub fn allowed_egress_cidrs(&self) -> &[String] {
        &self.allowed_egress_cidrs
    }

    pub fn cpu_cores(&self) -> u8 {
        self.cpu_cores
    }

    pub fn memory_mib(&self) -> u32 {
        self.memory_mib
    }

    pub fn mount_latency_budget_ms(&self) -> u64 {
        self.mount_latency_budget_ms
    }

    /// Enforce `<200ms` VirtioFS mount latency SLA (`INV-NIX-VIRTIOFS-01`).
    pub fn check_mount_latency(&self, observed_ms: u64) -> Result<(), CleanroomVmError> {
        if observed_ms > self.mount_latency_budget_ms {
            return Err(CleanroomVmError::MountLatencyExceeded {
                observed_ms,
                budget_ms: self.mount_latency_budget_ms,
            });
        }
        Ok(())
    }

    /// Exact `tart clone <base> <run-vm>` argument vector.
    pub fn clone_argv(&self) -> Vec<String> {
        vec![
            "clone".to_owned(),
            self.base_image.clone(),
            self.run_vm_name.clone(),
        ]
    }

    /// Exact `tart set <run-vm> --cpu <cores> --memory <mib>` argument vector.
    pub fn set_resources_argv(&self) -> Vec<String> {
        vec![
            "set".to_owned(),
            self.run_vm_name.clone(),
            "--cpu".to_owned(),
            self.cpu_cores.to_string(),
            "--memory".to_owned(),
            self.memory_mib.to_string(),
        ]
    }

    /// Exact `tart run --no-graphics --no-clipboard --no-audio --net-softnet [--net-softnet-allow=...] --dir=...:ro <run-vm>` argv.
    pub fn run_argv(&self) -> Vec<String> {
        let mut args = vec![
            "run".to_owned(),
            "--no-graphics".to_owned(),
            "--no-clipboard".to_owned(),
            "--no-audio".to_owned(),
            "--net-softnet".to_owned(),
        ];
        if self.network_policy == NetworkEgressPolicy::Offline {
            args.push("--net-softnet-allow=127.0.0.1/32".to_owned());
        } else if !self.allowed_egress_cidrs.is_empty() {
            args.push(format!(
                "--net-softnet-allow={}",
                self.allowed_egress_cidrs.join(",")
            ));
        }
        args.push(self.nix_store_mount.to_tart_dir_arg());
        args.push(self.sccache_mount.to_tart_dir_arg());
        for extra in &self.extra_ro_mounts {
            args.push(extra.to_tart_dir_arg());
        }
        args.push(self.run_vm_name.clone());
        args
    }

    /// Exact `tart exec <run-vm> -- /usr/bin/true` guest-agent readiness probe argument vector.
    pub fn guest_readiness_argv(&self) -> Vec<String> {
        vec![
            "exec".to_owned(),
            self.run_vm_name.clone(),
            "--".to_owned(),
            "/usr/bin/true".to_owned(),
        ]
    }

    /// Exact `tart exec <run-vm> -- /usr/bin/sandbox-exec -p <sbpl> -- /usr/bin/env -i <guest_command...>` argv
    /// with an empty sanitized environment.
    pub fn guest_sandbox_exec_argv(
        &self,
        seatbelt: &SeatbeltProfile,
        guest_command: &[String],
    ) -> Result<Vec<String>, CleanroomVmError> {
        self.guest_sandbox_exec_with_env_argv(seatbelt, &BTreeMap::new(), guest_command)
    }

    /// Exact `tart exec <run-vm> -- /usr/bin/sandbox-exec -p <sbpl> -- /usr/bin/env -i K=V ... <guest_command...>` argv
    /// applying both XNU Seatbelt and a scrubbed `/usr/bin/env -i` allowlist inside the guest.
    pub fn guest_sandbox_exec_with_env_argv(
        &self,
        seatbelt: &SeatbeltProfile,
        sanitized_env: &BTreeMap<String, String>,
        guest_command: &[String],
    ) -> Result<Vec<String>, CleanroomVmError> {
        if guest_command.is_empty() || guest_command[0].trim().is_empty() {
            return Err(CleanroomVmError::EmptyGuestCommand);
        }
        let prog = &guest_command[0];
        if prog.starts_with('-') || prog.contains('=') {
            return Err(CleanroomVmError::InvalidGuestCommand(format!(
                "guest executable `{prog}` cannot start with '-' or contain '='"
            )));
        }
        for arg in guest_command {
            if arg.contains('\0') {
                return Err(CleanroomVmError::InvalidGuestCommand(
                    "guest command argument contains NUL byte".to_owned(),
                ));
            }
        }
        for (k, v) in sanitized_env {
            if !is_valid_env_key(k) {
                return Err(CleanroomVmError::InvalidGuestCommand(format!(
                    "invalid sanitized environment variable name `{k}`"
                )));
            }
            if v.contains('\0') {
                return Err(CleanroomVmError::InvalidGuestCommand(format!(
                    "sanitized environment variable `{k}` contains NUL byte"
                )));
            }
        }

        let mut argv = Vec::with_capacity(9 + sanitized_env.len() + guest_command.len());
        argv.push("exec".to_owned());
        argv.push(self.run_vm_name.clone());
        argv.push("--".to_owned());
        argv.push("/usr/bin/sandbox-exec".to_owned());
        argv.push("-p".to_owned());
        argv.push(seatbelt.sbpl.clone());
        argv.push("--".to_owned());
        argv.push("/usr/bin/env".to_owned());
        argv.push("-i".to_owned());
        for (k, v) in sanitized_env {
            argv.push(format!("{k}={v}"));
        }
        argv.extend(guest_command.iter().cloned());
        Ok(argv)
    }

    /// Exact `tart stop <run-vm>` shutdown argument vector.
    pub fn stop_argv(&self) -> Vec<String> {
        vec!["stop".to_owned(), self.run_vm_name.clone()]
    }

    /// Exact `tart delete <run-vm>` cleanup argument vector.
    pub fn delete_argv(&self) -> Vec<String> {
        vec!["delete".to_owned(), self.run_vm_name.clone()]
    }
}

/// Runtime startup and VirtioFS mount telemetry captured during `EphemeralTartSession`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanroomStartupTelemetry {
    pub mount_latency_ms: u64,
    pub mount_budget_ms: u64,
    pub boot_ready_ms: u64,
    pub readiness_attempts: u32,
}

/// Recorded command execution trace for deterministic audit & testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TartCommandRecord {
    pub step: String,
    pub argv: Vec<String>,
}

/// Handle to a concurrently running `tart run --no-graphics ...` hypervisor process.
pub trait RunningTartVm {
    /// Non-blocking check for premature hypervisor exit.
    fn try_poll_exited(&mut self) -> Result<Option<Result<(), String>>, CleanroomVmError>;

    /// Reaps the background `tart run` process (killing + waiting if still alive after `tart stop`).
    fn reap(&mut self) -> Result<(), CleanroomVmError>;
}

/// Abstract executor for `tart` hypervisor operations.
pub trait TartExecutor {
    /// Live host preflight hook called before cloning/mounting.
    fn validate_live_mounts(&self, spec: &TartCleanroomSpec) -> Result<(), CleanroomVmError> {
        let _ = spec;
        Ok(())
    }

    fn exec_tart(&mut self, step: &'static str, argv: &[String]) -> Result<(), CleanroomVmError>;

    fn spawn_tart_run(
        &mut self,
        argv: &[String],
    ) -> Result<Box<dyn RunningTartVm>, CleanroomVmError>;
}

struct ProcessRunningTartVm {
    child: Option<Child>,
    stderr_reader: Option<JoinHandle<String>>,
}

impl ProcessRunningTartVm {
    fn join_stderr(&mut self) -> String {
        match self.stderr_reader.take() {
            Some(handle) => handle.join().unwrap_or_default().trim().to_owned(),
            None => String::new(),
        }
    }
}

impl RunningTartVm for ProcessRunningTartVm {
    fn try_poll_exited(&mut self) -> Result<Option<Result<(), String>>, CleanroomVmError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(Some(Ok(())));
        };
        match child.try_wait() {
            Ok(None) => Ok(None),
            Ok(Some(status)) => {
                let _ = self.child.take();
                let stderr = self.join_stderr();
                if status.success() {
                    Ok(Some(Ok(())))
                } else {
                    let detail = if stderr.is_empty() {
                        format!("exit status {status}")
                    } else {
                        stderr
                    };
                    Ok(Some(Err(detail)))
                }
            }
            Err(e) => Err(CleanroomVmError::TartExecutionFailed {
                step: "run",
                detail: e.to_string(),
            }),
        }
    }

    fn reap(&mut self) -> Result<(), CleanroomVmError> {
        let Some(mut child) = self.child.take() else {
            let _ = self.join_stderr();
            return Ok(());
        };
        for _ in 0..40 {
            match child.try_wait() {
                Ok(Some(_)) => {
                    let _ = self.join_stderr();
                    return Ok(());
                }
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = self.join_stderr();
                    return Err(CleanroomVmError::TartExecutionFailed {
                        step: "reap-run",
                        detail: e.to_string(),
                    });
                }
            }
        }
        let _ = child.kill();
        let wait_res = child.wait();
        let _ = self.join_stderr();
        wait_res
            .map(|_| ())
            .map_err(|e| CleanroomVmError::TartExecutionFailed {
                step: "reap-run",
                detail: e.to_string(),
            })
    }
}

impl Drop for ProcessRunningTartVm {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = self.join_stderr();
    }
}

fn spawn_bounded_stderr_drain(mut pipe: std::process::ChildStderr) -> JoinHandle<String> {
    thread::spawn(move || {
        let mut captured: Vec<u8> = Vec::with_capacity(4096);
        let mut truncated = false;
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if captured.len() < MAX_CAPTURED_TART_STDERR_BYTES {
                        let avail = MAX_CAPTURED_TART_STDERR_BYTES - captured.len();
                        let copy_len = n.min(avail);
                        captured.extend_from_slice(&chunk[..copy_len]);
                        if copy_len < n {
                            truncated = true;
                        }
                    } else {
                        truncated = true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let mut text = String::from_utf8_lossy(&captured).into_owned();
        if truncated {
            text.push_str("\n...[truncated tart stderr]");
        }
        text
    })
}

/// Subprocess executor invoking an explicit validated absolute `tart` binary path
/// (or resolving strictly across fixed root-owned system directories, rejecting relative `PATH`).
#[derive(Debug, Clone, Default)]
pub struct ProcessTartExecutor {
    executable: Option<PathBuf>,
}

impl ProcessTartExecutor {
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        let p = executable.into();
        if p == Path::new("tart") {
            Self { executable: None }
        } else {
            Self {
                executable: Some(p),
            }
        }
    }

    fn resolve_verified_executable(&self) -> Result<PathBuf, CleanroomVmError> {
        match self.executable {
            Some(ref explicit) => {
                verify_trusted_executable_path(explicit)?;
                Ok(explicit.clone())
            }
            None => {
                for candidate in TRUSTED_TART_BINARY_PATHS {
                    let p = Path::new(candidate);
                    if p.exists() && verify_trusted_executable_path(p).is_ok() {
                        return Ok(p.to_path_buf());
                    }
                }
                Err(CleanroomVmError::InvalidTartExecutable {
                    path: "tart".to_owned(),
                    reason: format!(
                        "no verified non-symlink tart binary found in trusted system directories {:?}",
                        TRUSTED_TART_BINARY_PATHS
                    ),
                })
            }
        }
    }

    fn scrubbed_command(&self, argv: &[String]) -> Result<Command, CleanroomVmError> {
        let verified_bin = self.resolve_verified_executable()?;
        let mut cmd = Command::new(verified_bin);
        cmd.args(argv)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        for key in ["HOME", "TMPDIR", "USER", "LOGNAME"] {
            if let Some(val) = std::env::var_os(key) {
                cmd.env(key, val);
            }
        }
        Ok(cmd)
    }
}

impl TartExecutor for ProcessTartExecutor {
    fn validate_live_mounts(&self, spec: &TartCleanroomSpec) -> Result<(), CleanroomVmError> {
        spec.verify_host_mounts()
    }

    fn exec_tart(&mut self, step: &'static str, argv: &[String]) -> Result<(), CleanroomVmError> {
        let mut cmd = self.scrubbed_command(argv)?;
        let output = cmd
            .output()
            .map_err(|e| CleanroomVmError::TartExecutionFailed {
                step,
                detail: e.to_string(),
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(CleanroomVmError::TartExecutionFailed {
                step,
                detail: if stderr.is_empty() {
                    format!("exit status {}", output.status)
                } else {
                    stderr
                },
            });
        }
        Ok(())
    }

    fn spawn_tart_run(
        &mut self,
        argv: &[String],
    ) -> Result<Box<dyn RunningTartVm>, CleanroomVmError> {
        let mut cmd = self.scrubbed_command(argv)?;
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CleanroomVmError::TartExecutionFailed {
                step: "run",
                detail: e.to_string(),
            })?;
        let stderr_reader = child.stderr.take().map(spawn_bounded_stderr_drain);
        Ok(Box::new(ProcessRunningTartVm {
            child: Some(child),
            stderr_reader,
        }))
    }
}

/// RAII ephemeral cleanroom session guaranteeing `defer tart delete <run-vm>` runs
/// deterministically on normal completion, error, or panic unwind (`Drop`).
pub struct EphemeralTartSession<E: TartExecutor> {
    spec: TartCleanroomSpec,
    executor: Option<E>,
    cloned: bool,
    deleted: bool,
    startup_telemetry: Option<CleanroomStartupTelemetry>,
}

impl<E: TartExecutor> EphemeralTartSession<E> {
    /// Verifies live host mounts (when backed by `ProcessTartExecutor`), clones
    /// `<base>` -> `<run-vm>`, configures CPU/RAM bounds, and arms the deterministic
    /// `tart delete` guard immediately upon clone creation.
    pub fn clone_and_arm(
        spec: TartCleanroomSpec,
        mut executor: E,
    ) -> Result<Self, CleanroomVmError> {
        executor.validate_live_mounts(&spec)?;
        let clone_argv = spec.clone_argv();
        executor.exec_tart("clone", &clone_argv)?;
        let mut session = Self {
            spec,
            executor: Some(executor),
            cloned: true,
            deleted: false,
            startup_telemetry: None,
        };
        let set_argv = session.spec.set_resources_argv();
        if let Some(exec) = session.executor.as_mut() {
            exec.exec_tart("set", &set_argv)?;
        }
        Ok(session)
    }

    pub fn spec(&self) -> &TartCleanroomSpec {
        &self.spec
    }

    pub const fn startup_telemetry(&self) -> Option<CleanroomStartupTelemetry> {
        self.startup_telemetry
    }

    /// Runs `guest_command` with an empty `/usr/bin/env -i` environment under XNU Seatbelt.
    pub fn run_ephemeral_with_seatbelt(
        &mut self,
        seatbelt: &SeatbeltProfile,
        guest_command: &[String],
    ) -> Result<(), CleanroomVmError> {
        self.run_ephemeral_with_seatbelt_and_env(seatbelt, &BTreeMap::new(), guest_command)
    }

    /// Spawns the headless cleanroom VM (`tart run`) in the background, enforces the
    /// `<200ms` VirtioFS mount startup SLA (`check_mount_latency`), waits for guest
    /// readiness (`tart exec <vm> -- /usr/bin/true`), executes `guest_command` inside the
    /// live running VM under `/usr/bin/sandbox-exec -p <sbpl> -- /usr/bin/env -i ...`,
    /// issues `tart stop <vm>` + reaps the hypervisor handle, and guarantees `defer tart delete`.
    pub fn run_ephemeral_with_seatbelt_and_env(
        &mut self,
        seatbelt: &SeatbeltProfile,
        sanitized_env: &BTreeMap<String, String>,
        guest_command: &[String],
    ) -> Result<(), CleanroomVmError> {
        let exec_argv =
            self.spec
                .guest_sandbox_exec_with_env_argv(seatbelt, sanitized_env, guest_command)?;
        let run_argv = self.spec.run_argv();
        let readiness_argv = self.spec.guest_readiness_argv();
        let stop_argv = self.spec.stop_argv();
        let max_attempts = self.spec.boot_ready_attempts.max(1);
        let poll_ms = self.spec.boot_ready_poll_ms;

        let exec = self
            .executor
            .as_mut()
            .ok_or_else(|| CleanroomVmError::TartExecutionFailed {
                step: "run",
                detail: "session already finalized".to_owned(),
            })?;

        let mount_start = Instant::now();
        let mut running_vm = exec.spawn_tart_run(&run_argv)?;
        let mount_latency_ms = mount_start.elapsed().as_millis() as u64;
        if let Err(lat_err) = self.spec.check_mount_latency(mount_latency_ms) {
            let _ = exec.exec_tart("stop", &stop_argv);
            let _ = running_vm.reap();
            return Err(lat_err);
        }

        let ready_start = Instant::now();
        let mut readiness_attempts = 0u32;
        let mut readiness_res: Result<(), CleanroomVmError> = Ok(());
        for attempt in 1..=max_attempts {
            readiness_attempts = attempt;
            if let Some(exit_state) = running_vm.try_poll_exited()? {
                let _ = running_vm.reap();
                let detail = match exit_state {
                    Ok(()) => "tart run exited prematurely before guest workload".to_owned(),
                    Err(msg) => msg,
                };
                return Err(CleanroomVmError::TartExecutionFailed {
                    step: "run",
                    detail,
                });
            }
            match exec.exec_tart("wait-ready", &readiness_argv) {
                Ok(()) => {
                    readiness_res = Ok(());
                    break;
                }
                Err(err) => {
                    readiness_res = Err(err);
                    if attempt < max_attempts && poll_ms > 0 {
                        thread::sleep(Duration::from_millis(poll_ms));
                    }
                }
            }
        }

        if let Err(ready_err) = readiness_res {
            let _ = exec.exec_tart("stop", &stop_argv);
            let _ = running_vm.reap();
            return Err(ready_err);
        }

        self.startup_telemetry = Some(CleanroomStartupTelemetry {
            mount_latency_ms,
            mount_budget_ms: self.spec.mount_latency_budget_ms,
            boot_ready_ms: ready_start.elapsed().as_millis() as u64,
            readiness_attempts,
        });

        if let Some(exit_state) = running_vm.try_poll_exited()? {
            let _ = running_vm.reap();
            let detail = match exit_state {
                Ok(()) => "tart run exited before guest sandbox-exec".to_owned(),
                Err(msg) => msg,
            };
            return Err(CleanroomVmError::TartExecutionFailed {
                step: "run",
                detail,
            });
        }

        let workload_res = exec.exec_tart("exec", &exec_argv);
        let stop_res = exec.exec_tart("stop", &stop_argv);
        let reap_res = running_vm.reap();

        workload_res.and(stop_res).and(reap_res)
    }

    /// Explicitly destroys the ephemeral VM and returns any underlying executor + teardown result.
    pub fn finish(mut self) -> (Option<E>, Result<(), CleanroomVmError>) {
        let delete_res = self.delete_now();
        self.cloned = false;
        self.deleted = true;
        (self.executor.take(), delete_res)
    }

    fn delete_now(&mut self) -> Result<(), CleanroomVmError> {
        if self.cloned && !self.deleted {
            let delete_argv = self.spec.delete_argv();
            self.deleted = true;
            if let Some(exec) = self.executor.as_mut() {
                return exec.exec_tart("delete", &delete_argv);
            }
        }
        Ok(())
    }
}

impl<E: TartExecutor> Drop for EphemeralTartSession<E> {
    fn drop(&mut self) {
        let _ = self.delete_now();
    }
}

fn is_valid_env_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn validate_cidr_spec(cidr: &str) -> Result<(), CleanroomVmError> {
    if cidr.is_empty()
        || cidr.len() > 64
        || cidr.starts_with('-')
        || cidr
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == ',')
    {
        return Err(CleanroomVmError::InvalidEgressCidr(cidr.to_owned()));
    }
    let Some((ip_part, prefix_part)) = cidr.split_once('/') else {
        return Err(CleanroomVmError::InvalidEgressCidr(cidr.to_owned()));
    };
    let ip: IpAddr = ip_part
        .parse()
        .map_err(|_| CleanroomVmError::InvalidEgressCidr(cidr.to_owned()))?;
    let prefix: u8 = prefix_part
        .parse()
        .map_err(|_| CleanroomVmError::InvalidEgressCidr(cidr.to_owned()))?;
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(CleanroomVmError::InvalidEgressCidr(cidr.to_owned()));
    }
    Ok(())
}

fn validate_vm_name(name: &str) -> Result<(), CleanroomVmError> {
    if name.is_empty()
        || name.len() > MAX_VM_NAME_LEN
        || name.starts_with('-')
        || name.starts_with('.')
        || name.ends_with('.')
        || name.contains("..")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(CleanroomVmError::InvalidVmName(name.to_owned()));
    }
    Ok(())
}

fn validate_share_tag(tag: &str) -> Result<(), CleanroomVmError> {
    if tag.is_empty()
        || tag.len() > 64
        || tag.starts_with('-')
        || !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(CleanroomVmError::InvalidShareTag(tag.to_owned()));
    }
    Ok(())
}

fn validate_clean_abs_path(path: &Path) -> Result<PathBuf, CleanroomVmError> {
    let text = path
        .to_str()
        .ok_or_else(|| CleanroomVmError::InvalidMountPath(path.display().to_string()))?;
    if text.is_empty()
        || text.len() > MAX_MOUNT_PATH_LEN
        || text.starts_with('-')
        || !path.is_absolute()
        || (text.len() > 1 && text.ends_with('/'))
        || text.contains("//")
        || text
            .chars()
            .any(|c| c.is_control() || matches!(c, ':' | ',' | '"' | '\'' | '\\'))
    {
        return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
    }

    let mut rebuilt = PathBuf::new();
    let mut normals: Vec<&str> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::RootDir => rebuilt.push("/"),
            Component::Normal(seg) => {
                let Some(s) = seg.to_str() else {
                    return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
                };
                if s.is_empty() {
                    return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
                }
                normals.push(s);
                rebuilt.push(seg);
            }
            Component::ParentDir | Component::CurDir | Component::Prefix(_) => {
                return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
            }
        }
    }

    // Require >= 3 total components (`/` + >= 2 Normal segments), blocking `/`, `/Users`, `/System`, `/Volumes`, `/private`, `/etc`, `/var`, `/tmp`
    if normals.len() < 2 || rebuilt.to_str() != Some(text) {
        return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
    }

    // Explicitly block sensitive or broad host trees even at depth >= 3
    let first = normals[0];
    let second = normals[1];
    if first == "System"
        || first == "Volumes"
        || first == "etc"
        || (first == "private" && second == "etc")
        || (first == "Library" && second == "Keychains")
        || (first == "var" && second == "root")
        || (first == "private" && second == "var" && normals.get(2) == Some(&"root"))
    {
        return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
    }
    if first == "Users" {
        // Block mounting an entire user home directory (`/Users/<user>`) or sensitive home subtrees
        if normals.len() < 3 {
            return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
        }
        let third = normals[2];
        if third.starts_with('.') || third == "Library" {
            return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
        }
    }

    Ok(rebuilt)
}

/// Verifies on the live host filesystem that every component of `path` is a non-symlink
/// directory owned by `root` (`uid 0`) or `geteuid()`.
pub fn verify_host_mount_directory(path: &Path) -> Result<PathBuf, CleanroomVmError> {
    let clean = validate_clean_abs_path(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let euid = rustix::process::geteuid().as_raw();
        let mut cursor = PathBuf::from("/");
        let root_meta = fs::symlink_metadata(&cursor)
            .map_err(|_| CleanroomVmError::InvalidMountPath(clean.display().to_string()))?;
        if root_meta.file_type().is_symlink() || !root_meta.is_dir() || root_meta.uid() != 0 {
            return Err(CleanroomVmError::InvalidMountPath(
                clean.display().to_string(),
            ));
        }

        for (idx, comp) in clean.components().enumerate() {
            let Component::Normal(seg) = comp else {
                continue;
            };
            cursor.push(seg);
            let meta = fs::symlink_metadata(&cursor)
                .map_err(|_| CleanroomVmError::InvalidMountPath(clean.display().to_string()))?;
            if meta.file_type().is_symlink() {
                // Allow only macOS's root-owned top-level `/var -> private/var` and `/tmp -> private/tmp` firmlinks
                if idx == 1 && meta.uid() == 0 && (seg == "var" || seg == "tmp") {
                    let target = fs::read_link(&cursor).map_err(|_| {
                        CleanroomVmError::InvalidMountPath(clean.display().to_string())
                    })?;
                    let expected_rel = if seg == "var" {
                        Path::new("private/var")
                    } else {
                        Path::new("private/tmp")
                    };
                    let expected_abs = Path::new("/").join(expected_rel);
                    if target == expected_rel || target == expected_abs {
                        let priv_meta = fs::symlink_metadata("/private").map_err(|_| {
                            CleanroomVmError::InvalidMountPath(clean.display().to_string())
                        })?;
                        if priv_meta.file_type().is_symlink()
                            || !priv_meta.is_dir()
                            || priv_meta.uid() != 0
                        {
                            return Err(CleanroomVmError::InvalidMountPath(
                                clean.display().to_string(),
                            ));
                        }
                        cursor = expected_abs;
                        let redirected_meta = fs::symlink_metadata(&cursor).map_err(|_| {
                            CleanroomVmError::InvalidMountPath(clean.display().to_string())
                        })?;
                        if redirected_meta.file_type().is_symlink()
                            || !redirected_meta.is_dir()
                            || redirected_meta.uid() != 0
                        {
                            return Err(CleanroomVmError::InvalidMountPath(
                                clean.display().to_string(),
                            ));
                        }
                        continue;
                    }
                }
                return Err(CleanroomVmError::InvalidMountPath(
                    clean.display().to_string(),
                ));
            }
            if !meta.is_dir() {
                return Err(CleanroomVmError::InvalidMountPath(
                    clean.display().to_string(),
                ));
            }
            let uid = meta.uid();
            if uid != 0 && uid != euid {
                return Err(CleanroomVmError::InvalidMountPath(
                    clean.display().to_string(),
                ));
            }
        }
        Ok(cursor)
    }
    #[cfg(not(unix))]
    {
        if !clean.is_dir() {
            return Err(CleanroomVmError::InvalidMountPath(
                clean.display().to_string(),
            ));
        }
        Ok(clean)
    }
}

/// Verifies that `bin_path` is an absolute, non-symlink regular executable file owned by
/// `root` (`uid 0`) or `geteuid()`, with zero group/world write permissions and trusted ancestors.
pub fn verify_trusted_executable_path(bin_path: &Path) -> Result<(), CleanroomVmError> {
    let display = bin_path.display().to_string();
    let Some(text) = bin_path.to_str() else {
        return Err(CleanroomVmError::InvalidTartExecutable {
            path: display,
            reason: "executable path must be valid UTF-8".to_owned(),
        });
    };
    if text.is_empty() || !bin_path.is_absolute() || text.contains("//") || text.contains('\0') {
        return Err(CleanroomVmError::InvalidTartExecutable {
            path: display,
            reason: "executable path must be normalized absolute path (relative PATH rejected)"
                .to_owned(),
        });
    }
    for comp in bin_path.components() {
        if matches!(
            comp,
            Component::CurDir | Component::ParentDir | Component::Prefix(_)
        ) {
            return Err(CleanroomVmError::InvalidTartExecutable {
                path: display,
                reason: "relative `.` or `..` segments are forbidden".to_owned(),
            });
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let euid = rustix::process::geteuid().as_raw();
        let meta = fs::symlink_metadata(bin_path).map_err(|e| {
            CleanroomVmError::InvalidTartExecutable {
                path: display.clone(),
                reason: e.to_string(),
            }
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(CleanroomVmError::InvalidTartExecutable {
                path: display,
                reason: "executable must be a regular non-symlink file".to_owned(),
            });
        }
        let uid = meta.uid();
        if uid != 0 && uid != euid {
            return Err(CleanroomVmError::InvalidTartExecutable {
                path: display,
                reason: format!("executable owned by untrusted uid {uid}"),
            });
        }
        let mode = meta.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(CleanroomVmError::InvalidTartExecutable {
                path: display,
                reason: "file is not executable".to_owned(),
            });
        }
        if mode & 0o022 != 0 {
            return Err(CleanroomVmError::InvalidTartExecutable {
                path: display,
                reason: "executable must not be group- or world-writable".to_owned(),
            });
        }

        let Some(parent) = bin_path.parent() else {
            return Err(CleanroomVmError::InvalidTartExecutable {
                path: display,
                reason: "missing parent directory".to_owned(),
            });
        };
        let mut cursor = PathBuf::from("/");
        for (idx, comp) in parent.components().enumerate() {
            let Component::Normal(seg) = comp else {
                continue;
            };
            cursor.push(seg);
            let dir_meta = fs::symlink_metadata(&cursor).map_err(|e| {
                CleanroomVmError::InvalidTartExecutable {
                    path: display.clone(),
                    reason: e.to_string(),
                }
            })?;
            if dir_meta.file_type().is_symlink() {
                if idx == 1 && dir_meta.uid() == 0 && (seg == "var" || seg == "tmp") {
                    let target = fs::read_link(&cursor).map_err(|e| {
                        CleanroomVmError::InvalidTartExecutable {
                            path: display.clone(),
                            reason: e.to_string(),
                        }
                    })?;
                    let expected = if seg == "var" {
                        Path::new("private/var")
                    } else {
                        Path::new("private/tmp")
                    };
                    if target == expected {
                        cursor = Path::new("/").join(expected);
                        let redir_meta = fs::symlink_metadata(&cursor).map_err(|e| {
                            CleanroomVmError::InvalidTartExecutable {
                                path: display.clone(),
                                reason: e.to_string(),
                            }
                        })?;
                        if redir_meta.file_type().is_symlink()
                            || !redir_meta.is_dir()
                            || redir_meta.uid() != 0
                        {
                            return Err(CleanroomVmError::InvalidTartExecutable {
                                path: display,
                                reason: "invalid macOS /private firmlink target".to_owned(),
                            });
                        }
                        continue;
                    }
                }
                return Err(CleanroomVmError::InvalidTartExecutable {
                    path: display,
                    reason: "ancestor directory cannot be a symlink".to_owned(),
                });
            }
            if !dir_meta.is_dir() {
                return Err(CleanroomVmError::InvalidTartExecutable {
                    path: display,
                    reason: "ancestor component is not a directory".to_owned(),
                });
            }
            let d_uid = dir_meta.uid();
            if d_uid != 0 && d_uid != euid {
                return Err(CleanroomVmError::InvalidTartExecutable {
                    path: display,
                    reason: format!("ancestor directory owned by untrusted uid {d_uid}"),
                });
            }
            let d_mode = dir_meta.permissions().mode();
            if (d_mode & 0o002) != 0 && (d_mode & 0o1000) == 0 {
                return Err(CleanroomVmError::InvalidTartExecutable {
                    path: display,
                    reason: "ancestor directory is world-writable without sticky bit".to_owned(),
                });
            }
        }
    }
    Ok(())
}
