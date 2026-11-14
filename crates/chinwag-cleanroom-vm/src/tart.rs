// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Ephemeral Tart cleanroom VM lifecycle (`tart clone` -> background `tart run --no-graphics
//! --dir=nix-store:/nix/store:ro --dir=sccache:<cache>:ro` -> readiness probe ->
//! `tart exec <run-vm> /usr/bin/sandbox-exec -p <sbpl> -- <cmd...>` -> `tart stop` + reap ->
//! deterministic `defer tart delete`).
//!
//! Enforces `INV-NIX-VIRTIOFS-01` (sub-200ms read-only VirtioFS mount budget) and
//! `INV-NIX-RO-STORE-01` (hypervisor `:ro` tag enforcement + runtime guest Seatbelt).

use crate::seatbelt::SeatbeltProfile;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

/// Maximum permitted VirtioFS mount latency budget in milliseconds (`INV-NIX-VIRTIOFS-01`).
pub const MAX_VIRTIOFS_MOUNT_LATENCY_MS: u64 = 200;

/// Canonical VirtioFS share tag for the immutable host `/nix/store`.
pub const NIX_STORE_TAG: &str = "nix-store";

/// Canonical VirtioFS share tag for the content-addressed host `sccache`.
pub const SCCACHE_TAG: &str = "sccache";

/// Canonical Nix store path inside host/guest filesystems.
pub const CANONICAL_NIX_STORE_PATH: &str = "/nix/store";

const MAX_VM_NAME_LEN: usize = 128;
const MAX_MOUNT_PATH_LEN: usize = 1024;
const DEFAULT_BOOT_READY_ATTEMPTS: u32 = 60;
const DEFAULT_BOOT_READY_POLL_MS: u64 = 250;

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
        "invalid VirtioFS host path `{0}`: must be normalized absolute path without ':', ',', or control characters"
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
    #[error(
        "VirtioFS mount latency {observed_ms}ms exceeded budget {budget_ms}ms (INV-NIX-VIRTIOFS-01)"
    )]
    MountLatencyExceeded { observed_ms: u64, budget_ms: u64 },
    #[error("cleanroom guest command cannot be empty")]
    EmptyGuestCommand,
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

/// Validated VirtioFS directory share passed to `tart run --dir=<tag>:<path>:ro`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtioFsMount {
    tag: String,
    host_path: PathBuf,
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

/// Complete validated specification for an ephemeral Tart cleanroom VM run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TartCleanroomSpec {
    base_image: String,
    run_vm_name: String,
    nix_store_mount: VirtioFsMount,
    sccache_mount: VirtioFsMount,
    extra_ro_mounts: Vec<VirtioFsMount>,
    cpu_cores: u8,
    memory_mib: u32,
    no_graphics: bool,
    mount_latency_budget_ms: u64,
    boot_ready_attempts: u32,
    boot_ready_poll_ms: u64,
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

    /// Exact `tart run --no-graphics --dir=nix-store:<store>:ro --dir=sccache:<cache>:ro <run-vm>` argv.
    pub fn run_argv(&self) -> Vec<String> {
        let mut args = vec![
            "run".to_owned(),
            "--no-graphics".to_owned(),
            self.nix_store_mount.to_tart_dir_arg(),
            self.sccache_mount.to_tart_dir_arg(),
        ];
        for extra in &self.extra_ro_mounts {
            args.push(extra.to_tart_dir_arg());
        }
        args.push(self.run_vm_name.clone());
        args
    }

    /// Exact `tart exec <run-vm> /usr/bin/true` guest-agent readiness probe argument vector.
    pub fn guest_readiness_argv(&self) -> Vec<String> {
        vec![
            "exec".to_owned(),
            self.run_vm_name.clone(),
            "/usr/bin/true".to_owned(),
        ]
    }

    /// Exact `tart exec <run-vm> /usr/bin/sandbox-exec -p <sbpl> -- <guest_command...>` argv
    /// applying the compiled XNU Seatbelt profile at runtime inside the live guest (`INV-NIX-RO-STORE-01`).
    pub fn guest_sandbox_exec_argv(
        &self,
        seatbelt: &SeatbeltProfile,
        guest_command: &[String],
    ) -> Result<Vec<String>, CleanroomVmError> {
        if guest_command.is_empty() || guest_command[0].trim().is_empty() {
            return Err(CleanroomVmError::EmptyGuestCommand);
        }
        let mut argv = Vec::with_capacity(6 + guest_command.len());
        argv.push("exec".to_owned());
        argv.push(self.run_vm_name.clone());
        argv.push("/usr/bin/sandbox-exec".to_owned());
        argv.push("-p".to_owned());
        argv.push(seatbelt.sbpl.clone());
        argv.push("--".to_owned());
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

/// Recorded command execution trace for deterministic audit & testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TartCommandRecord {
    pub step: String,
    pub argv: Vec<String>,
}

/// Handle to a concurrently running `tart run --no-graphics ...` hypervisor process.
///
/// Because `tart run` blocks for the lifetime of the booted guest VM, `EphemeralTartSession`
/// spawns `tart run` in the background, probes guest readiness via `tart exec <vm> /usr/bin/true`,
/// runs the workload via `tart exec <vm> /usr/bin/sandbox-exec -p <sbpl> -- ...`, issues
/// `tart stop <vm>`, and reaps this handle before `tart delete <vm>`.
pub trait RunningTartVm {
    /// Non-blocking check for premature hypervisor exit.
    /// Returns `Ok(None)` while the VM is still running, `Ok(Some(Ok(())))` if it exited `0`,
    /// or `Ok(Some(Err(detail)))` if `tart run` exited non-zero.
    fn try_poll_exited(&mut self) -> Result<Option<Result<(), String>>, CleanroomVmError>;

    /// Reaps the background `tart run` process (killing + waiting if still alive after `tart stop`).
    fn reap(&mut self) -> Result<(), CleanroomVmError>;
}

/// Abstract executor for `tart` hypervisor operations.
pub trait TartExecutor {
    fn exec_tart(&mut self, step: &'static str, argv: &[String]) -> Result<(), CleanroomVmError>;

    fn spawn_tart_run(
        &mut self,
        argv: &[String],
    ) -> Result<Box<dyn RunningTartVm>, CleanroomVmError>;
}

struct ProcessRunningTartVm {
    child: Option<Child>,
}

impl ProcessRunningTartVm {
    fn collect_stderr(child: &mut Child) -> String {
        let mut buf = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut buf);
        }
        buf.trim().to_owned()
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
                let mut owned = self.child.take().expect("checked Some");
                let stderr = Self::collect_stderr(&mut owned);
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
            return Ok(());
        };
        // Allow brief grace window after `tart stop <vm>` before sending SIGKILL
        for _ in 0..40 {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CleanroomVmError::TartExecutionFailed {
                        step: "reap-run",
                        detail: e.to_string(),
                    });
                }
            }
        }
        let _ = child.kill();
        child
            .wait()
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
    }
}

/// Subprocess executor invoking an explicit customer-configured `tart` binary path
/// (or `"tart"` resolved via standard `PATH`) with a scrubbed environment.
#[derive(Debug, Clone)]
pub struct ProcessTartExecutor {
    executable: PathBuf,
}

impl ProcessTartExecutor {
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }

    fn scrubbed_command(&self, argv: &[String]) -> Command {
        let mut cmd = Command::new(&self.executable);
        cmd.args(argv).env_clear();
        for key in ["HOME", "PATH", "TMPDIR", "USER", "LOGNAME"] {
            if let Some(val) = std::env::var_os(key) {
                cmd.env(key, val);
            }
        }
        cmd
    }
}

impl Default for ProcessTartExecutor {
    fn default() -> Self {
        Self {
            executable: PathBuf::from("tart"),
        }
    }
}

impl TartExecutor for ProcessTartExecutor {
    fn exec_tart(&mut self, step: &'static str, argv: &[String]) -> Result<(), CleanroomVmError> {
        let output = self.scrubbed_command(argv).output().map_err(|e| {
            CleanroomVmError::TartExecutionFailed {
                step,
                detail: e.to_string(),
            }
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
        let child = self
            .scrubbed_command(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CleanroomVmError::TartExecutionFailed {
                step: "run",
                detail: e.to_string(),
            })?;
        Ok(Box::new(ProcessRunningTartVm { child: Some(child) }))
    }
}

/// RAII ephemeral cleanroom session guaranteeing `defer tart delete <run-vm>` runs
/// deterministically on normal completion, error, or panic unwind (`Drop`).
pub struct EphemeralTartSession<E: TartExecutor> {
    spec: TartCleanroomSpec,
    executor: Option<E>,
    cloned: bool,
    deleted: bool,
}

impl<E: TartExecutor> EphemeralTartSession<E> {
    /// Clones `<base>` -> `<run-vm>`, configures CPU/RAM bounds, and arms the
    /// deterministic `tart delete` guard immediately upon clone creation.
    pub fn clone_and_arm(
        spec: TartCleanroomSpec,
        mut executor: E,
    ) -> Result<Self, CleanroomVmError> {
        let clone_argv = spec.clone_argv();
        executor.exec_tart("clone", &clone_argv)?;
        let mut session = Self {
            spec,
            executor: Some(executor),
            cloned: true,
            deleted: false,
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

    /// Spawns the headless cleanroom VM (`tart run`) in the background, waits for guest
    /// readiness (`tart exec <vm> /usr/bin/true`), executes `guest_command` inside the
    /// live running VM under `/usr/bin/sandbox-exec -p <sbpl>`, issues `tart stop <vm>`
    /// + reaps the hypervisor handle, and guarantees `defer tart delete` on any failure.
    pub fn run_ephemeral_with_seatbelt(
        &mut self,
        seatbelt: &SeatbeltProfile,
        guest_command: &[String],
    ) -> Result<(), CleanroomVmError> {
        let exec_argv = self.spec.guest_sandbox_exec_argv(seatbelt, guest_command)?;
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

        let mut running_vm = exec.spawn_tart_run(&run_argv)?;

        let mut readiness_res: Result<(), CleanroomVmError> = Ok(());
        for attempt in 1..=max_attempts {
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
        || !path.is_absolute()
        || text
            .chars()
            .any(|c| c.is_control() || matches!(c, ':' | ',' | '"' | '\'' | '\\'))
    {
        return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir | Component::CurDir) {
            return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
        }
    }
    Ok(path.to_path_buf())
}
