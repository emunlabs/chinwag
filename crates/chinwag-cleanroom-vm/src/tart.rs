// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Ephemeral Tart cleanroom VM lifecycle (`tart clone` -> `tart run --no-graphics
//! --dir=nix-store:/nix/store:ro --dir=sccache:<cache>:ro` -> deterministic
//! `defer tart delete`).
//!
//! Enforces `INV-NIX-VIRTIOFS-01` (sub-200ms read-only VirtioFS mount budget) and
//! `INV-NIX-RO-STORE-01` (hypervisor `:ro` tag enforcement on `/nix/store` and `sccache`).

use crate::seatbelt::SeatbeltProfile;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

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

    /// Exact `tart exec <run-vm> /usr/bin/sandbox-exec -p <sbpl> -- <guest_command...>` argv
    /// applying the compiled XNU Seatbelt profile at runtime inside the guest (`INV-NIX-RO-STORE-01`).
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

/// Abstract executor for `tart` hypervisor operations.
pub trait TartExecutor {
    fn exec_tart(&mut self, step: &'static str, argv: &[String]) -> Result<(), CleanroomVmError>;
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
        let mut cmd = Command::new(&self.executable);
        cmd.args(argv).env_clear();
        for key in ["HOME", "PATH", "TMPDIR", "USER", "LOGNAME"] {
            if let Some(val) = std::env::var_os(key) {
                cmd.env(key, val);
            }
        }
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

    /// Executes `tart run --no-graphics --dir=nix-store:... --dir=sccache:... <run-vm>`.
    /// Even if `tart run` fails, the `Drop` guard (or explicit `finish`) deletes `<run-vm>`.
    pub fn run_ephemeral(&mut self) -> Result<(), CleanroomVmError> {
        let run_argv = self.spec.run_argv();
        let exec = self
            .executor
            .as_mut()
            .ok_or_else(|| CleanroomVmError::TartExecutionFailed {
                step: "run",
                detail: "session already finalized".to_owned(),
            })?;
        exec.exec_tart("run", &run_argv)
    }

    /// Boots the headless cleanroom VM (`tart run`) AND executes `guest_command` inside
    /// `/usr/bin/sandbox-exec -p <sbpl>` (`tart exec`), enforcing XNU Seatbelt store/socket
    /// immutability at runtime while guaranteeing `defer tart delete` on any failure.
    pub fn run_ephemeral_with_seatbelt(
        &mut self,
        seatbelt: &SeatbeltProfile,
        guest_command: &[String],
    ) -> Result<(), CleanroomVmError> {
        let exec_argv = self.spec.guest_sandbox_exec_argv(seatbelt, guest_command)?;
        self.run_ephemeral()?;
        let exec = self
            .executor
            .as_mut()
            .ok_or_else(|| CleanroomVmError::TartExecutionFailed {
                step: "exec",
                detail: "session already finalized".to_owned(),
            })?;
        exec.exec_tart("exec", &exec_argv)
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
        match comp {
            Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(CleanroomVmError::InvalidMountPath(text.to_owned()));
            }
        }
    }
    Ok(path.to_path_buf())
}
