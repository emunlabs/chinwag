// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! XNU Seatbelt (`sandbox_init` / `sandbox-exec`) SBPL profile compiler for
//! ephemeral cleanroom workers (`INV-NIX-VIRTIOFS-01` & `INV-NIX-RO-STORE-01`).
//!
//! Enforces default-deny file read, file write, and network posture:
//! - Explicit `(deny default)`, `(deny file-read*)`, `(deny file-write*)`, and `(deny network*)`.
//! - Canonicalized realpath normalization (`/var/...` -> `/private/var/...`) rejecting
//!   repeated `//` slashes and `<3`-component broad mounts prior to overlap checks.
//! - Read-only `/nix/store`, `sccache`, and VirtioFS guest shares (`/Volumes/My Shared Files/...`),
//!   blocking all `nix-daemon` socket reads/writes/connects.
//! - Keychain, `~/.ssh`, and `~/.chinwag` credential read denies across both `Public` and `Release` tiers.
//! - Scoped network egress matching `NetworkEgressPolicy`.

use crate::runner_pool::{NetworkEgressPolicy, RunnerTrustProfile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const DEFAULT_NIX_STORE_SUBPATH: &str = "/nix/store";
pub const DEFAULT_NIX_DAEMON_SOCKET_DIR: &str = "/nix/var/nix/daemon-socket";
pub const DEFAULT_NIX_DAEMON_SOCKET_PATH: &str = "/nix/var/nix/daemon-socket/socket";

/// Canonical Tart `Virtualization.framework` VirtioFS mount root inside macOS guests.
pub const GUEST_VIRTIOFS_ROOT: &str = "/Volumes/My Shared Files";
pub const GUEST_NIX_STORE_MOUNT: &str = "/Volumes/My Shared Files/nix-store";
pub const GUEST_SCCACHE_MOUNT: &str = "/Volumes/My Shared Files/sccache";
pub const GUEST_WORKTREE_MOUNT: &str = "/Volumes/My Shared Files/worktree";
pub const GUEST_RELEASE_SIGNING_MOUNT: &str = "/Volumes/My Shared Files/release-signing";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SeatbeltError {
    #[error(
        "seatbelt path `{0}` must be normalized >=3-component absolute UTF-8 without repeated slashes or SBPL metacharacters"
    )]
    InvalidPath(String),
    #[error("writable worktree/scratch directory `{0}` cannot overlap read-only path `{1}`")]
    ReadOnlyOverlap(String, String),
    #[error("release signing directory may only be attached to `chinwag-ephemeral-release`")]
    ReleaseMountOnPublicProfile,
    #[error("release network egress policy `{0:?}` is forbidden on `chinwag-ephemeral-public`")]
    NetworkPolicyProfileMismatch(NetworkEgressPolicy),
}

/// Signal disposition when a sandboxed cleanroom process attempts to write to `/nix/store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeatbeltSignalMode {
    /// Emits `(deny file-write* (subpath "/nix/store"))` (standard kernel EPERM deny,
    /// universally accepted by userland `/usr/bin/sandbox-exec -p` across macOS releases).
    KernelDeny,
    /// Emits `(deny file-write* (subpath "/nix/store") (with send-signal SIGKILL))`
    /// per `PRD-0035` hard-kill cleanroom trampoline profile.
    SigKill,
}

fn default_signal_mode() -> SeatbeltSignalMode {
    SeatbeltSignalMode::SigKill
}

fn default_daemon_socket_dir() -> PathBuf {
    PathBuf::from(DEFAULT_NIX_DAEMON_SOCKET_DIR)
}

fn default_daemon_socket_path() -> PathBuf {
    PathBuf::from(DEFAULT_NIX_DAEMON_SOCKET_PATH)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCleanroomSeatbeltSpec {
    trust_profile: RunnerTrustProfile,
    #[serde(default)]
    network_policy: Option<NetworkEgressPolicy>,
    nix_store_path: PathBuf,
    sccache_path: PathBuf,
    #[serde(default)]
    extra_read_only_mounts: Vec<PathBuf>,
    writable_worktree: PathBuf,
    writable_scratch: PathBuf,
    #[serde(default)]
    release_signing_dir: Option<PathBuf>,
    #[serde(default = "default_daemon_socket_dir")]
    nix_daemon_socket_dir: PathBuf,
    #[serde(default = "default_daemon_socket_path")]
    nix_daemon_socket_path: PathBuf,
    #[serde(default = "default_signal_mode")]
    signal_mode: SeatbeltSignalMode,
}

/// Validated XNU Seatbelt specification with private fields and `#[serde(try_from = ...)]`
/// enforcement so deserialization cannot bypass normalization or overlap checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCleanroomSeatbeltSpec")]
pub struct CleanroomSeatbeltSpec {
    trust_profile: RunnerTrustProfile,
    network_policy: NetworkEgressPolicy,
    nix_store_path: PathBuf,
    sccache_path: PathBuf,
    extra_read_only_mounts: Vec<PathBuf>,
    writable_worktree: PathBuf,
    writable_scratch: PathBuf,
    release_signing_dir: Option<PathBuf>,
    nix_daemon_socket_dir: PathBuf,
    nix_daemon_socket_path: PathBuf,
    signal_mode: SeatbeltSignalMode,
}

impl TryFrom<RawCleanroomSeatbeltSpec> for CleanroomSeatbeltSpec {
    type Error = SeatbeltError;

    fn try_from(raw: RawCleanroomSeatbeltSpec) -> Result<Self, Self::Error> {
        let mut spec = Self::new(
            raw.trust_profile,
            &raw.nix_store_path,
            &raw.sccache_path,
            &raw.writable_worktree,
            &raw.writable_scratch,
        )?
        .with_signal_mode(raw.signal_mode)
        .with_nix_daemon_socket(&raw.nix_daemon_socket_dir, &raw.nix_daemon_socket_path)?;

        if let Some(policy) = raw.network_policy {
            spec = spec.with_network_policy(policy)?;
        }
        for ro in raw.extra_read_only_mounts {
            spec = spec.with_extra_read_only_mount(ro)?;
        }
        if let Some(rel_dir) = raw.release_signing_dir {
            spec = spec.with_release_signing_dir(rel_dir)?;
        }
        Ok(spec)
    }
}

impl CleanroomSeatbeltSpec {
    pub fn new(
        trust_profile: RunnerTrustProfile,
        nix_store_path: impl AsRef<Path>,
        sccache_path: impl AsRef<Path>,
        writable_worktree: impl AsRef<Path>,
        writable_scratch: impl AsRef<Path>,
    ) -> Result<Self, SeatbeltError> {
        let nix_store = normalize_and_canonicalize_sbpl_path(nix_store_path.as_ref())?;
        let sccache = normalize_and_canonicalize_sbpl_path(sccache_path.as_ref())?;
        let worktree = normalize_and_canonicalize_sbpl_path(writable_worktree.as_ref())?;
        let scratch = normalize_and_canonicalize_sbpl_path(writable_scratch.as_ref())?;
        let daemon_dir =
            normalize_and_canonicalize_sbpl_path(Path::new(DEFAULT_NIX_DAEMON_SOCKET_DIR))?;
        let daemon_sock =
            normalize_and_canonicalize_sbpl_path(Path::new(DEFAULT_NIX_DAEMON_SOCKET_PATH))?;

        let default_net = match trust_profile {
            RunnerTrustProfile::Public => NetworkEgressPolicy::RegistriesAndBinaryCacheOnly,
            RunnerTrustProfile::Release => NetworkEgressPolicy::ScopedReleaseUploadAndNotarization,
        };

        let spec = Self {
            trust_profile,
            network_policy: default_net,
            nix_store_path: nix_store,
            sccache_path: sccache,
            extra_read_only_mounts: Vec::new(),
            writable_worktree: worktree,
            writable_scratch: scratch,
            release_signing_dir: None,
            nix_daemon_socket_dir: daemon_dir,
            nix_daemon_socket_path: daemon_sock,
            signal_mode: SeatbeltSignalMode::SigKill,
        };
        spec.validate_invariants()?;
        Ok(spec)
    }

    /// Constructs a guest-side XNU Seatbelt specification using only guest-visible
    /// VirtioFS mount paths (`/Volumes/My Shared Files/...`) and ephemeral guest-local
    /// scratch/worktree paths so zero host filesystem paths leak into guest `ps` argv.
    pub fn for_guest_virtiofs(
        trust_profile: RunnerTrustProfile,
        vm_instance_name: &str,
        guest_scratch_root: impl AsRef<Path>,
    ) -> Result<Self, SeatbeltError> {
        if vm_instance_name.is_empty()
            || vm_instance_name.len() > 128
            || vm_instance_name.starts_with('-')
            || vm_instance_name.starts_with('.')
            || vm_instance_name.contains('/')
            || vm_instance_name.contains("..")
            || vm_instance_name.chars().any(char::is_control)
        {
            return Err(SeatbeltError::InvalidPath(vm_instance_name.to_owned()));
        }
        let scratch_root = normalize_and_canonicalize_sbpl_path(guest_scratch_root.as_ref())?;
        let guest_worktree = scratch_root.join(format!("{vm_instance_name}-worktree"));
        let guest_scratch = scratch_root.join(format!("{vm_instance_name}-scratch"));

        Self::new(
            trust_profile,
            DEFAULT_NIX_STORE_SUBPATH,
            GUEST_SCCACHE_MOUNT,
            &guest_worktree,
            &guest_scratch,
        )?
        .with_extra_read_only_mount(GUEST_NIX_STORE_MOUNT)?
        .with_extra_read_only_mount(GUEST_WORKTREE_MOUNT)
    }

    pub fn with_signal_mode(mut self, mode: SeatbeltSignalMode) -> Self {
        self.signal_mode = mode;
        self
    }

    pub fn with_network_policy(
        mut self,
        policy: NetworkEgressPolicy,
    ) -> Result<Self, SeatbeltError> {
        if self.trust_profile == RunnerTrustProfile::Public
            && policy == NetworkEgressPolicy::ScopedReleaseUploadAndNotarization
        {
            return Err(SeatbeltError::NetworkPolicyProfileMismatch(policy));
        }
        self.network_policy = policy;
        self.validate_invariants()?;
        Ok(self)
    }

    pub fn with_extra_read_only_mount(
        mut self,
        dir: impl AsRef<Path>,
    ) -> Result<Self, SeatbeltError> {
        let clean = normalize_and_canonicalize_sbpl_path(dir.as_ref())?;
        if !self.extra_read_only_mounts.contains(&clean) {
            self.extra_read_only_mounts.push(clean);
        }
        self.validate_invariants()?;
        Ok(self)
    }

    pub fn with_release_signing_dir(
        mut self,
        dir: impl AsRef<Path>,
    ) -> Result<Self, SeatbeltError> {
        if self.trust_profile != RunnerTrustProfile::Release {
            return Err(SeatbeltError::ReleaseMountOnPublicProfile);
        }
        let clean = normalize_and_canonicalize_sbpl_path(dir.as_ref())?;
        self.release_signing_dir = Some(clean);
        self.validate_invariants()?;
        Ok(self)
    }

    pub fn with_nix_daemon_socket(
        mut self,
        socket_dir: impl AsRef<Path>,
        socket_path: impl AsRef<Path>,
    ) -> Result<Self, SeatbeltError> {
        let clean_dir = normalize_and_canonicalize_sbpl_path(socket_dir.as_ref())?;
        let clean_sock = normalize_and_canonicalize_sbpl_path(socket_path.as_ref())?;
        if !clean_sock.starts_with(&clean_dir) || clean_sock == clean_dir {
            return Err(SeatbeltError::InvalidPath(clean_sock.display().to_string()));
        }
        self.nix_daemon_socket_dir = clean_dir;
        self.nix_daemon_socket_path = clean_sock;
        self.validate_invariants()?;
        Ok(self)
    }

    pub const fn trust_profile(&self) -> RunnerTrustProfile {
        self.trust_profile
    }

    pub const fn network_policy(&self) -> NetworkEgressPolicy {
        self.network_policy
    }

    pub fn nix_store_path(&self) -> &Path {
        &self.nix_store_path
    }

    pub fn sccache_path(&self) -> &Path {
        &self.sccache_path
    }

    pub fn extra_read_only_mounts(&self) -> &[PathBuf] {
        &self.extra_read_only_mounts
    }

    pub fn writable_worktree(&self) -> &Path {
        &self.writable_worktree
    }

    pub fn writable_scratch(&self) -> &Path {
        &self.writable_scratch
    }

    pub fn release_signing_dir(&self) -> Option<&Path> {
        self.release_signing_dir.as_deref()
    }

    pub fn nix_daemon_socket_dir(&self) -> &Path {
        &self.nix_daemon_socket_dir
    }

    pub fn nix_daemon_socket_path(&self) -> &Path {
        &self.nix_daemon_socket_path
    }

    pub const fn signal_mode(&self) -> SeatbeltSignalMode {
        self.signal_mode
    }

    fn validate_invariants(&self) -> Result<(), SeatbeltError> {
        if self.release_signing_dir.is_some() && self.trust_profile != RunnerTrustProfile::Release {
            return Err(SeatbeltError::ReleaseMountOnPublicProfile);
        }
        if self.trust_profile == RunnerTrustProfile::Public
            && self.network_policy == NetworkEgressPolicy::ScopedReleaseUploadAndNotarization
        {
            return Err(SeatbeltError::NetworkPolicyProfileMismatch(
                self.network_policy,
            ));
        }
        if !self
            .nix_daemon_socket_path
            .starts_with(&self.nix_daemon_socket_dir)
            || self.nix_daemon_socket_path == self.nix_daemon_socket_dir
        {
            return Err(SeatbeltError::InvalidPath(
                self.nix_daemon_socket_path.display().to_string(),
            ));
        }

        let mut ro_paths: Vec<&Path> = vec![
            &self.nix_store_path,
            &self.sccache_path,
            &self.nix_daemon_socket_dir,
        ];
        for extra in &self.extra_read_only_mounts {
            ro_paths.push(extra.as_path());
        }
        if let Some(ref rel_dir) = self.release_signing_dir {
            ro_paths.push(rel_dir.as_path());
        }

        for writable in [
            self.writable_worktree.as_path(),
            self.writable_scratch.as_path(),
        ] {
            for ro in &ro_paths {
                if writable.starts_with(ro) || ro.starts_with(writable) {
                    return Err(SeatbeltError::ReadOnlyOverlap(
                        writable.display().to_string(),
                        ro.display().to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatbeltProfile {
    pub profile_name: String,
    pub sbpl: String,
    pub sha256_hex: String,
    pub signal_mode: SeatbeltSignalMode,
}

/// Compiles a deterministic default-deny XNU Seatbelt SBPL `(version 1)` profile enforcing
/// `INV-NIX-RO-STORE-01`, `INV-NIX-VIRTIOFS-01`, and `INV-CLEANROOM-TRUST-SPLIT-01`.
pub fn compile_seatbelt_profile(
    spec: &CleanroomSeatbeltSpec,
) -> Result<SeatbeltProfile, SeatbeltError> {
    let nix_store = normalize_and_canonicalize_sbpl_path(&spec.nix_store_path)?;
    let sccache = normalize_and_canonicalize_sbpl_path(&spec.sccache_path)?;
    let worktree = normalize_and_canonicalize_sbpl_path(&spec.writable_worktree)?;
    let scratch = normalize_and_canonicalize_sbpl_path(&spec.writable_scratch)?;
    let daemon_dir = normalize_and_canonicalize_sbpl_path(&spec.nix_daemon_socket_dir)?;
    let daemon_sock = normalize_and_canonicalize_sbpl_path(&spec.nix_daemon_socket_path)?;

    let mut extra_ro = Vec::with_capacity(spec.extra_read_only_mounts.len());
    for m in &spec.extra_read_only_mounts {
        extra_ro.push(normalize_and_canonicalize_sbpl_path(m)?);
    }
    let clean_rel = match spec.release_signing_dir {
        Some(ref dir) => {
            if spec.trust_profile != RunnerTrustProfile::Release {
                return Err(SeatbeltError::ReleaseMountOnPublicProfile);
            }
            Some(normalize_and_canonicalize_sbpl_path(dir)?)
        }
        None => None,
    };

    // Defense-in-depth: re-verify all canonicalized overlap & profile invariants inside compiler
    let revalidated = CleanroomSeatbeltSpec {
        trust_profile: spec.trust_profile,
        network_policy: spec.network_policy,
        nix_store_path: nix_store.clone(),
        sccache_path: sccache.clone(),
        extra_read_only_mounts: extra_ro.clone(),
        writable_worktree: worktree.clone(),
        writable_scratch: scratch.clone(),
        release_signing_dir: clean_rel.clone(),
        nix_daemon_socket_dir: daemon_dir.clone(),
        nix_daemon_socket_path: daemon_sock.clone(),
        signal_mode: spec.signal_mode,
    };
    revalidated.validate_invariants()?;

    let suffix = match spec.signal_mode {
        SeatbeltSignalMode::SigKill => " (with send-signal SIGKILL)",
        SeatbeltSignalMode::KernelDeny => "",
    };

    let mut lines = Vec::with_capacity(56);
    lines.push("(version 1)".to_owned());
    lines.push(format!(
        ";; Chinwag Cleanroom Seatbelt Profile ({}) — INV-NIX-RO-STORE-01 & INV-CLEANROOM-TRUST-SPLIT-01",
        spec.trust_profile.as_str()
    ));
    lines.push("(deny default)".to_owned());
    lines.push("(allow process-exec*)".to_owned());
    lines.push("(allow process-fork)".to_owned());
    lines.push("(allow process-info* (target self))".to_owned());
    lines.push("(allow signal (target self))".to_owned());
    lines.push("(allow sysctl-read)".to_owned());
    lines.push("(allow mach-lookup)".to_owned());
    lines.push("(allow ipc-posix-shm*)".to_owned());
    lines.push("(allow system-mac-syscall)".to_owned());
    lines.push("(allow file-map-executable)".to_owned());

    // Explicit default-deny posture for file reads, file writes, and network
    lines.push("(deny file-read*)".to_owned());
    lines.push("(deny file-write*)".to_owned());
    lines.push("(deny network*)".to_owned());
    lines.push("(deny network-inbound)".to_owned());
    lines.push("(deny network-bind)".to_owned());

    // Minimal stat metadata + OS runtime binaries/frameworks allowlist
    lines.push("(allow file-read-metadata)".to_owned());
    lines.push(
        "(allow file-read* (literal \"/\") (literal \"/private/etc/localtime\") (literal \"/private/etc/resolv.conf\") (literal \"/private/etc/ssl/cert.pem\"))"
            .to_owned(),
    );
    lines.push(
        "(allow file-read* (subpath \"/System\") (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Library/Apple\") (subpath \"/dev\"))"
            .to_owned(),
    );

    // Job-scoped writable worktree & scratch directories (read + write)
    lines.push(format!(
        "(allow file-read* (subpath \"{}\"))",
        worktree.display()
    ));
    lines.push(format!(
        "(allow file-read* (subpath \"{}\"))",
        scratch.display()
    ));
    lines.push(format!(
        "(allow file-write* (subpath \"{}\"))",
        worktree.display()
    ));
    lines.push(format!(
        "(allow file-write* (subpath \"{}\"))",
        scratch.display()
    ));
    lines.push(
        "(allow file-write* (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/dtracehelper\"))"
            .to_owned(),
    );

    // INV-NIX-RO-STORE-01: Read-only /nix/store, sccache, & extra VirtioFS shares
    lines.push(format!(
        "(allow file-read* (subpath \"{}\"))",
        nix_store.display()
    ));
    lines.push(format!(
        "(deny file-write* (subpath \"{}\"){suffix})",
        nix_store.display()
    ));
    lines.push(format!(
        "(deny file-write-xattr file-write-mode file-write-owner (subpath \"{}\"){suffix})",
        nix_store.display()
    ));

    lines.push(format!(
        "(allow file-read* (subpath \"{}\"))",
        sccache.display()
    ));
    lines.push(format!(
        "(deny file-write* (subpath \"{}\"){suffix})",
        sccache.display()
    ));

    for ro_mount in &extra_ro {
        lines.push(format!(
            "(allow file-read* (subpath \"{}\"))",
            ro_mount.display()
        ));
        lines.push(format!(
            "(deny file-write* (subpath \"{}\"){suffix})",
            ro_mount.display()
        ));
    }

    if spec.trust_profile == RunnerTrustProfile::Release
        && let Some(ref rel_dir) = clean_rel
    {
        lines.push(";; Release verified tier: scoped read-only ephemeral signing lease".to_owned());
        lines.push(format!(
            "(allow file-read* (subpath \"{}\"))",
            rel_dir.display()
        ));
        lines.push(format!(
            "(deny file-write* (subpath \"{}\"){suffix})",
            rel_dir.display()
        ));
    }

    // Scoped network egress matching NetworkEgressPolicy
    match spec.network_policy {
        NetworkEgressPolicy::Offline => {
            lines.push(";; NetworkEgressPolicy::Offline — zero outbound network".to_owned());
        }
        NetworkEgressPolicy::RegistriesAndBinaryCacheOnly => {
            lines.push(
                ";; NetworkEgressPolicy::RegistriesAndBinaryCacheOnly — TLS :443 & DNS :53 only"
                    .to_owned(),
            );
            lines.push(
                "(allow network-outbound (remote tcp \"*:443\") (remote udp \"*:53\"))".to_owned(),
            );
            lines.push("(deny network-outbound (remote ip \"localhost:*\"))".to_owned());
        }
        NetworkEgressPolicy::ScopedReleaseUploadAndNotarization => {
            lines.push(
                ";; NetworkEgressPolicy::ScopedReleaseUploadAndNotarization — TLS :443 & DNS :53"
                    .to_owned(),
            );
            lines.push(
                "(allow network-outbound (remote tcp \"*:443\") (remote udp \"*:53\") (remote tcp \"*:53\"))"
                    .to_owned(),
            );
            lines.push("(deny network-outbound (remote ip \"localhost:*\"))".to_owned());
        }
    }

    // Nix daemon socket denies (both customer-configured path and canonical default)
    lines.push(format!(
        "(deny file-read* file-write* (subpath \"{}\"){suffix})",
        daemon_dir.display()
    ));
    lines.push(format!(
        "(deny network-outbound (remote unix-socket (path-literal \"{}\")))",
        daemon_sock.display()
    ));
    if daemon_dir != Path::new(DEFAULT_NIX_DAEMON_SOCKET_DIR) {
        lines.push(format!(
            "(deny file-read* file-write* (subpath \"{DEFAULT_NIX_DAEMON_SOCKET_DIR}\"){suffix})"
        ));
    }
    if daemon_sock != Path::new(DEFAULT_NIX_DAEMON_SOCKET_PATH) {
        lines.push(format!(
            "(deny network-outbound (remote unix-socket (path-literal \"{DEFAULT_NIX_DAEMON_SOCKET_PATH}\")))"
        ));
    }

    // Unconditional final credential denies across BOTH Public and Release profiles
    lines.push(
        ";; Mandatory Keychain, SSH, and Chinwag credential denies across Public and Release tiers"
            .to_owned(),
    );
    lines.push("(deny file-read* (regex #\"/\\.ssh(/|$)\"))".to_owned());
    lines.push("(deny file-read* (regex #\"/Library/Keychains(/|$)\"))".to_owned());
    lines.push("(deny file-read* (regex #\"/Users/[^/]+/\\.chinwag(/|$)\"))".to_owned());
    lines.push("(deny file-read* (regex #\"/var/root/\\.chinwag(/|$)\"))".to_owned());
    lines.push("(deny file-read* (regex #\"/\\.chinwag/signing(/|$)\"))".to_owned());
    lines.push("(deny file-read* (regex #\"/\\.chinwag/.*\\.(env|key|seed)(/|$)\"))".to_owned());

    let mut sbpl = lines.join("\n");
    sbpl.push('\n');
    let sha256_hex = hex::encode(Sha256::digest(sbpl.as_bytes()));

    Ok(SeatbeltProfile {
        profile_name: spec.trust_profile.as_str().to_owned(),
        sbpl,
        sha256_hex,
        signal_mode: spec.signal_mode,
    })
}

/// Validates strict SBPL path syntax (no `//` repeated slashes, no trailing `/`,
/// `>= 3` components including `/`, no `.`/`..` or metacharacters) AND canonicalizes
/// macOS realpaths (`/var/...` -> `/private/var/...`, `/tmp/...` -> `/private/tmp/...`,
/// plus live symlink resolution on existing ancestors).
pub fn normalize_and_canonicalize_sbpl_path(path: &Path) -> Result<PathBuf, SeatbeltError> {
    let strictly_normalized = validate_strict_sbpl_syntax(path)?;
    let real = resolve_darwin_realpath(&strictly_normalized);
    validate_strict_sbpl_syntax(&real)
}

fn validate_strict_sbpl_syntax(path: &Path) -> Result<PathBuf, SeatbeltError> {
    let text = path
        .to_str()
        .ok_or_else(|| SeatbeltError::InvalidPath(path.display().to_string()))?;
    if text.is_empty()
        || text.len() > 1024
        || !path.is_absolute()
        || (text.len() > 1 && text.ends_with('/'))
        || text.contains("//")
        || text
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '(' | ')' | ';' | '#'))
    {
        return Err(SeatbeltError::InvalidPath(text.to_owned()));
    }

    let mut rebuilt = PathBuf::new();
    let mut normal_segments = 0usize;
    for comp in path.components() {
        match comp {
            Component::RootDir => rebuilt.push("/"),
            Component::Normal(seg) => {
                if seg.is_empty() {
                    return Err(SeatbeltError::InvalidPath(text.to_owned()));
                }
                normal_segments += 1;
                rebuilt.push(seg);
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(SeatbeltError::InvalidPath(text.to_owned()));
            }
        }
    }

    // Require >= 3 total components (`/` + at least 2 Normal segments) and exact string parity
    if normal_segments < 2 || rebuilt.to_str() != Some(text) {
        return Err(SeatbeltError::InvalidPath(text.to_owned()));
    }
    Ok(rebuilt)
}

fn resolve_darwin_realpath(path: &Path) -> PathBuf {
    // Resolve existing filesystem prefix symlinks first when present on host
    let resolved = if let Ok(canon) = fs::canonicalize(path) {
        canon
    } else {
        let mut tail: Vec<std::ffi::OsString> = Vec::new();
        let mut cursor = path.to_path_buf();
        let mut base_canon: Option<PathBuf> = None;
        while let Some(name) = cursor.file_name().map(|n| n.to_os_string()) {
            let Some(parent) = cursor.parent().map(Path::to_path_buf) else {
                break;
            };
            tail.push(name);
            if parent != Path::new("/")
                && let Ok(canon_parent) = fs::canonicalize(&parent)
            {
                base_canon = Some(canon_parent);
                break;
            }
            cursor = parent;
        }
        match base_canon {
            Some(mut base) => {
                for seg in tail.into_iter().rev() {
                    base.push(seg);
                }
                base
            }
            None => path.to_path_buf(),
        }
    };

    // Deterministically map macOS root symlinks even when non-existent/virtual
    if let Ok(rest) = resolved.strip_prefix("/var") {
        Path::new("/private/var").join(rest)
    } else if let Ok(rest) = resolved.strip_prefix("/tmp") {
        Path::new("/private/tmp").join(rest)
    } else if let Ok(rest) = resolved.strip_prefix("/etc") {
        Path::new("/private/etc").join(rest)
    } else {
        resolved
    }
}
