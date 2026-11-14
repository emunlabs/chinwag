// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! XNU Seatbelt (`sandbox_init` / `sandbox-exec`) SBPL profile compiler for
//! ephemeral cleanroom workers (`INV-NIX-VIRTIOFS-01` & `INV-NIX-RO-STORE-01`).
//!
//! Guarantees read-only `/nix/store` and `sccache` immutability, blocks all
//! `nix-daemon` socket tampering, denies credential/Keychain reads in public
//! untrusted profiles, and restricts file mutations strictly to the job's
//! isolated worktree and scratch directory.

use crate::runner_pool::RunnerTrustProfile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

pub const DEFAULT_NIX_STORE_SUBPATH: &str = "/nix/store";
pub const DEFAULT_NIX_DAEMON_SOCKET_DIR: &str = "/nix/var/nix/daemon-socket";
pub const DEFAULT_NIX_DAEMON_SOCKET_PATH: &str = "/nix/var/nix/daemon-socket/socket";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SeatbeltError {
    #[error("seatbelt path `{0}` must be normalized absolute UTF-8 without SBPL metacharacters")]
    InvalidPath(String),
    #[error("writable worktree/scratch directory `{0}` cannot overlap read-only store `{1}`")]
    ReadOnlyOverlap(String, String),
    #[error("release signing directory may only be attached to `chinwag-ephemeral-release`")]
    ReleaseMountOnPublicProfile,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanroomSeatbeltSpec {
    pub trust_profile: RunnerTrustProfile,
    pub nix_store_path: PathBuf,
    pub sccache_path: PathBuf,
    pub writable_worktree: PathBuf,
    pub writable_scratch: PathBuf,
    pub release_signing_dir: Option<PathBuf>,
    pub signal_mode: SeatbeltSignalMode,
}

impl CleanroomSeatbeltSpec {
    pub fn new(
        trust_profile: RunnerTrustProfile,
        nix_store_path: impl AsRef<Path>,
        sccache_path: impl AsRef<Path>,
        writable_worktree: impl AsRef<Path>,
        writable_scratch: impl AsRef<Path>,
    ) -> Result<Self, SeatbeltError> {
        let nix_store = sanitize_sbpl_path(nix_store_path.as_ref())?;
        let sccache = sanitize_sbpl_path(sccache_path.as_ref())?;
        let worktree = sanitize_sbpl_path(writable_worktree.as_ref())?;
        let scratch = sanitize_sbpl_path(writable_scratch.as_ref())?;

        for writable in [&worktree, &scratch] {
            for ro in [&nix_store, &sccache] {
                if writable.starts_with(ro) || ro.starts_with(writable) {
                    return Err(SeatbeltError::ReadOnlyOverlap(
                        writable.display().to_string(),
                        ro.display().to_string(),
                    ));
                }
            }
        }

        Ok(Self {
            trust_profile,
            nix_store_path: nix_store,
            sccache_path: sccache,
            writable_worktree: worktree,
            writable_scratch: scratch,
            release_signing_dir: None,
            signal_mode: SeatbeltSignalMode::SigKill,
        })
    }

    pub fn with_signal_mode(mut self, mode: SeatbeltSignalMode) -> Self {
        self.signal_mode = mode;
        self
    }

    pub fn with_release_signing_dir(
        mut self,
        dir: impl AsRef<Path>,
    ) -> Result<Self, SeatbeltError> {
        if self.trust_profile != RunnerTrustProfile::Release {
            return Err(SeatbeltError::ReleaseMountOnPublicProfile);
        }
        let clean = sanitize_sbpl_path(dir.as_ref())?;
        for ro in [&self.nix_store_path, &self.sccache_path] {
            if clean.starts_with(ro) || ro.starts_with(&clean) {
                return Err(SeatbeltError::ReadOnlyOverlap(
                    clean.display().to_string(),
                    ro.display().to_string(),
                ));
            }
        }
        self.release_signing_dir = Some(clean);
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatbeltProfile {
    pub profile_name: String,
    pub sbpl: String,
    pub sha256_hex: String,
    pub signal_mode: SeatbeltSignalMode,
}

/// Compiles a deterministic XNU Seatbelt SBPL `(version 1)` profile enforcing
/// `INV-NIX-RO-STORE-01`, `INV-NIX-VIRTIOFS-01`, and `INV-CLEANROOM-TRUST-SPLIT-01`.
pub fn compile_seatbelt_profile(
    spec: &CleanroomSeatbeltSpec,
) -> Result<SeatbeltProfile, SeatbeltError> {
    let nix_store = sanitize_sbpl_path(&spec.nix_store_path)?;
    let sccache = sanitize_sbpl_path(&spec.sccache_path)?;
    let worktree = sanitize_sbpl_path(&spec.writable_worktree)?;
    let scratch = sanitize_sbpl_path(&spec.writable_scratch)?;
    if spec.release_signing_dir.is_some() && spec.trust_profile != RunnerTrustProfile::Release {
        return Err(SeatbeltError::ReleaseMountOnPublicProfile);
    }

    let suffix = match spec.signal_mode {
        SeatbeltSignalMode::SigKill => " (with send-signal SIGKILL)",
        SeatbeltSignalMode::KernelDeny => "",
    };

    let mut lines = Vec::with_capacity(32);
    lines.push("(version 1)".to_owned());
    lines.push(format!(
        ";; Chinwag Cleanroom Seatbelt Profile ({}) — INV-NIX-RO-STORE-01 & INV-CLEANROOM-TRUST-SPLIT-01",
        spec.trust_profile.as_str()
    ));
    lines.push("(allow default)".to_owned());
    lines.push("(deny file-write*)".to_owned());
    lines.push(format!(
        "(allow file-write* (subpath \"{}\"))",
        worktree.display()
    ));
    lines.push(format!(
        "(allow file-write* (subpath \"{}\"))",
        scratch.display()
    ));
    lines.push("(allow file-write* (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/dtracehelper\"))".to_owned());

    // INV-NIX-RO-STORE-01: Read-only /nix/store & sccache; explicit deny on all store writes & nix-daemon sockets
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
        "(deny file-read* file-write* (subpath \"{DEFAULT_NIX_DAEMON_SOCKET_DIR}\"){suffix})"
    ));
    lines.push(format!(
        "(deny network-outbound (remote unix-socket (path-literal \"{DEFAULT_NIX_DAEMON_SOCKET_PATH}\")))"
    ));

    // Read-only host sccache mount
    lines.push(format!(
        "(allow file-read* (subpath \"{}\"))",
        sccache.display()
    ));
    lines.push(format!(
        "(deny file-write* (subpath \"{}\"){suffix})",
        sccache.display()
    ));

    match spec.trust_profile {
        RunnerTrustProfile::Public => {
            lines.push(
                ";; Public untrusted tier: zero Keychain, SSH, or cloud credential reads"
                    .to_owned(),
            );
            lines.push("(deny file-read* (regex #\"/\\.ssh(/|$)\"))".to_owned());
            lines.push("(deny file-read* (regex #\"/Library/Keychains(/|$)\"))".to_owned());
            lines.push("(deny file-read* (regex #\"/\\.chinwag/signing(/|$)\"))".to_owned());
            lines.push("(deny network-inbound)".to_owned());
        }
        RunnerTrustProfile::Release => {
            lines.push(";; Release verified tier: scoped ephemeral signing lease only".to_owned());
            lines.push("(deny file-read* (regex #\"/\\.ssh(/|$)\"))".to_owned());
            if let Some(ref rel_dir) = spec.release_signing_dir {
                let clean_rel = sanitize_sbpl_path(rel_dir)?;
                lines.push(format!(
                    "(allow file-read* (subpath \"{}\"))",
                    clean_rel.display()
                ));
            }
            lines.push("(deny network-inbound)".to_owned());
        }
    }

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

fn sanitize_sbpl_path(path: &Path) -> Result<PathBuf, SeatbeltError> {
    let text = path
        .to_str()
        .ok_or_else(|| SeatbeltError::InvalidPath(path.display().to_string()))?;
    if text.is_empty()
        || text.len() > 1024
        || !path.is_absolute()
        || text
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '(' | ')' | ';' | '#'))
    {
        return Err(SeatbeltError::InvalidPath(text.to_owned()));
    }
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(SeatbeltError::InvalidPath(text.to_owned()));
            }
        }
    }
    Ok(path.to_path_buf())
}
