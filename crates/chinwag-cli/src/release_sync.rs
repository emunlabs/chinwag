#![forbid(unsafe_code)]

//! Symmetric Chinwag Bus `RELEASE_BUILT` publisher and fail-closed subscriber
//! auto-installer backed by content-addressed Cloudflare R2 storage.
//!
//! Security & Reliability Properties:
//! - Signer pinning: `RELEASE_BUILT` messages on `#all` must pass strict
//!   `Ed25519` (`verify_strict`) over `chinwag-bus-sig-v2` against compiled-in
//!   `CANONICAL_SEAT_PUBKEYS` AND originate from `ALLOWED_RELEASE_SIGNERS`
//!   (`"INFRAJR"`). Valid signatures from any other seat fail closed.
//! - Hash-before-exec: Subscriber downloads land in `$HOME/.local/bin/.staging/`
//!   (`0700` directory, `0600` regular file). Exact `size_bytes`, `SHA-256`,
//!   and `BLAKE3` digests are verified in constant time (plus macOS
//!   `codesign --verify --strict`) BEFORE `0755` execute permissions are set.
//!   Any mismatch unlinks the `0600` file immediately.
//! - Byte-for-byte peer parity: Publisher runs `codesign --verify --strict`
//!   (applying ad-hoc `codesign -f -s -` once on its staged copy only if
//!   unsigned) BEFORE computing `SHA-256` and `BLAKE3`. Subscribers never
//!   re-sign, guaranteeing identical digests across `1..N` peers.
//! - Monotonic anti-downgrade: `(commit_epoch, built_at_ms)` must strictly
//!   advance relative to `$HOME/.chinwag/release_sync_state.json` unless
//!   `manifest.rollback == true` (which still requires strictly newer
//!   `built_at_ms` so historical rollback messages cannot be replayed).
//! - Zero topology assumptions: All paths derive dynamically from `$HOME` and
//!   all peer receipts identify peers solely by `iroh` `EndpointId`.

use crate::agent_instance::{self, ActorAddress};
use crate::bus_federation::BusMessage;
use crate::canonical_seat_pubkeys::CANONICAL_SEAT_PUBKEYS;
use chinwag_swarm::identity::Identity;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{TryRngCore, rngs::OsRng};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open as rustix_open};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "macos")]
use std::os::darwin::fs::MetadataExt as DarwinMetadataExt;
#[cfg(target_os = "macos")]
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub const RELEASE_MANIFEST_SCHEMA: &str = "chinwag.release-manifest.v1";
pub const RELEASE_INSTALLED_SCHEMA: &str = "chinwag.release-installed.v1";
pub const RELEASE_SYNC_STATE_SCHEMA: &str = "chinwag.release-sync-state.v1";

pub const RELEASE_BUILT_PREFIX: &str = "RELEASE_BUILT ";
pub const RELEASE_INSTALLED_PREFIX: &str = "RELEASE_INSTALLED ";

pub const ALLOWED_RELEASE_SIGNERS: &[&str] = &["INFRAJR"];
pub const ALLOWED_BINARIES: &[&str] = &["chinwag", "chinwag-ci"];

pub const R2_BUCKET_NAME: &str = "emunlabs-backups";
pub const R2_ARTIFACT_PREFIX: &str = "chinwag-artifacts/releases";

const MAX_RELEASE_MANIFEST_JSON_BYTES: usize = 16 * 1024;
const MAX_RELEASE_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_STATE_FILE_BYTES: u64 = 256 * 1024;
const MAX_APPLIED_RELEASE_HISTORY: usize = 64;
const VERSION_SMOKE_TIMEOUT: Duration = Duration::from_secs(5);
const WRANGLER_R2_TIMEOUT: Duration = Duration::from_secs(120);
const CRATE_MEMORY_SYNC_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const CURRENT_TARGET_TRIPLE: &str = "aarch64-apple-darwin";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub const CURRENT_TARGET_TRIPLE: &str = "x86_64-apple-darwin";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const CURRENT_TARGET_TRIPLE: &str = "x86_64-unknown-linux-gnu";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub const CURRENT_TARGET_TRIPLE: &str = "aarch64-unknown-linux-gnu";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifestV1 {
    pub schema: String,
    pub binary: String,
    pub target_triple: String,
    pub git_commit: String,
    pub commit_epoch: u64,
    pub built_at_ms: u64,
    pub sha256: String,
    pub blake3: String,
    pub size_bytes: u64,
    pub artifact_key: String,
    pub rollback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInstalledReceiptV1 {
    pub schema: String,
    pub iroh_endpoint: String,
    pub binary: String,
    pub target_triple: String,
    pub sha256: String,
    pub blake3: String,
    pub git_commit: String,
    pub installed_at_ms: u64,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledBinaryState {
    pub binary: String,
    pub target_triple: String,
    pub git_commit: String,
    pub commit_epoch: u64,
    pub built_at_ms: u64,
    pub sha256: String,
    pub blake3: String,
    pub size_bytes: u64,
    pub rollback: bool,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub source_message_id: Option<String>,
    #[serde(default)]
    pub max_commit_epoch_seen: u64,
    #[serde(default)]
    pub max_built_at_ms_seen: u64,
    #[serde(default)]
    pub applied_release_keys: Vec<String>,
}

impl InstalledBinaryState {
    pub fn effective_max_commit_epoch(&self) -> u64 {
        self.max_commit_epoch_seen.max(self.commit_epoch)
    }

    pub fn effective_max_built_at_ms(&self) -> u64 {
        self.max_built_at_ms_seen.max(self.built_at_ms)
    }

    pub fn release_history_key(manifest: &ReleaseManifestV1) -> String {
        format!(
            "{}:{}:{}:{}",
            manifest.sha256,
            manifest.commit_epoch,
            manifest.built_at_ms,
            u8::from(manifest.rollback)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSyncStateV1 {
    pub schema: String,
    pub binaries: BTreeMap<String, InstalledBinaryState>,
}

impl Default for ReleaseSyncStateV1 {
    fn default() -> Self {
        Self {
            schema: RELEASE_SYNC_STATE_SCHEMA.to_owned(),
            binaries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReleaseApplyOutcome {
    Installed {
        manifest: ReleaseManifestV1,
        install_path: PathBuf,
        previous_backup_path: Option<PathBuf>,
        receipt_message: Option<Box<BusMessage>>,
    },
    AlreadyInstalled {
        manifest: ReleaseManifestV1,
        install_path: PathBuf,
    },
    SkippedTargetMismatch {
        manifest_target: String,
        local_target: String,
    },
}

#[derive(Debug, Clone)]
pub struct ReleasePublishOutcome {
    pub manifest: ReleaseManifestV1,
    pub install_path: PathBuf,
    pub previous_backup_path: Option<PathBuf>,
    pub release_built_message: BusMessage,
    pub bus_seq: u64,
    pub crate_memory_synced: bool,
}

pub type ReleaseOrderKey = (u64, u64, u8, String);

#[derive(Debug, Clone)]
pub struct BinarySyncReport {
    pub binary: String,
    pub release_key: String,
    pub manifest: ReleaseManifestV1,
    pub outcome: Result<ReleaseApplyOutcome, ReleaseSyncError>,
    pub completed_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingBinaryCutoff {
    release_key: String,
    built_at_ms: u64,
    commit_epoch: u64,
}

impl PendingBinaryCutoff {
    fn is_superseded_by(&self, manifest: &ReleaseManifestV1) -> bool {
        manifest.built_at_ms > self.built_at_ms
            && (manifest.rollback || manifest.commit_epoch >= self.commit_epoch)
    }
}

#[derive(Debug, Default, Clone)]
pub struct ReleaseEligibilityFilter {
    only_binaries: Option<std::collections::BTreeSet<String>>,
    blocked_cutoffs: BTreeMap<String, PendingBinaryCutoff>,
}

impl ReleaseEligibilityFilter {
    pub fn is_manifest_eligible(&self, manifest: &ReleaseManifestV1) -> bool {
        if let Some(ref allowed) = self.only_binaries
            && !allowed.contains(&manifest.binary)
        {
            return false;
        }
        match self.blocked_cutoffs.get(&manifest.binary) {
            None => true,
            Some(cutoff) => cutoff.is_superseded_by(manifest),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JournalCatchupBatch {
    pub present_winners: BTreeMap<String, ReleaseManifestV1>,
    pub executed_reports: Vec<BinarySyncReport>,
}

pub struct PreparedImmutableReexec {
    pub dir_fd: File,
    pub dir_path: PathBuf,
    pub binary_path: PathBuf,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseSyncError {
    InvalidBinaryName,
    InvalidManifest(&'static str),
    NotAReleaseMessage,
    UnauthorizedSigner,
    SignatureInvalid,
    DowngradeOrReplayRejected,
    TransientIo(String),
    SourceUnavailable(String),
    SafePathViolation(&'static str),
    ArtifactStoreFailed(String),
    DigestMismatch,
    CodesignFailed(String),
    SmokeTestFailed(String),
    InstallFailed(String),
    StatePersistenceFailed(String),
    SigningIdentityUnavailable(&'static str),
    BusPublishFailed(String),
}

impl std::fmt::Display for ReleaseSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBinaryName => {
                write!(f, "binary must be strictly 'chinwag' or 'chinwag-ci'")
            }
            Self::InvalidManifest(reason) => write!(f, "invalid release manifest ({reason})"),
            Self::NotAReleaseMessage => write!(f, "message is not a RELEASE_BUILT payload on #all"),
            Self::UnauthorizedSigner => {
                write!(
                    f,
                    "release signer rejected: only pinned INFRAJR identity is authorized"
                )
            }
            Self::SignatureInvalid => {
                write!(
                    f,
                    "release message failed strict Ed25519 or canonical digest verification"
                )
            }
            Self::DowngradeOrReplayRejected => {
                write!(
                    f,
                    "release manifest rejected by monotonic anti-downgrade / replay gate"
                )
            }
            Self::TransientIo(reason) => write!(f, "transient filesystem I/O error: {reason}"),
            Self::SourceUnavailable(reason) => write!(f, "release source unavailable: {reason}"),
            Self::SafePathViolation(reason) => {
                write!(f, "unsafe filesystem path rejected ({reason})")
            }
            Self::ArtifactStoreFailed(reason) => write!(f, "R2 artifact store failed: {reason}"),
            Self::DigestMismatch => {
                write!(
                    f,
                    "downloaded artifact failed pre-exec size/SHA-256/BLAKE3 verification"
                )
            }
            Self::CodesignFailed(reason) => {
                write!(f, "macOS codesign verification failed: {reason}")
            }
            Self::SmokeTestFailed(reason) => {
                write!(f, "binary --version smoke check failed: {reason}")
            }
            Self::InstallFailed(reason) => write!(f, "atomic binary installation failed: {reason}"),
            Self::StatePersistenceFailed(reason) => {
                write!(f, "release sync state persistence failed: {reason}")
            }
            Self::SigningIdentityUnavailable(reason) => {
                write!(f, "release signing identity unavailable ({reason})")
            }
            Self::BusPublishFailed(reason) => write!(f, "bus broadcast failed: {reason}"),
        }
    }
}

impl std::error::Error for ReleaseSyncError {}

impl ReleaseSyncError {
    /// True only for transient storage/transport/OS-resource errors where reconciling
    /// later from the durable bus journal can succeed without sacrificing fail-closed
    /// rejection of unsafe paths, invalid state, signatures, digests, or downgrades.
    pub fn is_transient_retryable(&self) -> bool {
        matches!(
            self,
            Self::TransientIo(_) | Self::ArtifactStoreFailed(_) | Self::BusPublishFailed(_)
        )
    }
}

pub trait ReleaseArtifactStore: Send + Sync {
    fn upload_artifact(
        &self,
        artifact_key: &str,
        source_file: &File,
    ) -> Result<(), ReleaseSyncError>;
    fn download_artifact(
        &self,
        artifact_key: &str,
        destination_file: &Path,
    ) -> Result<(), ReleaseSyncError>;
}

pub struct WranglerR2ArtifactStore {
    home_dir: PathBuf,
    bucket: String,
    #[cfg(test)]
    wrangler_bin_override: Option<PathBuf>,
}

impl WranglerR2ArtifactStore {
    pub fn new(home_dir: PathBuf) -> Self {
        Self {
            home_dir,
            bucket: R2_BUCKET_NAME.to_owned(),
            #[cfg(test)]
            wrangler_bin_override: None,
        }
    }

    #[cfg(test)]
    fn with_wrangler_bin(home_dir: PathBuf, wrangler_bin: PathBuf) -> Self {
        Self {
            home_dir,
            bucket: R2_BUCKET_NAME.to_owned(),
            wrangler_bin_override: Some(wrangler_bin),
        }
    }

    fn resolve_wrangler_bin(&self) -> Result<PathBuf, ReleaseSyncError> {
        #[cfg(test)]
        if let Some(ref candidate) = self.wrangler_bin_override
            && is_resolvable_host_cli_binary(candidate)
        {
            return Ok(candidate.clone());
        }
        if let Some(override_bin) = std::env::var_os("CHINWAG_WRANGLER_BIN") {
            let candidate = PathBuf::from(override_bin);
            if is_resolvable_host_cli_binary(&candidate) {
                return Ok(candidate);
            }
        }
        for candidate in ["/opt/homebrew/bin/wrangler", "/usr/local/bin/wrangler"] {
            let path = Path::new(candidate);
            if is_resolvable_host_cli_binary(path) {
                return Ok(path.to_path_buf());
            }
        }
        if let Some(path_os) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_os) {
                let candidate = dir.join("wrangler");
                if is_resolvable_host_cli_binary(&candidate) {
                    return Ok(candidate);
                }
            }
        }
        Err(ReleaseSyncError::ArtifactStoreFailed(
            "wrangler CLI not found in /opt/homebrew/bin, /usr/local/bin, or PATH".into(),
        ))
    }

    fn run_wrangler(
        &self,
        args: &[&str],
        stdin_source: Option<&File>,
    ) -> Result<(), ReleaseSyncError> {
        let wrangler = self.resolve_wrangler_bin()?;
        let chinwag_dir = ensure_private_dir(&self.home_dir.join(".chinwag"))?;
        let stdin_cfg = match stdin_source {
            Some(file) => {
                let mut dup_fd = file.try_clone().map_err(|e| {
                    ReleaseSyncError::ArtifactStoreFailed(format!("dup upload fd: {e}"))
                })?;
                dup_fd.seek(SeekFrom::Start(0)).map_err(|e| {
                    ReleaseSyncError::ArtifactStoreFailed(format!("rewind upload fd: {e}"))
                })?;
                Stdio::from(dup_fd)
            }
            None => Stdio::null(),
        };
        let mut cmd = Command::new(wrangler);
        // Critical under launchd (where default cwd is `/`): running wrangler in
        // `$HOME/.chinwag` ensures `.wrangler/cache` resolves inside a writable
        // private directory rather than failing on `/.wrangler/cache`.
        cmd.args(args)
            .current_dir(&chinwag_dir)
            .env("HOME", &self.home_dir)
            .env(
                "PATH",
                "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            )
            .env("CI", "1")
            .stdin(stdin_cfg)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run_bounded_command(&mut cmd, WRANGLER_R2_TIMEOUT).map_err(|reason| {
            ReleaseSyncError::ArtifactStoreFailed(format!("wrangler r2 failed: {reason}"))
        })
    }
}

impl ReleaseArtifactStore for WranglerR2ArtifactStore {
    fn upload_artifact(
        &self,
        artifact_key: &str,
        source_file: &File,
    ) -> Result<(), ReleaseSyncError> {
        validate_artifact_key_structure(artifact_key)?;
        let object_path = format!("{}/{artifact_key}", self.bucket);
        // Stream directly from the caller's verified, kernel-immutable (`UF_IMMUTABLE`)
        // open file descriptor via `--pipe` (`stdin`) so no `.staging` pathname is ever
        // resolved after digest + smoke verification.
        self.run_wrangler(
            &[
                "r2",
                "object",
                "put",
                &object_path,
                "--pipe",
                "--content-type",
                "application/octet-stream",
                "--remote",
            ],
            Some(source_file),
        )
    }

    fn download_artifact(
        &self,
        artifact_key: &str,
        destination_file: &Path,
    ) -> Result<(), ReleaseSyncError> {
        validate_artifact_key_structure(artifact_key)?;
        let object_path = format!("{}/{artifact_key}", self.bucket);
        let file_str = destination_file
            .to_str()
            .ok_or(ReleaseSyncError::SafePathViolation("non_utf8_staging_path"))?;
        self.run_wrangler(
            &[
                "r2",
                "object",
                "get",
                &object_path,
                "--file",
                file_str,
                "--remote",
            ],
            None,
        )
    }
}

struct ReleaseTrustRoots<'a> {
    seat_pubkeys: &'a [(&'a str, [u8; 32])],
    allowed_signers: &'a [&'a str],
}

impl ReleaseTrustRoots<'static> {
    const fn production() -> Self {
        Self {
            seat_pubkeys: CANONICAL_SEAT_PUBKEYS,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        }
    }
}

impl<'a> ReleaseTrustRoots<'a> {
    fn lookup_pubkey(&self, base_seat: &str) -> Option<[u8; 32]> {
        for (seat, pubkey) in self.seat_pubkeys {
            if (*seat).eq_ignore_ascii_case(base_seat) {
                return Some(*pubkey);
            }
        }
        None
    }

    fn is_allowed_release_signer(&self, base_seat: &str) -> bool {
        let mut matched = subtle::Choice::from(0u8);
        for allowed in self.allowed_signers {
            matched |= allowed.as_bytes().ct_eq(base_seat.as_bytes());
        }
        bool::from(matched)
    }
}

pub fn resolve_home_dir() -> Result<PathBuf, ReleaseSyncError> {
    let raw =
        std::env::var_os("HOME").ok_or(ReleaseSyncError::SafePathViolation("missing_home"))?;
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(ReleaseSyncError::SafePathViolation("relative_home"));
    }
    let meta = fs::symlink_metadata(&path).map_err(|err| {
        if is_transient_io_error(&err) {
            ReleaseSyncError::TransientIo(format!("home lstat: {err}"))
        } else {
            ReleaseSyncError::SafePathViolation("unreadable_home")
        }
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(ReleaseSyncError::SafePathViolation(
            "symlink_or_non_dir_home",
        ));
    }
    Ok(path)
}

pub fn validate_binary_name(binary: &str) -> Result<(), ReleaseSyncError> {
    if binary.is_empty()
        || binary.contains('/')
        || binary.contains('\\')
        || binary.contains("..")
        || binary.contains('\0')
        || !ALLOWED_BINARIES.contains(&binary)
    {
        return Err(ReleaseSyncError::InvalidBinaryName);
    }
    Ok(())
}

fn validate_target_triple(triple: &str) -> Result<(), ReleaseSyncError> {
    if triple.is_empty()
        || triple.len() > 64
        || triple.contains("..")
        || !triple
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ReleaseSyncError::InvalidManifest("target_triple"));
    }
    Ok(())
}

fn validate_artifact_key_structure(key: &str) -> Result<(), ReleaseSyncError> {
    if key.contains("..") || key.contains('\\') || key.starts_with('/') {
        return Err(ReleaseSyncError::InvalidManifest("artifact_key_traversal"));
    }
    let parts: Vec<&str> = key.split('/').collect();
    if parts.len() != 5
        || parts[0] != "chinwag-artifacts"
        || parts[1] != "releases"
        || validate_binary_name(parts[2]).is_err()
        || validate_target_triple(parts[3]).is_err()
        || decode_lowercase_hex_32(parts[4]).is_none()
    {
        return Err(ReleaseSyncError::InvalidManifest("artifact_key_format"));
    }
    Ok(())
}

pub fn expected_artifact_key(binary: &str, target_triple: &str, sha256_hex: &str) -> String {
    format!("{R2_ARTIFACT_PREFIX}/{binary}/{target_triple}/{sha256_hex}")
}

impl ReleaseManifestV1 {
    pub fn order_key(&self) -> ReleaseOrderKey {
        (
            self.built_at_ms,
            self.commit_epoch,
            u8::from(self.rollback),
            self.sha256.clone(),
        )
    }

    pub fn validate_structural(&self) -> Result<([u8; 32], [u8; 32]), ReleaseSyncError> {
        if self.schema != RELEASE_MANIFEST_SCHEMA {
            return Err(ReleaseSyncError::InvalidManifest("schema"));
        }
        validate_binary_name(&self.binary)?;
        validate_target_triple(&self.target_triple)?;
        if !(7..=64).contains(&self.git_commit.len())
            || !self.git_commit.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(ReleaseSyncError::InvalidManifest("git_commit"));
        }
        if self.commit_epoch == 0 {
            return Err(ReleaseSyncError::InvalidManifest("commit_epoch"));
        }
        if self.built_at_ms == 0 {
            return Err(ReleaseSyncError::InvalidManifest("built_at_ms"));
        }
        if self.size_bytes == 0 || self.size_bytes > MAX_RELEASE_BINARY_BYTES {
            return Err(ReleaseSyncError::InvalidManifest("size_bytes"));
        }
        let sha256_bytes = decode_lowercase_hex_32(&self.sha256)
            .ok_or(ReleaseSyncError::InvalidManifest("sha256"))?;
        let blake3_bytes = decode_lowercase_hex_32(&self.blake3)
            .ok_or(ReleaseSyncError::InvalidManifest("blake3"))?;
        let expected_key = expected_artifact_key(&self.binary, &self.target_triple, &self.sha256);
        if self.artifact_key != expected_key {
            return Err(ReleaseSyncError::InvalidManifest("artifact_key"));
        }
        Ok((sha256_bytes, blake3_bytes))
    }
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

pub fn decode_lowercase_hex_32(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 32];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&raw[idx * 2..idx * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn decode_hex_32_any_case(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 || !raw.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&raw[idx * 2..idx * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn decode_hex_64_any_case(raw: &str) -> Option<[u8; 64]> {
    if raw.len() != 128 || !raw.is_ascii() {
        return None;
    }
    let mut out = [0u8; 64];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&raw[idx * 2..idx * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn csprng_hex_16() -> Result<String, ReleaseSyncError> {
    let mut bytes = [0u8; 8];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ReleaseSyncError::InstallFailed("os_csprng_unavailable".into()))?;
    Ok(encode_hex(&bytes))
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn iso_now_string() -> String {
    if let Ok(output) = Command::new("/bin/date")
        .args(["+%Y-%m-%dT%H:%M:%S%z %Z"])
        .output()
        && output.status.success()
    {
        return String::from_utf8_lossy(&output.stdout).trim().to_owned();
    }
    now_unix_secs().to_string()
}

fn is_transient_errno(errno: rustix::io::Errno) -> bool {
    matches!(
        errno,
        rustix::io::Errno::IO
            | rustix::io::Errno::MFILE
            | rustix::io::Errno::NFILE
            | rustix::io::Errno::NOMEM
            | rustix::io::Errno::NOBUFS
            | rustix::io::Errno::AGAIN
            | rustix::io::Errno::INTR
            | rustix::io::Errno::BUSY
            | rustix::io::Errno::TIMEDOUT
            | rustix::io::Errno::STALE
    )
}

fn is_transient_io_error(err: &std::io::Error) -> bool {
    if let Some(errno) = rustix::io::Errno::from_io_error(err)
        && is_transient_errno(errno)
    {
        return true;
    }
    matches!(
        err.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::OutOfMemory
    )
}

fn classify_journal_io_error(context: &str, err: &std::io::Error) -> ReleaseSyncError {
    let msg = format!("{context}: {err}");
    if is_transient_io_error(err) {
        ReleaseSyncError::TransientIo(msg)
    } else {
        ReleaseSyncError::SourceUnavailable(msg)
    }
}

fn classify_state_io_error(context: &str, err: &std::io::Error) -> ReleaseSyncError {
    let msg = format!("{context}: {err}");
    if is_transient_io_error(err) {
        ReleaseSyncError::TransientIo(msg)
    } else {
        ReleaseSyncError::StatePersistenceFailed(msg)
    }
}

fn classify_install_io_error(context: &str, err: &std::io::Error) -> ReleaseSyncError {
    let msg = format!("{context}: {err}");
    if is_transient_io_error(err) {
        ReleaseSyncError::TransientIo(msg)
    } else {
        ReleaseSyncError::InstallFailed(msg)
    }
}

/// Opens `path` strictly with `O_NOFOLLOW | O_CLOEXEC`, cross-checking `lstat`
/// and `fstat` `(dev, ino)` to eliminate symlink/TOCTOU swap races.
fn open_regular_file_nofollow(
    path: &Path,
    require_single_link: bool,
    require_owner: bool,
) -> Result<(File, fs::Metadata), ReleaseSyncError> {
    let lstat =
        fs::symlink_metadata(path).map_err(|e| classify_journal_io_error("lstat failed", &e))?;
    if lstat.file_type().is_symlink() || !lstat.file_type().is_file() {
        return Err(ReleaseSyncError::SafePathViolation(
            "non_regular_binary_file",
        ));
    }
    let fd = match rustix_open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(err) if err == rustix::io::Errno::LOOP || err == rustix::io::Errno::MLINK => {
            return Err(ReleaseSyncError::SafePathViolation("symlink_open_refused"));
        }
        Err(err) if is_transient_errno(err) => {
            return Err(ReleaseSyncError::TransientIo(format!("open failed: {err}")));
        }
        Err(err) => {
            return Err(ReleaseSyncError::SourceUnavailable(format!(
                "open failed: {err}"
            )));
        }
    };
    let file = File::from(fd);
    let fstat = file
        .metadata()
        .map_err(|e| classify_journal_io_error("fstat failed", &e))?;
    if fstat.file_type().is_symlink() || !fstat.file_type().is_file() {
        return Err(ReleaseSyncError::SafePathViolation(
            "non_regular_binary_file",
        ));
    }
    if (fstat.dev(), fstat.ino()) != (lstat.dev(), lstat.ino()) {
        return Err(ReleaseSyncError::SafePathViolation("inode_swap_detected"));
    }
    if require_single_link && fstat.nlink() != 1 {
        return Err(ReleaseSyncError::SafePathViolation("unexpected_hardlink"));
    }
    if require_owner && fstat.uid() != rustix::process::geteuid().as_raw() {
        return Err(ReleaseSyncError::SafePathViolation("unexpected_file_owner"));
    }
    Ok((file, fstat))
}

fn compute_digests_from_open_file(
    file: &mut File,
    expected_len: u64,
    expected_id: (u64, u64),
) -> Result<(u64, [u8; 32], [u8; 32]), ReleaseSyncError> {
    let mut sha256_hasher = Sha256::new();
    let mut blake3_hasher = blake3::Hasher::new();
    let mut total: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = match file.read(&mut buf) {
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(classify_journal_io_error("read failed", &err)),
        };
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(ReleaseSyncError::InvalidManifest("size_overflow"))?;
        if total > MAX_RELEASE_BINARY_BYTES {
            return Err(ReleaseSyncError::InvalidManifest("size_bytes"));
        }
        sha256_hasher.update(&buf[..read]);
        blake3_hasher.update(&buf[..read]);
    }
    let post = file
        .metadata()
        .map_err(|e| classify_journal_io_error("post-read fstat", &e))?;
    if (post.dev(), post.ino()) != expected_id
        || total != expected_len
        || total != post.len()
        || total == 0
    {
        return Err(ReleaseSyncError::SourceUnavailable(
            "concurrent size/inode mutation or empty binary".into(),
        ));
    }
    let sha_out: [u8; 32] = sha256_hasher.finalize().into();
    let b3_out: [u8; 32] = *blake3_hasher.finalize().as_bytes();
    Ok((total, sha_out, b3_out))
}

pub fn compute_file_digests(path: &Path) -> Result<(u64, [u8; 32], [u8; 32]), ReleaseSyncError> {
    let (mut file, fstat) = open_regular_file_nofollow(path, false, false)?;
    compute_digests_from_open_file(&mut file, fstat.len(), (fstat.dev(), fstat.ino()))
}

pub fn compute_sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn compute_blake3_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

pub fn local_binary_sha256(path: &Path) -> Option<[u8; 32]> {
    let (_, sha256, _) = compute_file_digests(path).ok()?;
    Some(sha256)
}

/// Used solely to locate host `wrangler` CLI (which on Homebrew is a symlink
/// into `/opt/homebrew/Cellar/...`). Never used for release artifacts, state,
/// or signing keys, all of which use `open_regular_file_nofollow` (`O_NOFOLLOW`).
fn is_resolvable_host_cli_binary(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file())
}

/// Acquires an exclusive cross-process `flock` (`O_NOFOLLOW | O_CLOEXEC`, `0600`)
/// on `$HOME/.chinwag/release_sync.lock` to serialize release installation and
/// watermark state updates across concurrent daemons and CLI invocations.
fn acquire_release_sync_lock(home_dir: &Path) -> Result<File, ReleaseSyncError> {
    acquire_release_sync_lock_with_mode(home_dir, false)
}

fn acquire_release_sync_lock_with_mode(
    home_dir: &Path,
    nonblocking: bool,
) -> Result<File, ReleaseSyncError> {
    let chinwag_dir = ensure_private_dir(&home_dir.join(".chinwag"))?;
    let lock_path = chinwag_dir.join("release_sync.lock");
    let fd = match rustix_open(
        &lock_path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => fd,
        Err(err) if err == rustix::io::Errno::LOOP || err == rustix::io::Errno::MLINK => {
            return Err(ReleaseSyncError::SafePathViolation("lock_file_symlink"));
        }
        Err(err) if is_transient_errno(err) => {
            return Err(ReleaseSyncError::TransientIo(format!("lock open: {err}")));
        }
        Err(err) => {
            return Err(ReleaseSyncError::StatePersistenceFailed(format!(
                "lock open: {err}"
            )));
        }
    };
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|e| classify_state_io_error("lock_fstat", &e))?;
    if meta.file_type().is_symlink()
        || !meta.file_type().is_file()
        || meta.nlink() != 1
        || meta.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(ReleaseSyncError::SafePathViolation("unsafe_lock_file"));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| classify_state_io_error("chmod_lock_file", &e))?;
    let op = if nonblocking {
        FlockOperation::NonBlockingLockExclusive
    } else {
        FlockOperation::LockExclusive
    };
    loop {
        match flock(&file, op) {
            Ok(()) => return Ok(file),
            Err(err) if err == rustix::io::Errno::INTR => continue,
            Err(err)
                if nonblocking
                    && (err == rustix::io::Errno::WOULDBLOCK
                        || err == rustix::io::Errno::AGAIN) =>
            {
                return Err(ReleaseSyncError::TransientIo(
                    "release_sync.lock contended".into(),
                ));
            }
            Err(err) if is_transient_errno(err) => {
                return Err(ReleaseSyncError::TransientIo(format!(
                    "flock failed: {err}"
                )));
            }
            Err(err) => {
                return Err(ReleaseSyncError::StatePersistenceFailed(format!(
                    "flock failed: {err}"
                )));
            }
        }
    }
}

fn ensure_private_dir(dir: &Path) -> Result<PathBuf, ReleaseSyncError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return Err(ReleaseSyncError::SafePathViolation("symlink_or_non_dir"));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|e| classify_state_io_error("mkdir_failed", &e))?;
        }
        Err(err) => return Err(classify_state_io_error("dir_stat_failed", &err)),
    }
    let (dir_fd, _) = open_dir_nofollow(dir)?;
    dir_fd
        .set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(|e| classify_state_io_error("chmod_private_dir", &e))?;
    let post = dir_fd
        .metadata()
        .map_err(|e| classify_state_io_error("fstat_private_dir", &e))?;
    if post.file_type().is_symlink() || !post.file_type().is_dir() || (post.mode() & 0o777) != 0o700
    {
        return Err(ReleaseSyncError::SafePathViolation(
            "private_dir_mode_or_type_invalid",
        ));
    }
    Ok(dir.to_path_buf())
}

fn ensure_bin_and_staging_dirs(home_dir: &Path) -> Result<(PathBuf, PathBuf), ReleaseSyncError> {
    let local_dir = home_dir.join(".local");
    match fs::symlink_metadata(&local_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return Err(ReleaseSyncError::SafePathViolation("invalid_dot_local"));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&local_dir)
                .map_err(|e| classify_state_io_error("mkdir_dot_local", &e))?;
        }
        Err(err) => return Err(classify_state_io_error("stat_dot_local", &err)),
    }
    let _ = open_dir_nofollow(&local_dir)?;

    let bin_dir = local_dir.join("bin");
    let mut created_bin_dir = false;
    match fs::symlink_metadata(&bin_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return Err(ReleaseSyncError::SafePathViolation("invalid_local_bin"));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&bin_dir)
                .map_err(|e| classify_state_io_error("mkdir_local_bin", &e))?;
            created_bin_dir = true;
        }
        Err(err) => return Err(classify_state_io_error("stat_local_bin", &err)),
    }
    let (bin_dir_fd, _) = open_dir_nofollow(&bin_dir)?;
    let bin_meta = bin_dir_fd
        .metadata()
        .map_err(|e| classify_state_io_error("fstat_local_bin", &e))?;
    if created_bin_dir || (bin_meta.mode() & 0o022) != 0 {
        bin_dir_fd
            .set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|e| classify_state_io_error("chmod_local_bin", &e))?;
    }
    let staging_dir = bin_dir.join(".staging");
    ensure_private_dir(&staging_dir)?;
    Ok((bin_dir, staging_dir))
}

pub fn release_sync_state_path(home_dir: &Path) -> PathBuf {
    home_dir.join(".chinwag").join("release_sync_state.json")
}

pub fn load_release_sync_state(home_dir: &Path) -> Result<ReleaseSyncStateV1, ReleaseSyncError> {
    let path = release_sync_state_path(home_dir);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ReleaseSyncStateV1::default());
        }
        Err(err) => return Err(classify_state_io_error("stat", &err)),
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(ReleaseSyncError::SafePathViolation(
            "state_symlink_or_non_file",
        ));
    }
    let (file, fstat) = open_regular_file_nofollow(&path, true, true)?;
    if fstat.len() > MAX_STATE_FILE_BYTES {
        return Err(ReleaseSyncError::StatePersistenceFailed(
            "state_too_large".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(fstat.len() as usize);
    file.take(MAX_STATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| classify_state_io_error("read", &e))?;
    if bytes.len() as u64 > MAX_STATE_FILE_BYTES {
        return Err(ReleaseSyncError::StatePersistenceFailed(
            "state_too_large".into(),
        ));
    }
    let state: ReleaseSyncStateV1 = serde_json::from_slice(&bytes)
        .map_err(|_| ReleaseSyncError::StatePersistenceFailed("corrupt_state_json".into()))?;
    if state.schema != RELEASE_SYNC_STATE_SCHEMA {
        return Err(ReleaseSyncError::StatePersistenceFailed(
            "state_schema".into(),
        ));
    }
    Ok(state)
}

#[cfg(test)]
std::thread_local! {
    static TEST_INJECTED_SAVE_STATE_ERRNO: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    static TEST_INJECTED_PREPARE_REEXEC_ERRNO: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

pub fn save_release_sync_state(
    home_dir: &Path,
    state: &ReleaseSyncStateV1,
) -> Result<(), ReleaseSyncError> {
    let chinwag_dir = ensure_private_dir(&home_dir.join(".chinwag"))?;
    let (chinwag_dir_fd, _) = open_dir_nofollow(&chinwag_dir)?;
    let final_path = chinwag_dir.join("release_sync_state.json");
    match fs::symlink_metadata(&final_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                return Err(ReleaseSyncError::SafePathViolation(
                    "state_target_is_symlink",
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(classify_state_io_error("stat_final", &err)),
    }
    #[cfg(test)]
    if let Some(raw_errno) = TEST_INJECTED_SAVE_STATE_ERRNO.with(|c| c.take()) {
        let injected = std::io::Error::from_raw_os_error(raw_errno);
        return Err(classify_state_io_error("open_tmp", &injected));
    }
    let nonce = csprng_hex_16()?;
    let tmp_name = format!(".release_sync_state.tmp.{}.{nonce}", std::process::id());
    let serialized = serde_json::to_vec_pretty(state)
        .map_err(|_| ReleaseSyncError::StatePersistenceFailed("serialize".into()))?;
    let write_res = (|| -> Result<(), ReleaseSyncError> {
        let tmp_fd = rustix::fs::openat(
            &chinwag_dir_fd,
            &tmp_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|err| {
            if err == rustix::io::Errno::LOOP || err == rustix::io::Errno::MLINK {
                ReleaseSyncError::SafePathViolation("state_tmp_symlink")
            } else if is_transient_errno(err) {
                ReleaseSyncError::TransientIo(format!("open_tmp: {err}"))
            } else {
                ReleaseSyncError::StatePersistenceFailed(format!("open_tmp: {err}"))
            }
        })?;
        let mut file = File::from(tmp_fd);
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| classify_state_io_error("chmod_tmp", &e))?;
        file.write_all(&serialized)
            .map_err(|e| classify_state_io_error("write_tmp", &e))?;
        file.sync_all()
            .map_err(|e| classify_state_io_error("sync_tmp", &e))?;
        drop(file);
        rustix::fs::renameat(
            &chinwag_dir_fd,
            &tmp_name,
            &chinwag_dir_fd,
            "release_sync_state.json",
        )
        .map_err(|err| {
            if is_transient_errno(err) {
                ReleaseSyncError::TransientIo(format!("rename_state: {err}"))
            } else {
                ReleaseSyncError::StatePersistenceFailed(format!("rename_state: {err}"))
            }
        })?;
        chinwag_dir_fd
            .sync_all()
            .map_err(|e| classify_state_io_error("sync_state_dir", &e))?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = rustix::fs::unlinkat(&chinwag_dir_fd, &tmp_name, rustix::fs::AtFlags::empty());
    }
    write_res
}

fn kill_process_group_best_effort(raw_pid_u32: u32) {
    if let Ok(raw_pid) = i32::try_from(raw_pid_u32)
        && raw_pid > 1
        && let Some(pid) = rustix::process::Pid::from_raw(raw_pid)
    {
        // Signal only the dedicated process group (`kill(-pgid, SIGKILL)`), never a
        // bare PID: POSIX guarantees the kernel will not allocate `pgid` to an
        // unrelated process while any member of process group `pgid` still exists.
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

fn run_bounded_command(cmd: &mut Command, deadline: Duration) -> Result<(), String> {
    // Spawn in a dedicated process group (`pgid == child_pid`) so any background
    // descendant holding inherited stdout/stderr pipes can be terminated cleanly
    // at the deadline without stalling the release worker.
    cmd.process_group(0);
    let mut child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;
    let child_pid = child.id();
    let stdout_rx = child.stdout.take().map(|mut out_pipe| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut out_pipe, &mut std::io::sink());
            let _ = tx.send(());
        });
        rx
    });
    let stderr_rx = child.stderr.take().map(|mut err_pipe| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut preview = Vec::with_capacity(512);
            let _ = (&mut err_pipe).take(512).read_to_end(&mut preview);
            let _ = std::io::copy(&mut err_pipe, &mut std::io::sink());
            let _ = tx.send(preview);
        });
        rx
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Some(rx) = stdout_rx {
                    let remaining = deadline.saturating_sub(started.elapsed());
                    if rx.recv_timeout(remaining).is_err() {
                        kill_process_group_best_effort(child_pid);
                        let _ = rx.recv_timeout(Duration::from_millis(50));
                        return Err(format!(
                            "timed out waiting for stdout pipe EOF after {}ms",
                            deadline.as_millis()
                        ));
                    }
                }
                let stderr_buf = if let Some(rx) = stderr_rx {
                    let remaining = deadline.saturating_sub(started.elapsed());
                    match rx.recv_timeout(remaining) {
                        Ok(buf) => buf,
                        Err(_) => {
                            kill_process_group_best_effort(child_pid);
                            let _ = rx.recv_timeout(Duration::from_millis(50));
                            return Err(format!(
                                "timed out waiting for stderr pipe EOF after {}ms",
                                deadline.as_millis()
                            ));
                        }
                    }
                } else {
                    Vec::new()
                };
                if status.success() {
                    return Ok(());
                }
                let snippet = String::from_utf8_lossy(&stderr_buf).trim().to_owned();
                return Err(if snippet.is_empty() {
                    format!("exit status {status}")
                } else {
                    format!("exit status {status}: {snippet}")
                });
            }
            Ok(None) => {
                if started.elapsed() >= deadline {
                    kill_process_group_best_effort(child_pid);
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("timed out after {}ms", deadline.as_millis()));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                return Err(format!("wait failed: {err}"));
            }
        }
    }
}

#[cfg(target_os = "macos")]
struct BoundedOwnedSpawnFailure {
    message: String,
    process_group_quiesced: bool,
}

#[cfg(target_os = "macos")]
fn run_bounded_owned_spawn(
    mut child: chinwag_host_process::owned_spawn::OwnedChild,
    stdout_reader: Option<std::io::PipeReader>,
    stderr_reader: Option<std::io::PipeReader>,
    deadline: Duration,
) -> Result<(), BoundedOwnedSpawnFailure> {
    use chinwag_host_process::owned_spawn::Exit;

    let child_pid = child.pid();
    let stdout_rx = stdout_reader.map(|mut out_pipe| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut out_pipe, &mut std::io::sink());
            let _ = tx.send(());
        });
        rx
    });
    let stderr_rx = stderr_reader.map(|mut err_pipe| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut preview = Vec::with_capacity(512);
            let _ = (&mut err_pipe).take(512).read_to_end(&mut preview);
            let _ = std::io::copy(&mut err_pipe, &mut std::io::sink());
            let _ = tx.send(preview);
        });
        rx
    });

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(exit)) => {
                if let Some(rx) = stdout_rx {
                    let remaining = deadline.saturating_sub(started.elapsed());
                    if rx.recv_timeout(remaining).is_err() {
                        kill_process_group_best_effort(child_pid);
                        let stdout_eof = rx.recv_timeout(Duration::from_millis(100)).is_ok();
                        let stderr_eof = stderr_rx
                            .as_ref()
                            .is_none_or(|erx| erx.recv_timeout(Duration::from_millis(100)).is_ok());
                        return Err(BoundedOwnedSpawnFailure {
                            message: format!(
                                "timed out waiting for stdout pipe EOF after {}ms",
                                deadline.as_millis()
                            ),
                            process_group_quiesced: stdout_eof && stderr_eof,
                        });
                    }
                }
                let stderr_buf = if let Some(rx) = stderr_rx {
                    let remaining = deadline.saturating_sub(started.elapsed());
                    match rx.recv_timeout(remaining) {
                        Ok(buf) => buf,
                        Err(_) => {
                            kill_process_group_best_effort(child_pid);
                            let stderr_eof = rx.recv_timeout(Duration::from_millis(100)).is_ok();
                            return Err(BoundedOwnedSpawnFailure {
                                message: format!(
                                    "timed out waiting for stderr pipe EOF after {}ms",
                                    deadline.as_millis()
                                ),
                                process_group_quiesced: stderr_eof,
                            });
                        }
                    }
                } else {
                    Vec::new()
                };
                if exit == Exit::Code(0) {
                    return Ok(());
                }
                let snippet = String::from_utf8_lossy(&stderr_buf).trim().to_owned();
                let status_desc = match exit {
                    Exit::Code(code) => format!("exit code {code}"),
                    Exit::Signal(sig) => format!("signal {sig}"),
                };
                return Err(BoundedOwnedSpawnFailure {
                    message: if snippet.is_empty() {
                        status_desc
                    } else {
                        format!("{status_desc}: {snippet}")
                    },
                    process_group_quiesced: true,
                });
            }
            Ok(None) => {
                if started.elapsed() >= deadline {
                    kill_process_group_best_effort(child_pid);
                    let mut child_reaped = false;
                    for _ in 0..50 {
                        match child.try_wait() {
                            Ok(Some(_)) => {
                                child_reaped = true;
                                break;
                            }
                            Err(_) => break,
                            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                        }
                    }
                    let stdout_eof = stdout_rx
                        .as_ref()
                        .is_none_or(|rx| rx.recv_timeout(Duration::from_millis(100)).is_ok());
                    let stderr_eof = stderr_rx
                        .as_ref()
                        .is_none_or(|rx| rx.recv_timeout(Duration::from_millis(100)).is_ok());
                    return Err(BoundedOwnedSpawnFailure {
                        message: format!("timed out after {}ms", deadline.as_millis()),
                        process_group_quiesced: child_reaped && stdout_eof && stderr_eof,
                    });
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                // Quarantine: child status is uncertain; do not signal or report quiesced.
                return Err(BoundedOwnedSpawnFailure {
                    message: format!("wait failed: {err}"),
                    process_group_quiesced: false,
                });
            }
        }
    }
}

#[cfg(target_os = "macos")]
enum ToolRunError {
    TransientIo(String),
    Failed(String),
}

#[cfg(target_os = "macos")]
fn classify_tool_spawn_io(context: &str, err: &std::io::Error) -> ToolRunError {
    let msg = format!("{context}: {err}");
    if is_transient_io_error(err) {
        ToolRunError::TransientIo(msg)
    } else {
        ToolRunError::Failed(msg)
    }
}

#[cfg(target_os = "macos")]
fn spawn_tool_in_dir(
    program: &std::ffi::CStr,
    args: &[&str],
    dir_fd: &File,
    deadline: Duration,
) -> Result<(), ToolRunError> {
    use chinwag_host_process::owned_spawn::{SpawnStdio, spawn_at_group};

    let dev_null =
        File::open("/dev/null").map_err(|e| classify_tool_spawn_io("open /dev/null", &e))?;
    let (stderr_reader, stderr_writer) =
        std::io::pipe().map_err(|e| classify_tool_spawn_io("stderr pipe", &e))?;
    let c_args: Vec<CString> = args
        .iter()
        .map(|s| CString::new(*s))
        .collect::<Result<_, _>>()
        .map_err(|e| ToolRunError::Failed(format!("invalid tool argument: {e}")))?;
    let env = [
        CString::new("PATH=/usr/bin:/bin").unwrap(),
        CString::new("LC_ALL=C").unwrap(),
    ];
    let child = spawn_at_group(
        program,
        &c_args,
        &env,
        dir_fd.as_fd(),
        SpawnStdio {
            input: dev_null.as_fd(),
            output: dev_null.as_fd(),
            error: stderr_writer.as_fd(),
        },
        true,
    )
    .map_err(|e| classify_tool_spawn_io("spawn_at failed", &e))?;
    drop(stderr_writer);
    run_bounded_owned_spawn(child, None, Some(stderr_reader), deadline)
        .map_err(|e| ToolRunError::Failed(e.message))
}

#[cfg(target_os = "macos")]
const UF_IMMUTABLE: u32 = 0x0000_0002;

#[cfg(target_os = "macos")]
fn set_dir_and_entry_immutable(
    dir_fd: &File,
    entry_name: &str,
    immutable: bool,
) -> Result<(), ReleaseSyncError> {
    validate_binary_name(entry_name)?;
    let rel_entry = format!("./{entry_name}");
    if immutable {
        spawn_tool_in_dir(
            c"/usr/bin/chflags",
            &["uchg", &rel_entry, "."],
            dir_fd,
            VERSION_SMOKE_TIMEOUT,
        )
        .map_err(|err| match err {
            ToolRunError::TransientIo(msg) => {
                ReleaseSyncError::TransientIo(format!("chflags uchg failed: {msg}"))
            }
            ToolRunError::Failed(msg) => {
                ReleaseSyncError::InstallFailed(format!("chflags uchg failed: {msg}"))
            }
        })
    } else {
        spawn_tool_in_dir(
            c"/usr/bin/chflags",
            &["nouchg", ".", &rel_entry],
            dir_fd,
            VERSION_SMOKE_TIMEOUT,
        )
        .map_err(|err| match err {
            ToolRunError::TransientIo(msg) => {
                ReleaseSyncError::TransientIo(format!("chflags nouchg failed: {msg}"))
            }
            ToolRunError::Failed(msg) => {
                ReleaseSyncError::InstallFailed(format!("chflags nouchg failed: {msg}"))
            }
        })
    }
}

#[cfg(not(target_os = "macos"))]
fn set_dir_and_entry_immutable(
    _dir_fd: &File,
    entry_name: &str,
    _immutable: bool,
) -> Result<(), ReleaseSyncError> {
    validate_binary_name(entry_name)
}

#[cfg(target_os = "macos")]
fn verify_fd_immutable(file: &File) -> Result<(), ReleaseSyncError> {
    let meta = file
        .metadata()
        .map_err(|e| classify_install_io_error("fstat immutable pin", &e))?;
    if (meta.st_flags() & UF_IMMUTABLE) == 0 {
        return Err(ReleaseSyncError::InstallFailed(
            "kernel UF_IMMUTABLE flag missing on pinned vnode".into(),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn verify_fd_immutable(_file: &File) -> Result<(), ReleaseSyncError> {
    Ok(())
}

fn open_dir_nofollow(dir: &Path) -> Result<(File, (u64, u64)), ReleaseSyncError> {
    let lstat = fs::symlink_metadata(dir).map_err(|err| {
        if is_transient_io_error(&err) {
            ReleaseSyncError::TransientIo(format!("dir lstat failed: {err}"))
        } else {
            ReleaseSyncError::SafePathViolation("dir_lstat_failed")
        }
    })?;
    if lstat.file_type().is_symlink() || !lstat.file_type().is_dir() {
        return Err(ReleaseSyncError::SafePathViolation("symlink_or_non_dir"));
    }
    let fd = match rustix_open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(err) if is_transient_errno(err) => {
            return Err(ReleaseSyncError::TransientIo(format!(
                "dir open failed: {err}"
            )));
        }
        Err(_) => {
            return Err(ReleaseSyncError::SafePathViolation(
                "dir_open_nofollow_failed",
            ));
        }
    };
    let file = File::from(fd);
    let fstat = file.metadata().map_err(|err| {
        if is_transient_io_error(&err) {
            ReleaseSyncError::TransientIo(format!("dir fstat failed: {err}"))
        } else {
            ReleaseSyncError::SafePathViolation("dir_fstat_failed")
        }
    })?;
    if !fstat.file_type().is_dir()
        || (fstat.dev(), fstat.ino()) != (lstat.dev(), lstat.ino())
        || fstat.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(ReleaseSyncError::SafePathViolation(
            "dir_inode_or_owner_mismatch",
        ));
    }
    Ok((file, (fstat.dev(), fstat.ino())))
}

fn open_regular_at_dir_nofollow(
    dir_fd: &File,
    entry_name: &str,
    require_single_link: bool,
    require_owner: bool,
) -> Result<(File, fs::Metadata), ReleaseSyncError> {
    let fd = rustix::fs::openat(
        dir_fd,
        entry_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| {
        if err == rustix::io::Errno::LOOP || err == rustix::io::Errno::MLINK {
            ReleaseSyncError::SafePathViolation("symlink_open_refused")
        } else if is_transient_errno(err) {
            ReleaseSyncError::TransientIo(format!("openat failed: {err}"))
        } else {
            ReleaseSyncError::SourceUnavailable(format!("openat failed: {err}"))
        }
    })?;
    let file = File::from(fd);
    let fstat = file
        .metadata()
        .map_err(|e| classify_journal_io_error("fstat failed", &e))?;
    if fstat.file_type().is_symlink() || !fstat.file_type().is_file() {
        return Err(ReleaseSyncError::SafePathViolation(
            "non_regular_binary_file",
        ));
    }
    if require_single_link && fstat.nlink() != 1 {
        return Err(ReleaseSyncError::SafePathViolation("unexpected_hardlink"));
    }
    if require_owner && fstat.uid() != rustix::process::geteuid().as_raw() {
        return Err(ReleaseSyncError::SafePathViolation("unexpected_file_owner"));
    }
    Ok((file, fstat))
}

fn capture_ancestor_chain_inodes(
    home_dir: &Path,
    op_dir: &Path,
) -> Result<[(u64, u64); 5], ReleaseSyncError> {
    let local_dir = home_dir.join(".local");
    let bin_dir = local_dir.join("bin");
    let staging_dir = bin_dir.join(".staging");
    let paths = [home_dir, &local_dir, &bin_dir, &staging_dir, op_dir];
    let mut ids = [(0u64, 0u64); 5];
    for (slot, path) in ids.iter_mut().zip(paths) {
        let meta = fs::symlink_metadata(path).map_err(|err| {
            if is_transient_io_error(&err) {
                ReleaseSyncError::TransientIo(format!("ancestor stat failed: {err}"))
            } else {
                ReleaseSyncError::SafePathViolation("ancestor_stat_failed")
            }
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(ReleaseSyncError::SafePathViolation(
                "ancestor_symlink_or_non_dir",
            ));
        }
        *slot = (meta.dev(), meta.ino());
    }
    Ok(ids)
}

struct StagedOpGuard {
    op_dir: PathBuf,
    op_dir_fd: Option<File>,
    op_dir_id: Option<(u64, u64)>,
    entry_name: String,
    armed: bool,
}

impl StagedOpGuard {
    fn new(op_dir: PathBuf, entry_name: &str) -> Self {
        Self {
            op_dir,
            op_dir_fd: None,
            op_dir_id: None,
            entry_name: entry_name.to_owned(),
            armed: true,
        }
    }

    fn bind_dir_fd(&mut self, dir_fd: &File, dir_id: (u64, u64)) {
        self.op_dir_fd = dir_fd.try_clone().ok();
        self.op_dir_id = Some(dir_id);
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    /// Leaves `op_dir` and `./<binary>` locked (`UF_IMMUTABLE`) if a spawned
    /// child/descendant process group did not confirm terminal exit + pipe EOF,
    /// preserving the `owned_spawn` invariant until `cleanup_stale_reexec_dirs`
    /// later observes the parent PID is gone.
    fn quarantine(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagedOpGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(ref fd) = self.op_dir_fd {
            let _ = set_dir_and_entry_immutable(fd, &self.entry_name, false);
            let _ = rustix::fs::unlinkat(fd, &self.entry_name, rustix::fs::AtFlags::empty());
        }
        if let Ok((dir_fd, id)) = open_dir_nofollow(&self.op_dir)
            && self.op_dir_id.is_none_or(|expected| expected == id)
        {
            drop(dir_fd);
            clear_and_remove_immutable_dir(&self.op_dir);
        }
    }
}

pub fn clear_and_remove_immutable_dir(dir: &Path) {
    if let Ok((dir_fd, _)) = open_dir_nofollow(dir) {
        #[cfg(target_os = "macos")]
        {
            let _ = spawn_tool_in_dir(
                c"/usr/bin/chflags",
                &["nouchg", "."],
                &dir_fd,
                VERSION_SMOKE_TIMEOUT,
            );
            for bin in ALLOWED_BINARIES {
                let _ = spawn_tool_in_dir(
                    c"/usr/bin/chflags",
                    &["nouchg", &format!("./{bin}")],
                    &dir_fd,
                    VERSION_SMOKE_TIMEOUT,
                );
            }
        }
        let _ = &dir_fd;
    }
    let _ = fs::remove_dir_all(dir);
}

pub fn cleanup_stale_reexec_dirs(home_dir: &Path) {
    let current_exe_parent = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    let staging_dir = home_dir.join(".local/bin/.staging");
    let Ok(entries) = fs::read_dir(&staging_dir) else {
        return;
    };
    let self_pid = std::process::id();
    for entry in entries.flatten() {
        let path = entry.path();
        if current_exe_parent.as_deref() == Some(path.as_path()) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(rest) = name
            .strip_prefix("reexec.")
            .or_else(|| name.strip_prefix("op.pub."))
            .or_else(|| name.strip_prefix("op."))
        else {
            continue;
        };
        let Some(pid_str) = rest.split('.').next() else {
            continue;
        };
        let Ok(raw_pid) = pid_str.parse::<i32>() else {
            continue;
        };
        if raw_pid <= 0 {
            continue;
        }
        if raw_pid as u32 == self_pid {
            if name.starts_with("reexec.") {
                clear_and_remove_immutable_dir(&path);
            }
            continue;
        }
        if let Some(pid) = rustix::process::Pid::from_raw(raw_pid)
            && rustix::process::test_kill_process(pid) == Err(rustix::io::Errno::SRCH)
        {
            clear_and_remove_immutable_dir(&path);
        }
    }
}

pub fn cleanup_prepared_reexec(prepared: PreparedImmutableReexec) {
    let dir_path = prepared.dir_path;
    drop(prepared.dir_fd);
    clear_and_remove_immutable_dir(&dir_path);
}

/// Atomically refreshes the authoritative verified `chinwag` release under
/// `$HOME/.chinwag/release_sync.lock` (so concurrent `chinwag release publish` or
/// `chinwag release sync` updates sharing `HOME` never cause stale-digest `DigestMismatch`
/// while unauthorized on-disk tampering without matching verified state still fails closed),
/// copies `install_path` into a private per-process `0700` staging directory under the lock,
/// verifies digests in constant time + strict macOS `codesign` while non-executable (`0600`),
/// promotes to `0755`, locks BOTH the binary and its parent directory with kernel
/// `UF_IMMUTABLE` (`uchg`), and re-verifies the pinned FD via `openat`.
pub fn prepare_immutable_reexec_binary(
    home_dir: &Path,
    install_path: &Path,
    expected_sha256: &[u8; 32],
) -> Result<PreparedImmutableReexec, ReleaseSyncError> {
    let (_, staging_dir) = ensure_bin_and_staging_dirs(home_dir)?;
    let nonce = csprng_hex_16()?;
    let reexec_dir = staging_dir.join(format!("reexec.{}.{nonce}", std::process::id()));
    fs::create_dir(&reexec_dir).map_err(|e| classify_state_io_error("reexec mkdir", &e))?;
    fs::set_permissions(&reexec_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| classify_state_io_error("reexec chmod dir", &e))?;
    let binary_path = reexec_dir.join("chinwag");
    let mut guard = StagedOpGuard::new(reexec_dir.clone(), "chinwag");

    let (dir_fd, dir_id) = open_dir_nofollow(&reexec_dir)?;
    guard.bind_dir_fd(&dir_fd, dir_id);

    #[cfg(test)]
    if let Some(raw_errno) = TEST_INJECTED_PREPARE_REEXEC_ERRNO.with(|c| c.take()) {
        let injected = std::io::Error::from_raw_os_error(raw_errno);
        return Err(classify_journal_io_error(
            "injected_prepare_reexec",
            &injected,
        ));
    }

    let (target_sha256, verified_state_meta, copied_len) = {
        let _lock = acquire_release_sync_lock_with_mode(home_dir, true)?;
        let canonical_chinwag_path = home_dir.join(".local/bin/chinwag");
        let (target_sha256, verified_state_meta) = if install_path == canonical_chinwag_path {
            let sync_state = load_release_sync_state(home_dir)?;
            if let Some(st) = sync_state.binaries.get("chinwag") {
                if st.binary != "chinwag"
                    || st.target_triple != CURRENT_TARGET_TRIPLE
                    || st.size_bytes == 0
                    || st.size_bytes > MAX_RELEASE_BINARY_BYTES
                {
                    return Err(ReleaseSyncError::StatePersistenceFailed(
                        "invalid_chinwag_sync_state".into(),
                    ));
                }
                let st_sha = decode_lowercase_hex_32(&st.sha256).ok_or_else(|| {
                    ReleaseSyncError::StatePersistenceFailed("invalid_chinwag_sha256".into())
                })?;
                let st_blake3 = decode_lowercase_hex_32(&st.blake3).ok_or_else(|| {
                    ReleaseSyncError::StatePersistenceFailed("invalid_chinwag_blake3".into())
                })?;
                (st_sha, Some((st_blake3, st.size_bytes)))
            } else {
                (*expected_sha256, None)
            }
        } else {
            (*expected_sha256, None)
        };

        let (mut src, src_fstat) = open_regular_file_nofollow(install_path, false, true)?;
        if src_fstat.len() == 0 {
            return Err(ReleaseSyncError::SourceUnavailable(
                "reexec target is empty".into(),
            ));
        }

        let dst_fd = rustix::fs::openat(
            &dir_fd,
            "chinwag",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| {
            if is_transient_errno(e) {
                ReleaseSyncError::TransientIo(format!("reexec stage create: {e}"))
            } else {
                ReleaseSyncError::InstallFailed(format!("reexec stage create: {e}"))
            }
        })?;
        let mut dst = File::from(dst_fd);
        std::io::copy(&mut src, &mut dst)
            .map_err(|e| classify_state_io_error("reexec stage copy", &e))?;
        dst.sync_all()
            .map_err(|e| classify_state_io_error("reexec stage sync", &e))?;
        drop(dst);
        drop(src);
        (target_sha256, verified_state_meta, src_fstat.len())
    };

    let (mut pre_ro, pre_fstat) = open_regular_at_dir_nofollow(&dir_fd, "chinwag", true, true)?;
    let staged_id = (pre_fstat.dev(), pre_fstat.ino());
    let (actual_size, actual_sha, actual_blake3) =
        compute_digests_from_open_file(&mut pre_ro, copied_len, staged_id)?;
    if !bool::from(actual_sha.ct_eq(&target_sha256)) {
        return Err(ReleaseSyncError::DigestMismatch);
    }
    if let Some((expected_blake3, expected_size)) = verified_state_meta
        && (actual_size != expected_size || !bool::from(actual_blake3.ct_eq(&expected_blake3)))
    {
        return Err(ReleaseSyncError::DigestMismatch);
    }
    verify_codesign_strict_in_dir(&dir_fd, "chinwag")?;
    pre_ro
        .set_permissions(fs::Permissions::from_mode(0o755))
        .map_err(|e| classify_install_io_error("reexec chmod 0755", &e))?;
    drop(pre_ro);

    set_dir_and_entry_immutable(&dir_fd, "chinwag", true)?;

    let dir_post = dir_fd.metadata().map_err(|err| {
        if is_transient_io_error(&err) {
            ReleaseSyncError::TransientIo(format!("reexec_dir_fstat: {err}"))
        } else {
            ReleaseSyncError::SafePathViolation("reexec_dir_fstat")
        }
    })?;
    if (dir_post.dev(), dir_post.ino()) != dir_id {
        return Err(ReleaseSyncError::SafePathViolation("reexec_dir_inode_swap"));
    }
    verify_fd_immutable(&dir_fd)?;

    let (mut pinned_ro, pinned_fstat) =
        open_regular_at_dir_nofollow(&dir_fd, "chinwag", true, true)?;
    if (pinned_fstat.dev(), pinned_fstat.ino()) != staged_id {
        return Err(ReleaseSyncError::SafePathViolation("reexec_bin_inode_swap"));
    }
    verify_fd_immutable(&pinned_ro)?;
    let (post_size, post_sha, post_blake3) =
        compute_digests_from_open_file(&mut pinned_ro, copied_len, staged_id)?;
    if !bool::from(post_sha.ct_eq(&target_sha256)) {
        return Err(ReleaseSyncError::DigestMismatch);
    }
    if let Some((expected_blake3, expected_size)) = verified_state_meta
        && (post_size != expected_size || !bool::from(post_blake3.ct_eq(&expected_blake3)))
    {
        return Err(ReleaseSyncError::DigestMismatch);
    }

    guard.disarm();
    Ok(PreparedImmutableReexec {
        dir_fd,
        dir_path: reexec_dir,
        binary_path,
        sha256: target_sha256,
    })
}

#[cfg(target_os = "macos")]
fn verify_codesign_strict_in_dir(dir_fd: &File, binary_name: &str) -> Result<(), ReleaseSyncError> {
    validate_binary_name(binary_name)?;
    spawn_tool_in_dir(
        c"/usr/bin/codesign",
        &["--verify", "--strict", &format!("./{binary_name}")],
        dir_fd,
        VERSION_SMOKE_TIMEOUT,
    )
    .map_err(|err| match err {
        ToolRunError::TransientIo(msg) => ReleaseSyncError::TransientIo(msg),
        ToolRunError::Failed(msg) => ReleaseSyncError::CodesignFailed(msg),
    })
}

#[cfg(not(target_os = "macos"))]
fn verify_codesign_strict_in_dir(
    _dir_fd: &File,
    binary_name: &str,
) -> Result<(), ReleaseSyncError> {
    validate_binary_name(binary_name)
}

/// Publisher-only helper: checks strict signature first, applying ad-hoc
/// signing (`codesign -f -s -`) at most ONCE on the publisher's staged copy
/// inside `dir_fd` before canonical SHA-256 and BLAKE3 digests are computed.
#[cfg(target_os = "macos")]
fn ensure_publisher_codesigned_in_dir(
    dir_fd: &File,
    binary_name: &str,
) -> Result<(), ReleaseSyncError> {
    validate_binary_name(binary_name)?;
    match verify_codesign_strict_in_dir(dir_fd, binary_name) {
        Ok(()) => return Ok(()),
        Err(ReleaseSyncError::TransientIo(msg)) => return Err(ReleaseSyncError::TransientIo(msg)),
        Err(_) => {}
    }
    spawn_tool_in_dir(
        c"/usr/bin/codesign",
        &["-f", "-s", "-", &format!("./{binary_name}")],
        dir_fd,
        VERSION_SMOKE_TIMEOUT,
    )
    .map_err(|err| match err {
        ToolRunError::TransientIo(msg) => ReleaseSyncError::TransientIo(msg),
        ToolRunError::Failed(msg) => ReleaseSyncError::CodesignFailed(msg),
    })?;
    verify_codesign_strict_in_dir(dir_fd, binary_name)
}

#[cfg(not(target_os = "macos"))]
fn ensure_publisher_codesigned_in_dir(
    _dir_fd: &File,
    binary_name: &str,
) -> Result<(), ReleaseSyncError> {
    validate_binary_name(binary_name)
}

#[cfg(target_os = "macos")]
fn smoke_test_binary_version(
    op_dir_fd: &File,
    binary_name: &str,
    op_guard: &mut StagedOpGuard,
) -> Result<(), ReleaseSyncError> {
    use chinwag_host_process::owned_spawn::{SpawnStdio, spawn_relative_in_dir};

    validate_binary_name(binary_name)?;
    let entry_c = CString::new(binary_name)
        .map_err(|_| ReleaseSyncError::SmokeTestFailed("invalid binary name".into()))?;
    let args = [CString::new("--version").unwrap()];
    let env = [
        CString::new("PATH=/usr/bin:/bin").unwrap(),
        CString::new("LC_ALL=C").unwrap(),
    ];
    let dev_null = File::open("/dev/null")
        .map_err(|e| ReleaseSyncError::SmokeTestFailed(format!("open /dev/null: {e}")))?;
    let (stdout_reader, stdout_writer) =
        std::io::pipe().map_err(|e| ReleaseSyncError::SmokeTestFailed(format!("pipe: {e}")))?;
    let (stderr_reader, stderr_writer) =
        std::io::pipe().map_err(|e| ReleaseSyncError::SmokeTestFailed(format!("pipe: {e}")))?;
    // Anchor execution directly to `op_dir_fd` via child-only `fchdir` + `./<binary_name>`
    // while preserving exact `argv[0]` basename (`chinwag` / `chinwag-ci`).
    let child = spawn_relative_in_dir(
        &entry_c,
        &entry_c,
        &args,
        &env,
        op_dir_fd.as_fd(),
        SpawnStdio {
            input: dev_null.as_fd(),
            output: stdout_writer.as_fd(),
            error: stderr_writer.as_fd(),
        },
        true,
    )
    .map_err(|e| ReleaseSyncError::SmokeTestFailed(format!("spawn failed: {e}")))?;
    drop(stdout_writer);
    drop(stderr_writer);
    run_bounded_owned_spawn(
        child,
        Some(stdout_reader),
        Some(stderr_reader),
        VERSION_SMOKE_TIMEOUT,
    )
    .map_err(|failure| {
        if !failure.process_group_quiesced {
            op_guard.quarantine();
        }
        ReleaseSyncError::SmokeTestFailed(failure.message)
    })
}

#[cfg(not(target_os = "macos"))]
fn smoke_test_binary_version(
    op_dir_fd: &File,
    binary_name: &str,
    _op_guard: &mut StagedOpGuard,
) -> Result<(), ReleaseSyncError> {
    use std::os::fd::AsRawFd;

    validate_binary_name(binary_name)?;
    let proc_path = format!("/proc/self/fd/{}/{binary_name}", op_dir_fd.as_raw_fd());
    let mut cmd = Command::new(proc_path);
    cmd.arg0(binary_name)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_bounded_command(&mut cmd, VERSION_SMOKE_TIMEOUT).map_err(ReleaseSyncError::SmokeTestFailed)
}

/// Preserves `<bin_dir>/<binary>.prev` via an APFS hard-link + atomic rename
/// (so `<bin_dir>/<binary>` never disappears even momentarily) and atomically
/// renames `<binary>` directly out of `op_dir_fd` onto `<bin_dir>/<binary>` via
/// `renameat`, re-verifying staged inode identity (`expected_staged_id`) on
/// `op_dir_fd` immediately prior to `renameat` with zero `.staging` traversal.
fn atomic_install_staged_binary(
    bin_dir: &Path,
    binary: &str,
    op_dir_fd: &File,
    expected_staged_id: (u64, u64),
) -> Result<(PathBuf, Option<PathBuf>), ReleaseSyncError> {
    validate_binary_name(binary)?;
    let (bin_dir_fd, _) = open_dir_nofollow(bin_dir)?;
    let (_staged_check, staged_meta) = open_regular_at_dir_nofollow(op_dir_fd, binary, true, true)?;
    if (staged_meta.dev(), staged_meta.ino()) != expected_staged_id {
        return Err(ReleaseSyncError::SafePathViolation("staged_inode_swap"));
    }

    let install_path = bin_dir.join(binary);
    if let Ok(meta) = fs::symlink_metadata(&install_path)
        && meta.file_type().is_symlink()
    {
        return Err(ReleaseSyncError::SafePathViolation(
            "install_target_symlink",
        ));
    }

    let previous_backup = if fs::symlink_metadata(&install_path)
        .is_ok_and(|m| m.file_type().is_file() && !m.file_type().is_symlink())
    {
        let prev_path = bin_dir.join(format!("{binary}.prev"));
        if let Ok(meta) = fs::symlink_metadata(&prev_path)
            && meta.file_type().is_symlink()
        {
            return Err(ReleaseSyncError::SafePathViolation("prev_target_symlink"));
        }
        let nonce = csprng_hex_16()?;
        let prev_tmp_name = format!(".{binary}.prev.tmp.{}.{nonce}", std::process::id());
        if rustix::fs::linkat(
            &bin_dir_fd,
            binary,
            &bin_dir_fd,
            &prev_tmp_name,
            rustix::fs::AtFlags::empty(),
        )
        .is_err()
        {
            let (mut cur_src, _) = open_regular_at_dir_nofollow(&bin_dir_fd, binary, false, true)?;
            let prev_fd = rustix::fs::openat(
                &bin_dir_fd,
                &prev_tmp_name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o755),
            )
            .map_err(|err| {
                if is_transient_errno(err) {
                    ReleaseSyncError::TransientIo(format!("backup openat: {err}"))
                } else {
                    ReleaseSyncError::InstallFailed(format!("backup openat: {err}"))
                }
            })?;
            let mut prev_file = File::from(prev_fd);
            std::io::copy(&mut cur_src, &mut prev_file)
                .map_err(|e| classify_install_io_error("backup copy", &e))?;
            prev_file
                .set_permissions(fs::Permissions::from_mode(0o755))
                .map_err(|e| classify_install_io_error("backup chmod", &e))?;
            prev_file
                .sync_all()
                .map_err(|e| classify_install_io_error("backup sync", &e))?;
        }
        if let Err(err) = rustix::fs::renameat(
            &bin_dir_fd,
            &prev_tmp_name,
            &bin_dir_fd,
            format!("{binary}.prev"),
        ) {
            let _ = rustix::fs::unlinkat(&bin_dir_fd, &prev_tmp_name, rustix::fs::AtFlags::empty());
            if is_transient_errno(err) {
                return Err(ReleaseSyncError::TransientIo(format!(
                    "backup rename: {err}"
                )));
            }
            return Err(ReleaseSyncError::InstallFailed(format!(
                "backup rename: {err}"
            )));
        }
        Some(prev_path)
    } else {
        None
    };

    // Final inode recheck on `op_dir_fd` immediately before atomic `renameat` into `bin_dir_fd`.
    let (_pre_rename_fd, pre_rename) = open_regular_at_dir_nofollow(op_dir_fd, binary, true, true)?;
    if (pre_rename.dev(), pre_rename.ino()) != expected_staged_id {
        return Err(ReleaseSyncError::SafePathViolation("staged_inode_swap"));
    }

    rustix::fs::renameat(op_dir_fd, binary, &bin_dir_fd, binary).map_err(|err| {
        if is_transient_errno(err) {
            ReleaseSyncError::TransientIo(format!("atomic renameat: {err}"))
        } else {
            ReleaseSyncError::InstallFailed(format!("atomic renameat: {err}"))
        }
    })?;
    bin_dir_fd
        .sync_all()
        .map_err(|e| classify_install_io_error("bin_dir sync", &e))?;
    Ok((install_path, previous_backup))
}

fn canonical_bus_signing_payload(msg: &BusMessage) -> String {
    let to = msg.to.as_deref().unwrap_or("");
    let task = msg.task_id.as_deref().unwrap_or("");
    let ts = msg.ts_unix.to_string();
    format!(
        "chinwag-bus-sig-v2|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}",
        msg.id.len(),
        msg.id,
        ts.len(),
        ts,
        msg.sender.len(),
        msg.sender,
        to.len(),
        to,
        msg.room.len(),
        msg.room,
        task.len(),
        task,
        msg.body.len(),
        msg.body
    )
}

fn compute_bus_message_digest_bytes(
    ts_unix: u64,
    room: &str,
    sender: &str,
    sender_endpoint_id: &str,
    to: Option<&str>,
    task_id: Option<&str>,
    body: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!(
        "chinwag-bus-v1|{ts_unix}|{room}|{sender}|{sender_endpoint_id}|{}|{}|{body}",
        to.unwrap_or(""),
        task_id.unwrap_or("")
    ));
    hasher.finalize().into()
}

fn load_verified_seat_signing_key(
    home_dir: &Path,
    base_seat: &str,
    roots: &ReleaseTrustRoots<'_>,
) -> Result<SigningKey, ReleaseSyncError> {
    let expected_pubkey = roots
        .lookup_pubkey(base_seat)
        .ok_or(ReleaseSyncError::SigningIdentityUnavailable("unknown_seat"))?;
    let slug = base_seat.to_ascii_lowercase();
    if slug.is_empty()
        || !slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ReleaseSyncError::SigningIdentityUnavailable("invalid_seat"));
    }
    let signing_dir = home_dir.join(".chinwag").join("signing");
    let dir_meta = fs::symlink_metadata(&signing_dir)
        .map_err(|_| ReleaseSyncError::SigningIdentityUnavailable("signing_dir_missing"))?;
    if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
        return Err(ReleaseSyncError::SafePathViolation("signing_dir_symlink"));
    }
    let key_path = signing_dir.join(format!("{slug}_ed25519"));
    if fs::symlink_metadata(&key_path).is_err() {
        return Err(ReleaseSyncError::SigningIdentityUnavailable(
            "key_file_missing",
        ));
    }
    let (_pinned_key_file, key_fstat) =
        open_regular_file_nofollow(&key_path, true, true).map_err(|err| match err {
            ReleaseSyncError::SafePathViolation(_) => {
                ReleaseSyncError::SafePathViolation("signing_key_symlink")
            }
            _ => ReleaseSyncError::SigningIdentityUnavailable("key_file_missing"),
        })?;
    if (key_fstat.permissions().mode() & 0o077) != 0 {
        return Err(ReleaseSyncError::SafePathViolation(
            "signing_key_permissions",
        ));
    }
    let identity = Identity::from_ssh_signing_file(&key_path)
        .map_err(|_| ReleaseSyncError::SigningIdentityUnavailable("invalid_openssh_key"))?;
    let post_meta = fs::symlink_metadata(&key_path)
        .map_err(|_| ReleaseSyncError::SigningIdentityUnavailable("key_file_missing"))?;
    if post_meta.file_type().is_symlink()
        || (post_meta.dev(), post_meta.ino()) != (key_fstat.dev(), key_fstat.ino())
    {
        return Err(ReleaseSyncError::SafePathViolation("signing_key_symlink"));
    }
    let derived_pub = identity.ssh_public_bytes();
    if !bool::from(derived_pub.ct_eq(&expected_pubkey)) {
        return Err(ReleaseSyncError::SigningIdentityUnavailable(
            "canonical_pubkey_mismatch",
        ));
    }
    let iroh_secret = identity.iroh_secret_key();
    let mut seed = iroh_secret.to_bytes();
    let signing_key = SigningKey::from_bytes(&seed);
    zeroize::Zeroize::zeroize(&mut seed);
    Ok(signing_key)
}

fn sign_structured_bus_message(
    sender_address: &ActorAddress,
    room: &str,
    task_id: Option<String>,
    body: String,
    signing_key: &SigningKey,
) -> BusMessage {
    let sender = sender_address.to_string();
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let pubkey_hex = encode_hex(&pubkey_bytes);
    let ts_unix = now_unix_secs();
    let ts_iso = iso_now_string();
    let digest_bytes = compute_bus_message_digest_bytes(
        ts_unix,
        room,
        &sender,
        &pubkey_hex,
        None,
        task_id.as_deref(),
        &body,
    );
    let digest_hex = encode_hex(&digest_bytes);
    let msg_id = format!("bus-{ts_unix}-{}", &digest_hex[..8]);
    let mut msg = BusMessage {
        id: msg_id,
        seq: 0,
        ts_unix,
        ts_iso,
        room: room.to_owned(),
        sender,
        sender_cast: "■".to_owned(),
        sender_endpoint_id: pubkey_hex.clone(),
        to: None,
        task_id,
        body,
        digest_sha256: digest_hex,
        pubkey_ed25519: Some(pubkey_hex),
        signature_ed25519: None,
        sig_verified: false,
    };
    let payload = canonical_bus_signing_payload(&msg);
    let signature: Signature = signing_key.sign(payload.as_bytes());
    msg.signature_ed25519 = Some(encode_hex(&signature.to_bytes()));
    msg.sig_verified = true;
    msg
}

pub fn is_release_built_candidate(msg: &BusMessage) -> bool {
    msg.room.trim().eq_ignore_ascii_case("#all") && msg.body.starts_with(RELEASE_BUILT_PREFIX)
}

pub fn verify_release_built_message(
    msg: &BusMessage,
) -> Result<ReleaseManifestV1, ReleaseSyncError> {
    verify_release_built_message_with_roots(msg, &ReleaseTrustRoots::production())
}

fn verify_release_built_message_with_roots(
    msg: &BusMessage,
    roots: &ReleaseTrustRoots<'_>,
) -> Result<ReleaseManifestV1, ReleaseSyncError> {
    if !is_release_built_candidate(msg) {
        return Err(ReleaseSyncError::NotAReleaseMessage);
    }
    let address = ActorAddress::parse(&msg.sender)
        .and_then(ActorAddress::require_instance)
        .map_err(|_| ReleaseSyncError::SignatureInvalid)?;
    if let Some(ref to) = msg.to
        && agent_instance::parse_recipients(to).is_err()
    {
        return Err(ReleaseSyncError::SignatureInvalid);
    }
    let base_seat = address.seat();
    if !roots.is_allowed_release_signer(base_seat) {
        return Err(ReleaseSyncError::UnauthorizedSigner);
    }
    let pinned_pubkey = roots
        .lookup_pubkey(base_seat)
        .ok_or(ReleaseSyncError::UnauthorizedSigner)?;

    let pub_hex = msg
        .pubkey_ed25519
        .as_deref()
        .ok_or(ReleaseSyncError::SignatureInvalid)?;
    let sig_hex = msg
        .signature_ed25519
        .as_deref()
        .ok_or(ReleaseSyncError::SignatureInvalid)?;
    let msg_pub_bytes =
        decode_hex_32_any_case(pub_hex).ok_or(ReleaseSyncError::SignatureInvalid)?;
    let endpoint_pub_bytes = decode_hex_32_any_case(&msg.sender_endpoint_id)
        .ok_or(ReleaseSyncError::SignatureInvalid)?;
    let msg_digest_bytes =
        decode_hex_32_any_case(&msg.digest_sha256).ok_or(ReleaseSyncError::SignatureInvalid)?;
    let sig_bytes = decode_hex_64_any_case(sig_hex).ok_or(ReleaseSyncError::SignatureInvalid)?;

    if !bool::from(msg_pub_bytes.ct_eq(&pinned_pubkey))
        || !bool::from(endpoint_pub_bytes.ct_eq(&pinned_pubkey))
    {
        return Err(ReleaseSyncError::SignatureInvalid);
    }

    let expected_digest = compute_bus_message_digest_bytes(
        msg.ts_unix,
        &msg.room,
        &msg.sender,
        &msg.sender_endpoint_id,
        msg.to.as_deref(),
        msg.task_id.as_deref(),
        &msg.body,
    );
    if !bool::from(expected_digest.ct_eq(&msg_digest_bytes)) {
        return Err(ReleaseSyncError::SignatureInvalid);
    }

    let verifying_key =
        VerifyingKey::from_bytes(&pinned_pubkey).map_err(|_| ReleaseSyncError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let payload = canonical_bus_signing_payload(msg);
    verifying_key
        .verify_strict(payload.as_bytes(), &signature)
        .map_err(|_| ReleaseSyncError::SignatureInvalid)?;

    let raw_json = msg
        .body
        .strip_prefix(RELEASE_BUILT_PREFIX)
        .ok_or(ReleaseSyncError::NotAReleaseMessage)?
        .trim();
    if raw_json.is_empty() || raw_json.len() > MAX_RELEASE_MANIFEST_JSON_BYTES {
        return Err(ReleaseSyncError::InvalidManifest("manifest_size"));
    }
    let manifest: ReleaseManifestV1 = serde_json::from_str(raw_json)
        .map_err(|_| ReleaseSyncError::InvalidManifest("json_parse"))?;
    manifest.validate_structural()?;
    Ok(manifest)
}

fn check_monotonic_gate(
    prev: Option<&InstalledBinaryState>,
    manifest: &ReleaseManifestV1,
    manifest_sha256: &[u8; 32],
    local_matches_manifest: bool,
) -> Result<bool, ReleaseSyncError> {
    let Some(prev) = prev else {
        return Ok(local_matches_manifest);
    };
    let prev_sha = decode_lowercase_hex_32(&prev.sha256);
    let same_recorded_release = prev_sha.is_some_and(|p| bool::from(p.ct_eq(manifest_sha256)))
        && prev.commit_epoch == manifest.commit_epoch
        && prev.built_at_ms == manifest.built_at_ms
        && prev.rollback == manifest.rollback;
    if same_recorded_release && local_matches_manifest {
        return Ok(true);
    }

    // Reject any historical release that was already applied and superseded,
    // preventing `normal (200,2000) -> rollback (100,3000) -> normal (200,2000)` cycles.
    let candidate_key = InstalledBinaryState::release_history_key(manifest);
    if !same_recorded_release
        && prev
            .applied_release_keys
            .iter()
            .any(|k| k == &candidate_key)
    {
        return Err(ReleaseSyncError::DowngradeOrReplayRejected);
    }

    let max_built = prev.effective_max_built_at_ms();
    let max_epoch = prev.effective_max_commit_epoch();
    if !same_recorded_release {
        if manifest.built_at_ms <= max_built {
            return Err(ReleaseSyncError::DowngradeOrReplayRejected);
        }
        if !manifest.rollback && manifest.commit_epoch < max_epoch {
            return Err(ReleaseSyncError::DowngradeOrReplayRejected);
        }
    }
    Ok(local_matches_manifest)
}

fn record_installed_state(
    home_dir: &Path,
    state: &mut ReleaseSyncStateV1,
    manifest: &ReleaseManifestV1,
    source_message_id: Option<String>,
    observed_max_epoch: Option<u64>,
) -> Result<(), ReleaseSyncError> {
    let existing = state.binaries.get(&manifest.binary);
    let max_commit_epoch_seen = existing
        .map_or(0, InstalledBinaryState::effective_max_commit_epoch)
        .max(manifest.commit_epoch)
        .max(observed_max_epoch.unwrap_or(0));
    let max_built_at_ms_seen = existing
        .map_or(0, InstalledBinaryState::effective_max_built_at_ms)
        .max(manifest.built_at_ms);

    let mut applied_release_keys: Vec<String> = existing
        .map(|p| p.applied_release_keys.clone())
        .unwrap_or_default();
    if let Some(prev) = existing {
        let prev_key = format!(
            "{}:{}:{}:{}",
            prev.sha256,
            prev.commit_epoch,
            prev.built_at_ms,
            u8::from(prev.rollback)
        );
        if !applied_release_keys.contains(&prev_key) {
            applied_release_keys.push(prev_key);
        }
    }
    let current_key = InstalledBinaryState::release_history_key(manifest);
    if !applied_release_keys.contains(&current_key) {
        applied_release_keys.push(current_key);
    }
    if applied_release_keys.len() > MAX_APPLIED_RELEASE_HISTORY {
        let drain_count = applied_release_keys.len() - MAX_APPLIED_RELEASE_HISTORY;
        applied_release_keys.drain(0..drain_count);
    }

    state.binaries.insert(
        manifest.binary.clone(),
        InstalledBinaryState {
            binary: manifest.binary.clone(),
            target_triple: manifest.target_triple.clone(),
            git_commit: manifest.git_commit.clone(),
            commit_epoch: manifest.commit_epoch,
            built_at_ms: manifest.built_at_ms,
            sha256: manifest.sha256.clone(),
            blake3: manifest.blake3.clone(),
            size_bytes: manifest.size_bytes,
            rollback: manifest.rollback,
            updated_at_ms: now_unix_ms(),
            source_message_id,
            max_commit_epoch_seen,
            max_built_at_ms_seen,
            applied_release_keys,
        },
    );
    save_release_sync_state(home_dir, state)
}

type BeforeSmokeExecHook<'a> = Option<&'a mut dyn FnMut(&Path, &Path)>;

pub fn apply_release_built_message(
    home_dir: &Path,
    store: &dyn ReleaseArtifactStore,
    msg: &BusMessage,
    local_iroh_endpoint: Option<&str>,
) -> Result<ReleaseApplyOutcome, ReleaseSyncError> {
    apply_release_built_message_inner(
        home_dir,
        store,
        msg,
        local_iroh_endpoint,
        &ReleaseTrustRoots::production(),
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_release_built_message_inner(
    home_dir: &Path,
    store: &dyn ReleaseArtifactStore,
    msg: &BusMessage,
    local_iroh_endpoint: Option<&str>,
    roots: &ReleaseTrustRoots<'_>,
    receipt_key_override: Option<&SigningKey>,
    observed_max_epoch: Option<u64>,
    before_smoke_exec: BeforeSmokeExecHook<'_>,
) -> Result<ReleaseApplyOutcome, ReleaseSyncError> {
    let manifest = verify_release_built_message_with_roots(msg, roots)?;
    if manifest.target_triple != CURRENT_TARGET_TRIPLE {
        return Ok(ReleaseApplyOutcome::SkippedTargetMismatch {
            manifest_target: manifest.target_triple,
            local_target: CURRENT_TARGET_TRIPLE.to_owned(),
        });
    }
    let (expected_sha256, expected_blake3) = manifest.validate_structural()?;
    let (bin_dir, staging_dir) = ensure_bin_and_staging_dirs(home_dir)?;
    let install_path = bin_dir.join(&manifest.binary);

    // Pre-download check under the cross-process lock so replays, downgrades,
    // and already-installed publisher/peer binaries short-circuit in 0ms without R2 I/O.
    {
        let _lock = acquire_release_sync_lock(home_dir)?;
        let local_matches = compute_file_digests(&install_path).is_ok_and(|(sz, sha, b3)| {
            sz == manifest.size_bytes
                && bool::from(sha.ct_eq(&expected_sha256))
                && bool::from(b3.ct_eq(&expected_blake3))
        });
        let mut sync_state = load_release_sync_state(home_dir)?;
        let was_recorded = sync_state
            .binaries
            .get(&manifest.binary)
            .is_some_and(|prev| {
                decode_lowercase_hex_32(&prev.sha256)
                    .is_some_and(|p| bool::from(p.ct_eq(&expected_sha256)))
                    && prev.commit_epoch == manifest.commit_epoch
                    && prev.built_at_ms == manifest.built_at_ms
                    && prev.rollback == manifest.rollback
            });
        let already_satisfied = check_monotonic_gate(
            sync_state.binaries.get(&manifest.binary),
            &manifest,
            &expected_sha256,
            local_matches,
        )?;
        if already_satisfied {
            record_installed_state(
                home_dir,
                &mut sync_state,
                &manifest,
                Some(msg.id.clone()),
                observed_max_epoch,
            )?;
            if !was_recorded {
                let receipt_message = build_release_installed_bus_message(
                    home_dir,
                    &manifest,
                    local_iroh_endpoint.unwrap_or("unknown"),
                    roots,
                    receipt_key_override,
                )
                .ok()
                .map(Box::new);
                return Ok(ReleaseApplyOutcome::Installed {
                    manifest,
                    install_path,
                    previous_backup_path: None,
                    receipt_message,
                });
            }
            return Ok(ReleaseApplyOutcome::AlreadyInstalled {
                manifest,
                install_path,
            });
        }
    }

    let nonce = csprng_hex_16()?;
    let op_dir = staging_dir.join(format!("op.{}.{nonce}", std::process::id()));
    fs::create_dir(&op_dir)
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("op_dir create failed: {e}")))?;
    fs::set_permissions(&op_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("op_dir chmod failed: {e}")))?;
    let staged_path = op_dir.join(&manifest.binary);
    let mut op_guard = StagedOpGuard::new(op_dir.clone(), &manifest.binary);

    let (op_dir_fd, op_dir_id) = open_dir_nofollow(&op_dir)?;
    op_guard.bind_dir_fd(&op_dir_fd, op_dir_id);
    let pre_created_fd = rustix::fs::openat(
        &op_dir_fd,
        manifest.binary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| ReleaseSyncError::InstallFailed(format!("stage create failed: {e}")))?;
    drop(File::from(pre_created_fd));

    store.download_artifact(&manifest.artifact_key, &staged_path)?;
    let (mut staged_file, staged_fstat) =
        open_regular_at_dir_nofollow(&op_dir_fd, &manifest.binary, true, true)?;
    let staged_id = (staged_fstat.dev(), staged_fstat.ino());
    // Explicitly lock permissions to 0600 on the open FD (zero execute bits!)
    // BEFORE computing and comparing digests in constant time (`INV-HASH-BEFORE-EXEC-01`).
    staged_file
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| ReleaseSyncError::InstallFailed("chmod_0600_failed".into()))?;

    let (actual_size, actual_sha256, actual_blake3) =
        compute_digests_from_open_file(&mut staged_file, staged_fstat.len(), staged_id)?;
    let size_ok = actual_size == manifest.size_bytes;
    let sha_ok = bool::from(actual_sha256.ct_eq(&expected_sha256));
    let b3_ok = bool::from(actual_blake3.ct_eq(&expected_blake3));
    if !(size_ok && sha_ok && b3_ok) {
        return Err(ReleaseSyncError::DigestMismatch);
    }

    // Verify macOS code signature strictly inside `op_dir_fd` while still non-executable (never `-f`!).
    verify_codesign_strict_in_dir(&op_dir_fd, &manifest.binary)?;

    let post_codesign = staged_file
        .metadata()
        .map_err(|_| ReleaseSyncError::SafePathViolation("staged_stat_failed"))?;
    if post_codesign.nlink() != 1 || (post_codesign.dev(), post_codesign.ino()) != staged_id {
        return Err(ReleaseSyncError::SafePathViolation("staged_inode_swap"));
    }

    // Only AFTER size + SHA-256 + BLAKE3 + strict codesign pass do we set 0755 on the pinned FD,
    // lock BOTH file and per-op directory with kernel `UF_IMMUTABLE` (`uchg`) via `op_dir_fd`,
    // and re-verify digests on the immutable vnode before executing `--version`.
    staged_file
        .set_permissions(fs::Permissions::from_mode(0o755))
        .map_err(|_| ReleaseSyncError::InstallFailed("chmod_0755_failed".into()))?;
    drop(staged_file);

    set_dir_and_entry_immutable(&op_dir_fd, &manifest.binary, true)?;

    let op_dir_post = op_dir_fd
        .metadata()
        .map_err(|_| ReleaseSyncError::SafePathViolation("op_dir_fstat_failed"))?;
    if (op_dir_post.dev(), op_dir_post.ino()) != op_dir_id {
        return Err(ReleaseSyncError::SafePathViolation("op_dir_inode_swap"));
    }
    verify_fd_immutable(&op_dir_fd)?;

    let (mut pinned_exec_file, pinned_exec_fstat) =
        open_regular_at_dir_nofollow(&op_dir_fd, &manifest.binary, true, true)?;
    if (pinned_exec_fstat.dev(), pinned_exec_fstat.ino()) != staged_id {
        return Err(ReleaseSyncError::SafePathViolation("staged_inode_swap"));
    }
    verify_fd_immutable(&pinned_exec_file)?;
    let (pin_size, pin_sha256, pin_blake3) =
        compute_digests_from_open_file(&mut pinned_exec_file, manifest.size_bytes, staged_id)?;
    if pin_size != manifest.size_bytes
        || !bool::from(pin_sha256.ct_eq(&expected_sha256))
        || !bool::from(pin_blake3.ct_eq(&expected_blake3))
    {
        return Err(ReleaseSyncError::DigestMismatch);
    }

    let ancestors_before = capture_ancestor_chain_inodes(home_dir, &op_dir)?;
    if let Some(hook) = before_smoke_exec {
        hook(&staged_path, &op_dir);
    }
    smoke_test_binary_version(&op_dir_fd, &manifest.binary, &mut op_guard)?;
    if capture_ancestor_chain_inodes(home_dir, &op_dir)? != ancestors_before {
        return Err(ReleaseSyncError::SafePathViolation("ancestor_inode_swap"));
    }
    verify_fd_immutable(&op_dir_fd)?;
    verify_fd_immutable(&pinned_exec_file)?;

    // Re-acquire exclusive lock and revalidate against current on-disk state so a
    // stalled download of an older epoch can NEVER overwrite a newer epoch committed
    // concurrently by `chinwag release sync` or `chinwag release publish`.
    let (install_path, previous_backup_path) = {
        let _lock = acquire_release_sync_lock(home_dir)?;
        let local_matches = local_binary_sha256(&install_path)
            .is_some_and(|actual| bool::from(actual.ct_eq(&expected_sha256)));
        let mut sync_state = load_release_sync_state(home_dir)?;
        let already_satisfied = check_monotonic_gate(
            sync_state.binaries.get(&manifest.binary),
            &manifest,
            &expected_sha256,
            local_matches,
        )?;
        if already_satisfied {
            record_installed_state(
                home_dir,
                &mut sync_state,
                &manifest,
                Some(msg.id.clone()),
                observed_max_epoch,
            )?;
            return Ok(ReleaseApplyOutcome::AlreadyInstalled {
                manifest,
                install_path,
            });
        }
        set_dir_and_entry_immutable(&op_dir_fd, &manifest.binary, false)?;
        let paths =
            atomic_install_staged_binary(&bin_dir, &manifest.binary, &op_dir_fd, staged_id)?;
        drop(pinned_exec_file);
        drop(op_dir_fd);
        let _ = fs::remove_dir(&op_dir);
        op_guard.disarm();
        record_installed_state(
            home_dir,
            &mut sync_state,
            &manifest,
            Some(msg.id.clone()),
            observed_max_epoch,
        )?;
        paths
    };

    let receipt_message = build_release_installed_bus_message(
        home_dir,
        &manifest,
        local_iroh_endpoint.unwrap_or("unknown"),
        roots,
        receipt_key_override,
    )
    .ok()
    .map(Box::new);

    Ok(ReleaseApplyOutcome::Installed {
        manifest,
        install_path,
        previous_backup_path,
        receipt_message,
    })
}

pub fn build_release_installed_receipt_for_already_installed(
    home_dir: &Path,
    manifest: &ReleaseManifestV1,
    local_iroh_endpoint: &str,
) -> Option<BusMessage> {
    build_release_installed_bus_message(
        home_dir,
        manifest,
        local_iroh_endpoint,
        &ReleaseTrustRoots::production(),
        None,
    )
    .ok()
}

fn build_release_installed_bus_message(
    home_dir: &Path,
    manifest: &ReleaseManifestV1,
    local_iroh_endpoint: &str,
    roots: &ReleaseTrustRoots<'_>,
    receipt_key_override: Option<&SigningKey>,
) -> Result<BusMessage, ReleaseSyncError> {
    let owned_key;
    let signing_key = match receipt_key_override {
        Some(key) => key,
        None => {
            owned_key = load_verified_seat_signing_key(home_dir, "INFRAJR", roots)?;
            &owned_key
        }
    };
    let instance = agent_instance::new_instance_id()
        .map_err(|_| ReleaseSyncError::SigningIdentityUnavailable("instance_id"))?;
    let actor = ActorAddress::parse(&format!("INFRAJR#{instance}"))
        .map_err(|_| ReleaseSyncError::SigningIdentityUnavailable("actor_address"))?;
    let receipt = ReleaseInstalledReceiptV1 {
        schema: RELEASE_INSTALLED_SCHEMA.to_owned(),
        iroh_endpoint: local_iroh_endpoint.to_owned(),
        binary: manifest.binary.clone(),
        target_triple: manifest.target_triple.clone(),
        sha256: manifest.sha256.clone(),
        blake3: manifest.blake3.clone(),
        git_commit: manifest.git_commit.clone(),
        installed_at_ms: now_unix_ms(),
        outcome: if manifest.rollback {
            "rolled_back".to_owned()
        } else {
            "installed".to_owned()
        },
    };
    let json_payload = serde_json::to_string(&receipt)
        .map_err(|_| ReleaseSyncError::InstallFailed("receipt_serialize".into()))?;
    let body = format!("{RELEASE_INSTALLED_PREFIX}{json_payload}");
    Ok(sign_structured_bus_message(
        &actor,
        "#ops",
        Some("CHWG-0261".to_owned()),
        body,
        signing_key,
    ))
}

fn resolve_git_commit_and_epoch(repo_root: &Path) -> Result<(String, u64), ReleaseSyncError> {
    let rev_out = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "HEAD"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("git rev-parse: {e}")))?;
    if !rev_out.status.success() {
        return Err(ReleaseSyncError::SourceUnavailable(
            "git rev-parse HEAD failed".into(),
        ));
    }
    let commit = String::from_utf8_lossy(&rev_out.stdout)
        .trim()
        .to_ascii_lowercase();
    if !(7..=64).contains(&commit.len()) || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ReleaseSyncError::InvalidManifest("git_commit"));
    }

    let epoch_out = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repo_root)
        .args(["show", "-s", "--format=%ct", "HEAD"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("git commit epoch: {e}")))?;
    if !epoch_out.status.success() {
        return Err(ReleaseSyncError::SourceUnavailable(
            "git show --format=%ct HEAD failed".into(),
        ));
    }
    let commit_epoch: u64 = String::from_utf8_lossy(&epoch_out.stdout)
        .trim()
        .parse()
        .map_err(|_| ReleaseSyncError::InvalidManifest("commit_epoch"))?;
    if commit_epoch == 0 {
        return Err(ReleaseSyncError::InvalidManifest("commit_epoch"));
    }
    Ok((commit, commit_epoch))
}

fn resolve_publisher_actor(explicit_from: Option<&str>) -> Result<ActorAddress, ReleaseSyncError> {
    if let Some(raw) = explicit_from {
        let addr = ActorAddress::parse(raw)
            .and_then(ActorAddress::require_instance)
            .map_err(|_| ReleaseSyncError::UnauthorizedSigner)?;
        if !bool::from(addr.seat().as_bytes().ct_eq(b"INFRAJR")) {
            return Err(ReleaseSyncError::UnauthorizedSigner);
        }
        return Ok(addr);
    }
    if let Ok(env_actor) = std::env::var("CHINWAG_ACTOR")
        && !env_actor.trim().is_empty()
    {
        let addr = agent_instance::resolve_from_environment(&env_actor, None)
            .and_then(ActorAddress::require_instance)
            .map_err(|_| ReleaseSyncError::UnauthorizedSigner)?;
        // Never spoof or override another bound seat (`INV-NO-SEAT-IMPERSONATION-01`).
        if !bool::from(addr.seat().as_bytes().ct_eq(b"INFRAJR")) {
            return Err(ReleaseSyncError::UnauthorizedSigner);
        }
        return Ok(addr);
    }
    let instance = match std::env::var("CHINWAG_INSTANCE_ID") {
        Ok(existing) if !existing.trim().is_empty() => existing,
        _ => agent_instance::new_instance_id()
            .map_err(|_| ReleaseSyncError::SigningIdentityUnavailable("instance_id"))?,
    };
    ActorAddress::parse(&format!("INFRAJR#{instance}"))
        .and_then(ActorAddress::require_instance)
        .map_err(|_| ReleaseSyncError::SigningIdentityUnavailable("actor_address"))
}

fn maybe_run_crate_memory_sync(home_dir: &Path, repo_root: &Path) -> bool {
    if std::env::var_os("CHINWAG_SKIP_CRATE_MEMORY_SYNC").is_some() {
        return false;
    }
    let script = home_dir.join(".local/bin/chinwag-crate-memory-sync");
    let Ok(meta) = fs::symlink_metadata(&script) else {
        return false;
    };
    if meta.file_type().is_symlink()
        || !meta.file_type().is_file()
        || (meta.permissions().mode() & 0o111) == 0
    {
        return false;
    }
    let mut cmd = Command::new(&script);
    cmd.current_dir(repo_root)
        .env("HOME", home_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    run_bounded_command(&mut cmd, CRATE_MEMORY_SYNC_TIMEOUT).is_ok()
}

pub struct PublishReleaseRequest<'a> {
    pub home_dir: &'a Path,
    pub repo_root: &'a Path,
    pub binary: &'a str,
    pub source_binary_path: &'a Path,
    pub explicit_from: Option<&'a str>,
    pub rollback: bool,
    pub commit_override: Option<(String, u64)>,
}

pub fn publish_release(
    req: PublishReleaseRequest<'_>,
    store: &dyn ReleaseArtifactStore,
    publish_bus: impl FnOnce(&BusMessage) -> Result<u64, String>,
) -> Result<ReleasePublishOutcome, ReleaseSyncError> {
    publish_release_inner(
        req,
        store,
        publish_bus,
        &ReleaseTrustRoots::production(),
        None,
    )
}

fn publish_release_inner(
    req: PublishReleaseRequest<'_>,
    store: &dyn ReleaseArtifactStore,
    publish_bus: impl FnOnce(&BusMessage) -> Result<u64, String>,
    roots: &ReleaseTrustRoots<'_>,
    signing_key_override: Option<&SigningKey>,
) -> Result<ReleasePublishOutcome, ReleaseSyncError> {
    validate_binary_name(req.binary)?;
    let publisher_actor = resolve_publisher_actor(req.explicit_from)?;
    let owned_key;
    let signing_key = match signing_key_override {
        Some(key) => key,
        None => {
            owned_key = load_verified_seat_signing_key(req.home_dir, "INFRAJR", roots)?;
            &owned_key
        }
    };

    let (mut src, src_fstat) = open_regular_file_nofollow(req.source_binary_path, false, true)?;
    if src_fstat.len() == 0 {
        return Err(ReleaseSyncError::SourceUnavailable(
            "source must be a non-empty regular file (not a symlink)".into(),
        ));
    }

    let (git_commit, commit_epoch) = match req.commit_override {
        Some(pair) => pair,
        None => resolve_git_commit_and_epoch(req.repo_root)?,
    };

    // Fast pre-flight monotonic check under the cross-process lock before staging/uploading.
    {
        let _lock = acquire_release_sync_lock(req.home_dir)?;
        let sync_state = load_release_sync_state(req.home_dir)?;
        if let Some(prev) = sync_state.binaries.get(req.binary)
            && !req.rollback
            && commit_epoch < prev.effective_max_commit_epoch()
        {
            return Err(ReleaseSyncError::DowngradeOrReplayRejected);
        }
    }

    let (bin_dir, staging_dir) = ensure_bin_and_staging_dirs(req.home_dir)?;
    let nonce = csprng_hex_16()?;
    let op_dir = staging_dir.join(format!("op.{}.pub.{nonce}", std::process::id()));
    fs::create_dir(&op_dir)
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("pub op_dir create: {e}")))?;
    fs::set_permissions(&op_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("pub op_dir chmod: {e}")))?;
    let mut op_guard = StagedOpGuard::new(op_dir.clone(), req.binary);

    let (op_dir_fd, op_dir_id) = open_dir_nofollow(&op_dir)?;
    op_guard.bind_dir_fd(&op_dir_fd, op_dir_id);
    let dst_fd = rustix::fs::openat(
        &op_dir_fd,
        req.binary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o755),
    )
    .map_err(|e| ReleaseSyncError::InstallFailed(format!("stage create: {e}")))?;
    let mut dst = File::from(dst_fd);
    std::io::copy(&mut src, &mut dst)
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("stage copy: {e}")))?;
    dst.sync_all()
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("stage sync: {e}")))?;
    drop(dst);
    drop(src);

    // Ensure valid macOS signature ONCE on the publisher's staged copy inside
    // `op_dir_fd` BEFORE locking with `UF_IMMUTABLE` (`uchg`) and computing
    // SHA-256 + BLAKE3 so every peer verifies identical bytes.
    ensure_publisher_codesigned_in_dir(&op_dir_fd, req.binary)?;

    set_dir_and_entry_immutable(&op_dir_fd, req.binary, true)?;

    let op_dir_post = op_dir_fd
        .metadata()
        .map_err(|_| ReleaseSyncError::SafePathViolation("pub_op_dir_fstat"))?;
    if (op_dir_post.dev(), op_dir_post.ino()) != op_dir_id {
        return Err(ReleaseSyncError::SafePathViolation("pub_op_dir_inode_swap"));
    }
    verify_fd_immutable(&op_dir_fd)?;

    let (mut staged_file, staged_fstat) =
        open_regular_at_dir_nofollow(&op_dir_fd, req.binary, true, true)?;
    verify_fd_immutable(&staged_file)?;
    let staged_id = (staged_fstat.dev(), staged_fstat.ino());
    let (size_bytes, sha256_bytes, blake3_bytes) =
        compute_digests_from_open_file(&mut staged_file, staged_fstat.len(), staged_id)?;
    let sha256 = encode_hex(&sha256_bytes);
    let blake3 = encode_hex(&blake3_bytes);

    let ancestors_before = capture_ancestor_chain_inodes(req.home_dir, &op_dir)?;
    smoke_test_binary_version(&op_dir_fd, req.binary, &mut op_guard)?;
    if capture_ancestor_chain_inodes(req.home_dir, &op_dir)? != ancestors_before {
        return Err(ReleaseSyncError::SafePathViolation("ancestor_inode_swap"));
    }
    verify_fd_immutable(&op_dir_fd)?;
    verify_fd_immutable(&staged_file)?;

    let target_triple = CURRENT_TARGET_TRIPLE.to_owned();
    let artifact_key = expected_artifact_key(req.binary, &target_triple, &sha256);

    store.upload_artifact(&artifact_key, &staged_file)?;
    if capture_ancestor_chain_inodes(req.home_dir, &op_dir)? != ancestors_before {
        return Err(ReleaseSyncError::SafePathViolation("ancestor_inode_swap"));
    }

    // Re-acquire exclusive lock for commit-time revalidation, strictly monotonic
    // `built_at_ms` assignment, atomic local installation, and watermark persistence.
    let (manifest, install_path, previous_backup_path, release_built_message) = {
        let _lock = acquire_release_sync_lock(req.home_dir)?;
        let mut sync_state = load_release_sync_state(req.home_dir)?;
        let mut built_at_ms = now_unix_ms().max(1);
        if let Some(prev) = sync_state.binaries.get(req.binary) {
            if !req.rollback && commit_epoch < prev.effective_max_commit_epoch() {
                return Err(ReleaseSyncError::DowngradeOrReplayRejected);
            }
            let max_built = prev.effective_max_built_at_ms();
            if built_at_ms <= max_built {
                built_at_ms = max_built.saturating_add(1);
            }
        }

        let manifest = ReleaseManifestV1 {
            schema: RELEASE_MANIFEST_SCHEMA.to_owned(),
            binary: req.binary.to_owned(),
            target_triple: target_triple.clone(),
            git_commit,
            commit_epoch,
            built_at_ms,
            sha256,
            blake3,
            size_bytes,
            artifact_key: artifact_key.clone(),
            rollback: req.rollback,
        };
        manifest.validate_structural()?;

        set_dir_and_entry_immutable(&op_dir_fd, req.binary, false)?;
        let (install_path, previous_backup_path) =
            atomic_install_staged_binary(&bin_dir, req.binary, &op_dir_fd, staged_id)?;
        drop(staged_file);
        drop(op_dir_fd);
        let _ = fs::remove_dir(&op_dir);
        op_guard.disarm();

        let manifest_json = serde_json::to_string(&manifest)
            .map_err(|_| ReleaseSyncError::InstallFailed("manifest_serialize".into()))?;
        let body = format!("{RELEASE_BUILT_PREFIX}{manifest_json}");
        let release_built_message = sign_structured_bus_message(
            &publisher_actor,
            "#all",
            Some("CHWG-0261".to_owned()),
            body,
            signing_key,
        );

        record_installed_state(
            req.home_dir,
            &mut sync_state,
            &manifest,
            Some(release_built_message.id.clone()),
            None,
        )?;

        (
            manifest,
            install_path,
            previous_backup_path,
            release_built_message,
        )
    };

    let crate_memory_synced = maybe_run_crate_memory_sync(req.home_dir, req.repo_root);

    let bus_seq =
        publish_bus(&release_built_message).map_err(ReleaseSyncError::BusPublishFailed)?;

    Ok(ReleasePublishOutcome {
        manifest,
        install_path,
        previous_backup_path,
        release_built_message,
        bus_seq,
        crate_memory_synced,
    })
}

/// Scans `.chinwag/bus/messages.jsonl` for the latest cryptographically verified
/// `INFRAJR` `RELEASE_BUILT` per binary matching `CURRENT_TARGET_TRIPLE` and
/// applies each binary independently from content-addressed R2 storage so one
/// binary's transient failure never drops another binary's install receipt.
pub fn sync_releases_from_journal_per_binary(
    home_dir: &Path,
    messages_jsonl_path: &Path,
    store: &dyn ReleaseArtifactStore,
    local_iroh_endpoint: Option<&str>,
) -> Result<Vec<BinarySyncReport>, ReleaseSyncError> {
    sync_releases_from_journal_per_binary_inner(
        home_dir,
        messages_jsonl_path,
        store,
        local_iroh_endpoint,
        &ReleaseTrustRoots::production(),
        None,
    )
}

fn sync_releases_from_journal_per_binary_inner(
    home_dir: &Path,
    messages_jsonl_path: &Path,
    store: &dyn ReleaseArtifactStore,
    local_iroh_endpoint: Option<&str>,
    roots: &ReleaseTrustRoots<'_>,
    receipt_key_override: Option<&SigningKey>,
) -> Result<Vec<BinarySyncReport>, ReleaseSyncError> {
    Ok(sync_releases_from_journal_per_binary_filtered_inner(
        home_dir,
        messages_jsonl_path,
        store,
        local_iroh_endpoint,
        roots,
        receipt_key_override,
        None,
        &mut Instant::now,
    )?
    .executed_reports)
}

fn open_regular_journal_if_present(
    messages_jsonl_path: &Path,
) -> Result<Option<File>, ReleaseSyncError> {
    let lstat = match fs::symlink_metadata(messages_jsonl_path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(classify_journal_io_error("journal stat failed", &err)),
        Ok(meta) => meta,
    };
    if lstat.file_type().is_symlink() || !lstat.file_type().is_file() {
        return Err(ReleaseSyncError::SafePathViolation(
            "non_regular_journal_file",
        ));
    }
    let fd = match rustix_open(
        messages_jsonl_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(err) if err == rustix::io::Errno::NOENT => return Ok(None),
        Err(err) if err == rustix::io::Errno::LOOP || err == rustix::io::Errno::MLINK => {
            return Err(ReleaseSyncError::SafePathViolation("symlink_open_refused"));
        }
        Err(err) if is_transient_errno(err) => {
            return Err(ReleaseSyncError::TransientIo(format!(
                "journal open failed: {err}"
            )));
        }
        Err(err) => {
            return Err(ReleaseSyncError::SourceUnavailable(format!(
                "journal open failed: {err}"
            )));
        }
    };
    let file = File::from(fd);
    let fstat = file
        .metadata()
        .map_err(|e| classify_journal_io_error("journal fstat failed", &e))?;
    if fstat.file_type().is_symlink() || !fstat.file_type().is_file() {
        return Err(ReleaseSyncError::SafePathViolation(
            "non_regular_journal_file",
        ));
    }
    if (fstat.dev(), fstat.ino()) != (lstat.dev(), lstat.ino()) {
        // Atomic journal rotation mid-open is transient; symlinks and non-regular
        // files were already refused via `O_NOFOLLOW` + `fstat.is_file()`.
        return Err(ReleaseSyncError::TransientIo(
            "journal rotated during open".to_owned(),
        ));
    }
    Ok(Some(file))
}

#[allow(clippy::too_many_arguments)]
fn sync_releases_from_journal_per_binary_filtered_inner(
    home_dir: &Path,
    messages_jsonl_path: &Path,
    store: &dyn ReleaseArtifactStore,
    local_iroh_endpoint: Option<&str>,
    roots: &ReleaseTrustRoots<'_>,
    receipt_key_override: Option<&SigningKey>,
    eligibility: Option<&ReleaseEligibilityFilter>,
    clock: &mut dyn FnMut() -> Instant,
) -> Result<JournalCatchupBatch, ReleaseSyncError> {
    sync_releases_from_journal_per_binary_filtered_with_opener(
        home_dir,
        messages_jsonl_path,
        store,
        local_iroh_endpoint,
        roots,
        receipt_key_override,
        eligibility,
        clock,
        &mut open_regular_journal_if_present,
    )
}

#[allow(clippy::too_many_arguments)]
fn sync_releases_from_journal_per_binary_filtered_with_opener(
    home_dir: &Path,
    messages_jsonl_path: &Path,
    store: &dyn ReleaseArtifactStore,
    local_iroh_endpoint: Option<&str>,
    roots: &ReleaseTrustRoots<'_>,
    receipt_key_override: Option<&SigningKey>,
    eligibility: Option<&ReleaseEligibilityFilter>,
    clock: &mut dyn FnMut() -> Instant,
    journal_opener: &mut dyn FnMut(&Path) -> Result<Option<File>, ReleaseSyncError>,
) -> Result<JournalCatchupBatch, ReleaseSyncError> {
    let mut candidates_per_binary: BTreeMap<String, Vec<(BusMessage, ReleaseManifestV1)>> =
        BTreeMap::new();

    if let Some(file) = journal_opener(messages_jsonl_path)? {
        let mut reader = BufReader::new(file);
        let mut raw_line = Vec::new();
        loop {
            raw_line.clear();
            let bytes_read = reader
                .read_until(b'\n', &mut raw_line)
                .map_err(|e| classify_journal_io_error("journal read failed", &e))?;
            if bytes_read == 0 {
                break;
            }
            let Ok(line) = std::str::from_utf8(&raw_line) else {
                continue;
            };
            let trimmed = line.trim();
            if !trimmed.contains(RELEASE_BUILT_PREFIX) {
                continue;
            }
            if let Ok(msg) = serde_json::from_str::<BusMessage>(trimmed)
                && let Ok(manifest) = verify_release_built_message_with_roots(&msg, roots)
                && manifest.target_triple == CURRENT_TARGET_TRIPLE
            {
                candidates_per_binary
                    .entry(manifest.binary.clone())
                    .or_default()
                    .push((msg, manifest));
            }
        }
    }

    let current_state = {
        let _lock = acquire_release_sync_lock(home_dir)?;
        load_release_sync_state(home_dir)?
    };

    let mut winners: BTreeMap<String, (BusMessage, ReleaseManifestV1, u64)> = BTreeMap::new();
    for (binary, mut list) in candidates_per_binary {
        list.sort_by_key(|(_, m)| m.order_key());

        let prev = current_state.binaries.get(&binary);
        let mut watermark_built = prev.map_or(0, InstalledBinaryState::effective_max_built_at_ms);
        let mut watermark_epoch = prev.map_or(0, InstalledBinaryState::effective_max_commit_epoch);
        let mut seen_keys: std::collections::BTreeSet<String> = prev
            .map(|p| p.applied_release_keys.iter().cloned().collect())
            .unwrap_or_default();
        if let Some(p) = prev {
            seen_keys.insert(format!(
                "{}:{}:{}:{}",
                p.sha256,
                p.commit_epoch,
                p.built_at_ms,
                u8::from(p.rollback)
            ));
        }

        let mut winner: Option<(BusMessage, ReleaseManifestV1, u64)> = None;
        let mut last_dedup_key: Option<String> = None;
        for (msg, m) in list {
            let key = InstalledBinaryState::release_history_key(&m);
            if last_dedup_key.as_deref() == Some(key.as_str()) {
                continue;
            }
            last_dedup_key = Some(key.clone());

            let same_as_prev = prev.is_some_and(|p| {
                p.sha256 == m.sha256
                    && p.commit_epoch == m.commit_epoch
                    && p.built_at_ms == m.built_at_ms
                    && p.rollback == m.rollback
            });
            if same_as_prev {
                if winner.is_none() {
                    winner = Some((msg, m, watermark_epoch));
                }
                continue;
            }
            if seen_keys.contains(&key) {
                continue;
            }
            if m.built_at_ms > watermark_built && (m.rollback || m.commit_epoch >= watermark_epoch)
            {
                watermark_built = m.built_at_ms;
                watermark_epoch = watermark_epoch.max(m.commit_epoch);
                seen_keys.insert(key);
                winner = Some((msg, m, watermark_epoch));
            }
        }
        if let Some(selected) = winner {
            winners.insert(binary, selected);
        }
    }

    let present_winners: BTreeMap<String, ReleaseManifestV1> = winners
        .iter()
        .map(|(bin, (_, m, _))| (bin.clone(), m.clone()))
        .collect();
    let mut executed_reports = Vec::with_capacity(winners.len());
    for (binary, (msg, manifest, observed_max_epoch)) in winners {
        let release_key = InstalledBinaryState::release_history_key(&manifest);
        if eligibility.is_some_and(|filter| !filter.is_manifest_eligible(&manifest)) {
            continue;
        }
        let outcome = apply_release_built_message_inner(
            home_dir,
            store,
            &msg,
            local_iroh_endpoint,
            roots,
            receipt_key_override,
            Some(observed_max_epoch),
            None,
        );
        let completed_at = clock();
        executed_reports.push(BinarySyncReport {
            binary,
            release_key,
            manifest,
            outcome,
            completed_at,
        });
    }
    Ok(JournalCatchupBatch {
        present_winners,
        executed_reports,
    })
}

pub const MAX_RELEASE_SYNC_TRANSIENT_RETRIES: u32 = 12;

pub enum ReleaseDaemonJob {
    StartupCatchup,
    LiveMessage(Box<BusMessage>),
}

#[derive(Debug, Clone)]
pub enum ReleaseDaemonEvent {
    Applied {
        binary: String,
        outcome: Box<ReleaseApplyOutcome>,
    },
    Rejected {
        binary: String,
        reason: String,
        retryable: bool,
        next_retry_secs: Option<u64>,
    },
    Suppressed {
        binary: String,
        release_key: String,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PerBinaryRetryState {
    release_key: String,
    built_at_ms: u64,
    commit_epoch: u64,
    retryable: bool,
    attempts: u32,
    next_due_at: Option<Instant>,
    in_flight: bool,
}

impl PerBinaryRetryState {
    fn cutoff(&self) -> PendingBinaryCutoff {
        PendingBinaryCutoff {
            release_key: self.release_key.clone(),
            built_at_ms: self.built_at_ms,
            commit_epoch: self.commit_epoch,
        }
    }

    fn is_superseded_by(&self, manifest: &ReleaseManifestV1) -> bool {
        self.cutoff().is_superseded_by(manifest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JournalOpenRetryState {
    retryable: bool,
    attempts: u32,
    next_due_at: Option<Instant>,
    in_flight: bool,
}

#[derive(Debug, Default)]
pub struct ReleaseDaemonScheduler {
    per_binary: BTreeMap<String, PerBinaryRetryState>,
    journal_open_retry: Option<JournalOpenRetryState>,
    initial_catchup_pending: bool,
    overflow_reconcile_pending: bool,
    catchup_queued: bool,
}

impl ReleaseDaemonScheduler {
    pub fn new_with_initial_catchup() -> Self {
        Self {
            initial_catchup_pending: true,
            catchup_queued: false,
            ..Self::default()
        }
    }

    pub fn backoff_for_attempt(attempt: u32) -> Duration {
        let secs = 10u64.saturating_mul(1u64 << attempt.min(5)).min(300);
        Duration::from_secs(secs)
    }

    pub fn mark_queue_overflow(&mut self) {
        self.overflow_reconcile_pending = true;
    }

    pub fn should_dispatch_catchup(&self, now: Instant) -> bool {
        if self.initial_catchup_pending || self.overflow_reconcile_pending {
            return true;
        }
        if let Some(ref jr) = self.journal_open_retry
            && !jr.in_flight
            && jr.retryable
            && jr.next_due_at.is_some_and(|due| now >= due)
        {
            return true;
        }
        self.per_binary
            .values()
            .any(|st| !st.in_flight && st.retryable && st.next_due_at.is_some_and(|due| now >= due))
    }

    pub fn poll_catchup_dispatch(&mut self, overflow_seen: bool, now: Instant) -> bool {
        if overflow_seen {
            self.overflow_reconcile_pending = true;
        }
        if self.catchup_queued || !self.should_dispatch_catchup(now) {
            return false;
        }
        self.catchup_queued = true;
        true
    }

    pub fn on_catchup_send_full(&mut self) {
        self.catchup_queued = false;
    }

    pub fn on_worker_env_error(
        &mut self,
        retryable: bool,
        is_catchup: bool,
        now: Instant,
    ) -> Option<Duration> {
        if is_catchup {
            self.catchup_queued = false;
            self.initial_catchup_pending = false;
            self.overflow_reconcile_pending = false;
        }
        self.on_catchup_failed(retryable, now)
    }

    pub fn on_worker_panic(&mut self, now: Instant) {
        self.catchup_queued = false;
        if let Some(ref mut jr) = self.journal_open_retry
            && jr.in_flight
        {
            jr.in_flight = false;
            if jr.retryable && jr.attempts < MAX_RELEASE_SYNC_TRANSIENT_RETRIES {
                let delay = Self::backoff_for_attempt(jr.attempts);
                jr.attempts = jr.attempts.saturating_add(1);
                jr.next_due_at = Some(now + delay);
            } else {
                jr.next_due_at = None;
            }
        }
        for st in self.per_binary.values_mut() {
            if st.in_flight {
                st.in_flight = false;
                if st.retryable && st.attempts < MAX_RELEASE_SYNC_TRANSIENT_RETRIES {
                    let delay = Self::backoff_for_attempt(st.attempts);
                    st.attempts = st.attempts.saturating_add(1);
                    st.next_due_at = Some(now + delay);
                } else {
                    st.next_due_at = None;
                }
            }
        }
    }

    fn begin_catchup_execution(&mut self, now: Instant) -> Option<ReleaseEligibilityFilter> {
        self.catchup_queued = false;
        let initial = std::mem::replace(&mut self.initial_catchup_pending, false);
        let overflow = std::mem::replace(&mut self.overflow_reconcile_pending, false);
        let mut due_binaries = std::collections::BTreeSet::new();
        let mut filter = ReleaseEligibilityFilter::default();
        for (binary, st) in &mut self.per_binary {
            let due_now =
                !st.in_flight && st.retryable && st.next_due_at.is_some_and(|due| now >= due);
            if due_now {
                st.in_flight = true;
                st.next_due_at = None;
                due_binaries.insert(binary.clone());
            } else {
                filter.blocked_cutoffs.insert(binary.clone(), st.cutoff());
            }
        }
        let any_binary_due = !due_binaries.is_empty();
        let mut jr_due = false;
        if let Some(ref mut jr) = self.journal_open_retry {
            jr_due = !jr.in_flight && jr.retryable && jr.next_due_at.is_some_and(|due| now >= due);
            if jr_due {
                jr.in_flight = true;
                jr.next_due_at = None;
            }
        }
        if !initial && !overflow && !any_binary_due && !jr_due {
            return None;
        }
        if !initial && !overflow && !jr_due {
            filter.only_binaries = Some(due_binaries);
        }
        Some(filter)
    }

    fn on_catchup_opened(&mut self, present_winners: &BTreeMap<String, ReleaseManifestV1>) {
        self.journal_open_retry = None;
        self.per_binary.retain(|binary, state| {
            if state.in_flight {
                let Some(winner) = present_winners.get(binary) else {
                    return false;
                };
                let winner_key = InstalledBinaryState::release_history_key(winner);
                if winner_key != state.release_key && !state.is_superseded_by(winner) {
                    return false;
                }
            }
            true
        });
    }

    fn on_catchup_failed(&mut self, retryable: bool, now: Instant) -> Option<Duration> {
        let jr = self
            .journal_open_retry
            .get_or_insert(JournalOpenRetryState {
                retryable,
                attempts: 0,
                next_due_at: None,
                in_flight: false,
            });
        jr.in_flight = false;
        jr.retryable = retryable;
        let jr_next_delay = if retryable && jr.attempts < MAX_RELEASE_SYNC_TRANSIENT_RETRIES {
            let delay = Self::backoff_for_attempt(jr.attempts);
            jr.attempts = jr.attempts.saturating_add(1);
            jr.next_due_at = Some(now + delay);
            Some(delay)
        } else {
            jr.next_due_at = None;
            None
        };
        for st in self.per_binary.values_mut() {
            if st.in_flight {
                st.in_flight = false;
                // Because top-level catch-up failed before per-binary execution ran,
                // preserve `st.attempts` and re-arm `st.next_due_at` iff catch-up itself
                // remains retryable within budget.
                if jr_next_delay.is_some()
                    && st.retryable
                    && st.attempts <= MAX_RELEASE_SYNC_TRANSIENT_RETRIES
                {
                    let delay = Self::backoff_for_attempt(st.attempts.saturating_sub(1));
                    st.next_due_at = Some(now + delay);
                } else {
                    st.next_due_at = None;
                }
            }
        }
        jr_next_delay
    }

    fn precheck_live_eligibility(
        &mut self,
        manifest: &ReleaseManifestV1,
        now: Instant,
    ) -> LiveEligibilityPrecheck {
        if manifest.target_triple != CURRENT_TARGET_TRIPLE {
            return LiveEligibilityPrecheck::Eligible;
        }
        let release_key = InstalledBinaryState::release_history_key(manifest);
        if let Some(st) = self.per_binary.get_mut(&manifest.binary) {
            if st.release_key == release_key {
                if !st.retryable {
                    return LiveEligibilityPrecheck::Suppressed("deterministic_failure_cached");
                }
                if st.in_flight {
                    return LiveEligibilityPrecheck::Suppressed("attempt_in_flight");
                }
                if let Some(due) = st.next_due_at {
                    if now < due {
                        return LiveEligibilityPrecheck::Suppressed("backoff_active");
                    }
                    st.in_flight = true;
                    st.next_due_at = None;
                    return LiveEligibilityPrecheck::Eligible;
                }
                if st.attempts >= MAX_RELEASE_SYNC_TRANSIENT_RETRIES {
                    return LiveEligibilityPrecheck::Suppressed("retry_budget_exhausted");
                }
                st.in_flight = true;
                return LiveEligibilityPrecheck::Eligible;
            }
            if !st.is_superseded_by(manifest) {
                return LiveEligibilityPrecheck::NeedsLocalSatisfactionCheck;
            }
        }
        LiveEligibilityPrecheck::Eligible
    }

    fn confirm_live_eligibility_after_local_check(
        &mut self,
        manifest: &ReleaseManifestV1,
        now: Instant,
        satisfied_locally: bool,
    ) -> Result<(), &'static str> {
        match self.precheck_live_eligibility(manifest, now) {
            LiveEligibilityPrecheck::Eligible => Ok(()),
            LiveEligibilityPrecheck::Suppressed(reason) => Err(reason),
            LiveEligibilityPrecheck::NeedsLocalSatisfactionCheck => {
                if satisfied_locally {
                    Ok(())
                } else {
                    Err("superseded_by_newer_pending_release")
                }
            }
        }
    }

    pub fn on_outcome(&mut self, outcome: &ReleaseApplyOutcome) {
        match outcome {
            ReleaseApplyOutcome::SkippedTargetMismatch { .. } => {}
            ReleaseApplyOutcome::Installed { manifest, .. }
            | ReleaseApplyOutcome::AlreadyInstalled { manifest, .. } => {
                if manifest.target_triple != CURRENT_TARGET_TRIPLE {
                    return;
                }
                let applied_key = InstalledBinaryState::release_history_key(manifest);
                let should_clear = self.per_binary.get(&manifest.binary).is_some_and(|st| {
                    st.release_key == applied_key || st.is_superseded_by(manifest)
                });
                if should_clear {
                    self.per_binary.remove(&manifest.binary);
                }
            }
        }
    }

    pub fn on_manifest_failed(
        &mut self,
        manifest: &ReleaseManifestV1,
        err: &ReleaseSyncError,
        now: Instant,
    ) -> Option<Duration> {
        if manifest.target_triple != CURRENT_TARGET_TRIPLE {
            return None;
        }
        let release_key = InstalledBinaryState::release_history_key(manifest);
        if matches!(err, ReleaseSyncError::DowngradeOrReplayRejected) {
            if self
                .per_binary
                .get(&manifest.binary)
                .is_some_and(|st| st.release_key == release_key)
            {
                self.per_binary.remove(&manifest.binary);
            }
            return None;
        }
        if let Some(existing) = self.per_binary.get(&manifest.binary)
            && existing.release_key != release_key
            && !existing.is_superseded_by(manifest)
        {
            return None;
        }
        let retryable = err.is_transient_retryable();
        let entry = self
            .per_binary
            .entry(manifest.binary.clone())
            .or_insert_with(|| PerBinaryRetryState {
                release_key: release_key.clone(),
                built_at_ms: manifest.built_at_ms,
                commit_epoch: manifest.commit_epoch,
                retryable,
                attempts: 0,
                next_due_at: None,
                in_flight: false,
            });
        if entry.release_key != release_key {
            entry.release_key = release_key;
            entry.built_at_ms = manifest.built_at_ms;
            entry.commit_epoch = manifest.commit_epoch;
            entry.attempts = 0;
        }
        entry.retryable = retryable;
        entry.in_flight = false;
        if !retryable {
            entry.attempts = entry.attempts.max(1);
            entry.next_due_at = None;
            return None;
        }
        if entry.attempts >= MAX_RELEASE_SYNC_TRANSIENT_RETRIES {
            entry.next_due_at = None;
            return None;
        }
        let delay = Self::backoff_for_attempt(entry.attempts);
        entry.attempts = entry.attempts.saturating_add(1);
        entry.next_due_at = Some(now + delay);
        Some(delay)
    }
}

enum LiveEligibilityPrecheck {
    Eligible,
    Suppressed(&'static str),
    NeedsLocalSatisfactionCheck,
}

fn is_manifest_already_satisfied_locally(home_dir: &Path, manifest: &ReleaseManifestV1) -> bool {
    let Ok((expected_sha256, _)) = manifest.validate_structural() else {
        return false;
    };
    let install_path = home_dir.join(".local/bin").join(&manifest.binary);
    let local_matches = local_binary_sha256(&install_path)
        .is_some_and(|actual| bool::from(actual.ct_eq(&expected_sha256)));
    if !local_matches {
        return false;
    }
    let Ok(_lock) = acquire_release_sync_lock(home_dir) else {
        return false;
    };
    let Ok(sync_state) = load_release_sync_state(home_dir) else {
        return false;
    };
    check_monotonic_gate(
        sync_state.binaries.get(&manifest.binary),
        manifest,
        &expected_sha256,
        true,
    )
    .unwrap_or(false)
}

pub fn execute_release_daemon_job(
    home_dir: &Path,
    messages_jsonl_path: &Path,
    store: &dyn ReleaseArtifactStore,
    local_iroh_endpoint: &str,
    scheduler: &Mutex<ReleaseDaemonScheduler>,
    job: ReleaseDaemonJob,
) -> Vec<ReleaseDaemonEvent> {
    execute_release_daemon_job_inner(
        home_dir,
        messages_jsonl_path,
        store,
        local_iroh_endpoint,
        &ReleaseTrustRoots::production(),
        None,
        scheduler,
        job,
        &mut Instant::now,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_release_daemon_job_inner(
    home_dir: &Path,
    messages_jsonl_path: &Path,
    store: &dyn ReleaseArtifactStore,
    local_iroh_endpoint: &str,
    roots: &ReleaseTrustRoots<'_>,
    receipt_key_override: Option<&SigningKey>,
    scheduler: &Mutex<ReleaseDaemonScheduler>,
    job: ReleaseDaemonJob,
    clock: &mut dyn FnMut() -> Instant,
) -> Vec<ReleaseDaemonEvent> {
    execute_release_daemon_job_with_hooks(
        home_dir,
        messages_jsonl_path,
        store,
        local_iroh_endpoint,
        roots,
        receipt_key_override,
        scheduler,
        job,
        clock,
        &mut open_regular_journal_if_present,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_release_daemon_job_with_hooks(
    home_dir: &Path,
    messages_jsonl_path: &Path,
    store: &dyn ReleaseArtifactStore,
    local_iroh_endpoint: &str,
    roots: &ReleaseTrustRoots<'_>,
    receipt_key_override: Option<&SigningKey>,
    scheduler: &Mutex<ReleaseDaemonScheduler>,
    job: ReleaseDaemonJob,
    clock: &mut dyn FnMut() -> Instant,
    journal_opener: &mut dyn FnMut(&Path) -> Result<Option<File>, ReleaseSyncError>,
) -> Vec<ReleaseDaemonEvent> {
    match job {
        ReleaseDaemonJob::StartupCatchup => {
            let started_at = clock();
            let eligibility = {
                let mut sched = scheduler.lock().unwrap_or_else(|e| e.into_inner());
                sched.begin_catchup_execution(started_at)
            };
            let Some(filter) = eligibility else {
                return Vec::new();
            };
            match sync_releases_from_journal_per_binary_filtered_with_opener(
                home_dir,
                messages_jsonl_path,
                store,
                Some(local_iroh_endpoint),
                roots,
                receipt_key_override,
                Some(&filter),
                clock,
                journal_opener,
            ) {
                Ok(batch) => {
                    let mut sched = scheduler.lock().unwrap_or_else(|e| e.into_inner());
                    sched.on_catchup_opened(&batch.present_winners);
                    let mut events = Vec::with_capacity(batch.executed_reports.len());
                    for report in batch.executed_reports {
                        match report.outcome {
                            Ok(outcome) => {
                                sched.on_outcome(&outcome);
                                events.push(ReleaseDaemonEvent::Applied {
                                    binary: report.binary,
                                    outcome: Box::new(outcome),
                                });
                            }
                            Err(err) => {
                                let retryable = err.is_transient_retryable();
                                let next_delay = sched.on_manifest_failed(
                                    &report.manifest,
                                    &err,
                                    report.completed_at,
                                );
                                events.push(ReleaseDaemonEvent::Rejected {
                                    binary: report.binary,
                                    reason: err.to_string(),
                                    retryable,
                                    next_retry_secs: next_delay.map(|d| d.as_secs()),
                                });
                            }
                        }
                    }
                    events
                }
                Err(err) => {
                    let failed_at = clock();
                    let retryable = err.is_transient_retryable();
                    let next_delay = {
                        let mut sched = scheduler.lock().unwrap_or_else(|e| e.into_inner());
                        sched.on_catchup_failed(retryable, failed_at)
                    };
                    vec![ReleaseDaemonEvent::Rejected {
                        binary: "all".to_owned(),
                        reason: err.to_string(),
                        retryable,
                        next_retry_secs: next_delay.map(|d| d.as_secs()),
                    }]
                }
            }
        }
        ReleaseDaemonJob::LiveMessage(msg) => {
            let manifest = match verify_release_built_message_with_roots(&msg, roots) {
                Ok(m) => m,
                Err(err) => {
                    return vec![ReleaseDaemonEvent::Rejected {
                        binary: "unknown".to_owned(),
                        reason: err.to_string(),
                        retryable: false,
                        next_retry_secs: None,
                    }];
                }
            };
            if manifest.target_triple != CURRENT_TARGET_TRIPLE {
                return vec![ReleaseDaemonEvent::Applied {
                    binary: manifest.binary,
                    outcome: Box::new(ReleaseApplyOutcome::SkippedTargetMismatch {
                        manifest_target: manifest.target_triple,
                        local_target: CURRENT_TARGET_TRIPLE.to_owned(),
                    }),
                }];
            }
            let release_key = InstalledBinaryState::release_history_key(&manifest);
            let precheck = {
                let check_at = clock();
                let mut sched = scheduler.lock().unwrap_or_else(|e| e.into_inner());
                sched.precheck_live_eligibility(&manifest, check_at)
            };
            match precheck {
                LiveEligibilityPrecheck::Eligible => {}
                LiveEligibilityPrecheck::Suppressed(reason) => {
                    return vec![ReleaseDaemonEvent::Suppressed {
                        binary: manifest.binary,
                        release_key,
                        reason,
                    }];
                }
                LiveEligibilityPrecheck::NeedsLocalSatisfactionCheck => {
                    // Inspect local binary digest + sync state OUTSIDE the scheduler mutex
                    // so a blocking filesystem lock never stalls the daemon select! heartbeat.
                    let satisfied_locally =
                        is_manifest_already_satisfied_locally(home_dir, &manifest);
                    let confirm_at = clock();
                    let mut sched = scheduler.lock().unwrap_or_else(|e| e.into_inner());
                    if let Err(reason) = sched.confirm_live_eligibility_after_local_check(
                        &manifest,
                        confirm_at,
                        satisfied_locally,
                    ) {
                        return vec![ReleaseDaemonEvent::Suppressed {
                            binary: manifest.binary,
                            release_key,
                            reason,
                        }];
                    }
                }
            }
            let outcome = apply_release_built_message_inner(
                home_dir,
                store,
                &msg,
                Some(local_iroh_endpoint),
                roots,
                receipt_key_override,
                None,
                None,
            );
            let finished_at = clock();
            let mut sched = scheduler.lock().unwrap_or_else(|e| e.into_inner());
            match outcome {
                Ok(applied) => {
                    sched.on_outcome(&applied);
                    vec![ReleaseDaemonEvent::Applied {
                        binary: manifest.binary,
                        outcome: Box::new(applied),
                    }]
                }
                Err(err) => {
                    let retryable = err.is_transient_retryable();
                    let next_delay = sched.on_manifest_failed(&manifest, &err, finished_at);
                    vec![ReleaseDaemonEvent::Rejected {
                        binary: manifest.binary,
                        reason: err.to_string(),
                        retryable,
                        next_retry_secs: next_delay.map(|d| d.as_secs()),
                    }]
                }
            }
        }
    }
}

/// Scans `.chinwag/bus/messages.jsonl` for the latest cryptographically verified
/// `INFRAJR` `RELEASE_BUILT` per binary matching `CURRENT_TARGET_TRIPLE` and
/// applies each monotonically.
pub fn sync_releases_from_journal(
    home_dir: &Path,
    messages_jsonl_path: &Path,
    store: &dyn ReleaseArtifactStore,
    local_iroh_endpoint: Option<&str>,
) -> Result<Vec<(String, ReleaseApplyOutcome)>, ReleaseSyncError> {
    let per_binary = sync_releases_from_journal_per_binary(
        home_dir,
        messages_jsonl_path,
        store,
        local_iroh_endpoint,
    )?;
    let mut outcomes = Vec::with_capacity(per_binary.len());
    for report in per_binary {
        outcomes.push((report.binary, report.outcome?));
    }
    Ok(outcomes)
}

pub fn collect_release_status_json(home_dir: &Path) -> Result<serde_json::Value, ReleaseSyncError> {
    let state = load_release_sync_state(home_dir)?;
    let bin_dir = home_dir.join(".local/bin");
    let mut local_binaries = serde_json::Map::new();
    for binary in ALLOWED_BINARIES {
        let path = bin_dir.join(binary);
        let prev_path = bin_dir.join(format!("{binary}.prev"));
        let disk_info = match compute_file_digests(&path) {
            Ok((size_bytes, sha256, blake3)) => json!({
                "present": true,
                "path": path.to_string_lossy(),
                "size_bytes": size_bytes,
                "sha256": encode_hex(&sha256),
                "blake3": encode_hex(&blake3),
                "prev_present": prev_path.is_file(),
            }),
            Err(_) => json!({
                "present": false,
                "path": path.to_string_lossy(),
                "prev_present": prev_path.is_file(),
            }),
        };
        local_binaries.insert((*binary).to_owned(), disk_info);
    }
    Ok(json!({
        "ok": true,
        "schema": "chinwag.release-status.v1",
        "target_triple": CURRENT_TARGET_TRIPLE,
        "allowed_release_signers": ALLOWED_RELEASE_SIGNERS,
        "allowed_binaries": ALLOWED_BINARIES,
        "state_path": release_sync_state_path(home_dir).to_string_lossy(),
        "recorded_state": state,
        "local_binaries": local_binaries,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_seat_pubkeys::canonical_seat_pubkey;
    use std::sync::Mutex;

    struct InMemoryArtifactStore {
        blobs: Mutex<BTreeMap<String, Vec<u8>>>,
        download_calls: Mutex<usize>,
        on_download: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl InMemoryArtifactStore {
        fn new() -> Self {
            Self {
                blobs: Mutex::new(BTreeMap::new()),
                download_calls: Mutex::new(0),
                on_download: Mutex::new(None),
            }
        }

        fn downloads(&self) -> usize {
            *self.download_calls.lock().unwrap()
        }

        fn tamper_blob(&self, key: &str, new_bytes: Vec<u8>) {
            self.blobs.lock().unwrap().insert(key.to_owned(), new_bytes);
        }

        fn set_on_download(&self, hook: impl FnOnce() + Send + 'static) {
            *self.on_download.lock().unwrap() = Some(Box::new(hook));
        }
    }

    fn read_all_from_pinned_fd(source_file: &File) -> Result<Vec<u8>, ReleaseSyncError> {
        let mut dup_fd = source_file
            .try_clone()
            .map_err(|e| ReleaseSyncError::ArtifactStoreFailed(e.to_string()))?;
        dup_fd
            .seek(SeekFrom::Start(0))
            .map_err(|e| ReleaseSyncError::ArtifactStoreFailed(e.to_string()))?;
        let mut bytes = Vec::new();
        dup_fd
            .read_to_end(&mut bytes)
            .map_err(|e| ReleaseSyncError::ArtifactStoreFailed(e.to_string()))?;
        Ok(bytes)
    }

    impl ReleaseArtifactStore for InMemoryArtifactStore {
        fn upload_artifact(
            &self,
            artifact_key: &str,
            source_file: &File,
        ) -> Result<(), ReleaseSyncError> {
            validate_artifact_key_structure(artifact_key)?;
            let bytes = read_all_from_pinned_fd(source_file)?;
            self.blobs
                .lock()
                .unwrap()
                .insert(artifact_key.to_owned(), bytes);
            Ok(())
        }

        fn download_artifact(
            &self,
            artifact_key: &str,
            destination_file: &Path,
        ) -> Result<(), ReleaseSyncError> {
            *self.download_calls.lock().unwrap() += 1;
            let bytes = self
                .blobs
                .lock()
                .unwrap()
                .get(artifact_key)
                .cloned()
                .ok_or_else(|| ReleaseSyncError::ArtifactStoreFailed("missing_blob".into()))?;
            fs::write(destination_file, bytes)
                .map_err(|e| ReleaseSyncError::ArtifactStoreFailed(e.to_string()))?;
            let maybe_hook = self.on_download.lock().unwrap().take();
            if let Some(hook) = maybe_hook {
                hook();
            }
            Ok(())
        }
    }

    fn random_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).unwrap();
        let key = SigningKey::from_bytes(&seed);
        zeroize::Zeroize::zeroize(&mut seed);
        key
    }

    /// Compiles a tiny real Mach-O binary (`fn main()`) once per test dir so
    /// macOS `codesign --verify --strict` and `--version` exercise genuine
    /// Mach-O code signing rather than shell-script mocks.
    fn build_macho_test_binary(dir: &Path, tag: &str) -> PathBuf {
        let src = dir.join(format!("bin_{tag}.rs"));
        let out = dir.join(format!("bin_{tag}"));
        fs::write(
            &src,
            format!("fn main() {{ println!(\"chinwag 0.1.0 ({tag})\"); }}\n"),
        )
        .unwrap();
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
        let status = Command::new(rustc)
            .arg(&src)
            .arg("-O")
            .arg("-o")
            .arg(&out)
            .status()
            .expect("rustc must compile synthetic Mach-O test binary");
        assert!(status.success());
        out
    }

    #[test]
    fn canonical_seat_pubkeys_table_is_sorted_bijective_and_pins_infrajr() {
        assert_eq!(CANONICAL_SEAT_PUBKEYS.len(), 127);
        let mut prev_seat = "";
        let mut unique_keys = std::collections::BTreeSet::new();
        for (seat, pubkey) in CANONICAL_SEAT_PUBKEYS {
            assert!(
                *seat > prev_seat,
                "seats must be strictly sorted for binary_search"
            );
            prev_seat = seat;
            assert!(
                unique_keys.insert(*pubkey),
                "duplicate Ed25519 public key in CANONICAL_SEAT_PUBKEYS"
            );
            assert!(VerifyingKey::from_bytes(pubkey).is_ok());
        }
        let infrajr = canonical_seat_pubkey("INFRAJR").expect("INFRAJR must be pinned");
        assert_eq!(
            encode_hex(&infrajr),
            "43773984f321fde6c85e1d8c55cf3bb02cd078ab08f81e3356b4c61ccc7a5109"
        );
    }

    #[test]
    fn published_nist_sha256_blakespec_and_rfc8032_vectors_match() {
        // NIST FIPS 180-4 official SHA-256 vectors:
        assert_eq!(
            encode_hex(&compute_sha256_bytes(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            encode_hex(&compute_sha256_bytes(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            encode_hex(&compute_sha256_bytes(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );

        // Official BLAKE3 spec `test_vectors/test_vectors.json` (`BLAKE3-team/BLAKE3`,
        // input pattern `i % 251`) for lengths 0, 3, 65 (2 blocks), and 1025 (2 chunks):
        assert_eq!(
            encode_hex(&compute_blake3_bytes(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            encode_hex(&compute_blake3_bytes(&[0x00, 0x01, 0x02])),
            "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
        );
        let seq65: Vec<u8> = (0usize..65).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            encode_hex(&compute_blake3_bytes(&seq65)),
            "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"
        );
        let seq1025: Vec<u8> = (0usize..1025).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            encode_hex(&compute_blake3_bytes(&seq1025)),
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"
        );

        // RFC 8032 §7.1 TEST 1 (empty message) & TEST 2 (1-byte 0x72) Ed25519 public verification vectors:
        let rfc_pub_1 = decode_hex_32_any_case(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .unwrap();
        let rfc_sig_1 = decode_hex_64_any_case(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .unwrap();
        let vk1 = VerifyingKey::from_bytes(&rfc_pub_1).unwrap();
        vk1.verify_strict(b"", &Signature::from_bytes(&rfc_sig_1))
            .unwrap();
        // Negative vector: bit-flipped message and bit-flipped signature must fail strict verification.
        assert!(
            vk1.verify_strict(b"x", &Signature::from_bytes(&rfc_sig_1))
                .is_err()
        );
        let mut bad_sig = rfc_sig_1;
        bad_sig[0] ^= 0x01;
        assert!(
            vk1.verify_strict(b"", &Signature::from_bytes(&bad_sig))
                .is_err()
        );
    }

    #[test]
    fn end_to_end_publish_install_prev_backup_idempotency_and_rollback_lifecycle() {
        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let build_dir = temp.path().join("build");
        fs::create_dir_all(&pub_home).unwrap();
        fs::create_dir_all(&sub_home).unwrap();
        fs::create_dir_all(&build_dir).unwrap();

        let infrajr_key = random_signing_key();
        let infrajr_pub = infrajr_key.verifying_key().to_bytes();
        let seat_table = [("INFRAJR", infrajr_pub)];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };

        let store = InMemoryArtifactStore::new();
        let v1_bin = build_macho_test_binary(&build_dir, "v1");
        let v2_bin = build_macho_test_binary(&build_dir, "v2");

        // 1. Publish v1 from publisher peer.
        let actor_v1 = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());
        let pub_v1 = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &v1_bin,
                explicit_from: Some(&actor_v1),
                rollback: false,
                commit_override: Some(("1111111111111111".into(), 1_700_000_100)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        // Publisher peer observing its own RELEASE_BUILT hits 0ms AlreadyInstalled with zero downloads!
        let self_apply = apply_release_built_message_inner(
            &pub_home,
            &store,
            &pub_v1.release_built_message,
            Some("peer-pub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            None,
        )
        .unwrap();
        assert!(matches!(
            self_apply,
            ReleaseApplyOutcome::AlreadyInstalled { .. }
        ));
        assert_eq!(store.downloads(), 0);

        // 2. Subscriber peer receives v1 and installs it cleanly with exact SHA-256 parity!
        let sub_v1 = apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_v1.release_built_message,
            Some("peer-sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            None,
        )
        .unwrap();
        let ReleaseApplyOutcome::Installed {
            manifest: installed_v1,
            install_path: sub_bin_path,
            previous_backup_path: sub_prev_v1,
            receipt_message: Some(receipt_v1),
        } = sub_v1
        else {
            panic!("expected fresh install on subscriber");
        };
        assert!(sub_prev_v1.is_none());
        assert_eq!(store.downloads(), 1);
        assert_eq!(receipt_v1.room, "#ops");
        assert!(receipt_v1.body.starts_with(RELEASE_INSTALLED_PREFIX));
        assert!(receipt_v1.body.contains("peer-sub-ep"));

        let (_, pub_sha_v1, _) = compute_file_digests(&pub_v1.install_path).unwrap();
        let (_, sub_sha_v1, _) = compute_file_digests(&sub_bin_path).unwrap();
        assert_eq!(pub_sha_v1, sub_sha_v1, "100% byte-for-byte SHA-256 parity");
        assert_eq!(encode_hex(&sub_sha_v1), installed_v1.sha256);

        // Catchup replay of v1 on subscriber hits AlreadyInstalled with zero extra R2 downloads!
        let replay_same = apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_v1.release_built_message,
            Some("peer-sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            None,
        )
        .unwrap();
        assert!(matches!(
            replay_same,
            ReleaseApplyOutcome::AlreadyInstalled { .. }
        ));
        assert_eq!(store.downloads(), 1);

        // 3. Publish v2 (newer commit_epoch) -> subscriber installs v2 and preserves v1 at `chinwag.prev`!
        let pub_v2 = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &v2_bin,
                explicit_from: Some(&actor_v1),
                rollback: false,
                commit_override: Some(("2222222222222222".into(), 1_700_000_200)),
            },
            &store,
            |_| Ok(2),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        let sub_v2 = apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_v2.release_built_message,
            Some("peer-sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            None,
        )
        .unwrap();
        let ReleaseApplyOutcome::Installed {
            previous_backup_path: Some(prev_path),
            ..
        } = sub_v2
        else {
            panic!("expected v2 upgrade with .prev backup");
        };
        let (_, prev_sha, _) = compute_file_digests(&prev_path).unwrap();
        assert_eq!(prev_sha, sub_sha_v1, ".prev must preserve exact v1 binary");

        // 4. Anti-downgrade gate: replaying v1 (`rollback: false`) after v2 is rejected!
        let downgrade = apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_v1.release_built_message,
            Some("peer-sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            None,
        );
        assert_eq!(
            downgrade.unwrap_err(),
            ReleaseSyncError::DowngradeOrReplayRejected
        );

        // 5. Explicit `rollback: true` with newer `built_at_ms` succeeds, and replaying that
        //    same rollback after a newer build is still rejected!
        let pub_rb = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &v1_bin,
                explicit_from: Some(&actor_v1),
                rollback: true,
                commit_override: Some(("1111111111111111".into(), 1_700_000_100)),
            },
            &store,
            |_| Ok(3),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        let sub_rb = apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_rb.release_built_message,
            Some("peer-sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            None,
        )
        .unwrap();
        assert!(matches!(sub_rb, ReleaseApplyOutcome::Installed { .. }));
        let (_, after_rb_sha, _) = compute_file_digests(&sub_bin_path).unwrap();
        assert_eq!(after_rb_sha, sub_sha_v1);
    }

    #[test]
    fn non_infrajr_seats_with_valid_ed25519_signatures_are_rejected_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let sub_home = temp.path().join("sub-home");
        fs::create_dir_all(&sub_home).unwrap();

        let infrajr_key = random_signing_key();
        let sales_key = random_signing_key();
        let workhorse_key = random_signing_key();
        let seat_table = [
            ("INFRAJR", infrajr_key.verifying_key().to_bytes()),
            ("SALES", sales_key.verifying_key().to_bytes()),
            ("WORKHORSE", workhorse_key.verifying_key().to_bytes()),
        ];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = InMemoryArtifactStore::new();

        let fake_sha = "a".repeat(64);
        let fake_b3 = "b".repeat(64);
        let manifest = ReleaseManifestV1 {
            schema: RELEASE_MANIFEST_SCHEMA.to_owned(),
            binary: "chinwag".to_owned(),
            target_triple: CURRENT_TARGET_TRIPLE.to_owned(),
            git_commit: "deadbeef12345678".to_owned(),
            commit_epoch: 1_700_000_500,
            built_at_ms: 1_700_000_500_000,
            artifact_key: expected_artifact_key("chinwag", CURRENT_TARGET_TRIPLE, &fake_sha),
            sha256: fake_sha,
            blake3: fake_b3,
            size_bytes: 4096,
            rollback: false,
        };
        let body = format!(
            "{RELEASE_BUILT_PREFIX}{}",
            serde_json::to_string(&manifest).unwrap()
        );
        let instance = agent_instance::new_instance_id().unwrap();

        for (seat, key) in [("SALES", &sales_key), ("WORKHORSE", &workhorse_key)] {
            let actor = ActorAddress::parse(&format!("{seat}#{instance}")).unwrap();
            let valid_signed_msg = sign_structured_bus_message(
                &actor,
                "#all",
                Some("CHWG-0261".into()),
                body.clone(),
                key,
            );
            let res = apply_release_built_message_inner(
                &sub_home,
                &store,
                &valid_signed_msg,
                None,
                &roots,
                None,
                None,
                None,
            );
            assert_eq!(res.unwrap_err(), ReleaseSyncError::UnauthorizedSigner);
            assert_eq!(store.downloads(), 0);

            // Also verify that INFRAJR sender signed by WORKHORSE/SALES key fails SignatureInvalid!
            let spoofed_actor = ActorAddress::parse(&format!("INFRAJR#{instance}")).unwrap();
            let spoofed_msg = sign_structured_bus_message(
                &spoofed_actor,
                "#all",
                Some("CHWG-0261".into()),
                body.clone(),
                key,
            );
            let spoof_res = apply_release_built_message_inner(
                &sub_home,
                &store,
                &spoofed_msg,
                None,
                &roots,
                None,
                None,
                None,
            );
            assert_eq!(spoof_res.unwrap_err(), ReleaseSyncError::SignatureInvalid);
            assert_eq!(store.downloads(), 0);
        }
    }

    #[test]
    fn tampered_r2_bytes_fail_before_0755_chmod_and_unlink_staging_immediately() {
        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let build_dir = temp.path().join("build");
        fs::create_dir_all(&pub_home).unwrap();
        fs::create_dir_all(&sub_home).unwrap();
        fs::create_dir_all(&build_dir).unwrap();

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = InMemoryArtifactStore::new();
        let v1_bin = build_macho_test_binary(&build_dir, "tamper");
        let actor = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());
        let pub_v1 = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &v1_bin,
                explicit_from: Some(&actor),
                rollback: false,
                commit_override: Some(("abcdef0123456789".into(), 1_700_000_900)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        // Corrupt a single byte in the R2 blob (same exact file length!).
        let mut corrupted = fs::read(&pub_v1.install_path).unwrap();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xff;
        store.tamper_blob(&pub_v1.manifest.artifact_key, corrupted);

        let res = apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_v1.release_built_message,
            None,
            &roots,
            Some(&infrajr_key),
            None,
            None,
        );
        assert_eq!(res.unwrap_err(), ReleaseSyncError::DigestMismatch);
        assert!(!sub_home.join(".local/bin/chinwag").exists());
        let staging_entries: Vec<_> = fs::read_dir(sub_home.join(".local/bin/.staging"))
            .unwrap()
            .collect();
        assert!(
            staging_entries.is_empty(),
            "corrupted staging file must be unlinked immediately on digest failure"
        );
    }

    #[test]
    fn release_sync_surfaces_contain_zero_hardcoded_topology_or_user_paths() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = crate_dir.parent().and_then(Path::parent).unwrap();
        let targets = [
            crate_dir.join("src/release_sync.rs"),
            crate_dir.join("src/canonical_seat_pubkeys.rs"),
            repo_root.join("crates/chinwag-swarm/src/room.rs"),
            repo_root.join("crates/chinwag-swarm/src/room_binding.rs"),
            repo_root.join("scripts/chinwag-release-publish"),
        ];
        // Build forbidden tokens dynamically so this test file itself never
        // contains literal prohibited substrings either.
        let forbidden = [
            format!("{}.json", "nodes"),
            format!("node{}", 1),
            format!("node{}", 2),
            format!("100.{}.", 108),
            format!("100.{}.", 66),
            format!("100.{}.", 89),
            format!("Brians-{}", "Mac"),
            format!("/Users/{}", "brianspector"),
        ];
        for path in targets {
            if !path.exists() {
                continue;
            }
            let content = fs::read_to_string(&path).unwrap();
            for needle in &forbidden {
                assert!(
                    !content.contains(needle),
                    "{} must not contain hardcoded topology/path token '{needle}'",
                    path.display()
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unsigned_payload_with_matching_digests_fails_strict_codesign_before_0755_and_unlinks() {
        let temp = tempfile::tempdir().unwrap();
        let sub_home = temp.path().join("sub-home");
        fs::create_dir_all(&sub_home).unwrap();

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = InMemoryArtifactStore::new();

        // Craft an unsigned script payload whose SHA-256 and BLAKE3 match the signed manifest.
        let unsigned_bytes = b"#!/bin/sh\necho chinwag 0.0.0\n";
        let sha_hex = encode_hex(&compute_sha256_bytes(unsigned_bytes));
        let b3_hex = encode_hex(&compute_blake3_bytes(unsigned_bytes));
        let artifact_key = expected_artifact_key("chinwag", CURRENT_TARGET_TRIPLE, &sha_hex);
        let tmp_src = temp.path().join("unsigned.bin");
        fs::write(&tmp_src, unsigned_bytes).unwrap();
        let tmp_src_file = File::open(&tmp_src).unwrap();
        store.upload_artifact(&artifact_key, &tmp_src_file).unwrap();

        let manifest = ReleaseManifestV1 {
            schema: RELEASE_MANIFEST_SCHEMA.to_owned(),
            binary: "chinwag".to_owned(),
            target_triple: CURRENT_TARGET_TRIPLE.to_owned(),
            git_commit: "feedface12345678".to_owned(),
            commit_epoch: 1_700_001_000,
            built_at_ms: 1_700_001_000_000,
            sha256: sha_hex,
            blake3: b3_hex,
            size_bytes: unsigned_bytes.len() as u64,
            artifact_key,
            rollback: false,
        };
        let instance = agent_instance::new_instance_id().unwrap();
        let actor = ActorAddress::parse(&format!("INFRAJR#{instance}")).unwrap();
        let msg = sign_structured_bus_message(
            &actor,
            "#all",
            Some("CHWG-0261".into()),
            format!(
                "{RELEASE_BUILT_PREFIX}{}",
                serde_json::to_string(&manifest).unwrap()
            ),
            &infrajr_key,
        );

        let res = apply_release_built_message_inner(
            &sub_home,
            &store,
            &msg,
            None,
            &roots,
            Some(&infrajr_key),
            None,
            None,
        );
        assert!(matches!(res, Err(ReleaseSyncError::CodesignFailed(_))));
        assert!(!sub_home.join(".local/bin/chinwag").exists());
        assert!(
            fs::read_dir(sub_home.join(".local/bin/.staging"))
                .unwrap()
                .next()
                .is_none(),
            "unsigned staged file must be unlinked before 0755 execute bits are ever set"
        );
    }

    #[test]
    fn rollback_preserves_replay_protection_and_blocks_historical_cycles() {
        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let cold_home = temp.path().join("cold-home");
        let build_dir = temp.path().join("build");
        for d in [&pub_home, &sub_home, &cold_home, &build_dir] {
            fs::create_dir_all(d).unwrap();
        }

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = InMemoryArtifactStore::new();
        let bin_100 = build_macho_test_binary(&build_dir, "ep100");
        let bin_150 = build_macho_test_binary(&build_dir, "ep150");
        let bin_200 = build_macho_test_binary(&build_dir, "ep200");
        let bin_210 = build_macho_test_binary(&build_dir, "ep210");
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());
        let actor = ActorAddress::parse(&actor_str).unwrap();

        // Publish normal (epoch=200), then rollback (epoch=100).
        let pub_200 = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &bin_200,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("2000200020002000".into(), 200)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        let pub_rb_100 = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &bin_100,
                explicit_from: Some(&actor_str),
                rollback: true,
                commit_override: Some(("1000100010001000".into(), 100)),
            },
            &store,
            |_| Ok(2),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        assert!(pub_rb_100.manifest.built_at_ms > pub_200.manifest.built_at_ms);

        // Apply normal (200), then rollback (100) on subscriber.
        apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_200.release_built_message,
            Some("sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            None,
        )
        .unwrap();
        apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_rb_100.release_built_message,
            Some("sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            None,
        )
        .unwrap();

        // 1. Replaying historical normal (200) MUST fail closed instead of undoing rollback!
        let replay_200 = apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_200.release_built_message,
            Some("sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            None,
        );
        assert_eq!(
            replay_200.unwrap_err(),
            ReleaseSyncError::DowngradeOrReplayRejected
        );

        // 2. Unflagged normal build with commit_epoch=150 (< max_commit_epoch_seen=200) MUST fail closed
        //    even if its built_at_ms is newer than rollback (100)!
        let (_, sha_150, b3_150) = compute_file_digests(&bin_150).unwrap();
        let sha_150_hex = encode_hex(&sha_150);
        let key_150 = expected_artifact_key("chinwag", CURRENT_TARGET_TRIPLE, &sha_150_hex);
        let bin_150_file = File::open(&bin_150).unwrap();
        store.upload_artifact(&key_150, &bin_150_file).unwrap();
        let unflagged_150 = ReleaseManifestV1 {
            schema: RELEASE_MANIFEST_SCHEMA.to_owned(),
            binary: "chinwag".into(),
            target_triple: CURRENT_TARGET_TRIPLE.into(),
            git_commit: "1500150015001500".into(),
            commit_epoch: 150,
            built_at_ms: pub_rb_100.manifest.built_at_ms + 500,
            sha256: sha_150_hex,
            blake3: encode_hex(&b3_150),
            size_bytes: fs::metadata(&bin_150).unwrap().len(),
            artifact_key: key_150,
            rollback: false,
        };
        let msg_150 = sign_structured_bus_message(
            &actor,
            "#all",
            Some("CHWG-0261".into()),
            format!(
                "{RELEASE_BUILT_PREFIX}{}",
                serde_json::to_string(&unflagged_150).unwrap()
            ),
            &infrajr_key,
        );
        assert_eq!(
            apply_release_built_message_inner(
                &sub_home,
                &store,
                &msg_150,
                Some("sub-ep"),
                &roots,
                Some(&infrajr_key),
                None,
                None,
            )
            .unwrap_err(),
            ReleaseSyncError::DowngradeOrReplayRejected
        );

        // 3. Even if journal contains normal (200), rollback (100), and a replayed copy of
        //    stale normal (200) appended out of order, both an already-rolled-back peer AND
        //    a cold peer select rollback (100) cleanly!
        let journal = temp.path().join("messages.jsonl");
        fs::write(
            &journal,
            format!(
                "{}\n{}\n{}\n",
                serde_json::to_string(&pub_200.release_built_message).unwrap(),
                serde_json::to_string(&pub_rb_100.release_built_message).unwrap(),
                serde_json::to_string(&pub_200.release_built_message).unwrap()
            ),
        )
        .unwrap();

        let sub_sync = sync_releases_from_journal_per_binary_inner(
            &sub_home,
            &journal,
            &store,
            Some("sub-ep"),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        assert_eq!(sub_sync.len(), 1);
        assert!(matches!(
            sub_sync[0].outcome,
            Ok(ReleaseApplyOutcome::AlreadyInstalled { .. })
        ));

        let cold_sync = sync_releases_from_journal_per_binary_inner(
            &cold_home,
            &journal,
            &store,
            Some("cold-ep"),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        let ReleaseApplyOutcome::Installed {
            manifest: cold_m, ..
        } = cold_sync.into_iter().next().unwrap().outcome.unwrap()
        else {
            panic!("expected cold peer to install rollback winner");
        };
        assert!(cold_m.rollback);
        assert_eq!(cold_m.commit_epoch, 100);
        let cold_state = load_release_sync_state(&cold_home).unwrap();
        assert_eq!(
            cold_state.binaries["chinwag"].max_commit_epoch_seen, 200,
            "cold peer fold must preserve observed epoch 200 watermark"
        );

        // 4. Genuine forward fix (epoch=210) succeeds, and replaying rollback (100) after 210 is rejected!
        let pub_210 = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &bin_210,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("2100210021002100".into(), 210)),
            },
            &store,
            |_| Ok(3),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        assert!(matches!(
            apply_release_built_message_inner(
                &sub_home,
                &store,
                &pub_210.release_built_message,
                Some("sub-ep"),
                &roots,
                Some(&infrajr_key),
                None,
                None,
            )
            .unwrap(),
            ReleaseApplyOutcome::Installed { .. }
        ));
        assert_eq!(
            apply_release_built_message_inner(
                &sub_home,
                &store,
                &pub_rb_100.release_built_message,
                Some("sub-ep"),
                &roots,
                Some(&infrajr_key),
                None,
                None,
            )
            .unwrap_err(),
            ReleaseSyncError::DowngradeOrReplayRejected
        );
    }

    #[test]
    fn commit_time_revalidation_blocks_stalled_installer_downgrade() {
        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let build_dir = temp.path().join("build");
        for d in [&pub_home, &sub_home, &build_dir] {
            fs::create_dir_all(d).unwrap();
        }

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = std::sync::Arc::new(InMemoryArtifactStore::new());
        let bin_101 = build_macho_test_binary(&build_dir, "ep101");
        let bin_102 = build_macho_test_binary(&build_dir, "ep102");
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());

        let pub_101 = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &bin_101,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("1010101010101010".into(), 101)),
            },
            store.as_ref(),
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        let pub_102 = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &bin_102,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("1020102010201020".into(), 102)),
            },
            store.as_ref(),
            |_| Ok(2),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        // Simulate a concurrent `chinwag release sync` installing epoch 102 while
        // the slower installer is mid-download on epoch 101.
        let sub_home_race = sub_home.clone();
        let store_race = store.clone();
        let msg_102 = pub_102.release_built_message.clone();
        let key_race = infrajr_key.clone();
        let pub_bytes_race = infrajr_key.verifying_key().to_bytes();
        store.set_on_download(move || {
            let race_table = [("INFRAJR", pub_bytes_race)];
            let race_roots = ReleaseTrustRoots {
                seat_pubkeys: &race_table,
                allowed_signers: ALLOWED_RELEASE_SIGNERS,
            };
            apply_release_built_message_inner(
                &sub_home_race,
                store_race.as_ref(),
                &msg_102,
                Some("sub-ep"),
                &race_roots,
                Some(&key_race),
                None,
                None,
            )
            .expect("concurrent newer epoch 102 install must succeed");
        });

        let stalled_101 = apply_release_built_message_inner(
            &sub_home,
            store.as_ref(),
            &pub_101.release_built_message,
            Some("sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            None,
        );
        assert_eq!(
            stalled_101.unwrap_err(),
            ReleaseSyncError::DowngradeOrReplayRejected,
            "stalled epoch 101 installer must fail closed at commit-time lock revalidation"
        );

        let (_, on_disk_sha, _) =
            compute_file_digests(&sub_home.join(".local/bin/chinwag")).unwrap();
        assert_eq!(
            encode_hex(&on_disk_sha),
            pub_102.manifest.sha256,
            "installed binary must remain epoch 102"
        );
        let final_state = load_release_sync_state(&sub_home).unwrap();
        assert_eq!(final_state.binaries["chinwag"].commit_epoch, 102);
    }

    #[test]
    fn symlink_source_and_state_files_fail_closed_with_o_nofollow() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let real_file = temp.path().join("real.bin");
        fs::write(&real_file, b"non-empty-payload").unwrap();
        let link_file = temp.path().join("link.bin");
        symlink(&real_file, &link_file).unwrap();

        assert!(matches!(
            open_regular_file_nofollow(&link_file, false, false),
            Err(ReleaseSyncError::SafePathViolation(_))
        ));

        let home = temp.path().join("home");
        fs::create_dir_all(home.join(".chinwag")).unwrap();
        #[cfg(unix)]
        fs::set_permissions(home.join(".chinwag"), fs::Permissions::from_mode(0o700)).unwrap();

        // Symlinked `release_sync_state.json` must fail closed.
        symlink(&real_file, home.join(".chinwag/release_sync_state.json")).unwrap();
        assert!(matches!(
            load_release_sync_state(&home),
            Err(ReleaseSyncError::SafePathViolation(_))
        ));
        fs::remove_file(home.join(".chinwag/release_sync_state.json")).unwrap();

        // Symlinked `release_sync.lock` must fail closed with `O_NOFOLLOW`.
        symlink(&real_file, home.join(".chinwag/release_sync.lock")).unwrap();
        assert!(matches!(
            acquire_release_sync_lock(&home),
            Err(ReleaseSyncError::SafePathViolation(_))
        ));
        fs::remove_file(home.join(".chinwag/release_sync.lock")).unwrap();

        // Missing journal returns empty report, whereas symlinked journal fails closed!
        let store = InMemoryArtifactStore::new();
        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        assert!(
            sync_releases_from_journal_per_binary_inner(
                &home,
                &temp.path().join("absent-messages.jsonl"),
                &store,
                None,
                &roots,
                None,
            )
            .unwrap()
            .is_empty()
        );
        let link_journal = temp.path().join("symlink-messages.jsonl");
        symlink(&real_file, &link_journal).unwrap();
        assert!(matches!(
            sync_releases_from_journal_per_binary_inner(
                &home,
                &link_journal,
                &store,
                None,
                &roots,
                None,
            ),
            Err(ReleaseSyncError::SafePathViolation(_))
        ));
    }

    #[test]
    fn per_binary_catchup_preserves_chinwag_install_when_chinwag_ci_fails() {
        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let build_dir = temp.path().join("build");
        for d in [&pub_home, &sub_home, &build_dir] {
            fs::create_dir_all(d).unwrap();
        }

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = InMemoryArtifactStore::new();
        let cw_bin = build_macho_test_binary(&build_dir, "cw");
        let ci_bin = build_macho_test_binary(&build_dir, "ci");
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());

        let pub_cw = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &cw_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("aaaa1111aaaa1111".into(), 300)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        let pub_ci = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag-ci",
                source_binary_path: &ci_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("bbbb2222bbbb2222".into(), 300)),
            },
            &store,
            |_| Ok(2),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        // Corrupt `chinwag-ci` blob while keeping `chinwag` intact.
        store.tamper_blob(&pub_ci.manifest.artifact_key, b"corrupted".to_vec());

        let journal = temp.path().join("messages.jsonl");
        fs::write(
            &journal,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&pub_cw.release_built_message).unwrap(),
                serde_json::to_string(&pub_ci.release_built_message).unwrap()
            ),
        )
        .unwrap();

        let outcomes = sync_releases_from_journal_per_binary_inner(
            &sub_home,
            &journal,
            &store,
            Some("sub-ep"),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].binary, "chinwag");
        assert!(matches!(
            outcomes[0].outcome,
            Ok(ReleaseApplyOutcome::Installed {
                receipt_message: Some(_),
                ..
            })
        ));
        assert_eq!(outcomes[1].binary, "chinwag-ci");
        assert_eq!(
            outcomes[1].outcome.as_ref().unwrap_err(),
            &ReleaseSyncError::DigestMismatch
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn immutable_exec_pin_blocks_replacement_between_check_and_exec_and_on_reexec() {
        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let build_dir = temp.path().join("build");
        for d in [&pub_home, &sub_home, &build_dir] {
            fs::create_dir_all(d).unwrap();
        }

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = InMemoryArtifactStore::new();
        let good_bin = build_macho_test_binary(&build_dir, "good");
        let evil_bin = build_macho_test_binary(&build_dir, "evil");
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());

        let pub_good = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &good_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("cccccccc44444444".into(), 400)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        // 1A. Mutable `.staging` ancestor substitution between pre-smoke check and spawn:
        //     Build an attacker Mach-O binary that writes a sentinel file and exits 42 if executed!
        let sentinel_file = temp.path().join("evil_substitute_was_executed");
        let trap_src = build_dir.join("bin_trap.rs");
        let trap_bin = build_dir.join("bin_trap");
        fs::write(
            &trap_src,
            format!(
                "fn main() {{ let _ = std::fs::write({:?}, b\"pwned\"); std::process::exit(42); }}\n",
                sentinel_file
            ),
        )
        .unwrap();
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
        assert!(
            Command::new(&rustc)
                .arg(&trap_src)
                .arg("-O")
                .arg("-o")
                .arg(&trap_bin)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/usr/bin/codesign")
                .args(["-f", "-s", "-"])
                .arg(&trap_bin)
                .status()
                .unwrap()
                .success()
        );

        let displaced_staging = sub_home.join(".local/bin/.staging.displaced");
        let mut ancestor_hook_ran = false;
        let trap_for_ancestor = trap_bin.clone();
        let displaced_for_ancestor = displaced_staging.clone();
        let mut substitute_mutable_staging_ancestor = |_staged_path: &Path, op_dir: &Path| {
            ancestor_hook_ran = true;
            let staging_dir = op_dir.parent().unwrap().to_path_buf();
            let op_name = op_dir.file_name().unwrap().to_os_string();
            // Rename mutable `.staging` ancestor even though leaf `op_dir` and `chinwag` are `UF_IMMUTABLE`!
            fs::rename(&staging_dir, &displaced_for_ancestor).unwrap();
            let fake_op = staging_dir.join(op_name);
            fs::create_dir_all(&fake_op).unwrap();
            let fake_bin = fake_op.join("chinwag");
            fs::copy(&trap_for_ancestor, &fake_bin).unwrap();
            fs::set_permissions(&fake_bin, fs::Permissions::from_mode(0o755)).unwrap();
        };

        let ancestor_attack_res = apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_good.release_built_message,
            Some("sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            Some(&mut substitute_mutable_staging_ancestor),
        );
        assert!(ancestor_hook_ran);
        assert!(
            !sentinel_file.exists(),
            "smoke execution MUST anchor to verified op_dir_fd and NEVER execute substituted .staging/<op>/chinwag!"
        );
        assert_eq!(
            ancestor_attack_res.err(),
            Some(ReleaseSyncError::SafePathViolation("ancestor_inode_swap"))
        );
        // Clean up the attacker's fake `.staging` and displaced staging dir before 1B.
        let _ = fs::remove_dir_all(sub_home.join(".local/bin/.staging"));
        if let Ok(entries) = fs::read_dir(&displaced_staging) {
            for e in entries.flatten() {
                clear_and_remove_immutable_dir(&e.path());
            }
        }
        let _ = fs::remove_dir_all(&displaced_staging);

        // 1B. Leaf file + leaf `op_dir` direct replacement attempts during subscriber smoke test:
        let mut hook_ran = false;
        let evil_for_hook = evil_bin.clone();
        let mut attack_between_verify_and_exec = |staged_path: &Path, op_dir: &Path| {
            hook_ran = true;
            assert_eq!(
                fs::write(staged_path, b"evil").unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied,
                "UF_IMMUTABLE must reject overwrite between verification and smoke exec"
            );
            assert_eq!(
                fs::remove_file(staged_path).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied,
                "UF_IMMUTABLE must reject unlink between verification and smoke exec"
            );
            let same_fs_evil = op_dir.parent().unwrap().join("evil.swap");
            fs::copy(&evil_for_hook, &same_fs_evil).unwrap();
            assert_eq!(
                fs::rename(&same_fs_evil, staged_path).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied,
                "UF_IMMUTABLE must reject atomic rename replacement over staged binary"
            );
            let _ = fs::remove_file(&same_fs_evil);
            assert_eq!(
                fs::rename(op_dir, op_dir.with_extension("moved"))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::PermissionDenied,
                "UF_IMMUTABLE must reject renaming per-op staging directory"
            );
        };

        let applied = apply_release_built_message_inner(
            &sub_home,
            &store,
            &pub_good.release_built_message,
            Some("sub-ep"),
            &roots,
            Some(&infrajr_key),
            None,
            Some(&mut attack_between_verify_and_exec),
        )
        .unwrap();
        assert!(hook_ran);
        let ReleaseApplyOutcome::Installed { install_path, .. } = applied else {
            panic!("expected verified install to succeed after blocked replacement attempt");
        };
        let expected_sha = decode_lowercase_hex_32(&pub_good.manifest.sha256).unwrap();
        let (_, installed_sha, _) = compute_file_digests(&install_path).unwrap();
        assert_eq!(installed_sha, expected_sha);

        // 2. Daemon Reexec pinning: prepared copy rejects replacement attempts and pins `dir_fd`.
        let prepared =
            prepare_immutable_reexec_binary(&sub_home, &install_path, &expected_sha).unwrap();
        assert_eq!(
            fs::write(&prepared.binary_path, b"evil")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let same_fs_evil = prepared.dir_path.parent().unwrap().join("evil.reexec");
        fs::copy(&evil_bin, &same_fs_evil).unwrap();
        assert_eq!(
            fs::rename(&same_fs_evil, &prepared.binary_path)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let _ = fs::remove_file(&same_fs_evil);
        let (mut pinned_ro, pinned_stat) =
            open_regular_at_dir_nofollow(&prepared.dir_fd, "chinwag", true, true).unwrap();
        let (_, pinned_sha, _) = compute_digests_from_open_file(
            &mut pinned_ro,
            pinned_stat.len(),
            (pinned_stat.dev(), pinned_stat.ino()),
        )
        .unwrap();
        assert_eq!(pinned_sha, expected_sha);
        drop(pinned_ro);
        let dir_to_clean = prepared.dir_path.clone();
        drop(prepared);
        clear_and_remove_immutable_dir(&dir_to_clean);
        assert!(!dir_to_clean.exists());

        // 3. If an attacker replaces `~/.local/bin/chinwag` before `prepare_immutable_reexec_binary`,
        //    preparation fails closed with `DigestMismatch` and leaves `.staging` clean!
        fs::copy(&evil_bin, &install_path).unwrap();
        let rejected = prepare_immutable_reexec_binary(&sub_home, &install_path, &expected_sha);
        assert_eq!(rejected.err(), Some(ReleaseSyncError::DigestMismatch));
        assert!(
            fs::read_dir(sub_home.join(".local/bin/.staging"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn bounded_command_drains_large_pipe_output_without_blocking() {
        // Emit 512 KiB to stdout AND 512 KiB to stderr (8x larger than the 64 KiB OS pipe buffer).
        let mut ok_cmd = Command::new("/bin/sh");
        ok_cmd
            .args([
                "-c",
                "dd if=/dev/zero bs=1024 count=512 2>/dev/null; dd if=/dev/zero bs=1024 count=512 >&2 2>/dev/null",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        run_bounded_command(&mut ok_cmd, Duration::from_secs(5))
            .expect("large pipe output must drain concurrently without deadlocking");
        assert!(started.elapsed() < Duration::from_secs(4));

        // Also verify non-zero exit preserves the leading stderr diagnostic snippet.
        let mut fail_cmd = Command::new("/bin/sh");
        fail_cmd
            .args(["-c", "echo 'synthetic-r2-auth-error' >&2; exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let err_msg = run_bounded_command(&mut fail_cmd, Duration::from_secs(5)).unwrap_err();
        assert!(
            err_msg.contains("synthetic-r2-auth-error"),
            "got: {err_msg}"
        );
    }

    #[test]
    fn bounded_command_enforces_deadline_when_descendant_holds_pipe_open() {
        // Direct child `/bin/sh` exits 0 immediately while background `/bin/sleep 10`
        // inherits stdout/stderr pipes. Deadline MUST apply across pipe EOF and kill
        // the spawned process group instead of blocking on unconditional thread joins.
        let mut leak_cmd = Command::new("/bin/sh");
        leak_cmd
            .args(["-c", "/bin/sleep 10 & exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let err = run_bounded_command(&mut leak_cmd, Duration::from_millis(250))
            .expect_err("descendant holding pipe past deadline must time out");
        let elapsed = started.elapsed();
        assert!(
            err.contains("timed out"),
            "expected timeout error, got: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "pipe timeout must not wait 10s for descendant sleep (took {elapsed:?})"
        );
    }

    #[test]
    fn daemon_worker_enforces_eligibility_and_preserves_pending_retry_across_mismatch_and_replay() {
        struct PerKeyFaultStore {
            blobs: Mutex<BTreeMap<String, Vec<u8>>>,
            failing_keys: Mutex<std::collections::BTreeSet<String>>,
            per_key_downloads: Mutex<BTreeMap<String, usize>>,
        }

        impl PerKeyFaultStore {
            fn new() -> Self {
                Self {
                    blobs: Mutex::new(BTreeMap::new()),
                    failing_keys: Mutex::new(std::collections::BTreeSet::new()),
                    per_key_downloads: Mutex::new(BTreeMap::new()),
                }
            }

            fn set_failing(&self, key: &str, failing: bool) {
                let mut set = self.failing_keys.lock().unwrap();
                if failing {
                    set.insert(key.to_owned());
                } else {
                    set.remove(key);
                }
            }

            fn downloads_for(&self, key: &str) -> usize {
                self.per_key_downloads
                    .lock()
                    .unwrap()
                    .get(key)
                    .copied()
                    .unwrap_or(0)
            }
        }

        impl ReleaseArtifactStore for PerKeyFaultStore {
            fn upload_artifact(
                &self,
                artifact_key: &str,
                source_file: &File,
            ) -> Result<(), ReleaseSyncError> {
                validate_artifact_key_structure(artifact_key)?;
                let bytes = read_all_from_pinned_fd(source_file)?;
                self.blobs
                    .lock()
                    .unwrap()
                    .insert(artifact_key.to_owned(), bytes);
                Ok(())
            }

            fn download_artifact(
                &self,
                artifact_key: &str,
                destination_file: &Path,
            ) -> Result<(), ReleaseSyncError> {
                *self
                    .per_key_downloads
                    .lock()
                    .unwrap()
                    .entry(artifact_key.to_owned())
                    .or_insert(0) += 1;
                if self.failing_keys.lock().unwrap().contains(artifact_key) {
                    return Err(ReleaseSyncError::ArtifactStoreFailed(
                        "transient_r2_503".into(),
                    ));
                }
                let bytes = self
                    .blobs
                    .lock()
                    .unwrap()
                    .get(artifact_key)
                    .cloned()
                    .ok_or_else(|| ReleaseSyncError::ArtifactStoreFailed("missing_blob".into()))?;
                fs::write(destination_file, bytes)
                    .map_err(|e| ReleaseSyncError::ArtifactStoreFailed(e.to_string()))
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let build_dir = temp.path().join("build");
        for d in [&pub_home, &sub_home, &build_dir] {
            fs::create_dir_all(d).unwrap();
        }
        let journal = temp.path().join("messages.jsonl");

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = PerKeyFaultStore::new();
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());
        let actor = ActorAddress::parse(&actor_str).unwrap();

        let ci_a_bin = build_macho_test_binary(&build_dir, "ci_a");
        let ci_b_bin = build_macho_test_binary(&build_dir, "ci_b");
        let ci_c_bin = build_macho_test_binary(&build_dir, "ci_c");
        let cw_1_bin = build_macho_test_binary(&build_dir, "cw_1");

        // Publish `chinwag-ci` A (epoch 100) and install it cleanly on subscriber via LiveMessage.
        let pub_ci_a = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag-ci",
                source_binary_path: &ci_a_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("aaaa1111aaaa1111".into(), 100)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        let sched = Mutex::new(ReleaseDaemonScheduler::default());
        let mut now = Instant::now();

        let ev_a = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(pub_ci_a.release_built_message.clone())),
            &mut || now,
        );
        assert!(matches!(
            ev_a.as_slice(),
            [ReleaseDaemonEvent::Applied { outcome, .. }]
                if matches!(**outcome, ReleaseApplyOutcome::Installed { .. })
        ));
        assert_eq!(store.downloads_for(&pub_ci_a.manifest.artifact_key), 1);

        // Publish `chinwag-ci` B (epoch 200), write A + B to journal, and inject transient R2 failure on B.
        let pub_ci_b = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag-ci",
                source_binary_path: &ci_b_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("bbbb2222bbbb2222".into(), 200)),
            },
            &store,
            |_| Ok(2),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        store.set_failing(&pub_ci_b.manifest.artifact_key, true);
        fs::write(
            &journal,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&pub_ci_a.release_built_message).unwrap(),
                serde_json::to_string(&pub_ci_b.release_built_message).unwrap(),
            ),
        )
        .unwrap();

        // Attempt 1 on B via LiveMessage fails -> schedules 10s retry.
        let ev_b1 = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(pub_ci_b.release_built_message.clone())),
            &mut || now,
        );
        assert!(matches!(
            ev_b1.as_slice(),
            [ReleaseDaemonEvent::Rejected {
                retryable: true,
                next_retry_secs: Some(10),
                ..
            }]
        ));
        assert_eq!(store.downloads_for(&pub_ci_b.manifest.artifact_key), 1);

        // [P2 #3a] Foreign-target (`x86_64-pc-windows-msvc` / non-local target) release for `chinwag-ci`
        // returns `SkippedTargetMismatch` and MUST preserve B's pending retry!
        let foreign_target = if CURRENT_TARGET_TRIPLE == "aarch64-apple-darwin" {
            "x86_64-apple-darwin"
        } else {
            "aarch64-apple-darwin"
        };
        let foreign_sha = "dd".repeat(32);
        let foreign_manifest = ReleaseManifestV1 {
            schema: RELEASE_MANIFEST_SCHEMA.to_owned(),
            binary: "chinwag-ci".to_owned(),
            target_triple: foreign_target.to_owned(),
            git_commit: "dddd4444dddd4444".to_owned(),
            commit_epoch: 250,
            built_at_ms: pub_ci_b.manifest.built_at_ms + 500,
            sha256: foreign_sha.clone(),
            blake3: "ee".repeat(32),
            size_bytes: 4096,
            artifact_key: expected_artifact_key("chinwag-ci", foreign_target, &foreign_sha),
            rollback: false,
        };
        let foreign_msg = sign_structured_bus_message(
            &actor,
            "#all",
            Some("CHWG-0261".to_owned()),
            format!(
                "{RELEASE_BUILT_PREFIX}{}",
                serde_json::to_string(&foreign_manifest).unwrap()
            ),
            &infrajr_key,
        );
        let t_foreign = now + Duration::from_secs(1);
        let ev_foreign = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(foreign_msg)),
            &mut || t_foreign,
        );
        assert!(matches!(
            ev_foreign.as_slice(),
            [ReleaseDaemonEvent::Applied { outcome, .. }]
                if matches!(**outcome, ReleaseApplyOutcome::SkippedTargetMismatch { .. })
        ));
        assert!(
            sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(now + Duration::from_secs(10)),
            "SkippedTargetMismatch must NOT erase local-target release B's pending retry"
        );

        // [P2 #3b] Authenticated replay of currently installed release A returns `AlreadyInstalled`
        // (with 0 extra R2 downloads) and MUST ALSO preserve newer release B's pending retry!
        let t_replay_a = now + Duration::from_secs(2);
        let ev_replay_a = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(pub_ci_a.release_built_message.clone())),
            &mut || t_replay_a,
        );
        assert!(matches!(
            ev_replay_a.as_slice(),
            [ReleaseDaemonEvent::Applied { outcome, .. }]
                if matches!(**outcome, ReleaseApplyOutcome::AlreadyInstalled { .. })
        ));
        assert_eq!(store.downloads_for(&pub_ci_a.manifest.artifact_key), 1);
        assert!(
            sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(now + Duration::from_secs(10)),
            "Replay of older AlreadyInstalled release A must NOT erase newer release B's pending retry"
        );

        // [P2 #2] Duplicate LiveMessage replay of B during its 10s backoff is suppressed (0 extra downloads)!
        let t_dup_b = now + Duration::from_secs(3);
        let ev_dup_b = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(pub_ci_b.release_built_message.clone())),
            &mut || t_dup_b,
        );
        assert!(matches!(
            ev_dup_b.as_slice(),
            [ReleaseDaemonEvent::Suppressed {
                reason: "backoff_active",
                ..
            }]
        ));
        assert_eq!(store.downloads_for(&pub_ci_b.manifest.artifact_key), 1);

        // Exhaust B's 12 scheduled retries via StartupCatchup (1 initial + 12 retries = 13 total downloads).
        let remaining_delays = [10u64, 20, 40, 80, 160, 300, 300, 300, 300, 300, 300, 300];
        for delay_secs in remaining_delays {
            now += Duration::from_secs(delay_secs);
            assert!(sched.lock().unwrap().should_dispatch_catchup(now));
            let tick = now;
            let _ = execute_release_daemon_job_inner(
                &sub_home,
                &journal,
                &store,
                "sub-ep",
                &roots,
                Some(&infrajr_key),
                &sched,
                ReleaseDaemonJob::StartupCatchup,
                &mut || tick,
            );
        }
        let b_downloads_at_exhaustion = store.downloads_for(&pub_ci_b.manifest.artifact_key);
        assert_eq!(b_downloads_at_exhaustion, 13);
        assert!(
            !sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(now + Duration::from_secs(3600))
        );

        // [P2 #2] LiveMessage replay of exhausted B is suppressed with 0 R2 downloads!
        let t_exhausted = now + Duration::from_secs(30);
        let ev_exhausted_live = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(pub_ci_b.release_built_message.clone())),
            &mut || t_exhausted,
        );
        assert!(matches!(
            ev_exhausted_live.as_slice(),
            [ReleaseDaemonEvent::Suppressed {
                reason: "retry_budget_exhausted",
                ..
            }]
        ));
        assert_eq!(
            store.downloads_for(&pub_ci_b.manifest.artifact_key),
            b_downloads_at_exhaustion
        );

        // [P2 #2] Now publish a failing `chinwag` release `CW_1` into the journal:
        // When `CW_1` triggers `StartupCatchup` at `now + 10s`, exhausted `chinwag-ci` B
        // MUST NOT be downloaded again!
        let pub_cw_1 = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &cw_1_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("1111cccc1111cccc".into(), 220)),
            },
            &store,
            |_| Ok(3),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        store.set_failing(&pub_cw_1.manifest.artifact_key, true);
        fs::write(
            &journal,
            format!(
                "{}\n{}\n{}\n",
                serde_json::to_string(&pub_ci_a.release_built_message).unwrap(),
                serde_json::to_string(&pub_ci_b.release_built_message).unwrap(),
                serde_json::to_string(&pub_cw_1.release_built_message).unwrap(),
            ),
        )
        .unwrap();

        let tick_cw_1 = now;
        let _ = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(pub_cw_1.release_built_message.clone())),
            &mut || tick_cw_1,
        );
        assert_eq!(store.downloads_for(&pub_cw_1.manifest.artifact_key), 1);

        // Advance 10s -> `CW_1` is due (and advances to 20s backoff), while exhausted `B` gets ZERO downloads!
        now += Duration::from_secs(10);
        let tick_cw_1_retry = now;
        let _ = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::StartupCatchup,
            &mut || tick_cw_1_retry,
        );
        assert_eq!(store.downloads_for(&pub_cw_1.manifest.artifact_key), 2);
        assert_eq!(
            store.downloads_for(&pub_ci_b.manifest.artifact_key),
            b_downloads_at_exhaustion,
            "StartupCatchup for chinwag MUST NOT re-download exhausted chinwag-ci release B!"
        );

        // [P2 #2] Also verify early-backoff isolation: `CW_1` is now in a 20s backoff (`due = now + 20s`).
        // Publish a genuinely NEW `chinwag-ci` release `C` (epoch 300) that fails with a 10s backoff (`due = now + 10s`).
        // At `now + 10s`, `StartupCatchup` MUST retry ONLY `C` and NOT `CW_1` early!
        let pub_ci_c = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag-ci",
                source_binary_path: &ci_c_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("cccc3333cccc3333".into(), 300)),
            },
            &store,
            |_| Ok(4),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        store.set_failing(&pub_ci_c.manifest.artifact_key, true);
        fs::write(
            &journal,
            format!(
                "{}\n{}\n{}\n{}\n",
                serde_json::to_string(&pub_ci_a.release_built_message).unwrap(),
                serde_json::to_string(&pub_ci_b.release_built_message).unwrap(),
                serde_json::to_string(&pub_cw_1.release_built_message).unwrap(),
                serde_json::to_string(&pub_ci_c.release_built_message).unwrap(),
            ),
        )
        .unwrap();
        let tick_ci_c = now;
        let _ = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(pub_ci_c.release_built_message.clone())),
            &mut || tick_ci_c,
        );
        assert_eq!(store.downloads_for(&pub_ci_c.manifest.artifact_key), 1);

        // Heal R2 for `C` and `CW_1`; at `now + 10s`, ONLY `C` is due (`CW_1` due at `now + 20s`).
        store.set_failing(&pub_ci_c.manifest.artifact_key, false);
        store.set_failing(&pub_cw_1.manifest.artifact_key, false);

        let tick_plus_10 = now + Duration::from_secs(10);
        let events_at_10s = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::StartupCatchup,
            &mut || tick_plus_10,
        );
        assert_eq!(events_at_10s.len(), 1);
        assert_eq!(store.downloads_for(&pub_ci_c.manifest.artifact_key), 2);
        assert_eq!(
            store.downloads_for(&pub_cw_1.manifest.artifact_key),
            2,
            "CW_1 in 20s backoff MUST NOT be retried early at +10s!"
        );

        // At `now + 20s`, `CW_1`'s backoff matures and `StartupCatchup` installs `CW_1` cleanly!
        let tick_plus_20 = now + Duration::from_secs(20);
        let events_at_20s = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::StartupCatchup,
            &mut || tick_plus_20,
        );
        assert_eq!(events_at_20s.len(), 1);
        assert_eq!(store.downloads_for(&pub_cw_1.manifest.artifact_key), 3);
        assert!(
            !sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(now + Duration::from_secs(600))
        );
    }

    #[test]
    fn scheduler_mutex_not_held_while_local_satisfaction_waits_on_sync_flock() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let build_dir = temp.path().join("build");
        for d in [&pub_home, &sub_home, &build_dir] {
            fs::create_dir_all(d).unwrap();
        }
        let journal = temp.path().join("messages.jsonl");

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = InMemoryArtifactStore::new();
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());

        let ci_a_bin = build_macho_test_binary(&build_dir, "flock_a");
        let ci_b_bin = build_macho_test_binary(&build_dir, "flock_b");

        let pub_ci_a = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag-ci",
                source_binary_path: &ci_a_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("aaaa1000aaaa1000".into(), 100)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        let pub_ci_b = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag-ci",
                source_binary_path: &ci_b_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("bbbb2000bbbb2000".into(), 200)),
            },
            &store,
            |_| Ok(2),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        // Remove B's blob so B fails transiently and enters `per_binary` retry state.
        store
            .blobs
            .lock()
            .unwrap()
            .remove(&pub_ci_b.manifest.artifact_key);

        let sched = Mutex::new(ReleaseDaemonScheduler::default());
        let t0 = Instant::now();

        // Install A cleanly, then fail B so `sched` holds newer pending release B.
        let _ = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(pub_ci_a.release_built_message.clone())),
            &mut || t0,
        );
        let _ = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(pub_ci_b.release_built_message.clone())),
            &mut || t0,
        );
        assert!(
            sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(t0 + Duration::from_secs(10))
        );

        // Hold subscriber's cross-process release-sync flock on the main thread!
        let held_flock = acquire_release_sync_lock(&sub_home).unwrap();
        let worker_entered = AtomicBool::new(false);
        let worker_done = AtomicBool::new(false);

        std::thread::scope(|s| {
            let handle = s.spawn(|| {
                worker_entered.store(true, Ordering::SeqCst);
                let res = execute_release_daemon_job_inner(
                    &sub_home,
                    &journal,
                    &store,
                    "sub-ep",
                    &roots,
                    Some(&infrajr_key),
                    &sched,
                    ReleaseDaemonJob::LiveMessage(Box::new(pub_ci_a.release_built_message.clone())),
                    &mut || t0 + Duration::from_secs(1),
                );
                worker_done.store(true, Ordering::SeqCst);
                res
            });

            while !worker_entered.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            // Give the worker time to pass `precheck_live_eligibility` and block on `held_flock`
            // inside `is_manifest_already_satisfied_locally`.
            std::thread::sleep(Duration::from_millis(40));
            assert!(
                !worker_done.load(Ordering::SeqCst),
                "worker must be blocked waiting on held release-sync flock"
            );
            for _ in 0..10 {
                assert!(
                    sched.try_lock().is_ok(),
                    "scheduler mutex MUST NOT be held while worker waits on filesystem/flock I/O!"
                );
                std::thread::sleep(Duration::from_millis(5));
            }

            drop(held_flock);
            let ev = handle.join().unwrap();
            assert!(matches!(
                ev.as_slice(),
                [ReleaseDaemonEvent::Applied { outcome, .. }]
                    if matches!(**outcome, ReleaseApplyOutcome::AlreadyInstalled { .. })
            ));
        });

        assert!(
            sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(t0 + Duration::from_secs(10)),
            "newer release B's pending retry must still be preserved"
        );
    }

    #[test]
    fn wrangler_upload_streams_pinned_fd_via_pipe_even_under_staging_displacement() {
        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let build_dir = temp.path().join("build");
        let capture_dir = temp.path().join("capture");
        for d in [&pub_home, &build_dir, &capture_dir] {
            fs::create_dir_all(d).unwrap();
        }

        let captured_args = capture_dir.join("args.txt");
        let captured_body = capture_dir.join("stdin.bin");
        let mock_wrangler = capture_dir.join("mock-wrangler.sh");
        // Mock wrangler simulates an adversary renaming `$HOME/.local/bin/.staging` aside
        // and planting decoy bytes at the original `.staging/<op_dir>/chinwag` pathname
        // BEFORE draining `stdin`, then restoring `.staging` after reading `stdin`.
        let script = format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > \"{}\"\n\
             STAGING=\"$HOME/.local/bin/.staging\"\n\
             DISPLACED=\"$HOME/.local/bin/.staging.displaced\"\n\
             mv \"$STAGING\" \"$DISPLACED\"\n\
             mkdir -p \"$STAGING\"\n\
             for d in \"$DISPLACED\"/*; do\n\
               base=$(basename \"$d\")\n\
               mkdir -p \"$STAGING/$base\"\n\
               printf 'DECOY-ATTACKER-PAYLOAD' > \"$STAGING/$base/chinwag\"\n\
             done\n\
             cat > \"{}\"\n\
             rm -rf \"$STAGING\"\n\
             mv \"$DISPLACED\" \"$STAGING\"\n",
            captured_args.display(),
            captured_body.display()
        );
        fs::write(&mock_wrangler, script).unwrap();
        fs::set_permissions(&mock_wrangler, fs::Permissions::from_mode(0o755)).unwrap();

        let store = WranglerR2ArtifactStore::with_wrangler_bin(pub_home.clone(), mock_wrangler);
        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let src_bin = build_macho_test_binary(&build_dir, "pipe_upload_v1");
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());

        let outcome = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &src_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("cafebabecafebabe".into(), 500)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();

        let args_text = fs::read_to_string(&captured_args).unwrap();
        let args_lines: Vec<&str> = args_text.lines().collect();
        assert!(
            args_lines.contains(&"--pipe"),
            "wrangler upload MUST pass --pipe, got: {args_lines:?}"
        );
        assert!(
            !args_lines.contains(&"--file"),
            "wrangler upload MUST NOT pass --file, got: {args_lines:?}"
        );
        assert!(
            !args_text.contains(".staging"),
            "wrangler upload argv MUST NOT expose any .staging pathname, got: {args_lines:?}"
        );

        let uploaded_bytes = fs::read(&captured_body).unwrap();
        assert_ne!(uploaded_bytes, b"DECOY-ATTACKER-PAYLOAD");
        assert_eq!(uploaded_bytes.len() as u64, outcome.manifest.size_bytes);
        assert_eq!(
            encode_hex(&compute_sha256_bytes(&uploaded_bytes)),
            outcome.manifest.sha256,
            "uploaded R2 stream must match exact verified descriptor digest despite .staging swap"
        );
        assert_eq!(
            encode_hex(&compute_blake3_bytes(&uploaded_bytes)),
            outcome.manifest.blake3
        );
    }

    #[test]
    fn retry_backoff_measured_from_failure_completion_not_job_start() {
        struct SlowTimeoutStore {
            blobs: Mutex<BTreeMap<String, Vec<u8>>>,
            clock: std::sync::Arc<Mutex<Instant>>,
            timeout_duration: Duration,
        }

        impl ReleaseArtifactStore for SlowTimeoutStore {
            fn upload_artifact(
                &self,
                artifact_key: &str,
                source_file: &File,
            ) -> Result<(), ReleaseSyncError> {
                validate_artifact_key_structure(artifact_key)?;
                let bytes = read_all_from_pinned_fd(source_file)?;
                self.blobs
                    .lock()
                    .unwrap()
                    .insert(artifact_key.to_owned(), bytes);
                Ok(())
            }

            fn download_artifact(
                &self,
                _artifact_key: &str,
                _destination_file: &Path,
            ) -> Result<(), ReleaseSyncError> {
                *self.clock.lock().unwrap() += self.timeout_duration;
                Err(ReleaseSyncError::ArtifactStoreFailed(
                    "wrangler r2 timed out after 120s".into(),
                ))
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let build_dir = temp.path().join("build");
        for d in [&pub_home, &sub_home, &build_dir] {
            fs::create_dir_all(d).unwrap();
        }
        let journal = temp.path().join("messages.jsonl");

        let t0 = Instant::now();
        let shared_clock = std::sync::Arc::new(Mutex::new(t0));
        let store = SlowTimeoutStore {
            blobs: Mutex::new(BTreeMap::new()),
            clock: std::sync::Arc::clone(&shared_clock),
            timeout_duration: Duration::from_secs(120),
        };

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let src_bin = build_macho_test_binary(&build_dir, "slow_r2_v1");
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());

        let pub_v1 = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag-ci",
                source_binary_path: &src_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("9999000099990000".into(), 900)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        fs::write(
            &journal,
            format!(
                "{}\n",
                serde_json::to_string(&pub_v1.release_built_message).unwrap()
            ),
        )
        .unwrap();

        let sched = Mutex::new(ReleaseDaemonScheduler::default());
        // Clear initial_catchup_pending first so `should_dispatch_catchup` reflects retry schedule only.
        sched.lock().unwrap().initial_catchup_pending = false;

        // 1. LiveMessage starts at `t0`, spends 120s in `download_artifact` (`t0 + 120s`), and fails.
        //    10s retry #1 MUST be scheduled at `(t0 + 120s) + 10s = t0 + 130s`, NOT `t0 + 10s`!
        let ev1 = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(pub_v1.release_built_message.clone())),
            &mut || *shared_clock.lock().unwrap(),
        );
        assert!(matches!(
            ev1.as_slice(),
            [ReleaseDaemonEvent::Rejected {
                retryable: true,
                next_retry_secs: Some(10),
                ..
            }]
        ));
        assert_eq!(*shared_clock.lock().unwrap(), t0 + Duration::from_secs(120));
        assert!(
            !sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(t0 + Duration::from_secs(129)),
            "10s backoff after a 120s timeout must NOT fire before t0 + 130s!"
        );
        assert!(
            sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(t0 + Duration::from_secs(130)),
            "10s backoff after a 120s timeout MUST fire at t0 + 130s"
        );

        // 2. StartupCatchup starts at `t0 + 130s`, spends another 120s (`t0 + 250s`), and fails.
        //    20s retry #2 MUST be scheduled at `(t0 + 250s) + 20s = t0 + 270s`!
        *shared_clock.lock().unwrap() = t0 + Duration::from_secs(130);
        let ev2 = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::StartupCatchup,
            &mut || *shared_clock.lock().unwrap(),
        );
        assert!(matches!(
            ev2.as_slice(),
            [ReleaseDaemonEvent::Rejected {
                retryable: true,
                next_retry_secs: Some(20),
                ..
            }]
        ));
        assert_eq!(*shared_clock.lock().unwrap(), t0 + Duration::from_secs(250));
        assert!(
            !sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(t0 + Duration::from_secs(269))
        );
        assert!(
            sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(t0 + Duration::from_secs(270))
        );
    }

    #[test]
    fn cleanup_stale_reexec_dirs_reclaims_dead_pid_publisher_and_installer_immutable_dirs() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let (_, staging_dir) = ensure_bin_and_staging_dirs(&home).unwrap();

        // Spawn and reap a short-lived process to obtain a guaranteed-dead PID.
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let dead_pid = child.id();
        let _ = child.wait().unwrap();
        let dead_rustix_pid = rustix::process::Pid::from_raw(dead_pid as i32).unwrap();
        assert_eq!(
            rustix::process::test_kill_process(dead_rustix_pid),
            Err(rustix::io::Errno::SRCH)
        );

        let self_pid = std::process::id();
        let dead_names = [
            format!("op.{dead_pid}.pub.1111111111111111"),
            format!("op.pub.{dead_pid}.2222222222222222"),
            format!("op.{dead_pid}.3333333333333333"),
            format!("reexec.{dead_pid}.4444444444444444"),
        ];
        let live_name = format!("op.{self_pid}.pub.5555555555555555");

        for dir_name in dead_names.iter().chain(std::iter::once(&live_name)) {
            let dir_path = staging_dir.join(dir_name);
            fs::create_dir(&dir_path).unwrap();
            fs::write(dir_path.join("chinwag"), b"immutable-staged-bytes").unwrap();
            let (dir_fd, _) = open_dir_nofollow(&dir_path).unwrap();
            set_dir_and_entry_immutable(&dir_fd, "chinwag", true).unwrap();
        }

        cleanup_stale_reexec_dirs(&home);

        for dead_name in &dead_names {
            assert!(
                !staging_dir.join(dead_name).exists(),
                "dead-PID immutable staging dir '{dead_name}' MUST be unlocked and reclaimed"
            );
        }

        let live_dir = staging_dir.join(&live_name);
        assert!(
            live_dir.join("chinwag").is_file(),
            "live-PID publisher staging dir MUST remain untouched"
        );
        // Unlock live_dir before TempDir drops so cleanup succeeds cleanly on macOS.
        if let Ok((live_fd, _)) = open_dir_nofollow(&live_dir) {
            let _ = set_dir_and_entry_immutable(&live_fd, "chinwag", false);
        }
    }

    #[test]
    fn transient_journal_io_retries_and_recovers_while_unsafe_path_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let build_dir = temp.path().join("build");
        for d in [&pub_home, &sub_home, &build_dir] {
            fs::create_dir_all(d).unwrap();
        }
        let journal = temp.path().join("messages.jsonl");

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = InMemoryArtifactStore::new();
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());
        let src_bin = build_macho_test_binary(&build_dir, "journal_retry_v1");

        let published = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag-ci",
                source_binary_path: &src_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("1234567812345678".into(), 600)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        fs::write(
            &journal,
            format!(
                "{}\n",
                serde_json::to_string(&published.release_built_message).unwrap()
            ),
        )
        .unwrap();

        let sched = Mutex::new(ReleaseDaemonScheduler::new_with_initial_catchup());
        let t0 = Instant::now();

        // Verify `new_with_initial_catchup` dispatches cleanly on first poll (`FLINT` R5 check)
        // and does not double-enqueue while queued.
        assert!(sched.lock().unwrap().poll_catchup_dispatch(false, t0));
        assert!(!sched.lock().unwrap().poll_catchup_dispatch(false, t0));

        // 1. Inject one transient `EMFILE` journal-open failure through `classify_journal_io_error`.
        let mut injected_emfile_once = false;
        let ev1 = execute_release_daemon_job_with_hooks(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::StartupCatchup,
            &mut || t0,
            &mut |path| {
                if !injected_emfile_once {
                    injected_emfile_once = true;
                    let io_err = std::io::Error::from(rustix::io::Errno::MFILE);
                    return Err(classify_journal_io_error("journal open failed", &io_err));
                }
                open_regular_journal_if_present(path)
            },
        );
        assert!(matches!(
            ev1.as_slice(),
            [ReleaseDaemonEvent::Rejected {
                binary,
                retryable: true,
                next_retry_secs: Some(10),
                ..
            }] if binary == "all"
        ));
        assert!(
            !sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(t0 + Duration::from_secs(9))
        );
        assert!(
            sched
                .lock()
                .unwrap()
                .poll_catchup_dispatch(false, t0 + Duration::from_secs(10)),
            "healthy heartbeat at +10s MUST dispatch scheduled journal retry"
        );

        // 2. Retry at `t0 + 10s` succeeds against the real journal and installs `chinwag-ci`.
        let t_retry = t0 + Duration::from_secs(10);
        let ev2 = execute_release_daemon_job_with_hooks(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::StartupCatchup,
            &mut || t_retry,
            &mut open_regular_journal_if_present,
        );
        assert!(matches!(
            ev2.as_slice(),
            [ReleaseDaemonEvent::Applied { outcome, .. }]
                if matches!(**outcome, ReleaseApplyOutcome::Installed { .. })
        ));
        assert!(
            !sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(t0 + Duration::from_secs(600))
        );

        // 3. Unsafe symlinked journal path MUST fail closed (`retryable: false`, `next_retry_secs: None`)!
        let symlink_journal = temp.path().join("symlink_messages.jsonl");
        std::os::unix::fs::symlink(&journal, &symlink_journal).unwrap();
        assert!(
            sched
                .lock()
                .unwrap()
                .poll_catchup_dispatch(true, t0 + Duration::from_secs(20))
        );
        let t_sym = t0 + Duration::from_secs(20);
        let ev_sym = execute_release_daemon_job_inner(
            &sub_home,
            &symlink_journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::StartupCatchup,
            &mut || t_sym,
        );
        assert!(matches!(
            ev_sym.as_slice(),
            [ReleaseDaemonEvent::Rejected {
                retryable: false,
                next_retry_secs: None,
                ..
            }]
        ));
        assert!(
            !sched
                .lock()
                .unwrap()
                .should_dispatch_catchup(t0 + Duration::from_secs(3600)),
            "unsafe symlinked journal path must fail closed without scheduling retries"
        );
    }

    #[test]
    fn transient_state_persistence_failure_after_binary_replacement_retries_and_recovers() {
        let temp = tempfile::tempdir().unwrap();
        let pub_home = temp.path().join("pub-home");
        let sub_home = temp.path().join("sub-home");
        let build_dir = temp.path().join("build");
        for d in [&pub_home, &sub_home, &build_dir] {
            fs::create_dir_all(d).unwrap();
        }
        let journal = temp.path().join("messages.jsonl");

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = InMemoryArtifactStore::new();
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());
        let src_bin = build_macho_test_binary(&build_dir, "state_retry_chinwag_v1");

        let published = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &pub_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &src_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("abcdef0123456789".into(), 700)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        fs::write(
            &journal,
            format!(
                "{}\n",
                serde_json::to_string(&published.release_built_message).unwrap()
            ),
        )
        .unwrap();

        let sched = Mutex::new(ReleaseDaemonScheduler::default());
        let t0 = Instant::now();

        // 1. Inject a one-shot `EMFILE` inside `save_release_sync_state` AFTER
        //    `atomic_install_staged_binary` has already replaced `~/.local/bin/chinwag`!
        let emfile_errno = rustix::io::Errno::MFILE.raw_os_error();
        TEST_INJECTED_SAVE_STATE_ERRNO.with(|c| c.set(Some(emfile_errno)));

        let ev1 = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::LiveMessage(Box::new(published.release_built_message.clone())),
            &mut || t0,
        );
        assert!(
            matches!(
                ev1.as_slice(),
                [ReleaseDaemonEvent::Rejected {
                    binary,
                    retryable: true,
                    next_retry_secs: Some(10),
                    ..
                }] if binary == "chinwag"
            ),
            "post-install EMFILE during state save MUST be retryable (`next_retry_secs: Some(10)`), got {ev1:?}"
        );
        // Binary on disk was already replaced, while `release_sync_state.json` was not persisted yet.
        let expected_sha = decode_lowercase_hex_32(&published.manifest.sha256).unwrap();
        assert_eq!(
            local_binary_sha256(&sub_home.join(".local/bin/chinwag")),
            Some(expected_sha)
        );
        assert!(!release_sync_state_path(&sub_home).exists());

        // 2. Scheduler dispatches retry at `t0 + 10s`, persists state, and emits `Applied { Installed }`
        //    with a signed `#ops` receipt so the daemon arms `pending_reexec` cleanly!
        assert!(
            sched
                .lock()
                .unwrap()
                .poll_catchup_dispatch(false, t0 + Duration::from_secs(10))
        );
        let t_retry = t0 + Duration::from_secs(10);
        let ev2 = execute_release_daemon_job_inner(
            &sub_home,
            &journal,
            &store,
            "sub-ep",
            &roots,
            Some(&infrajr_key),
            &sched,
            ReleaseDaemonJob::StartupCatchup,
            &mut || t_retry,
        );
        match ev2.as_slice() {
            [ReleaseDaemonEvent::Applied { binary, outcome }] => {
                assert_eq!(binary, "chinwag");
                match outcome.as_ref() {
                    ReleaseApplyOutcome::Installed {
                        manifest,
                        receipt_message,
                        ..
                    } => {
                        assert_eq!(manifest.sha256, published.manifest.sha256);
                        assert!(
                            receipt_message.is_some(),
                            "recovery install MUST emit signed #ops receipt"
                        );
                    }
                    other => {
                        panic!("expected Installed on post-rename state recovery, got {other:?}")
                    }
                }
            }
            other => panic!("expected Applied event on retry recovery, got {other:?}"),
        }
        let persisted = load_release_sync_state(&sub_home).unwrap();
        assert_eq!(
            persisted.binaries["chinwag"].sha256,
            published.manifest.sha256
        );
    }

    #[test]
    fn concurrent_publisher_post_install_pre_publication_window_refreshes_and_pins_reexec_under_lock()
     {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let shared_home = temp.path().join("shared-home");
        let build_dir = temp.path().join("build");
        fs::create_dir_all(&shared_home).unwrap();
        fs::create_dir_all(&build_dir).unwrap();

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = Arc::new(InMemoryArtifactStore::new());
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());

        let src_a = build_macho_test_binary(&build_dir, "concurrent_pub_a");
        let src_b = build_macho_test_binary(&build_dir, "concurrent_pub_b");

        // 1. Daemon / initial publisher installs release A in `shared_home` and retains `sha_a`.
        let pub_a = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &shared_home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &src_a,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("1111111111111111".into(), 100)),
            },
            store.as_ref(),
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        let sha_a = decode_lowercase_hex_32(&pub_a.manifest.sha256).unwrap();

        // 2. Spawn a concurrent `chinwag release publish` for release B sharing `shared_home`,
        //    and pause it inside `publish_bus` (simulating the post-install, pre-publication
        //    window while crate-memory sync runs BEFORE B's bus message exists)!
        let entered_pre_pub = Arc::new(Barrier::new(2));
        let allow_finish_pub = Arc::new(Barrier::new(2));
        let entered_clone = entered_pre_pub.clone();
        let finish_clone = allow_finish_pub.clone();
        let home_for_pub = shared_home.clone();
        let build_for_pub = build_dir.clone();
        let src_b_for_pub = src_b.clone();
        let actor_for_pub = actor_str.clone();
        let store_for_pub = store.clone();
        let key_for_pub = infrajr_key.clone();

        let pub_b_handle = std::thread::spawn(move || {
            let local_table = [("INFRAJR", key_for_pub.verifying_key().to_bytes())];
            let local_roots = ReleaseTrustRoots {
                seat_pubkeys: &local_table,
                allowed_signers: ALLOWED_RELEASE_SIGNERS,
            };
            publish_release_inner(
                PublishReleaseRequest {
                    home_dir: &home_for_pub,
                    repo_root: &build_for_pub,
                    binary: "chinwag",
                    source_binary_path: &src_b_for_pub,
                    explicit_from: Some(&actor_for_pub),
                    rollback: false,
                    commit_override: Some(("2222222222222222".into(), 200)),
                },
                store_for_pub.as_ref(),
                |_| {
                    entered_clone.wait();
                    finish_clone.wait();
                    Ok(2)
                },
                &local_roots,
                Some(&key_for_pub),
            )
            .unwrap()
        });

        // Wait until concurrent publisher B has replaced `~/.local/bin/chinwag` under lock
        // and entered its pre-publication window (before B's bus message is published!).
        entered_pre_pub.wait();

        // 3. Daemon prepares re-exec while still holding stale `sha_a` from its own event loop:
        //    `prepare_immutable_reexec_binary` MUST refresh under `release_sync.lock` to `B`
        //    and pin an immutable `UF_IMMUTABLE` executable snapshot of `B` with zero `DigestMismatch`!
        let install_path = shared_home.join(".local/bin/chinwag");
        let prepared =
            prepare_immutable_reexec_binary(&shared_home, &install_path, &sha_a).unwrap();

        allow_finish_pub.wait();
        let pub_b = pub_b_handle.join().unwrap();
        let sha_b = decode_lowercase_hex_32(&pub_b.manifest.sha256).unwrap();
        assert_ne!(sha_a, sha_b);
        assert_eq!(
            prepared.sha256, sha_b,
            "re-exec preparation under lock MUST refresh to concurrent publisher B's verified digest"
        );
        assert_eq!(
            local_binary_sha256(&prepared.binary_path),
            Some(sha_b),
            "pinned immutable re-exec binary must match release B byte-for-byte"
        );
        cleanup_prepared_reexec(prepared);
    }

    #[test]
    fn prepare_reexec_lock_contention_and_transient_helper_errors_are_nonblocking_and_retryable() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let build_dir = temp.path().join("build");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&build_dir).unwrap();

        let infrajr_key = random_signing_key();
        let seat_table = [("INFRAJR", infrajr_key.verifying_key().to_bytes())];
        let roots = ReleaseTrustRoots {
            seat_pubkeys: &seat_table,
            allowed_signers: ALLOWED_RELEASE_SIGNERS,
        };
        let store = InMemoryArtifactStore::new();
        let actor_str = format!("INFRAJR#{}", agent_instance::new_instance_id().unwrap());
        let src_bin = build_macho_test_binary(&build_dir, "nonblocking_reexec_lock");

        let published = publish_release_inner(
            PublishReleaseRequest {
                home_dir: &home,
                repo_root: &build_dir,
                binary: "chinwag",
                source_binary_path: &src_bin,
                explicit_from: Some(&actor_str),
                rollback: false,
                commit_override: Some(("3333333333333333".into(), 300)),
            },
            &store,
            |_| Ok(1),
            &roots,
            Some(&infrajr_key),
        )
        .unwrap();
        let expected_sha = decode_lowercase_hex_32(&published.manifest.sha256).unwrap();
        let install_path = home.join(".local/bin/chinwag");

        // 1. Hold `release_sync.lock` on a separate thread: `prepare_immutable_reexec_binary`
        //    MUST return immediately (`< 300ms`) with retryable `TransientIo` instead of stalling!
        let lock_acquired = Arc::new(Barrier::new(2));
        let release_lock = Arc::new(Barrier::new(2));
        let home_for_holder = home.clone();
        let acq_clone = lock_acquired.clone();
        let rel_clone = release_lock.clone();
        let holder = std::thread::spawn(move || {
            let _held = acquire_release_sync_lock_with_mode(&home_for_holder, false).unwrap();
            acq_clone.wait();
            rel_clone.wait();
        });
        lock_acquired.wait();

        let started = Instant::now();
        let contended_err = prepare_immutable_reexec_binary(&home, &install_path, &expected_sha)
            .err()
            .expect("contended nonblocking flock must return TransientIo immediately");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "nonblocking flock took too long: {:?}",
            started.elapsed()
        );
        assert!(matches!(contended_err, ReleaseSyncError::TransientIo(_)));
        assert!(contended_err.is_transient_retryable());

        release_lock.wait();
        holder.join().unwrap();

        // 2. Transient OS `Errno`s (`EMFILE` = 24, `EIO` = 5) in preparation helpers
        //    classify as retryable `TransientIo`, whereas tampered digest/symlinks stay terminal!
        for raw_errno in [
            rustix::io::Errno::MFILE.raw_os_error(),
            rustix::io::Errno::IO.raw_os_error(),
        ] {
            TEST_INJECTED_PREPARE_REEXEC_ERRNO.with(|c| c.set(Some(raw_errno)));
            let err = prepare_immutable_reexec_binary(&home, &install_path, &expected_sha)
                .err()
                .expect("injected transient errno must fail attempt cleanly");
            assert!(
                matches!(err, ReleaseSyncError::TransientIo(_)),
                "expected TransientIo for raw errno {raw_errno}, got {err:?}"
            );
            assert!(err.is_transient_retryable());
        }
        assert!(
            classify_journal_io_error(
                "read",
                &std::io::Error::from_raw_os_error(rustix::io::Errno::IO.raw_os_error())
            )
            .is_transient_retryable()
        );
        assert!(
            classify_install_io_error(
                "chmod",
                &std::io::Error::from_raw_os_error(rustix::io::Errno::MFILE.raw_os_error())
            )
            .is_transient_retryable()
        );

        // Terminal path violation check: symlink directory still fails closed non-retryably.
        let sym_dir = temp.path().join("sym-dir");
        std::os::unix::fs::symlink(&build_dir, &sym_dir).unwrap();
        let sym_err = open_dir_nofollow(&sym_dir).unwrap_err();
        assert!(matches!(sym_err, ReleaseSyncError::SafePathViolation(_)));
        assert!(!sym_err.is_transient_retryable());

        // 3. Subsequent retry after lock release and transient clearing succeeds cleanly!
        let prepared =
            prepare_immutable_reexec_binary(&home, &install_path, &expected_sha).unwrap();
        assert_eq!(prepared.sha256, expected_sha);
        cleanup_prepared_reexec(prepared);
    }

    #[test]
    fn private_dir_and_state_file_permissions_remediate_preexisting_permissive_modes() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let chinwag_dir = home.join(".chinwag");
        let bin_dir = home.join(".local/bin");
        let staging_dir = bin_dir.join(".staging");
        fs::create_dir_all(&chinwag_dir).unwrap();
        fs::create_dir_all(&staging_dir).unwrap();
        fs::set_permissions(&chinwag_dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&bin_dir, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&staging_dir, fs::Permissions::from_mode(0o755)).unwrap();

        ensure_bin_and_staging_dirs(&home).unwrap();
        save_release_sync_state(&home, &ReleaseSyncStateV1::default()).unwrap();

        assert_eq!(
            fs::symlink_metadata(&chinwag_dir).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::symlink_metadata(&bin_dir).unwrap().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::symlink_metadata(&staging_dir).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::symlink_metadata(release_sync_state_path(&home))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }
}
