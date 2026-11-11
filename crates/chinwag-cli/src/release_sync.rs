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
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(target_os = "macos")]
use std::os::darwin::fs::MetadataExt as DarwinMetadataExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

#[derive(Debug, Clone)]
pub struct BinarySyncReport {
    pub binary: String,
    pub release_key: String,
    pub outcome: Result<ReleaseApplyOutcome, ReleaseSyncError>,
}

pub struct PreparedImmutableReexec {
    pub dir_fd: File,
    pub dir_path: PathBuf,
    pub binary_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseSyncError {
    InvalidBinaryName,
    InvalidManifest(&'static str),
    NotAReleaseMessage,
    UnauthorizedSigner,
    SignatureInvalid,
    DowngradeOrReplayRejected,
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
    /// True only for transient storage/transport errors where reconciling later
    /// from the durable bus journal can succeed without sacrificing fail-closed
    /// rejection of invalid signatures, digests, codesign checks, or downgrades.
    pub fn is_transient_retryable(&self) -> bool {
        matches!(
            self,
            Self::ArtifactStoreFailed(_) | Self::BusPublishFailed(_)
        )
    }
}

pub trait ReleaseArtifactStore: Send + Sync {
    fn upload_artifact(
        &self,
        artifact_key: &str,
        local_file: &Path,
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
}

impl WranglerR2ArtifactStore {
    pub fn new(home_dir: PathBuf) -> Self {
        Self {
            home_dir,
            bucket: R2_BUCKET_NAME.to_owned(),
        }
    }

    fn resolve_wrangler_bin() -> Result<PathBuf, ReleaseSyncError> {
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

    fn run_wrangler(&self, args: &[&str]) -> Result<(), ReleaseSyncError> {
        let wrangler = Self::resolve_wrangler_bin()?;
        let chinwag_dir = ensure_private_dir(&self.home_dir.join(".chinwag"))?;
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
            .stdin(Stdio::null())
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
        local_file: &Path,
    ) -> Result<(), ReleaseSyncError> {
        validate_artifact_key_structure(artifact_key)?;
        let object_path = format!("{}/{artifact_key}", self.bucket);
        let file_str = local_file
            .to_str()
            .ok_or(ReleaseSyncError::SafePathViolation("non_utf8_staging_path"))?;
        self.run_wrangler(&[
            "r2",
            "object",
            "put",
            &object_path,
            "--file",
            file_str,
            "--content-type",
            "application/octet-stream",
            "--remote",
        ])
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
        self.run_wrangler(&[
            "r2",
            "object",
            "get",
            &object_path,
            "--file",
            file_str,
            "--remote",
        ])
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
    let meta = fs::symlink_metadata(&path)
        .map_err(|_| ReleaseSyncError::SafePathViolation("unreadable_home"))?;
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

/// Opens `path` strictly with `O_NOFOLLOW | O_CLOEXEC`, cross-checking `lstat`
/// and `fstat` `(dev, ino)` to eliminate symlink/TOCTOU swap races.
fn open_regular_file_nofollow(
    path: &Path,
    require_single_link: bool,
    require_owner: bool,
) -> Result<(File, fs::Metadata), ReleaseSyncError> {
    let lstat = fs::symlink_metadata(path)
        .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("lstat failed: {e}")))?;
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
        Err(err) => {
            return Err(ReleaseSyncError::SourceUnavailable(format!(
                "open failed: {err}"
            )));
        }
    };
    let file = File::from(fd);
    let fstat = file
        .metadata()
        .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("fstat failed: {e}")))?;
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
        let read = file
            .read(&mut buf)
            .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("read failed: {e}")))?;
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
        .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("post-read fstat: {e}")))?;
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
        Err(err) => {
            return Err(ReleaseSyncError::StatePersistenceFailed(format!(
                "lock open: {err}"
            )));
        }
    };
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|_| ReleaseSyncError::StatePersistenceFailed("lock_fstat".into()))?;
    if meta.file_type().is_symlink()
        || !meta.file_type().is_file()
        || meta.nlink() != 1
        || meta.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(ReleaseSyncError::SafePathViolation("unsafe_lock_file"));
    }
    let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    loop {
        match flock(&file, FlockOperation::LockExclusive) {
            Ok(()) => return Ok(file),
            Err(err) if err == rustix::io::Errno::INTR => continue,
            Err(err) => {
                return Err(ReleaseSyncError::StatePersistenceFailed(format!(
                    "flock failed: {err}"
                )));
            }
        }
    }
}

fn ensure_private_dir(dir: &Path) -> Result<PathBuf, ReleaseSyncError> {
    if let Ok(meta) = fs::symlink_metadata(dir) {
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(ReleaseSyncError::SafePathViolation("symlink_or_non_dir"));
        }
    } else {
        fs::create_dir_all(dir).map_err(|_| ReleaseSyncError::SafePathViolation("mkdir_failed"))?;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let meta = fs::symlink_metadata(dir)
        .map_err(|_| ReleaseSyncError::SafePathViolation("dir_stat_failed"))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(ReleaseSyncError::SafePathViolation("symlink_or_non_dir"));
    }
    Ok(dir.to_path_buf())
}

fn ensure_bin_and_staging_dirs(home_dir: &Path) -> Result<(PathBuf, PathBuf), ReleaseSyncError> {
    let local_dir = home_dir.join(".local");
    if let Ok(meta) = fs::symlink_metadata(&local_dir) {
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(ReleaseSyncError::SafePathViolation("invalid_dot_local"));
        }
    } else {
        fs::create_dir_all(&local_dir)
            .map_err(|_| ReleaseSyncError::SafePathViolation("mkdir_dot_local"))?;
    }
    let bin_dir = local_dir.join("bin");
    if let Ok(meta) = fs::symlink_metadata(&bin_dir) {
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(ReleaseSyncError::SafePathViolation("invalid_local_bin"));
        }
    } else {
        fs::create_dir_all(&bin_dir)
            .map_err(|_| ReleaseSyncError::SafePathViolation("mkdir_local_bin"))?;
        let _ = fs::set_permissions(&bin_dir, fs::Permissions::from_mode(0o755));
    }
    let staging_dir = bin_dir.join(".staging");
    ensure_private_dir(&staging_dir)?;
    let _ = fs::set_permissions(&staging_dir, fs::Permissions::from_mode(0o700));
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
        Err(_) => return Err(ReleaseSyncError::StatePersistenceFailed("stat".into())),
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
        .map_err(|_| ReleaseSyncError::StatePersistenceFailed("read".into()))?;
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

pub fn save_release_sync_state(
    home_dir: &Path,
    state: &ReleaseSyncStateV1,
) -> Result<(), ReleaseSyncError> {
    let chinwag_dir = ensure_private_dir(&home_dir.join(".chinwag"))?;
    let final_path = chinwag_dir.join("release_sync_state.json");
    if let Ok(meta) = fs::symlink_metadata(&final_path)
        && meta.file_type().is_symlink()
    {
        return Err(ReleaseSyncError::SafePathViolation(
            "state_target_is_symlink",
        ));
    }
    let nonce = csprng_hex_16()?;
    let tmp_path = chinwag_dir.join(format!(
        ".release_sync_state.tmp.{}.{nonce}",
        std::process::id()
    ));
    let serialized = serde_json::to_vec_pretty(state)
        .map_err(|_| ReleaseSyncError::StatePersistenceFailed("serialize".into()))?;
    let write_res = (|| -> Result<(), ReleaseSyncError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|_| ReleaseSyncError::StatePersistenceFailed("open_tmp".into()))?;
        file.write_all(&serialized)
            .map_err(|_| ReleaseSyncError::StatePersistenceFailed("write_tmp".into()))?;
        file.sync_all()
            .map_err(|_| ReleaseSyncError::StatePersistenceFailed("sync_tmp".into()))?;
        fs::rename(&tmp_path, &final_path)
            .map_err(|_| ReleaseSyncError::StatePersistenceFailed("rename".into()))?;
        if let Ok(dir_file) = File::open(&chinwag_dir) {
            let _ = dir_file.sync_all();
        }
        Ok(())
    })();
    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_res
}

fn run_bounded_command(cmd: &mut Command, deadline: Duration) -> Result<(), String> {
    let mut child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;
    let stdout_drain = child.stdout.take().map(|mut out_pipe| {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut out_pipe, &mut std::io::sink());
        })
    });
    let stderr_drain = child.stderr.take().map(|mut err_pipe| {
        std::thread::spawn(move || {
            let mut preview = Vec::with_capacity(512);
            let _ = (&mut err_pipe).take(512).read_to_end(&mut preview);
            let _ = std::io::copy(&mut err_pipe, &mut std::io::sink());
            preview
        })
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Some(handle) = stdout_drain {
                    let _ = handle.join();
                }
                let stderr_buf = stderr_drain
                    .and_then(|handle| handle.join().ok())
                    .unwrap_or_default();
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
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("timed out after {}ms", deadline.as_millis()));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("wait failed: {err}"));
            }
        }
    }
}

#[cfg(target_os = "macos")]
const UF_IMMUTABLE: u32 = 0x0000_0002;

#[cfg(target_os = "macos")]
fn set_path_immutable(path: &Path, immutable: bool) -> Result<(), ReleaseSyncError> {
    let flag = if immutable { "uchg" } else { "nouchg" };
    let mut cmd = Command::new("/usr/bin/chflags");
    cmd.arg(flag)
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    run_bounded_command(&mut cmd, VERSION_SMOKE_TIMEOUT)
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("chflags {flag} failed: {e}")))
}

#[cfg(not(target_os = "macos"))]
fn set_path_immutable(_path: &Path, _immutable: bool) -> Result<(), ReleaseSyncError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_fd_immutable(file: &File) -> Result<(), ReleaseSyncError> {
    let meta = file
        .metadata()
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("fstat immutable pin: {e}")))?;
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
    let lstat = fs::symlink_metadata(dir)
        .map_err(|_| ReleaseSyncError::SafePathViolation("dir_lstat_failed"))?;
    if lstat.file_type().is_symlink() || !lstat.file_type().is_dir() {
        return Err(ReleaseSyncError::SafePathViolation("symlink_or_non_dir"));
    }
    let fd = rustix_open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ReleaseSyncError::SafePathViolation("dir_open_nofollow_failed"))?;
    let file = File::from(fd);
    let fstat = file
        .metadata()
        .map_err(|_| ReleaseSyncError::SafePathViolation("dir_fstat_failed"))?;
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
        } else {
            ReleaseSyncError::SourceUnavailable(format!("openat failed: {err}"))
        }
    })?;
    let file = File::from(fd);
    let fstat = file
        .metadata()
        .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("fstat failed: {e}")))?;
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
        let meta = fs::symlink_metadata(path)
            .map_err(|_| ReleaseSyncError::SafePathViolation("ancestor_stat_failed"))?;
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
    armed: bool,
}

impl StagedOpGuard {
    fn new(op_dir: PathBuf) -> Self {
        Self {
            op_dir,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagedOpGuard {
    fn drop(&mut self) {
        if self.armed {
            clear_and_remove_immutable_dir(&self.op_dir);
        }
    }
}

pub fn clear_and_remove_immutable_dir(dir: &Path) {
    let _ = set_path_immutable(dir, false);
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let _ = set_path_immutable(&entry.path(), false);
        }
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

/// Copies `install_path` into a private per-process `0700` staging directory,
/// verifies `expected_sha256` in constant time + strict macOS `codesign` while
/// non-executable (`0600`), promotes to `0755`, locks BOTH the binary and its
/// parent directory with kernel `UF_IMMUTABLE` (`uchg`), and re-verifies the
/// pinned FD via `openat` so `fchdir(&dir_fd)` + `exec("./chinwag")` executes
/// the exact verified vnode with zero ancestor or pathname TOCTOU window.
pub fn prepare_immutable_reexec_binary(
    home_dir: &Path,
    install_path: &Path,
    expected_sha256: &[u8; 32],
) -> Result<PreparedImmutableReexec, ReleaseSyncError> {
    let (_, staging_dir) = ensure_bin_and_staging_dirs(home_dir)?;
    let nonce = csprng_hex_16()?;
    let reexec_dir = staging_dir.join(format!("reexec.{}.{nonce}", std::process::id()));
    fs::create_dir(&reexec_dir)
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("reexec mkdir: {e}")))?;
    fs::set_permissions(&reexec_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("reexec chmod dir: {e}")))?;
    let binary_path = reexec_dir.join("chinwag");
    let mut guard = StagedOpGuard::new(reexec_dir.clone());

    let (dir_fd, dir_id) = open_dir_nofollow(&reexec_dir)?;
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
    .map_err(|e| ReleaseSyncError::InstallFailed(format!("reexec stage create: {e}")))?;
    let mut dst = File::from(dst_fd);
    std::io::copy(&mut src, &mut dst)
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("reexec stage copy: {e}")))?;
    dst.sync_all()
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("reexec stage sync: {e}")))?;
    drop(dst);
    drop(src);

    let (mut pre_ro, pre_fstat) = open_regular_at_dir_nofollow(&dir_fd, "chinwag", true, true)?;
    let staged_id = (pre_fstat.dev(), pre_fstat.ino());
    let (_, actual_sha, _) =
        compute_digests_from_open_file(&mut pre_ro, src_fstat.len(), staged_id)?;
    if !bool::from(actual_sha.ct_eq(expected_sha256)) {
        return Err(ReleaseSyncError::DigestMismatch);
    }
    verify_codesign_strict(&binary_path)?;
    pre_ro
        .set_permissions(fs::Permissions::from_mode(0o755))
        .map_err(|_| ReleaseSyncError::InstallFailed("reexec chmod 0755".into()))?;
    drop(pre_ro);

    set_path_immutable(&binary_path, true)?;
    set_path_immutable(&reexec_dir, true)?;

    let dir_post = dir_fd
        .metadata()
        .map_err(|_| ReleaseSyncError::SafePathViolation("reexec_dir_fstat"))?;
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
    let (_, post_sha, _) =
        compute_digests_from_open_file(&mut pinned_ro, src_fstat.len(), staged_id)?;
    if !bool::from(post_sha.ct_eq(expected_sha256)) {
        return Err(ReleaseSyncError::DigestMismatch);
    }

    guard.disarm();
    Ok(PreparedImmutableReexec {
        dir_fd,
        dir_path: reexec_dir,
        binary_path,
    })
}

#[cfg(target_os = "macos")]
fn verify_codesign_strict(staged_path: &Path) -> Result<(), ReleaseSyncError> {
    let mut cmd = Command::new("/usr/bin/codesign");
    cmd.args(["--verify", "--strict"])
        .arg(staged_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    run_bounded_command(&mut cmd, VERSION_SMOKE_TIMEOUT).map_err(ReleaseSyncError::CodesignFailed)
}

#[cfg(not(target_os = "macos"))]
fn verify_codesign_strict(_staged_path: &Path) -> Result<(), ReleaseSyncError> {
    Ok(())
}

/// Publisher-only helper: checks strict signature first, applying ad-hoc
/// signing (`codesign -f -s -`) at most ONCE on the publisher's staged copy
/// before canonical SHA-256 and BLAKE3 digests are computed.
#[cfg(target_os = "macos")]
fn ensure_publisher_codesigned(staged_path: &Path) -> Result<(), ReleaseSyncError> {
    if verify_codesign_strict(staged_path).is_ok() {
        return Ok(());
    }
    let mut sign = Command::new("/usr/bin/codesign");
    sign.args(["-f", "-s", "-"])
        .arg(staged_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    run_bounded_command(&mut sign, VERSION_SMOKE_TIMEOUT)
        .map_err(ReleaseSyncError::CodesignFailed)?;
    verify_codesign_strict(staged_path)
}

#[cfg(not(target_os = "macos"))]
fn ensure_publisher_codesigned(_staged_path: &Path) -> Result<(), ReleaseSyncError> {
    Ok(())
}

fn smoke_test_binary_version(
    staged_path: &Path,
    binary_name: &str,
) -> Result<(), ReleaseSyncError> {
    validate_binary_name(binary_name)?;
    let mut cmd = Command::new(staged_path);
    // Preserve exact argv[0] basename (`chinwag` / `chinwag-ci`) because
    // `chinwag`'s CLI dispatcher validates `argv[0]` basename strictly.
    cmd.arg0(binary_name)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_bounded_command(&mut cmd, VERSION_SMOKE_TIMEOUT).map_err(ReleaseSyncError::SmokeTestFailed)
}

/// Preserves `<bin_dir>/<binary>.prev` via an APFS hard-link + atomic rename
/// (so `<bin_dir>/<binary>` never disappears even momentarily) and atomically
/// renames `<staged_path>` onto `<bin_dir>/<binary>`, re-verifying staged inode
/// identity (`expected_staged_id`) immediately prior to `rename`.
fn atomic_install_staged_binary(
    bin_dir: &Path,
    binary: &str,
    staged_path: &Path,
    expected_staged_id: Option<(u64, u64)>,
) -> Result<(PathBuf, Option<PathBuf>), ReleaseSyncError> {
    validate_binary_name(binary)?;
    let staged_meta = fs::symlink_metadata(staged_path)
        .map_err(|_| ReleaseSyncError::SafePathViolation("staged_stat_failed"))?;
    if staged_meta.file_type().is_symlink()
        || !staged_meta.file_type().is_file()
        || staged_meta.nlink() != 1
        || staged_meta.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(ReleaseSyncError::SafePathViolation(
            "staged_symlink_or_hardlink",
        ));
    }
    if let Some(expected_id) = expected_staged_id
        && (staged_meta.dev(), staged_meta.ino()) != expected_id
    {
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
        let prev_tmp = bin_dir.join(format!(".{binary}.prev.tmp.{}.{nonce}", std::process::id()));
        if fs::hard_link(&install_path, &prev_tmp).is_err() {
            fs::copy(&install_path, &prev_tmp)
                .map_err(|e| ReleaseSyncError::InstallFailed(format!("backup copy: {e}")))?;
            let _ = fs::set_permissions(&prev_tmp, fs::Permissions::from_mode(0o755));
        }
        if let Err(err) = fs::rename(&prev_tmp, &prev_path) {
            let _ = fs::remove_file(&prev_tmp);
            return Err(ReleaseSyncError::InstallFailed(format!(
                "backup rename: {err}"
            )));
        }
        Some(prev_path)
    } else {
        None
    };

    // Final inode recheck immediately before atomic rename into `.local/bin`.
    if let Some(expected_id) = expected_staged_id {
        let pre_rename = fs::symlink_metadata(staged_path)
            .map_err(|_| ReleaseSyncError::SafePathViolation("staged_stat_failed"))?;
        if pre_rename.file_type().is_symlink()
            || !pre_rename.file_type().is_file()
            || pre_rename.nlink() != 1
            || (pre_rename.dev(), pre_rename.ino()) != expected_id
        {
            return Err(ReleaseSyncError::SafePathViolation("staged_inode_swap"));
        }
    }

    fs::rename(staged_path, &install_path)
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("atomic rename: {e}")))?;
    if let Ok(dir_file) = File::open(bin_dir) {
        let _ = dir_file.sync_all();
    }
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
    }

    let nonce = csprng_hex_16()?;
    let op_dir = staging_dir.join(format!("op.{}.{nonce}", std::process::id()));
    fs::create_dir(&op_dir)
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("op_dir create failed: {e}")))?;
    fs::set_permissions(&op_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("op_dir chmod failed: {e}")))?;
    let staged_path = op_dir.join(&manifest.binary);
    let mut op_guard = StagedOpGuard::new(op_dir.clone());

    let (op_dir_fd, op_dir_id) = open_dir_nofollow(&op_dir)?;
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

    // Verify macOS code signature strictly while still non-executable (never `-f`!).
    verify_codesign_strict(&staged_path)?;

    let post_codesign = staged_file
        .metadata()
        .map_err(|_| ReleaseSyncError::SafePathViolation("staged_stat_failed"))?;
    if post_codesign.nlink() != 1 || (post_codesign.dev(), post_codesign.ino()) != staged_id {
        return Err(ReleaseSyncError::SafePathViolation("staged_inode_swap"));
    }

    // Only AFTER size + SHA-256 + BLAKE3 + strict codesign pass do we set 0755 on the pinned FD,
    // lock BOTH file and per-op directory with kernel `UF_IMMUTABLE` (`uchg`), and re-verify
    // digests on the immutable vnode before executing `--version`.
    staged_file
        .set_permissions(fs::Permissions::from_mode(0o755))
        .map_err(|_| ReleaseSyncError::InstallFailed("chmod_0755_failed".into()))?;
    drop(staged_file);

    set_path_immutable(&staged_path, true)?;
    set_path_immutable(&op_dir, true)?;

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
    smoke_test_binary_version(&staged_path, &manifest.binary)?;
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
        set_path_immutable(&op_dir, false)?;
        set_path_immutable(&staged_path, false)?;
        let paths = atomic_install_staged_binary(
            &bin_dir,
            &manifest.binary,
            &staged_path,
            Some(staged_id),
        )?;
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
    let op_dir = staging_dir.join(format!("op.pub.{}.{nonce}", std::process::id()));
    fs::create_dir(&op_dir)
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("pub op_dir create: {e}")))?;
    fs::set_permissions(&op_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("pub op_dir chmod: {e}")))?;
    let staged_path = op_dir.join(req.binary);
    let mut op_guard = StagedOpGuard::new(op_dir.clone());

    let (op_dir_fd, op_dir_id) = open_dir_nofollow(&op_dir)?;
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

    // Ensure valid macOS signature ONCE on the publisher's staged copy BEFORE
    // locking with `UF_IMMUTABLE` (`uchg`) and computing SHA-256 + BLAKE3 so
    // every peer verifies identical bytes.
    ensure_publisher_codesigned(&staged_path)?;

    set_path_immutable(&staged_path, true)?;
    set_path_immutable(&op_dir, true)?;

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
    smoke_test_binary_version(&staged_path, req.binary)?;
    if capture_ancestor_chain_inodes(req.home_dir, &op_dir)? != ancestors_before {
        return Err(ReleaseSyncError::SafePathViolation("ancestor_inode_swap"));
    }
    verify_fd_immutable(&op_dir_fd)?;
    verify_fd_immutable(&staged_file)?;

    let target_triple = CURRENT_TARGET_TRIPLE.to_owned();
    let artifact_key = expected_artifact_key(req.binary, &target_triple, &sha256);

    store.upload_artifact(&artifact_key, &staged_path)?;

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

        set_path_immutable(&op_dir, false)?;
        set_path_immutable(&staged_path, false)?;
        let (install_path, previous_backup_path) =
            atomic_install_staged_binary(&bin_dir, req.binary, &staged_path, Some(staged_id))?;
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
    let mut candidates_per_binary: BTreeMap<String, Vec<(BusMessage, ReleaseManifestV1)>> =
        BTreeMap::new();

    match fs::symlink_metadata(messages_jsonl_path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(ReleaseSyncError::SourceUnavailable(format!(
                "journal stat failed: {err}"
            )));
        }
        Ok(_) => {
            let (file, _) = open_regular_file_nofollow(messages_jsonl_path, false, false)?;
            let reader = BufReader::new(file);
            for line_res in reader.lines() {
                let line = line_res.map_err(|e| {
                    ReleaseSyncError::SourceUnavailable(format!("journal read failed: {e}"))
                })?;
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
    }

    let current_state = {
        let _lock = acquire_release_sync_lock(home_dir)?;
        load_release_sync_state(home_dir)?
    };

    let mut winners: BTreeMap<String, (BusMessage, ReleaseManifestV1, u64)> = BTreeMap::new();
    for (binary, mut list) in candidates_per_binary {
        list.sort_by(|(_, a), (_, b)| {
            (
                a.built_at_ms,
                a.commit_epoch,
                u8::from(a.rollback),
                &a.sha256,
            )
                .cmp(&(
                    b.built_at_ms,
                    b.commit_epoch,
                    u8::from(b.rollback),
                    &b.sha256,
                ))
        });

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

    let mut outcomes = Vec::with_capacity(winners.len());
    for (binary, (msg, manifest, observed_max_epoch)) in winners {
        let release_key = InstalledBinaryState::release_history_key(&manifest);
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
        outcomes.push(BinarySyncReport {
            binary,
            release_key,
            outcome,
        });
    }
    Ok(outcomes)
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

    impl ReleaseArtifactStore for InMemoryArtifactStore {
        fn upload_artifact(
            &self,
            artifact_key: &str,
            local_file: &Path,
        ) -> Result<(), ReleaseSyncError> {
            validate_artifact_key_structure(artifact_key)?;
            let bytes = fs::read(local_file)
                .map_err(|e| ReleaseSyncError::ArtifactStoreFailed(e.to_string()))?;
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
        store.upload_artifact(&artifact_key, &tmp_src).unwrap();

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
        store.upload_artifact(&key_150, &bin_150).unwrap();
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

        // 1. Deterministic replacement-between-check-and-exec hook during subscriber smoke test:
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
}
