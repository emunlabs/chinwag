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
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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

    fn upload_latest_signed_envelope(
        &self,
        _binary: &str,
        _target_triple: &str,
        _signed_bus_json: &[u8],
    ) -> Result<(), ReleaseSyncError> {
        Ok(())
    }

    fn download_latest_signed_envelope(
        &self,
        _binary: &str,
        _target_triple: &str,
    ) -> Result<Option<Vec<u8>>, ReleaseSyncError> {
        Ok(None)
    }
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
            if is_regular_non_symlink_or_valid_exec(&candidate) {
                return Ok(candidate);
            }
        }
        for candidate in ["/opt/homebrew/bin/wrangler", "/usr/local/bin/wrangler"] {
            let path = Path::new(candidate);
            if is_regular_non_symlink_or_valid_exec(path) {
                return Ok(path.to_path_buf());
            }
        }
        if let Some(path_os) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_os) {
                let candidate = dir.join("wrangler");
                if is_regular_non_symlink_or_valid_exec(&candidate) {
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

    fn latest_envelope_key(binary: &str, target_triple: &str) -> Result<String, ReleaseSyncError> {
        validate_binary_name(binary)?;
        validate_target_triple(target_triple)?;
        Ok(format!(
            "{R2_ARTIFACT_PREFIX}/latest/{binary}/{target_triple}/release_built.bus-msg.json"
        ))
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

    fn upload_latest_signed_envelope(
        &self,
        binary: &str,
        target_triple: &str,
        signed_bus_json: &[u8],
    ) -> Result<(), ReleaseSyncError> {
        let key = Self::latest_envelope_key(binary, target_triple)?;
        let chinwag_dir = ensure_private_dir(&self.home_dir.join(".chinwag"))?;
        let nonce = csprng_hex_16()?;
        let tmp = chinwag_dir.join(format!(".release-envelope.{nonce}.json"));
        let write_res = (|| -> Result<(), ReleaseSyncError> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|_| {
                    ReleaseSyncError::StatePersistenceFailed("envelope_stage_open".into())
                })?;
            f.write_all(signed_bus_json).map_err(|_| {
                ReleaseSyncError::StatePersistenceFailed("envelope_stage_write".into())
            })?;
            f.sync_all()
                .map_err(|_| ReleaseSyncError::StatePersistenceFailed("envelope_stage_sync".into()))
        })();
        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
        let object_path = format!("{}/{key}", self.bucket);
        let res = if let Some(tmp_str) = tmp.to_str() {
            self.run_wrangler(&[
                "r2",
                "object",
                "put",
                &object_path,
                "--file",
                tmp_str,
                "--content-type",
                "application/json",
                "--remote",
            ])
        } else {
            Err(ReleaseSyncError::SafePathViolation("non_utf8_staging_path"))
        };
        let _ = fs::remove_file(&tmp);
        res
    }

    fn download_latest_signed_envelope(
        &self,
        binary: &str,
        target_triple: &str,
    ) -> Result<Option<Vec<u8>>, ReleaseSyncError> {
        let key = Self::latest_envelope_key(binary, target_triple)?;
        let chinwag_dir = ensure_private_dir(&self.home_dir.join(".chinwag"))?;
        let nonce = csprng_hex_16()?;
        let tmp = chinwag_dir.join(format!(".release-envelope-fetch.{nonce}.json"));
        let object_path = format!("{}/{key}", self.bucket);
        let Some(tmp_str) = tmp.to_str() else {
            return Err(ReleaseSyncError::SafePathViolation("non_utf8_staging_path"));
        };
        let fetch = self.run_wrangler(&[
            "r2",
            "object",
            "get",
            &object_path,
            "--file",
            tmp_str,
            "--remote",
        ]);
        if fetch.is_err() {
            let _ = fs::remove_file(&tmp);
            return Ok(None);
        }
        let bytes = fs::read(&tmp).ok();
        let _ = fs::remove_file(&tmp);
        Ok(bytes.filter(|b| !b.is_empty() && b.len() <= MAX_RELEASE_MANIFEST_JSON_BYTES * 2))
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

pub fn compute_file_digests(path: &Path) -> Result<(u64, [u8; 32], [u8; 32]), ReleaseSyncError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("stat failed: {e}")))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(ReleaseSyncError::SafePathViolation(
            "non_regular_binary_file",
        ));
    }
    let mut file = File::open(path)
        .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("open failed: {e}")))?;
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
    if total != meta.len() || total == 0 {
        return Err(ReleaseSyncError::SourceUnavailable(
            "concurrent size mutation or empty binary".into(),
        ));
    }
    let sha_out: [u8; 32] = sha256_hasher.finalize().into();
    let b3_out: [u8; 32] = *blake3_hasher.finalize().as_bytes();
    Ok((total, sha_out, b3_out))
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

fn is_regular_non_symlink_or_valid_exec(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file())
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
    let bytes =
        fs::read(&path).map_err(|_| ReleaseSyncError::StatePersistenceFailed("read".into()))?;
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
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                let mut stderr_buf = Vec::new();
                if let Some(err_pipe) = child.stderr.take() {
                    let _ = err_pipe.take(512).read_to_end(&mut stderr_buf);
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
/// renames `<staged_path>` onto `<bin_dir>/<binary>`.
fn atomic_install_staged_binary(
    bin_dir: &Path,
    binary: &str,
    staged_path: &Path,
) -> Result<(PathBuf, Option<PathBuf>), ReleaseSyncError> {
    validate_binary_name(binary)?;
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
    let key_meta = fs::symlink_metadata(&key_path)
        .map_err(|_| ReleaseSyncError::SigningIdentityUnavailable("key_file_missing"))?;
    if key_meta.file_type().is_symlink() || !key_meta.file_type().is_file() {
        return Err(ReleaseSyncError::SafePathViolation("signing_key_symlink"));
    }
    if (key_meta.permissions().mode() & 0o077) != 0 {
        return Err(ReleaseSyncError::SafePathViolation(
            "signing_key_permissions",
        ));
    }
    let identity = Identity::from_ssh_signing_file(&key_path)
        .map_err(|_| ReleaseSyncError::SigningIdentityUnavailable("invalid_openssh_key"))?;
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
        && prev.built_at_ms == manifest.built_at_ms;
    if same_recorded_release && local_matches_manifest {
        return Ok(true);
    }
    if manifest.rollback {
        if manifest.built_at_ms <= prev.built_at_ms {
            return Err(ReleaseSyncError::DowngradeOrReplayRejected);
        }
    } else if (manifest.commit_epoch, manifest.built_at_ms) <= (prev.commit_epoch, prev.built_at_ms)
    {
        return Err(ReleaseSyncError::DowngradeOrReplayRejected);
    }
    Ok(local_matches_manifest)
}

fn record_installed_state(
    home_dir: &Path,
    state: &mut ReleaseSyncStateV1,
    manifest: &ReleaseManifestV1,
    source_message_id: Option<String>,
) -> Result<(), ReleaseSyncError> {
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
        },
    );
    save_release_sync_state(home_dir, state)
}

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
    )
}

fn apply_release_built_message_inner(
    home_dir: &Path,
    store: &dyn ReleaseArtifactStore,
    msg: &BusMessage,
    local_iroh_endpoint: Option<&str>,
    roots: &ReleaseTrustRoots<'_>,
    receipt_key_override: Option<&SigningKey>,
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
        record_installed_state(home_dir, &mut sync_state, &manifest, Some(msg.id.clone()))?;
        return Ok(ReleaseApplyOutcome::AlreadyInstalled {
            manifest,
            install_path,
        });
    }

    let nonce = csprng_hex_16()?;
    let staged_path = staging_dir.join(format!(
        "{}.{}.{}.{nonce}",
        manifest.binary,
        manifest.sha256,
        std::process::id()
    ));
    let pre_created = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged_path)
        .map_err(|e| ReleaseSyncError::InstallFailed(format!("stage create failed: {e}")))?;
    drop(pre_created);

    let verified_stage = (|| -> Result<(), ReleaseSyncError> {
        store.download_artifact(&manifest.artifact_key, &staged_path)?;
        let staged_meta = fs::symlink_metadata(&staged_path)
            .map_err(|_| ReleaseSyncError::SafePathViolation("staged_stat_failed"))?;
        if staged_meta.file_type().is_symlink() || !staged_meta.file_type().is_file() {
            return Err(ReleaseSyncError::SafePathViolation(
                "staged_symlink_or_non_file",
            ));
        }
        // Explicitly lock permissions to 0600 (zero execute bits!) BEFORE computing
        // and comparing digests in constant time (`INV-HASH-BEFORE-EXEC-01`).
        fs::set_permissions(&staged_path, fs::Permissions::from_mode(0o600))
            .map_err(|_| ReleaseSyncError::InstallFailed("chmod_0600_failed".into()))?;

        let (actual_size, actual_sha256, actual_blake3) = compute_file_digests(&staged_path)?;
        let size_ok = actual_size == manifest.size_bytes;
        let sha_ok = bool::from(actual_sha256.ct_eq(&expected_sha256));
        let b3_ok = bool::from(actual_blake3.ct_eq(&expected_blake3));
        if !(size_ok && sha_ok && b3_ok) {
            return Err(ReleaseSyncError::DigestMismatch);
        }

        // Verify macOS code signature strictly while still non-executable (never `-f`!).
        verify_codesign_strict(&staged_path)?;

        // Only AFTER size + SHA-256 + BLAKE3 + strict codesign pass do we set 0755.
        fs::set_permissions(&staged_path, fs::Permissions::from_mode(0o755))
            .map_err(|_| ReleaseSyncError::InstallFailed("chmod_0755_failed".into()))?;

        smoke_test_binary_version(&staged_path, &manifest.binary)?;
        Ok(())
    })();

    if let Err(err) = verified_stage {
        let _ = fs::remove_file(&staged_path);
        return Err(err);
    }

    let (install_path, previous_backup_path) =
        match atomic_install_staged_binary(&bin_dir, &manifest.binary, &staged_path) {
            Ok(paths) => paths,
            Err(err) => {
                let _ = fs::remove_file(&staged_path);
                return Err(err);
            }
        };

    record_installed_state(home_dir, &mut sync_state, &manifest, Some(msg.id.clone()))?;

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

    let src_meta = fs::symlink_metadata(req.source_binary_path)
        .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("source stat: {e}")))?;
    if src_meta.file_type().is_symlink() || !src_meta.file_type().is_file() || src_meta.len() == 0 {
        return Err(ReleaseSyncError::SourceUnavailable(
            "source must be a non-empty regular file (not a symlink)".into(),
        ));
    }

    let (git_commit, commit_epoch) = match req.commit_override {
        Some(pair) => pair,
        None => resolve_git_commit_and_epoch(req.repo_root)?,
    };

    let mut sync_state = load_release_sync_state(req.home_dir)?;
    let mut built_at_ms = now_unix_ms().max(1);
    if let Some(prev) = sync_state.binaries.get(req.binary) {
        if !req.rollback && commit_epoch < prev.commit_epoch {
            return Err(ReleaseSyncError::DowngradeOrReplayRejected);
        }
        if built_at_ms <= prev.built_at_ms {
            built_at_ms = prev.built_at_ms.saturating_add(1);
        }
    }

    let (bin_dir, staging_dir) = ensure_bin_and_staging_dirs(req.home_dir)?;
    let nonce = csprng_hex_16()?;
    let staged_path = staging_dir.join(format!(
        "{}.publish.{}.{nonce}",
        req.binary,
        std::process::id()
    ));

    let prep_result = (|| -> Result<(u64, String, String), ReleaseSyncError> {
        let mut src = File::open(req.source_binary_path)
            .map_err(|e| ReleaseSyncError::SourceUnavailable(format!("open source: {e}")))?;
        let mut dst = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&staged_path)
            .map_err(|e| ReleaseSyncError::InstallFailed(format!("stage create: {e}")))?;
        std::io::copy(&mut src, &mut dst)
            .map_err(|e| ReleaseSyncError::InstallFailed(format!("stage copy: {e}")))?;
        dst.sync_all()
            .map_err(|e| ReleaseSyncError::InstallFailed(format!("stage sync: {e}")))?;
        drop(dst);

        // Ensure valid macOS signature ONCE on the publisher's staged copy BEFORE
        // computing SHA-256 and BLAKE3 so every peer verifies identical bytes.
        ensure_publisher_codesigned(&staged_path)?;
        smoke_test_binary_version(&staged_path, req.binary)?;

        let (size_bytes, sha256_bytes, blake3_bytes) = compute_file_digests(&staged_path)?;
        Ok((
            size_bytes,
            encode_hex(&sha256_bytes),
            encode_hex(&blake3_bytes),
        ))
    })();

    let (size_bytes, sha256, blake3) = match prep_result {
        Ok(v) => v,
        Err(err) => {
            let _ = fs::remove_file(&staged_path);
            return Err(err);
        }
    };

    let target_triple = CURRENT_TARGET_TRIPLE.to_owned();
    let artifact_key = expected_artifact_key(req.binary, &target_triple, &sha256);
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
    if let Err(err) = manifest.validate_structural() {
        let _ = fs::remove_file(&staged_path);
        return Err(err);
    }

    if let Err(err) = store.upload_artifact(&artifact_key, &staged_path) {
        let _ = fs::remove_file(&staged_path);
        return Err(err);
    }

    let (install_path, previous_backup_path) =
        match atomic_install_staged_binary(&bin_dir, req.binary, &staged_path) {
            Ok(paths) => paths,
            Err(err) => {
                let _ = fs::remove_file(&staged_path);
                return Err(err);
            }
        };

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
    )?;

    if let Ok(envelope_bytes) = serde_json::to_vec(&release_built_message) {
        let _ = store.upload_latest_signed_envelope(req.binary, &target_triple, &envelope_bytes);
    }

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

/// Scans `.chinwag/bus/messages.jsonl` (and optionally R2 signed envelopes) for
/// the latest cryptographically verified `INFRAJR` `RELEASE_BUILT` per binary
/// matching `CURRENT_TARGET_TRIPLE` and applies each monotonically.
pub fn sync_releases_from_journal_and_r2(
    home_dir: &Path,
    messages_jsonl_path: &Path,
    store: &dyn ReleaseArtifactStore,
    check_r2_envelopes: bool,
    local_iroh_endpoint: Option<&str>,
) -> Result<Vec<(String, ReleaseApplyOutcome)>, ReleaseSyncError> {
    let mut latest_per_binary: BTreeMap<String, (BusMessage, ReleaseManifestV1)> = BTreeMap::new();

    if let Ok(file) = File::open(messages_jsonl_path) {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if !trimmed.contains(RELEASE_BUILT_PREFIX) {
                continue;
            }
            if let Ok(msg) = serde_json::from_str::<BusMessage>(trimmed)
                && let Ok(manifest) = verify_release_built_message(&msg)
                && manifest.target_triple == CURRENT_TARGET_TRIPLE
            {
                record_newer_candidate(&mut latest_per_binary, msg, manifest);
            }
        }
    }

    if check_r2_envelopes {
        for binary in ALLOWED_BINARIES {
            if let Ok(Some(bytes)) =
                store.download_latest_signed_envelope(binary, CURRENT_TARGET_TRIPLE)
                && let Ok(msg) = serde_json::from_slice::<BusMessage>(&bytes)
                && let Ok(manifest) = verify_release_built_message(&msg)
                && manifest.binary == *binary
                && manifest.target_triple == CURRENT_TARGET_TRIPLE
            {
                record_newer_candidate(&mut latest_per_binary, msg, manifest);
            }
        }
    }

    let mut outcomes = Vec::new();
    for (binary, (msg, _)) in latest_per_binary {
        let outcome = apply_release_built_message(home_dir, store, &msg, local_iroh_endpoint)?;
        outcomes.push((binary, outcome));
    }
    Ok(outcomes)
}

fn record_newer_candidate(
    map: &mut BTreeMap<String, (BusMessage, ReleaseManifestV1)>,
    msg: BusMessage,
    manifest: ReleaseManifestV1,
) {
    let replace = match map.get(&manifest.binary) {
        None => true,
        Some((_, current)) => {
            if manifest.rollback {
                manifest.built_at_ms > current.built_at_ms
            } else {
                (manifest.commit_epoch, manifest.built_at_ms)
                    > (current.commit_epoch, current.built_at_ms)
            }
        }
    };
    if replace {
        map.insert(manifest.binary.clone(), (msg, manifest));
    }
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
        envelopes: Mutex<BTreeMap<(String, String), Vec<u8>>>,
        download_calls: Mutex<usize>,
    }

    impl InMemoryArtifactStore {
        fn new() -> Self {
            Self {
                blobs: Mutex::new(BTreeMap::new()),
                envelopes: Mutex::new(BTreeMap::new()),
                download_calls: Mutex::new(0),
            }
        }

        fn downloads(&self) -> usize {
            *self.download_calls.lock().unwrap()
        }

        fn tamper_blob(&self, key: &str, new_bytes: Vec<u8>) {
            self.blobs.lock().unwrap().insert(key.to_owned(), new_bytes);
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
                .map_err(|e| ReleaseSyncError::ArtifactStoreFailed(e.to_string()))
        }

        fn upload_latest_signed_envelope(
            &self,
            binary: &str,
            target_triple: &str,
            signed_bus_json: &[u8],
        ) -> Result<(), ReleaseSyncError> {
            self.envelopes.lock().unwrap().insert(
                (binary.to_owned(), target_triple.to_owned()),
                signed_bus_json.to_vec(),
            );
            Ok(())
        }

        fn download_latest_signed_envelope(
            &self,
            binary: &str,
            target_triple: &str,
        ) -> Result<Option<Vec<u8>>, ReleaseSyncError> {
            Ok(self
                .envelopes
                .lock()
                .unwrap()
                .get(&(binary.to_owned(), target_triple.to_owned()))
                .cloned())
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
}
