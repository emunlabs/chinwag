//! Deterministic double-build compiler and domain-separated Ed25519 + SLSA v1.0 provenance signer.
#![forbid(unsafe_code)]

use crate::{
    PLUGIN_RELEASE_DOMAIN_TAG, PackError,
    archive::BundleTree,
    manifest::{
        LoadedCanonicalBundle, check_json_no_hooks, check_toml_no_hooks, inspect_text_invariants,
        read_regular_file_no_symlink,
    },
    targets::{SharedCompiledAssets, StoreTarget, canonical_json_bytes, compile_target},
    verification::{
        NativeValidatorMode, VerificationReport, dsse_pae, verify_release_dir,
        verify_runtime_mcp_catalog_zero_drift,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Non-cloneable, zeroize-on-drop Ed25519 signing seed (`INV-PLUGIN-PROVENANCE-01`).
pub struct ReleaseSigningSeed {
    seed: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for ReleaseSigningSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReleaseSigningSeed([REDACTED])")
    }
}

impl ReleaseSigningSeed {
    /// Allocate a fresh ephemeral 256-bit Ed25519 seed from OS CSPRNG (`getrandom`).
    pub fn generate_ephemeral() -> Result<Self, PackError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed).map_err(|e| PackError::ProvenanceVerification {
            detail: format!("OS CSPRNG failure: {e}"),
        })?;
        Ok(Self { seed })
    }

    /// Construct from explicit 32-byte seed material (used by RFC 8032 KATs and offline seed files).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(bytes),
        }
    }

    /// Read an Ed25519 seed from an owner-only (`0600`) non-symlink, single-link regular file
    /// opened via `O_NOFOLLOW`, accepting either 32 raw bytes or 64 ASCII hex digits, and
    /// zeroizing all intermediate buffers immediately.
    pub fn from_seed_file(path: &Path) -> Result<Self, PackError> {
        let raw = read_private_0600_seed_bytes(path)?;
        let mut out = Zeroizing::new([0u8; 32]);
        if raw.len() == 32 {
            out.copy_from_slice(&raw);
            return Ok(Self { seed: out });
        }
        let text = std::str::from_utf8(&raw).map_err(|_| PackError::ProvenanceVerification {
            detail: "seed file must be 32 raw bytes or 64 hex characters".into(),
        })?;
        let trimmed = text.trim();
        if trimmed.len() != 64 {
            return Err(PackError::ProvenanceVerification {
                detail: format!(
                    "expected 32 raw bytes or 64 hex chars in seed file, got {} chars",
                    trimmed.len()
                ),
            });
        }
        let decoded = Zeroizing::new(hex::decode(trimmed).map_err(|e| {
            PackError::ProvenanceVerification {
                detail: format!("invalid hex in seed file: {e}"),
            }
        })?);
        out.copy_from_slice(&decoded);
        Ok(Self { seed: out })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        let sk = SigningKey::from_bytes(&self.seed);
        sk.verifying_key()
    }

    /// Sign `PLUGIN_RELEASE_DOMAIN_TAG || payload` (`"CHINWAG_PLUGIN_RELEASE_V1\0" || payload`).
    pub fn sign_domain_separated(&self, payload: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(&self.seed);
        let mut msg = Vec::with_capacity(PLUGIN_RELEASE_DOMAIN_TAG.len() + payload.len());
        msg.extend_from_slice(PLUGIN_RELEASE_DOMAIN_TAG);
        msg.extend_from_slice(payload);
        sk.sign(&msg).to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompiledArchiveRecord {
    pub target: StoreTarget,
    pub relative_path: String,
    pub sha256: String,
    pub blake3: String,
    pub size_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompiledReleaseSummary {
    pub plugin_id: String,
    pub version: String,
    pub output_dir: String,
    pub signing_public_key_hex: String,
    pub sha256sums_sha256: String,
    pub blake3sums_blake3: String,
    pub provenance_sha256: String,
    pub double_build_verified: bool,
    pub archives: Vec<CompiledArchiveRecord>,
    pub verification: Option<VerificationReport>,
}

/// Build the canonical signed message binding both `SHA256SUMS` and `BLAKE3SUMS`.
pub fn release_manifest_signing_payload(sha256sums: &[u8], blake3sums: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(sha256sums.len() + 1 + blake3sums.len());
    payload.extend_from_slice(sha256sums);
    payload.push(0u8);
    payload.extend_from_slice(blake3sums);
    payload
}

/// Execute two independent deterministic compilation passes in separate temporary directories,
/// assert byte-for-byte identity across every generated artifact, write the verified output to `out_dir`,
/// and optionally run full cryptographic, structural, live-MCP-drift, and native CLI verification.
pub fn build_deterministic_release(
    manifest_path: &Path,
    out_dir: &Path,
    seed_file: Option<&Path>,
    verify: bool,
    native_mode: NativeValidatorMode,
) -> Result<CompiledReleaseSummary, PackError> {
    let bundle = LoadedCanonicalBundle::load(manifest_path)?;
    verify_runtime_mcp_catalog_zero_drift(&bundle)?;

    let signing_seed = match seed_file {
        Some(path) => ReleaseSigningSeed::from_seed_file(path)?,
        None => ReleaseSigningSeed::generate_ephemeral()?,
    };

    let temp_a = TempBuildDir::create("pass-a")?;
    let temp_b = TempBuildDir::create("pass-b")?;

    let pass_a_files = compile_release_to_map(&bundle, &signing_seed)?;
    write_flat_tree(temp_a.path(), &pass_a_files)?;

    // Second independent pass from the canonical bundle in a separate directory:
    let pass_b_files = compile_release_to_map(&bundle, &signing_seed)?;
    write_flat_tree(temp_b.path(), &pass_b_files)?;

    assert_trees_byte_identical(temp_a.path(), temp_b.path(), &pass_a_files)?;

    // Populate destination `out_dir` cleanly (refusing symlinked out_dir)
    if out_dir.exists() {
        let meta = fs::symlink_metadata(out_dir).map_err(|e| PackError::Io {
            path: out_dir.display().to_string(),
            message: e.to_string(),
        })?;
        if meta.file_type().is_symlink() {
            return Err(PackError::SymlinkOrUnsafeFile {
                path: out_dir.display().to_string(),
            });
        }
        fs::remove_dir_all(out_dir).map_err(|e| PackError::Io {
            path: out_dir.display().to_string(),
            message: e.to_string(),
        })?;
    }
    write_flat_tree(out_dir, &pass_a_files)?;

    let mut archives = Vec::new();
    for target in StoreTarget::ALL {
        let filename =
            target.archive_filename(&bundle.manifest.plugin.id, &bundle.manifest.plugin.version);
        let rel = format!("archives/{filename}");
        let bytes = pass_a_files.get(&rel).ok_or_else(|| PackError::Archive {
            detail: format!("missing compiled archive `{rel}`"),
        })?;
        archives.push(CompiledArchiveRecord {
            target,
            relative_path: rel,
            sha256: sha256_hex(bytes),
            blake3: blake3_hex(bytes),
            size_bytes: bytes.len(),
        });
    }

    let sha256sums_bytes = pass_a_files.get("SHA256SUMS").unwrap();
    let blake3sums_bytes = pass_a_files.get("BLAKE3SUMS").unwrap();
    let provenance_bytes = pass_a_files.get("provenance.json").unwrap();

    let expected_pubkey = signing_seed.verifying_key().to_bytes();
    let verification = if verify {
        Some(verify_release_dir(
            out_dir,
            &bundle,
            Some(&expected_pubkey),
            native_mode,
        )?)
    } else {
        None
    };

    Ok(CompiledReleaseSummary {
        plugin_id: bundle.manifest.plugin.id.clone(),
        version: bundle.manifest.plugin.version.clone(),
        output_dir: out_dir.display().to_string(),
        signing_public_key_hex: hex::encode(signing_seed.verifying_key().to_bytes()),
        sha256sums_sha256: sha256_hex(sha256sums_bytes),
        blake3sums_blake3: blake3_hex(blake3sums_bytes),
        provenance_sha256: sha256_hex(provenance_bytes),
        double_build_verified: true,
        archives,
        verification,
    })
}

/// Compile all 7 store trees, archives, SLSA v1.0 provenance, checksums, and signatures in memory.
pub fn compile_release_to_map(
    bundle: &LoadedCanonicalBundle,
    signing_seed: &ReleaseSigningSeed,
) -> Result<BTreeMap<String, Vec<u8>>, PackError> {
    let shared_assets = SharedCompiledAssets::build(bundle)?;
    let mut all_files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut subjects: Vec<Value> = Vec::new();
    let mut checksum_targets: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for target in StoreTarget::ALL {
        let tree = compile_target(target, bundle, &shared_assets)?;
        inspect_compiled_tree(target, &tree)?;

        for (rel, entry) in tree.files() {
            let unpacked_rel = format!("targets/{}/{rel}", target.slug());
            all_files.insert(unpacked_rel, entry.bytes.clone());
        }

        let archive_bytes = tree.to_deterministic_tar_gz()?;
        let archive_name =
            target.archive_filename(&bundle.manifest.plugin.id, &bundle.manifest.plugin.version);
        let archive_rel = format!("archives/{archive_name}");

        subjects.push(json!({
            "name": archive_rel,
            "digest": {
                "sha256": sha256_hex(&archive_bytes),
                "blake3": blake3_hex(&archive_bytes),
            }
        }));
        checksum_targets.insert(archive_rel.clone(), archive_bytes.clone());
        all_files.insert(archive_rel, archive_bytes);
    }

    let manifest_sha256 = sha256_hex(&bundle.manifest_raw_bytes);
    let manifest_blake3 = blake3_hex(&bundle.manifest_raw_bytes);
    let pubkey_hex = hex::encode(signing_seed.verifying_key().to_bytes());

    // SLSA v1.0 in-toto Statement (`https://in-toto.io/Statement/v1` + `https://slsa.dev/provenance/v1`)
    let provenance_statement = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://chinwag.sh/plugin-pack/v1",
                "externalParameters": {
                    "pluginId": bundle.manifest.plugin.id,
                    "version": bundle.manifest.plugin.version,
                    "remoteMcpUrl": bundle.manifest.endpoints.remote_mcp_url,
                    "targets": StoreTarget::ALL.iter().map(|t| t.slug()).collect::<Vec<_>>(),
                },
                "internalParameters": {
                    "deterministicTarUstar": true,
                    "gzipMtimeZeroOsUnix": true,
                    "domainSeparationTag": "CHINWAG_PLUGIN_RELEASE_V1\\0",
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/emunlabs/chinwag#plugins/canonical/chinwag-plugin.toml",
                        "digest": {
                            "sha256": manifest_sha256,
                            "blake3": manifest_blake3,
                        }
                    }
                ]
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/emunlabs/chinwag/crates/chinwag-plugin-pack@v1",
                    "version": {
                        "chinwag-plugin-pack": env!("CARGO_PKG_VERSION"),
                    }
                },
                "metadata": {
                    "invocationId": format!("deterministic-{}-{}", bundle.manifest.plugin.id, bundle.manifest.plugin.version),
                }
            }
        }
    });
    let provenance_bytes = canonical_json_bytes(&provenance_statement)?;
    checksum_targets.insert("provenance.json".into(), provenance_bytes.clone());
    all_files.insert("provenance.json".into(), provenance_bytes.clone());

    let mut sha256sums = String::new();
    let mut blake3sums = String::new();
    for (rel, bytes) in &checksum_targets {
        sha256sums.push_str(&format!("{}  {rel}\n", sha256_hex(bytes)));
        blake3sums.push_str(&format!("{}  {rel}\n", blake3_hex(bytes)));
    }
    let sha256sums_bytes = sha256sums.into_bytes();
    let blake3sums_bytes = blake3sums.into_bytes();

    let manifest_payload = release_manifest_signing_payload(&sha256sums_bytes, &blake3sums_bytes);
    let manifest_sig = signing_seed.sign_domain_separated(&manifest_payload);

    let payload_type = "application/vnd.in-toto+json";
    let pae = dsse_pae(payload_type, &provenance_bytes);
    let dsse_sig = signing_seed.sign_domain_separated(&pae);
    let key_id = &pubkey_hex[..16];

    let sigstore_bundle = json!({
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {
            "publicKey": {
                "hint": key_id,
                "rawBytes": BASE64.encode(signing_seed.verifying_key().to_bytes()),
            }
        },
        "dsseEnvelope": {
            "payloadType": payload_type,
            "payload": BASE64.encode(&provenance_bytes),
            "signatures": [
                {
                    "keyid": key_id,
                    "sig": BASE64.encode(dsse_sig),
                }
            ]
        }
    });
    let sigstore_bytes = canonical_json_bytes(&sigstore_bundle)?;

    all_files.insert("SHA256SUMS".into(), sha256sums_bytes);
    all_files.insert("BLAKE3SUMS".into(), blake3sums_bytes);
    all_files.insert("SHA256SUMS.sig".into(), manifest_sig.to_vec());
    all_files.insert(
        "SHA256SUMS.sig.hex".into(),
        format!("{}\n", hex::encode(manifest_sig)).into_bytes(),
    );
    all_files.insert(
        "release-signing-pubkey.hex".into(),
        format!("{pubkey_hex}\n").into_bytes(),
    );
    all_files.insert("provenance.sigstore.json".into(), sigstore_bytes);

    Ok(all_files)
}

fn inspect_compiled_tree(target: StoreTarget, tree: &BundleTree) -> Result<(), PackError> {
    for (rel, entry) in tree.files() {
        if rel.ends_with(".png") {
            continue;
        }
        let ctx = format!("{}:{rel}", target.slug());
        let text = std::str::from_utf8(&entry.bytes).map_err(|e| PackError::StoreValidation {
            target: target.slug().into(),
            detail: format!("non-UTF-8 text file `{rel}`: {e}"),
        })?;
        if rel.ends_with(".json") {
            let parsed: Value =
                serde_json::from_str(text).map_err(|e| PackError::StoreValidation {
                    target: target.slug().into(),
                    detail: format!("invalid JSON in `{rel}`: {e}"),
                })?;
            check_json_no_hooks(&parsed, &ctx)?;
        } else {
            inspect_text_invariants(text, &ctx, true)?;
            if rel.ends_with(".toml") {
                let parsed: toml::Value =
                    toml::from_str(text).map_err(|e| PackError::StoreValidation {
                        target: target.slug().into(),
                        detail: format!("invalid TOML in `{rel}`: {e}"),
                    })?;
                check_toml_no_hooks(&parsed, &ctx)?;
            }
        }
    }
    Ok(())
}

fn write_flat_tree(root: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<(), PackError> {
    fs::create_dir_all(root).map_err(|e| PackError::Io {
        path: root.display().to_string(),
        message: e.to_string(),
    })?;
    for (rel, bytes) in files {
        let full = root.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).map_err(|e| PackError::Io {
                path: parent.display().to_string(),
                message: e.to_string(),
            })?;
        }
        fs::write(&full, bytes).map_err(|e| PackError::Io {
            path: full.display().to_string(),
            message: e.to_string(),
        })?;
    }
    Ok(())
}

fn assert_trees_byte_identical(
    dir_a: &Path,
    dir_b: &Path,
    expected: &BTreeMap<String, Vec<u8>>,
) -> Result<(), PackError> {
    for rel in expected.keys() {
        let bytes_a = read_regular_file_no_symlink(&dir_a.join(rel))?;
        let bytes_b = read_regular_file_no_symlink(&dir_b.join(rel))?;
        let sha_a = Sha256::digest(&bytes_a);
        let sha_b = Sha256::digest(&bytes_b);
        let b3_a = blake3::hash(&bytes_a);
        let b3_b = blake3::hash(&bytes_b);
        if bytes_a.len() != bytes_b.len()
            || !bool::from(sha_a.as_slice().ct_eq(sha_b.as_slice()))
            || !bool::from(b3_a.as_bytes().ct_eq(b3_b.as_bytes()))
            || bytes_a != bytes_b
        {
            return Err(PackError::NonDeterministicBuild {
                artifact: rel.clone(),
            });
        }
    }
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

struct TempBuildDir {
    path: PathBuf,
}

impl TempBuildDir {
    fn create(label: &str) -> Result<Self, PackError> {
        let mut rnd = [0u8; 12];
        getrandom::fill(&mut rnd).map_err(|e| PackError::ProvenanceVerification {
            detail: format!("CSPRNG error: {e}"),
        })?;
        let path =
            std::env::temp_dir().join(format!("chinwag-plugin-pack-{label}-{}", hex::encode(rnd)));
        fs::create_dir_all(&path).map_err(|e| PackError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempBuildDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn read_private_0600_seed_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>, PackError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    use std::io::Read as _;

    let lstat_meta = fs::symlink_metadata(path).map_err(|e| PackError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    if lstat_meta.file_type().is_symlink() || !lstat_meta.file_type().is_file() {
        return Err(PackError::SymlinkOrUnsafeFile {
            path: path.display().to_string(),
        });
    }

    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| PackError::SymlinkOrUnsafeFile {
        path: path.display().to_string(),
    })?;
    let stat = fstat(&fd).map_err(|e| PackError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    let raw_mode = u32::from(stat.st_mode);
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(PackError::SymlinkOrUnsafeFile {
            path: path.display().to_string(),
        });
    }
    if (raw_mode & 0o777) != 0o600 {
        return Err(PackError::ProvenanceVerification {
            detail: format!(
                "signing seed file `{}` must have exact 0600 permissions (got {:04o})",
                path.display(),
                raw_mode & 0o777
            ),
        });
    }
    if stat.st_size <= 0 || stat.st_size > 256 {
        return Err(PackError::ProvenanceVerification {
            detail: format!(
                "signing seed file `{}` must be 1..=256 bytes (got {})",
                path.display(),
                stat.st_size
            ),
        });
    }
    let mut file = fs::File::from(fd);
    let mut buf = Zeroizing::new(Vec::with_capacity(stat.st_size as usize));
    file.read_to_end(&mut buf).map_err(|e| PackError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    Ok(buf)
}

#[cfg(not(unix))]
fn read_private_0600_seed_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>, PackError> {
    Ok(Zeroizing::new(read_regular_file_no_symlink(path)?))
}
