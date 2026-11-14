// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Zero-Nix-Syntax Deterministic Lockfile Compiler (`chinwag env lock` · `INV-NIX-ZERO-SYNTAX-01`).
//!
//! Synthesizes `.chinwag/flake.lock` (Nix flake lock schema `version: 7`) directly
//! from repository manifests (`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`,
//! `package.json`, `pyproject.toml`, `go.mod`, and optional `.chinwag/env.ts`)
//! with content-addressed SRI `narHash` (`sha256-<base64>`), SHA-256 closure
//! pinning, and `Ed25519` `verify_strict` verification receipts.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const FLAKE_LOCK_SCHEMA_VERSION: u8 = 7;
pub const ENV_LOCK_RECEIPT_SCHEMA: &str = "chinwag.env.lock.receipt.v1";
const RECEIPT_SIGNING_DOMAIN: &[u8] = b"chinwag-env-lock-receipt/v1\0";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum EnvLockError {
    #[error("repository root `{0}` is invalid or contains a symlink at a protected boundary")]
    InvalidRepositoryRoot(String),
    #[error("forbidden `.nix` expression file detected at `{0}` (INV-NIX-ZERO-SYNTAX-01)")]
    ForbiddenNixSyntaxFile(String),
    #[error(
        "no supported workspace manifest found in `{0}` (expected Cargo.toml, rust-toolchain.toml, package.json, pyproject.toml, go.mod, or .chinwag/env.ts)"
    )]
    NoSupportedManifests(String),
    #[error("manifest `{path}` could not be read or parsed: {detail}")]
    ManifestParse { path: String, detail: String },
    #[error("failed to serialize or write `.chinwag/flake.lock`: {0}")]
    Io(String),
    #[error("Ed25519 receipt verification failed: {0}")]
    ReceiptVerification(&'static str),
    #[error("lockfile drift detected: {0}")]
    LockfileDrift(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestDigestRecord {
    pub relative_path: String,
    pub sha256_hex: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakeLockedRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub ecosystem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_pin: Option<String>,
    #[serde(rename = "narHash")]
    pub nar_hash: String,
    pub closure_sha256: String,
    pub source_manifests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakeNode {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputs: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<FlakeLockedRef>,
}

/// Deterministic Nix `flake.lock` v7 JSON document synthesized with zero `.nix` syntax.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakeLockV7 {
    pub nodes: BTreeMap<String, FlakeNode>,
    pub root: String,
    pub version: u8,
}

/// Complete compiled environment lock output before or after receipt signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledEnvLock {
    pub flake_lock: FlakeLockV7,
    pub canonical_json: String,
    pub flake_lock_sha256_hex: String,
    pub closure_sha256_hex: String,
    pub manifests: Vec<ManifestDigestRecord>,
    pub node_nar_hashes: BTreeMap<String, String>,
}

/// Detached `Ed25519` verification receipt binding `.chinwag/flake.lock`, its
/// `narHash` closure pins, and workspace manifest SHA-256 digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvLockReceiptV1 {
    pub schema: String,
    pub zero_nix_syntax: bool,
    pub flake_lock_sha256: String,
    pub closure_sha256: String,
    pub node_nar_hashes: BTreeMap<String, String>,
    pub manifests: Vec<ManifestDigestRecord>,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
}

/// Scans `.chinwag/` (if present) and root to ensure no `.nix` expression files
/// violate `INV-NIX-ZERO-SYNTAX-01`.
pub fn verify_zero_nix_syntax(repo_root: &Path) -> Result<(), EnvLockError> {
    check_no_nix_in_dir(repo_root, false)?;
    let dot_chinwag = repo_root.join(".chinwag");
    if dot_chinwag.exists() {
        let meta = fs::symlink_metadata(&dot_chinwag)
            .map_err(|e| EnvLockError::Io(format!(".chinwag metadata: {e}")))?;
        if meta.file_type().is_symlink() {
            return Err(EnvLockError::InvalidRepositoryRoot(
                dot_chinwag.display().to_string(),
            ));
        }
        if meta.is_dir() {
            check_no_nix_in_dir(&dot_chinwag, true)?;
        }
    }
    Ok(())
}

fn check_no_nix_in_dir(dir: &Path, recursive: bool) -> Result<(), EnvLockError> {
    let entries = fs::read_dir(dir).map_err(|e| EnvLockError::Io(e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| EnvLockError::Io(e.to_string()))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| EnvLockError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_file() && path.extension().and_then(|s| s.to_str()) == Some("nix") {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown.nix")
                .to_owned();
            return Err(EnvLockError::ForbiddenNixSyntaxFile(file_name));
        }
        if recursive && meta.is_dir() {
            check_no_nix_in_dir(&path, true)?;
        }
    }
    Ok(())
}

/// Deterministically compiles `.chinwag/flake.lock` from repository manifests (`INV-NIX-ZERO-SYNTAX-01`).
pub fn compile_workspace_env_lock(repo_root: &Path) -> Result<CompiledEnvLock, EnvLockError> {
    let root_meta = fs::symlink_metadata(repo_root)
        .map_err(|_| EnvLockError::InvalidRepositoryRoot(repo_root.display().to_string()))?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
        return Err(EnvLockError::InvalidRepositoryRoot(
            repo_root.display().to_string(),
        ));
    }

    verify_zero_nix_syntax(repo_root)?;

    let candidate_files = [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "pyproject.toml",
        "go.mod",
        ".chinwag/env.ts",
    ];

    let mut raw_manifests: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut manifests = Vec::new();

    for rel in candidate_files {
        let full = repo_root.join(rel);
        if !full.exists() {
            continue;
        }
        let meta = fs::symlink_metadata(&full).map_err(|e| EnvLockError::ManifestParse {
            path: rel.to_owned(),
            detail: e.to_string(),
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(EnvLockError::ManifestParse {
                path: rel.to_owned(),
                detail: "manifest must be a regular non-symlink file".to_owned(),
            });
        }
        if meta.len() > MAX_MANIFEST_BYTES {
            return Err(EnvLockError::ManifestParse {
                path: rel.to_owned(),
                detail: "manifest exceeds 16 MiB bound".to_owned(),
            });
        }
        let bytes = fs::read(&full).map_err(|e| EnvLockError::ManifestParse {
            path: rel.to_owned(),
            detail: e.to_string(),
        })?;
        let sha256_hex = hex::encode(Sha256::digest(&bytes));
        manifests.push(ManifestDigestRecord {
            relative_path: rel.to_owned(),
            sha256_hex,
            size_bytes: bytes.len() as u64,
        });
        raw_manifests.insert(rel.to_owned(), bytes);
    }

    if manifests.is_empty() {
        return Err(EnvLockError::NoSupportedManifests(
            repo_root.display().to_string(),
        ));
    }

    let mut nodes: BTreeMap<String, FlakeNode> = BTreeMap::new();
    let mut root_inputs: BTreeMap<String, String> = BTreeMap::new();
    let mut node_nar_hashes: BTreeMap<String, String> = BTreeMap::new();

    // 1. Rust ecosystem closure (`Cargo.toml` / `rust-toolchain.toml` / `Cargo.lock`)
    if raw_manifests.contains_key("Cargo.toml") || raw_manifests.contains_key("rust-toolchain.toml")
    {
        let mut rust_pin = None;
        if let Some(rt_bytes) = raw_manifests.get("rust-toolchain.toml") {
            let text = std::str::from_utf8(rt_bytes).map_err(|e| EnvLockError::ManifestParse {
                path: "rust-toolchain.toml".to_owned(),
                detail: e.to_string(),
            })?;
            let parsed: toml::Value =
                toml::from_str(text).map_err(|e| EnvLockError::ManifestParse {
                    path: "rust-toolchain.toml".to_owned(),
                    detail: e.to_string(),
                })?;
            if let Some(ch) = parsed
                .get("toolchain")
                .and_then(|t| t.get("channel"))
                .and_then(|v| v.as_str())
            {
                rust_pin = Some(ch.to_owned());
            }
        }
        if let Some(cargo_bytes) = raw_manifests.get("Cargo.toml") {
            let text =
                std::str::from_utf8(cargo_bytes).map_err(|e| EnvLockError::ManifestParse {
                    path: "Cargo.toml".to_owned(),
                    detail: e.to_string(),
                })?;
            let parsed: toml::Value =
                toml::from_str(text).map_err(|e| EnvLockError::ManifestParse {
                    path: "Cargo.toml".to_owned(),
                    detail: e.to_string(),
                })?;
            if rust_pin.is_none() {
                rust_pin = parsed
                    .get("workspace")
                    .and_then(|w| w.get("package"))
                    .and_then(|p| p.get("rust-version"))
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        parsed
                            .get("package")
                            .and_then(|p| p.get("rust-version"))
                            .and_then(|v| v.as_str())
                    })
                    .map(str::to_owned);
            }
        }
        let sources: Vec<String> = ["rust-toolchain.toml", "Cargo.toml", "Cargo.lock"]
            .into_iter()
            .filter(|k| raw_manifests.contains_key(*k))
            .map(str::to_owned)
            .collect();
        let locked = build_closure_node("rust", rust_pin, &sources, &raw_manifests);
        node_nar_hashes.insert("rust-toolchain".to_owned(), locked.nar_hash.clone());
        nodes.insert(
            "rust-toolchain".to_owned(),
            FlakeNode {
                inputs: None,
                locked: Some(locked),
            },
        );
        root_inputs.insert("rust-toolchain".to_owned(), "rust-toolchain".to_owned());
    }

    // 2. Node.js / TypeScript ecosystem closure (`package.json` + lockfiles)
    if let Some(pkg_bytes) = raw_manifests.get("package.json") {
        let parsed: serde_json::Value =
            serde_json::from_slice(pkg_bytes).map_err(|e| EnvLockError::ManifestParse {
                path: "package.json".to_owned(),
                detail: e.to_string(),
            })?;
        let node_pin = parsed
            .get("packageManager")
            .and_then(|v| v.as_str())
            .or_else(|| {
                parsed
                    .get("engines")
                    .and_then(|e| e.get("node"))
                    .and_then(|v| v.as_str())
            })
            .map(str::to_owned);
        let sources: Vec<String> = ["package.json", "package-lock.json", "pnpm-lock.yaml"]
            .into_iter()
            .filter(|k| raw_manifests.contains_key(*k))
            .map(str::to_owned)
            .collect();
        let locked = build_closure_node("nodejs", node_pin, &sources, &raw_manifests);
        node_nar_hashes.insert("nodejs-runtime".to_owned(), locked.nar_hash.clone());
        nodes.insert(
            "nodejs-runtime".to_owned(),
            FlakeNode {
                inputs: None,
                locked: Some(locked),
            },
        );
        root_inputs.insert("nodejs-runtime".to_owned(), "nodejs-runtime".to_owned());
    }

    // 3. Python (`pyproject.toml`)
    if let Some(py_bytes) = raw_manifests.get("pyproject.toml") {
        let text = std::str::from_utf8(py_bytes).map_err(|e| EnvLockError::ManifestParse {
            path: "pyproject.toml".to_owned(),
            detail: e.to_string(),
        })?;
        let parsed: toml::Value =
            toml::from_str(text).map_err(|e| EnvLockError::ManifestParse {
                path: "pyproject.toml".to_owned(),
                detail: e.to_string(),
            })?;
        let py_pin = parsed
            .get("project")
            .and_then(|p| p.get("requires-python"))
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let sources = vec!["pyproject.toml".to_owned()];
        let locked = build_closure_node("python", py_pin, &sources, &raw_manifests);
        node_nar_hashes.insert("python-runtime".to_owned(), locked.nar_hash.clone());
        nodes.insert(
            "python-runtime".to_owned(),
            FlakeNode {
                inputs: None,
                locked: Some(locked),
            },
        );
        root_inputs.insert("python-runtime".to_owned(), "python-runtime".to_owned());
    }

    // 4. Go (`go.mod`)
    if let Some(go_bytes) = raw_manifests.get("go.mod") {
        let text = std::str::from_utf8(go_bytes).map_err(|e| EnvLockError::ManifestParse {
            path: "go.mod".to_owned(),
            detail: e.to_string(),
        })?;
        let go_pin = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("go "))
            .map(|v| v.trim().to_owned());
        let sources = vec!["go.mod".to_owned()];
        let locked = build_closure_node("go", go_pin, &sources, &raw_manifests);
        node_nar_hashes.insert("go-toolchain".to_owned(), locked.nar_hash.clone());
        nodes.insert(
            "go-toolchain".to_owned(),
            FlakeNode {
                inputs: None,
                locked: Some(locked),
            },
        );
        root_inputs.insert("go-toolchain".to_owned(), "go-toolchain".to_owned());
    }

    // 5. Typed TypeScript environment spec (`.chinwag/env.ts`)
    if let Some(env_ts_bytes) = raw_manifests.get(".chinwag/env.ts") {
        let _ = std::str::from_utf8(env_ts_bytes).map_err(|e| EnvLockError::ManifestParse {
            path: ".chinwag/env.ts".to_owned(),
            detail: e.to_string(),
        })?;
        let sources = vec![".chinwag/env.ts".to_owned()];
        let locked = build_closure_node(
            "jinx-nixpkgs-ts",
            Some("v1".to_owned()),
            &sources,
            &raw_manifests,
        );
        node_nar_hashes.insert("chinwag-env-ts".to_owned(), locked.nar_hash.clone());
        nodes.insert(
            "chinwag-env-ts".to_owned(),
            FlakeNode {
                inputs: None,
                locked: Some(locked),
            },
        );
        root_inputs.insert("chinwag-env-ts".to_owned(), "chinwag-env-ts".to_owned());
    }

    if root_inputs.is_empty() {
        return Err(EnvLockError::NoSupportedManifests(
            repo_root.display().to_string(),
        ));
    }

    nodes.insert(
        "root".to_owned(),
        FlakeNode {
            inputs: Some(root_inputs),
            locked: None,
        },
    );

    let flake_lock = FlakeLockV7 {
        nodes,
        root: "root".to_owned(),
        version: FLAKE_LOCK_SCHEMA_VERSION,
    };

    let mut canonical_json =
        serde_json::to_string_pretty(&flake_lock).map_err(|e| EnvLockError::Io(e.to_string()))?;
    canonical_json.push('\n');

    let flake_lock_sha256_hex = hex::encode(Sha256::digest(canonical_json.as_bytes()));

    let mut closure_hasher = Sha256::new();
    closure_hasher.update(b"chinwag-cleanroom-closure-merkle/v1\0");
    for (node_id, nar_hash) in &node_nar_hashes {
        closure_hasher.update((node_id.len() as u32).to_be_bytes());
        closure_hasher.update(node_id.as_bytes());
        closure_hasher.update((nar_hash.len() as u32).to_be_bytes());
        closure_hasher.update(nar_hash.as_bytes());
    }
    let closure_sha256_hex = hex::encode(closure_hasher.finalize());

    Ok(CompiledEnvLock {
        flake_lock,
        canonical_json,
        flake_lock_sha256_hex,
        closure_sha256_hex,
        manifests,
        node_nar_hashes,
    })
}

fn build_closure_node(
    ecosystem: &str,
    version_pin: Option<String>,
    sources: &[String],
    raw_manifests: &BTreeMap<String, Vec<u8>>,
) -> FlakeLockedRef {
    let mut nar_hasher = Sha256::new();
    nar_hasher.update(b"chinwag-nar-closure/v1\0");
    nar_hasher.update(ecosystem.as_bytes());
    nar_hasher.update([0]);
    if let Some(ref pin) = version_pin {
        nar_hasher.update(pin.as_bytes());
    }
    nar_hasher.update([0]);
    for src in sources {
        nar_hasher.update((src.len() as u32).to_be_bytes());
        nar_hasher.update(src.as_bytes());
        if let Some(bytes) = raw_manifests.get(src) {
            let digest = Sha256::digest(bytes);
            nar_hasher.update(digest);
        }
    }
    let digest_bytes: [u8; 32] = nar_hasher.finalize().into();
    let nar_hash = format!("sha256-{}", BASE64_STANDARD.encode(digest_bytes));
    let closure_sha256 = hex::encode(digest_bytes);

    FlakeLockedRef {
        kind: "chinwag-cleanroom-closure".to_owned(),
        ecosystem: ecosystem.to_owned(),
        version_pin,
        nar_hash,
        closure_sha256,
        source_manifests: sources.to_vec(),
    }
}

fn canonical_receipt_preimage(
    flake_lock_sha256: &str,
    closure_sha256: &str,
    node_nar_hashes: &BTreeMap<String, String>,
    manifests: &[ManifestDigestRecord],
    signer_pubkey: &[u8; 32],
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(512);
    preimage.extend_from_slice(RECEIPT_SIGNING_DOMAIN);
    preimage.extend_from_slice(flake_lock_sha256.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(closure_sha256.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(signer_pubkey);
    preimage.extend_from_slice(&(node_nar_hashes.len() as u32).to_be_bytes());
    for (node, nar) in node_nar_hashes {
        preimage.extend_from_slice(&(node.len() as u32).to_be_bytes());
        preimage.extend_from_slice(node.as_bytes());
        preimage.extend_from_slice(&(nar.len() as u32).to_be_bytes());
        preimage.extend_from_slice(nar.as_bytes());
    }
    preimage.extend_from_slice(&(manifests.len() as u32).to_be_bytes());
    for m in manifests {
        preimage.extend_from_slice(&(m.relative_path.len() as u32).to_be_bytes());
        preimage.extend_from_slice(m.relative_path.as_bytes());
        preimage.extend_from_slice(&(m.sha256_hex.len() as u32).to_be_bytes());
        preimage.extend_from_slice(m.sha256_hex.as_bytes());
        preimage.extend_from_slice(&m.size_bytes.to_be_bytes());
    }
    preimage
}

/// Generates a fresh CSPRNG `Ed25519` receipt signing key with zeroized intermediate seed.
pub fn generate_receipt_signing_key() -> Result<SigningKey, EnvLockError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|e| EnvLockError::Io(e.to_string()))?;
    if bool::from(seed[..].ct_eq(&[0u8; 32])) {
        return Err(EnvLockError::ReceiptVerification(
            "degenerate zero entropy rejected",
        ));
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// Loads a 32-byte hex `Ed25519` seed from a regular (non-symlink) file with zeroized buffer.
pub fn signing_key_from_seed_file(path: &Path) -> Result<SigningKey, EnvLockError> {
    let raw = Zeroizing::new(read_non_symlink(path)?);
    let trimmed = std::str::from_utf8(&raw)
        .map_err(|_| EnvLockError::ReceiptVerification("seed file must be ASCII hex"))?
        .trim();
    let mut decoded = Zeroizing::new(
        hex::decode(trimmed)
            .map_err(|_| EnvLockError::ReceiptVerification("seed file must be 64 hex chars"))?,
    );
    let arr: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| EnvLockError::ReceiptVerification("seed file must decode to 32 bytes"))?;
    let mut seed = Zeroizing::new(arr);
    decoded.fill(0);
    if bool::from(seed[..].ct_eq(&[0u8; 32])) {
        seed.fill(0);
        return Err(EnvLockError::ReceiptVerification(
            "all-zero Ed25519 seed rejected",
        ));
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// Signs a compiled environment lock closure with the caller's `Ed25519` key.
pub fn sign_env_lock_receipt(
    compiled: &CompiledEnvLock,
    signing_key: &SigningKey,
) -> Result<EnvLockReceiptV1, EnvLockError> {
    let verifying = signing_key.verifying_key();
    if verifying.is_weak() {
        return Err(EnvLockError::ReceiptVerification("weak Ed25519 public key"));
    }
    let pub_bytes = verifying.to_bytes();
    let preimage = canonical_receipt_preimage(
        &compiled.flake_lock_sha256_hex,
        &compiled.closure_sha256_hex,
        &compiled.node_nar_hashes,
        &compiled.manifests,
        &pub_bytes,
    );
    let sig = signing_key.sign(&preimage);
    Ok(EnvLockReceiptV1 {
        schema: ENV_LOCK_RECEIPT_SCHEMA.to_owned(),
        zero_nix_syntax: true,
        flake_lock_sha256: compiled.flake_lock_sha256_hex.clone(),
        closure_sha256: compiled.closure_sha256_hex.clone(),
        node_nar_hashes: compiled.node_nar_hashes.clone(),
        manifests: compiled.manifests.clone(),
        signer_public_key_hex: hex::encode(pub_bytes),
        signature_hex: hex::encode(sig.to_bytes()),
    })
}

/// Strictly verifies an `EnvLockReceiptV1` (`verify_strict` + constant-time digest check).
pub fn verify_env_lock_receipt(
    receipt: &EnvLockReceiptV1,
    expected_flake_lock_bytes: &[u8],
    expected_signer: Option<&[u8; 32]>,
) -> Result<(), EnvLockError> {
    if receipt.schema != ENV_LOCK_RECEIPT_SCHEMA || !receipt.zero_nix_syntax {
        return Err(EnvLockError::ReceiptVerification(
            "unsupported receipt schema or zero_nix_syntax=false",
        ));
    }
    let actual_lock_sha = hex::encode(Sha256::digest(expected_flake_lock_bytes));
    if !bool::from(
        actual_lock_sha
            .as_bytes()
            .ct_eq(receipt.flake_lock_sha256.as_bytes()),
    ) {
        return Err(EnvLockError::ReceiptVerification(
            "flake.lock SHA-256 does not match signed receipt",
        ));
    }

    let pub_raw = hex::decode(&receipt.signer_public_key_hex)
        .map_err(|_| EnvLockError::ReceiptVerification("malformed signer public key hex"))?;
    let pub_arr: [u8; 32] = pub_raw
        .try_into()
        .map_err(|_| EnvLockError::ReceiptVerification("invalid signer public key length"))?;
    if let Some(pinned) = expected_signer
        && !bool::from(pub_arr.ct_eq(pinned))
    {
        return Err(EnvLockError::ReceiptVerification(
            "receipt signer does not match pinned Ed25519 key",
        ));
    }
    let vk = VerifyingKey::from_bytes(&pub_arr)
        .map_err(|_| EnvLockError::ReceiptVerification("invalid Ed25519 public key"))?;
    if vk.is_weak() {
        return Err(EnvLockError::ReceiptVerification(
            "weak small-order Ed25519 public key rejected",
        ));
    }

    let sig_raw = hex::decode(&receipt.signature_hex)
        .map_err(|_| EnvLockError::ReceiptVerification("malformed signature hex"))?;
    let sig_arr: [u8; 64] = sig_raw
        .try_into()
        .map_err(|_| EnvLockError::ReceiptVerification("invalid signature length"))?;
    let sig = Signature::from_bytes(&sig_arr);

    let preimage = canonical_receipt_preimage(
        &receipt.flake_lock_sha256,
        &receipt.closure_sha256,
        &receipt.node_nar_hashes,
        &receipt.manifests,
        &pub_arr,
    );
    vk.verify_strict(&preimage, &sig)
        .map_err(|_| EnvLockError::ReceiptVerification("Ed25519 verify_strict rejected signature"))
}

/// Writes `.chinwag/flake.lock` and `.chinwag/env-lock.receipt.json` safely,
/// rejecting symlinks at `.chinwag/` and output file targets.
pub fn write_env_lock_bundle(
    repo_root: &Path,
    compiled: &CompiledEnvLock,
    receipt: &EnvLockReceiptV1,
) -> Result<(std::path::PathBuf, std::path::PathBuf), EnvLockError> {
    verify_zero_nix_syntax(repo_root)?;
    let dot_chinwag = repo_root.join(".chinwag");
    if dot_chinwag.exists() {
        let meta =
            fs::symlink_metadata(&dot_chinwag).map_err(|e| EnvLockError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(EnvLockError::InvalidRepositoryRoot(
                dot_chinwag.display().to_string(),
            ));
        }
    } else {
        fs::create_dir_all(&dot_chinwag).map_err(|e| EnvLockError::Io(e.to_string()))?;
    }

    let lock_path = dot_chinwag.join("flake.lock");
    let receipt_path = dot_chinwag.join("env-lock.receipt.json");
    let mut receipt_json =
        serde_json::to_string_pretty(receipt).map_err(|e| EnvLockError::Io(e.to_string()))?;
    receipt_json.push('\n');

    atomic_write_regular_file(&lock_path, compiled.canonical_json.as_bytes())?;
    atomic_write_regular_file(&receipt_path, receipt_json.as_bytes())?;
    Ok((lock_path, receipt_path))
}

/// Re-compiles workspace manifests, verifies zero `.nix` syntax, checks `.chinwag/flake.lock`
/// byte-for-byte parity, and verifies the detached `Ed25519` receipt.
pub fn verify_env_lock_bundle(
    repo_root: &Path,
    expected_signer: Option<&[u8; 32]>,
) -> Result<EnvLockReceiptV1, EnvLockError> {
    let compiled = compile_workspace_env_lock(repo_root)?;
    let lock_path = repo_root.join(".chinwag").join("flake.lock");
    let receipt_path = repo_root.join(".chinwag").join("env-lock.receipt.json");

    let on_disk_lock = read_non_symlink(&lock_path)?;
    if on_disk_lock != compiled.canonical_json.as_bytes() {
        return Err(EnvLockError::LockfileDrift(
            ".chinwag/flake.lock is out of sync with workspace manifests; run `chinwag env lock`"
                .to_owned(),
        ));
    }
    let on_disk_receipt_bytes = read_non_symlink(&receipt_path)?;
    let receipt: EnvLockReceiptV1 = serde_json::from_slice(&on_disk_receipt_bytes)
        .map_err(|_| EnvLockError::ReceiptVerification("malformed env-lock.receipt.json"))?;
    verify_env_lock_receipt(&receipt, &on_disk_lock, expected_signer)?;
    if receipt.closure_sha256 != compiled.closure_sha256_hex {
        return Err(EnvLockError::LockfileDrift(
            "closure_sha256 mismatch between workspace manifests and receipt".to_owned(),
        ));
    }
    Ok(receipt)
}

fn read_non_symlink(path: &Path) -> Result<Vec<u8>, EnvLockError> {
    let meta = fs::symlink_metadata(path).map_err(|e| EnvLockError::Io(e.to_string()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(EnvLockError::Io(
            "refusing to read symlink or non-regular file".to_owned(),
        ));
    }
    fs::read(path).map_err(|e| EnvLockError::Io(e.to_string()))
}

fn atomic_write_regular_file(target: &Path, bytes: &[u8]) -> Result<(), EnvLockError> {
    if let Ok(meta) = fs::symlink_metadata(target)
        && meta.file_type().is_symlink()
    {
        return Err(EnvLockError::Io(
            "refusing to overwrite symlink target".to_owned(),
        ));
    }
    let parent = target
        .parent()
        .ok_or_else(|| EnvLockError::Io("missing parent directory".to_owned()))?;
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| EnvLockError::Io(e.to_string()))?;
    let tmp = parent.join(format!(
        ".chinwag-tmp-{}-{}",
        target.file_name().and_then(|n| n.to_str()).unwrap_or("out"),
        hex::encode(nonce)
    ));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| EnvLockError::Io(e.to_string()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| {
            let _ = fs::remove_file(&tmp);
            EnvLockError::Io(e.to_string())
        })?;
    drop(f);
    fs::rename(&tmp, target).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        EnvLockError::Io(e.to_string())
    })
}
