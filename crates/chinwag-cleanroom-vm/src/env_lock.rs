// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Zero-Nix-Syntax Deterministic Lockfile Compiler (`chinwag env lock` · `INV-NIX-ZERO-SYNTAX-01`).
//!
//! Synthesizes `.chinwag/flake.lock` (Nix flake lock schema `version: 7`) directly
//! from repository manifests (`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`,
//! `package.json`, `pyproject.toml`, `go.mod`, optional `.chinwag/env.ts`, and
//! resolved store closure pins in `.chinwag/store-closures.json`)
//! with content-addressed SRI `narHash` (`sha256-<base64>`), SHA-256 closure
//! pinning, strict `O_NOFOLLOW` + `nlink == 1` manifest reads, bounded NAR v1
//! serialization, and pinned `Ed25519` `verify_strict` verification receipts.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const FLAKE_LOCK_SCHEMA_VERSION: u8 = 7;
pub const ENV_LOCK_RECEIPT_SCHEMA: &str = "chinwag.env.lock.receipt.v1";
const RECEIPT_SIGNING_DOMAIN: &[u8] = b"chinwag-env-lock-receipt/v1\0";
const SSH_ED25519_WIRE_PREFIX: &[u8; 19] = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20";
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_NAR_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_NAR_DEPTH: usize = 64;
const MAX_SYMLINK_HOPS: usize = 16;

const CANDIDATE_MANIFEST_PATHS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "go.mod",
    ".chinwag/env.ts",
    ".chinwag/store-closures.json",
];

#[derive(Debug, thiserror::Error)]
pub enum EnvLockError {
    #[error("repository root `{0}` is invalid or contains a symlink at a protected boundary")]
    InvalidRepositoryRoot(String),
    #[error(
        "forbidden `.nix` expression file or symlink detected at `{0}` (INV-NIX-ZERO-SYNTAX-01)"
    )]
    ForbiddenNixSyntaxFile(String),
    #[error("forbidden symlink `{0}` detected inside cleanroom repository root")]
    SymlinkForbidden(String),
    #[error(
        "no supported workspace manifest found in `{0}` (expected Cargo.toml, rust-toolchain.toml, package.json, pyproject.toml, go.mod, or .chinwag/env.ts)"
    )]
    NoSupportedManifests(String),
    #[error(
        "missing resolved `/nix/store/...` closure pin for `{node}` (`{ecosystem}`) in `.chinwag/store-closures.json`"
    )]
    UnresolvedStoreClosure { node: String, ecosystem: String },
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

/// Resolved `/nix/store/<hash>-...` closure record in `.chinwag/store-closures.json`,
/// binding realized Nix store artifact NAR digests alongside workspace manifests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreClosureEntry {
    pub store_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nar_sha256_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlakeLockedRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub ecosystem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_pin: Option<String>,
    pub store_path: String,
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

/// Recursively walks the full repository tree (skipping only non-symlink `.git` VCS metadata)
/// and fails closed on ANY `.nix` file AND ANY symlink (`INV-NIX-ZERO-SYNTAX-01`).
pub fn verify_zero_nix_syntax(repo_root: &Path) -> Result<(), EnvLockError> {
    let canon_root = validate_repo_root_dir(repo_root)?;
    let dot_chinwag = repo_root.join(".chinwag");
    if let Ok(meta) = fs::symlink_metadata(&dot_chinwag)
        && meta.file_type().is_symlink()
    {
        return Err(EnvLockError::InvalidRepositoryRoot(
            dot_chinwag.display().to_string(),
        ));
    }
    check_no_nix_or_symlinks_recursive(repo_root, &canon_root, repo_root)
}

fn validate_repo_root_dir(repo_root: &Path) -> Result<PathBuf, EnvLockError> {
    let root_meta = fs::symlink_metadata(repo_root)
        .map_err(|_| EnvLockError::InvalidRepositoryRoot(repo_root.display().to_string()))?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
        return Err(EnvLockError::InvalidRepositoryRoot(
            repo_root.display().to_string(),
        ));
    }
    fs::canonicalize(repo_root)
        .map_err(|_| EnvLockError::InvalidRepositoryRoot(repo_root.display().to_string()))
}

fn check_no_nix_or_symlinks_recursive(
    repo_root: &Path,
    canon_root: &Path,
    dir: &Path,
) -> Result<(), EnvLockError> {
    let entries = fs::read_dir(dir).map_err(|e| EnvLockError::Io(e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| EnvLockError::Io(e.to_string()))?;
        let path = entry.path();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let meta = fs::symlink_metadata(&path).map_err(|e| EnvLockError::Io(e.to_string()))?;
        if file_name == ".git" {
            if meta.file_type().is_symlink() {
                return Err(EnvLockError::InvalidRepositoryRoot(
                    path.display().to_string(),
                ));
            }
            continue;
        }

        let rel_display = path
            .strip_prefix(repo_root)
            .unwrap_or(&path)
            .display()
            .to_string();

        if meta.file_type().is_symlink() {
            let link_is_nix = fs::read_link(&path)
                .ok()
                .and_then(|target| {
                    target
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|ext| ext.eq_ignore_ascii_case("nix"))
                })
                .unwrap_or(false);
            let name_is_nix = path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("nix"));
            if name_is_nix || link_is_nix {
                return Err(EnvLockError::ForbiddenNixSyntaxFile(rel_display));
            }
            if CANDIDATE_MANIFEST_PATHS.contains(&rel_display.as_str()) {
                return Err(EnvLockError::ManifestParse {
                    path: rel_display,
                    detail: "manifest must be a regular non-symlink file".to_owned(),
                });
            }
            return Err(EnvLockError::SymlinkForbidden(rel_display));
        }

        if meta.is_file()
            && path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("nix"))
        {
            return Err(EnvLockError::ForbiddenNixSyntaxFile(rel_display));
        }

        if meta.is_dir() {
            let canon_dir = fs::canonicalize(&path).map_err(|e| EnvLockError::Io(e.to_string()))?;
            if !canon_dir.starts_with(canon_root) {
                return Err(EnvLockError::InvalidRepositoryRoot(rel_display));
            }
            check_no_nix_or_symlinks_recursive(repo_root, canon_root, &path)?;
        }
    }
    Ok(())
}

/// Parses OpenSSH `allowed_signers` lines (`<principal> [opts] ssh-ed25519 <base64> [comment]`)
/// into validated non-weak 32-byte `Ed25519` public keys.
pub fn parse_openssh_allowed_signers_ed25519(content: &str) -> Result<Vec<[u8; 32]>, EnvLockError> {
    let mut keys = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(pos) = tokens.iter().position(|t| *t == "ssh-ed25519") else {
            continue;
        };
        let b64 = tokens
            .get(pos + 1)
            .ok_or(EnvLockError::ReceiptVerification(
                "malformed ssh-ed25519 entry in allowed_signers",
            ))?;
        let wire = BASE64_STANDARD
            .decode(b64)
            .map_err(|_| EnvLockError::ReceiptVerification("invalid base64 in allowed_signers"))?;
        if wire.len() != 51 || &wire[..19] != SSH_ED25519_WIRE_PREFIX {
            return Err(EnvLockError::ReceiptVerification(
                "invalid ssh-ed25519 wire framing in allowed_signers",
            ));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&wire[19..51]);
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| {
            EnvLockError::ReceiptVerification("invalid Ed25519 point in allowed_signers")
        })?;
        if vk.is_weak() {
            return Err(EnvLockError::ReceiptVerification(
                "weak Ed25519 public key rejected in allowed_signers",
            ));
        }
        keys.push(pk);
    }
    if keys.is_empty() {
        return Err(EnvLockError::ReceiptVerification(
            "allowed_signers contained zero ssh-ed25519 keys",
        ));
    }
    Ok(keys)
}

/// Formats a 32-byte `Ed25519` public key as a canonical OpenSSH `allowed_signers` line.
pub fn format_openssh_allowed_signer_line(
    principal: &str,
    ed25519_pubkey: &[u8; 32],
    comment: &str,
) -> String {
    let mut wire = Vec::with_capacity(51);
    wire.extend_from_slice(SSH_ED25519_WIRE_PREFIX);
    wire.extend_from_slice(ed25519_pubkey);
    format!(
        "{principal} ssh-ed25519 {} {comment}\n",
        BASE64_STANDARD.encode(&wire)
    )
}

/// Loads pinned `Ed25519` public keys from a regular (`O_NOFOLLOW`, `nlink == 1`) OpenSSH `allowed_signers` file.
pub fn load_allowed_signers_file(path: &Path) -> Result<Vec<[u8; 32]>, EnvLockError> {
    let bytes = read_non_symlink(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| EnvLockError::ReceiptVerification("allowed_signers must be UTF-8"))?;
    parse_openssh_allowed_signers_ed25519(text)
}

/// Deterministically compiles `.chinwag/flake.lock` from repository manifests (`INV-NIX-ZERO-SYNTAX-01`).
pub fn compile_workspace_env_lock(repo_root: &Path) -> Result<CompiledEnvLock, EnvLockError> {
    let canon_root = validate_repo_root_dir(repo_root)?;
    verify_zero_nix_syntax(repo_root)?;

    let mut raw_manifests: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut manifests = Vec::new();

    for rel in CANDIDATE_MANIFEST_PATHS {
        let full = repo_root.join(rel);
        if fs::symlink_metadata(&full).is_err() {
            continue;
        }
        let bytes = read_repo_regular_file_strict(repo_root, &canon_root, rel, MAX_MANIFEST_BYTES)
            .map_err(|e| match e {
                EnvLockError::ManifestParse { .. } => e,
                other => EnvLockError::ManifestParse {
                    path: (*rel).to_owned(),
                    detail: other.to_string(),
                },
            })?;
        let sha256_hex = hex::encode(Sha256::digest(&bytes));
        manifests.push(ManifestDigestRecord {
            relative_path: (*rel).to_owned(),
            sha256_hex,
            size_bytes: bytes.len() as u64,
        });
        raw_manifests.insert((*rel).to_owned(), bytes);
    }

    let store_closures: BTreeMap<String, StoreClosureEntry> =
        if let Some(closure_bytes) = raw_manifests.get(".chinwag/store-closures.json") {
            serde_json::from_slice(closure_bytes).map_err(|e| EnvLockError::ManifestParse {
                path: ".chinwag/store-closures.json".to_owned(),
                detail: e.to_string(),
            })?
        } else {
            BTreeMap::new()
        };

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
        let sources: Vec<String> = [
            "rust-toolchain.toml",
            "Cargo.toml",
            "Cargo.lock",
            ".chinwag/store-closures.json",
        ]
        .into_iter()
        .filter(|k| raw_manifests.contains_key(*k))
        .map(str::to_owned)
        .collect();
        let locked = build_closure_node(
            repo_root,
            &canon_root,
            "rust-toolchain",
            "rust",
            rust_pin,
            &sources,
            &raw_manifests,
            &store_closures,
        )?;
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
        let sources: Vec<String> = [
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            ".chinwag/store-closures.json",
        ]
        .into_iter()
        .filter(|k| raw_manifests.contains_key(*k))
        .map(str::to_owned)
        .collect();
        let locked = build_closure_node(
            repo_root,
            &canon_root,
            "nodejs-runtime",
            "nodejs",
            node_pin,
            &sources,
            &raw_manifests,
            &store_closures,
        )?;
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
        let sources: Vec<String> = ["pyproject.toml", ".chinwag/store-closures.json"]
            .into_iter()
            .filter(|k| raw_manifests.contains_key(*k))
            .map(str::to_owned)
            .collect();
        let locked = build_closure_node(
            repo_root,
            &canon_root,
            "python-runtime",
            "python",
            py_pin,
            &sources,
            &raw_manifests,
            &store_closures,
        )?;
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
        let sources: Vec<String> = ["go.mod", ".chinwag/store-closures.json"]
            .into_iter()
            .filter(|k| raw_manifests.contains_key(*k))
            .map(str::to_owned)
            .collect();
        let locked = build_closure_node(
            repo_root,
            &canon_root,
            "go-toolchain",
            "go",
            go_pin,
            &sources,
            &raw_manifests,
            &store_closures,
        )?;
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
        let sources: Vec<String> = [".chinwag/env.ts", ".chinwag/store-closures.json"]
            .into_iter()
            .filter(|k| raw_manifests.contains_key(*k))
            .map(str::to_owned)
            .collect();
        let locked = build_closure_node(
            repo_root,
            &canon_root,
            "chinwag-env-ts",
            "jinx-nixpkgs-ts",
            Some("v1".to_owned()),
            &sources,
            &raw_manifests,
            &store_closures,
        )?;
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
    for (node_id, node) in &flake_lock.nodes {
        if let Some(ref locked) = node.locked {
            closure_hasher.update((node_id.len() as u32).to_be_bytes());
            closure_hasher.update(node_id.as_bytes());
            closure_hasher.update((locked.nar_hash.len() as u32).to_be_bytes());
            closure_hasher.update(locked.nar_hash.as_bytes());
            closure_hasher.update((locked.closure_sha256.len() as u32).to_be_bytes());
            closure_hasher.update(locked.closure_sha256.as_bytes());
        }
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

const NAR_V1_MAGIC_HEADER: &[u8; 24] = b"\x0d\x00\x00\x00\x00\x00\x00\x00nix-archive-1\x00\x00\x00";

fn nar_write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), EnvLockError> {
    let pad = (8 - (bytes.len() % 8)) % 8;
    let added = 8usize.saturating_add(bytes.len()).saturating_add(pad);
    if out.len().saturating_add(added) > MAX_NAR_TOTAL_BYTES {
        return Err(EnvLockError::Io(format!(
            "NAR stream exceeds {} MiB total closure bound",
            MAX_NAR_TOTAL_BYTES / (1024 * 1024)
        )));
    }
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    if pad > 0 {
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    Ok(())
}

/// Serializes a regular file or directory tree into canonical Nix Archive v1 (`nix-archive-1`)
/// bytes (`INV-NIX-ZERO-SYNTAX-01`), enforcing a 64 MiB total closure byte bound, `O_NOFOLLOW`
/// file opens, and strictly intra-store relative symlinks (rejecting root symlinks and any
/// symlink escaping `root_path`).
pub fn serialize_nar_v1(path: &Path) -> Result<Vec<u8>, EnvLockError> {
    let root_meta = fs::symlink_metadata(path).map_err(|e| EnvLockError::Io(e.to_string()))?;
    if root_meta.file_type().is_symlink() {
        return Err(EnvLockError::Io(
            "refusing to serialize top-level symlink as NAR root".to_owned(),
        ));
    }
    let canon_root = fs::canonicalize(path).map_err(|e| EnvLockError::Io(e.to_string()))?;
    let mut out = Vec::with_capacity(256);
    nar_write_bytes(&mut out, b"nix-archive-1")?;
    serialize_nar_node(&canon_root, path, &[], 0, &mut out)?;
    Ok(out)
}

fn serialize_nar_node(
    canon_root: &Path,
    path: &Path,
    rel_stack: &[String],
    depth: usize,
    out: &mut Vec<u8>,
) -> Result<(), EnvLockError> {
    if depth > MAX_NAR_DEPTH {
        return Err(EnvLockError::Io(
            "NAR directory recursion depth exceeded".to_owned(),
        ));
    }
    let meta = fs::symlink_metadata(path).map_err(|e| EnvLockError::Io(e.to_string()))?;
    if meta.file_type().is_symlink() {
        if depth == 0 {
            return Err(EnvLockError::Io(
                "refusing to serialize symlink at NAR root".to_owned(),
            ));
        }
        let target = fs::read_link(path).map_err(|e| EnvLockError::Io(e.to_string()))?;
        let target_str = validate_intra_store_relative_symlink(canon_root, rel_stack, &target)?;
        nar_write_bytes(out, b"(")?;
        nar_write_bytes(out, b"type")?;
        nar_write_bytes(out, b"symlink")?;
        nar_write_bytes(out, b"target")?;
        nar_write_bytes(out, target_str.as_bytes())?;
        nar_write_bytes(out, b")")?;
        return Ok(());
    }

    nar_write_bytes(out, b"(")?;
    nar_write_bytes(out, b"type")?;
    if meta.is_file() {
        if meta.len() > MAX_MANIFEST_BYTES {
            return Err(EnvLockError::Io("NAR file exceeds 16 MiB bound".to_owned()));
        }
        if out.len().saturating_add(meta.len() as usize) > MAX_NAR_TOTAL_BYTES {
            return Err(EnvLockError::Io(
                "NAR stream exceeds 64 MiB total closure bound".to_owned(),
            ));
        }
        let (data, executable) = read_open_nofollow_for_nar(path, MAX_MANIFEST_BYTES)?;
        nar_write_bytes(out, b"regular")?;
        if executable {
            nar_write_bytes(out, b"executable")?;
            nar_write_bytes(out, b"")?;
        }
        nar_write_bytes(out, b"contents")?;
        nar_write_bytes(out, &data)?;
    } else if meta.is_dir() {
        let canon_dir = fs::canonicalize(path).map_err(|e| EnvLockError::Io(e.to_string()))?;
        if !canon_dir.starts_with(canon_root) {
            return Err(EnvLockError::Io(
                "NAR directory escaped closure root".to_owned(),
            ));
        }
        nar_write_bytes(out, b"directory")?;
        let mut children: Vec<(String, PathBuf)> = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| EnvLockError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| EnvLockError::Io(e.to_string()))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| EnvLockError::Io("non-UTF-8 filename in NAR directory".to_owned()))?;
            children.push((name, entry.path()));
        }
        children.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        for (name, child_path) in children {
            let mut child_stack = rel_stack.to_vec();
            child_stack.push(name.clone());
            nar_write_bytes(out, b"entry")?;
            nar_write_bytes(out, b"(")?;
            nar_write_bytes(out, b"name")?;
            nar_write_bytes(out, name.as_bytes())?;
            nar_write_bytes(out, b"node")?;
            serialize_nar_node(canon_root, &child_path, &child_stack, depth + 1, out)?;
            nar_write_bytes(out, b")")?;
        }
    } else {
        return Err(EnvLockError::Io(
            "unsupported special filesystem node in NAR serialization".to_owned(),
        ));
    }
    nar_write_bytes(out, b")")?;
    Ok(())
}

fn validate_intra_store_relative_symlink(
    canon_root: &Path,
    link_rel_stack: &[String],
    target: &Path,
) -> Result<String, EnvLockError> {
    let target_str = target
        .to_str()
        .ok_or_else(|| EnvLockError::Io("non-UTF-8 symlink target in NAR".to_owned()))?;
    if target_str.is_empty()
        || target_str.len() > 1024
        || target.is_absolute()
        || target_str.chars().any(char::is_control)
    {
        return Err(EnvLockError::Io(format!(
            "refusing non-relative or unsafe symlink target `{target_str}` in NAR closure"
        )));
    }

    // Start from parent directory of the symlink relative to `canon_root`
    let mut stack: Vec<String> = link_rel_stack
        .split_last()
        .map(|(_, parent)| parent.to_vec())
        .unwrap_or_default();
    for comp in target.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(seg) => {
                let s = seg
                    .to_str()
                    .ok_or_else(|| EnvLockError::Io("non-UTF-8 symlink segment".to_owned()))?;
                stack.push(s.to_owned());
            }
            Component::ParentDir => {
                if stack.pop().is_none() {
                    return Err(EnvLockError::Io(format!(
                        "symlink target `{target_str}` escapes NAR closure root"
                    )));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(EnvLockError::Io(format!(
                    "absolute symlink target `{target_str}` forbidden in NAR closure"
                )));
            }
        }
    }

    verify_symlink_hops_within_root(canon_root, &stack, 0)?;
    Ok(target_str.to_owned())
}

fn verify_symlink_hops_within_root(
    canon_root: &Path,
    rel_stack: &[String],
    hops: usize,
) -> Result<(), EnvLockError> {
    if hops > MAX_SYMLINK_HOPS {
        return Err(EnvLockError::Io(
            "symlink loop or excessive hop depth in NAR closure".to_owned(),
        ));
    }
    let mut cur = canon_root.to_path_buf();
    let mut built_stack: Vec<String> = Vec::new();
    for (idx, seg) in rel_stack.iter().enumerate() {
        cur.push(seg);
        built_stack.push(seg.clone());
        let Ok(meta) = fs::symlink_metadata(&cur) else {
            // Broken intra-store relative target that still resolves lexically inside `canon_root`
            return Ok(());
        };
        if meta.file_type().is_symlink() {
            let next_target = fs::read_link(&cur).map_err(|e| EnvLockError::Io(e.to_string()))?;
            if next_target.is_absolute() {
                return Err(EnvLockError::Io(
                    "chained symlink resolves to absolute path outside NAR root".to_owned(),
                ));
            }
            let mut next_stack = built_stack;
            let _ = next_stack.pop();
            for comp in next_target.components() {
                match comp {
                    Component::CurDir => {}
                    Component::Normal(s) => {
                        let part = s.to_str().ok_or_else(|| {
                            EnvLockError::Io("non-UTF-8 chained symlink".to_owned())
                        })?;
                        next_stack.push(part.to_owned());
                    }
                    Component::ParentDir => {
                        if next_stack.pop().is_none() {
                            return Err(EnvLockError::Io(
                                "chained symlink escapes NAR closure root".to_owned(),
                            ));
                        }
                    }
                    Component::RootDir | Component::Prefix(_) => {
                        return Err(EnvLockError::Io(
                            "chained symlink uses absolute prefix".to_owned(),
                        ));
                    }
                }
            }
            for rem in &rel_stack[idx + 1..] {
                next_stack.push(rem.clone());
            }
            return verify_symlink_hops_within_root(canon_root, &next_stack, hops + 1);
        }
    }
    Ok(())
}

fn validate_nix_store_path(store_path: &str) -> Result<(), EnvLockError> {
    let Some(rest) = store_path.strip_prefix("/nix/store/") else {
        return Err(EnvLockError::ManifestParse {
            path: ".chinwag/store-closures.json".to_owned(),
            detail: format!("invalid `/nix/store/` path `{store_path}`"),
        });
    };
    let Some((hash_part, name_part)) = rest.split_once('-') else {
        return Err(EnvLockError::ManifestParse {
            path: ".chinwag/store-closures.json".to_owned(),
            detail: format!(
                "store path `{store_path}` must match `/nix/store/<32-char-digest>-<name>`"
            ),
        });
    };
    if hash_part.len() != 32
        || !hash_part.bytes().all(|b| b.is_ascii_alphanumeric())
        || name_part.is_empty()
        || rest.contains('/')
        || rest.contains("..")
        || rest.chars().any(char::is_control)
    {
        return Err(EnvLockError::ManifestParse {
            path: ".chinwag/store-closures.json".to_owned(),
            detail: format!("malformed `/nix/store/` object identifier `{store_path}`"),
        });
    }
    Ok(())
}

fn resolve_store_nar_digest(
    repo_root: &Path,
    canon_root: &Path,
    entry: &StoreClosureEntry,
) -> Result<[u8; 32], EnvLockError> {
    validate_nix_store_path(&entry.store_path)?;

    let declared_digest = match entry.nar_sha256_hex {
        Some(ref hex_str) => {
            let decoded = hex::decode(hex_str.trim()).map_err(|_| EnvLockError::ManifestParse {
                path: ".chinwag/store-closures.json".to_owned(),
                detail: "nar_sha256_hex must be 64 hex chars".to_owned(),
            })?;
            let arr: [u8; 32] = decoded
                .try_into()
                .map_err(|_| EnvLockError::ManifestParse {
                    path: ".chinwag/store-closures.json".to_owned(),
                    detail: "nar_sha256_hex must decode to 32 bytes".to_owned(),
                })?;
            Some(arr)
        }
        None => None,
    };

    let artifact_digest = match entry.artifact_file {
        Some(ref rel_file) => {
            verify_repo_relative_components_no_symlink(repo_root, canon_root, rel_file)?;
            let target = repo_root.join(rel_file);
            let meta =
                fs::symlink_metadata(&target).map_err(|e| EnvLockError::Io(e.to_string()))?;
            if meta.file_type().is_symlink() {
                return Err(EnvLockError::Io(
                    "refusing to read symlinked store closure artifact".to_owned(),
                ));
            }
            let nar_stream = if meta.is_file() {
                let raw = read_repo_regular_file_strict(
                    repo_root,
                    canon_root,
                    rel_file,
                    MAX_MANIFEST_BYTES,
                )?;
                if raw.starts_with(NAR_V1_MAGIC_HEADER) {
                    raw
                } else {
                    serialize_nar_v1(&target)?
                }
            } else if meta.is_dir() {
                serialize_nar_v1(&target)?
            } else {
                return Err(EnvLockError::Io(
                    "store closure artifact must be a regular file or directory".to_owned(),
                ));
            };
            let arr: [u8; 32] = Sha256::digest(&nar_stream).into();
            Some(arr)
        }
        None => None,
    };

    // Always verify realized `/nix/store/...` paths on disk when present (`[F-08]`)
    let live_store = Path::new(&entry.store_path);
    let live_digest = if let Ok(live_meta) = fs::symlink_metadata(live_store) {
        if live_meta.file_type().is_symlink() {
            return Err(EnvLockError::ManifestParse {
                path: ".chinwag/store-closures.json".to_owned(),
                detail: format!(
                    "realized store path `{}` cannot be a symlink",
                    entry.store_path
                ),
            });
        }
        let nar_bytes = serialize_nar_v1(live_store)?;
        let arr: [u8; 32] = Sha256::digest(&nar_bytes).into();
        Some(arr)
    } else {
        None
    };

    if let (Some(decl), Some(actual_art)) = (declared_digest, artifact_digest)
        && !bool::from(decl.ct_eq(&actual_art))
    {
        return Err(EnvLockError::ManifestParse {
            path: ".chinwag/store-closures.json".to_owned(),
            detail: "NAR SHA-256 of artifact_file does not match declared nar_sha256_hex"
                .to_owned(),
        });
    }
    if let (Some(decl), Some(actual_live)) = (declared_digest, live_digest)
        && !bool::from(decl.ct_eq(&actual_live))
    {
        return Err(EnvLockError::ManifestParse {
            path: ".chinwag/store-closures.json".to_owned(),
            detail: format!(
                "NAR SHA-256 of realized `{}` does not match declared nar_sha256_hex",
                entry.store_path
            ),
        });
    }
    if let (Some(art), Some(actual_live)) = (artifact_digest, live_digest)
        && !bool::from(art.ct_eq(&actual_live))
    {
        return Err(EnvLockError::ManifestParse {
            path: ".chinwag/store-closures.json".to_owned(),
            detail: format!(
                "NAR SHA-256 of realized `{}` does not match artifact_file",
                entry.store_path
            ),
        });
    }

    live_digest
        .or(artifact_digest)
        .or(declared_digest)
        .ok_or_else(|| EnvLockError::ManifestParse {
            path: ".chinwag/store-closures.json".to_owned(),
            detail: "store closure entry requires `nar_sha256_hex`, `artifact_file`, or a realized local `/nix/store/...` path".to_owned(),
        })
}

#[allow(clippy::too_many_arguments)]
fn build_closure_node(
    repo_root: &Path,
    canon_root: &Path,
    node_name: &str,
    ecosystem: &str,
    version_pin: Option<String>,
    sources: &[String],
    raw_manifests: &BTreeMap<String, Vec<u8>>,
    store_closures: &BTreeMap<String, StoreClosureEntry>,
) -> Result<FlakeLockedRef, EnvLockError> {
    let mut closure_hasher = Sha256::new();
    closure_hasher.update(b"chinwag-nar-closure/v1\0");
    closure_hasher.update(ecosystem.as_bytes());
    closure_hasher.update([0]);
    if let Some(ref pin) = version_pin {
        closure_hasher.update(pin.as_bytes());
    }
    closure_hasher.update([0]);
    for src in sources {
        closure_hasher.update((src.len() as u32).to_be_bytes());
        closure_hasher.update(src.as_bytes());
        if let Some(bytes) = raw_manifests.get(src) {
            let digest = Sha256::digest(bytes);
            closure_hasher.update(digest);
        }
    }

    let entry = store_closures
        .get(node_name)
        .or_else(|| store_closures.get(ecosystem))
        .ok_or_else(|| EnvLockError::UnresolvedStoreClosure {
            node: node_name.to_owned(),
            ecosystem: ecosystem.to_owned(),
        })?;
    let store_digest = resolve_store_nar_digest(repo_root, canon_root, entry)?;
    closure_hasher.update(b"store-nar\0");
    closure_hasher.update((entry.store_path.len() as u32).to_be_bytes());
    closure_hasher.update(entry.store_path.as_bytes());
    closure_hasher.update(store_digest);

    let store_path = entry.store_path.clone();
    let nar_hash = format!("sha256-{}", BASE64_STANDARD.encode(store_digest));
    let closure_digest_bytes: [u8; 32] = closure_hasher.finalize().into();
    let closure_sha256 = hex::encode(closure_digest_bytes);

    Ok(FlakeLockedRef {
        kind: "chinwag-cleanroom-closure".to_owned(),
        ecosystem: ecosystem.to_owned(),
        version_pin,
        store_path,
        nar_hash,
        closure_sha256,
        source_manifests: sources.to_vec(),
    })
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

/// Loads a 32-byte hex `Ed25519` seed from a regular (`O_NOFOLLOW`, `nlink == 1`) file with zeroized buffer.
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
    let slice: &[[u8; 32]] = match expected_signer {
        Some(k) => std::slice::from_ref(k),
        None => &[],
    };
    verify_env_lock_receipt_against_allowlist(receipt, expected_flake_lock_bytes, slice, false)
}

fn verify_env_lock_receipt_against_allowlist(
    receipt: &EnvLockReceiptV1,
    expected_flake_lock_bytes: &[u8],
    pinned_signers: &[[u8; 32]],
    require_pinned: bool,
) -> Result<(), EnvLockError> {
    if require_pinned && pinned_signers.is_empty() {
        return Err(EnvLockError::ReceiptVerification(
            "no pinned Ed25519 signers configured for receipt verification",
        ));
    }
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
    if !pinned_signers.is_empty() {
        let mut matched = false;
        for pin in pinned_signers {
            if bool::from(pub_arr.ct_eq(pin)) {
                matched = true;
            }
        }
        if !matched {
            return Err(EnvLockError::ReceiptVerification(
                "receipt signer does not match pinned Ed25519 key",
            ));
        }
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
) -> Result<(PathBuf, PathBuf), EnvLockError> {
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

    atomic_write_regular_file(&lock_path, compiled.canonical_json.as_bytes(), 0o644)?;
    atomic_write_regular_file(&receipt_path, receipt_json.as_bytes(), 0o644)?;
    Ok((lock_path, receipt_path))
}

/// Re-compiles workspace manifests, verifies zero `.nix` syntax, checks `.chinwag/flake.lock`
/// byte-for-byte parity, asserts manifest/NAR/closure parity, and verifies the detached `Ed25519`
/// receipt against a non-empty allowlist of pinned `Ed25519` signers.
pub fn verify_env_lock_bundle_with_signers(
    repo_root: &Path,
    pinned_signers: &[[u8; 32]],
) -> Result<EnvLockReceiptV1, EnvLockError> {
    verify_env_lock_bundle_inner(repo_root, pinned_signers, true)
}

/// Re-compiles workspace manifests, verifies zero `.nix` syntax, checks `.chinwag/flake.lock`
/// byte-for-byte parity, and verifies the detached `Ed25519` receipt.
pub fn verify_env_lock_bundle(
    repo_root: &Path,
    expected_signer: Option<&[u8; 32]>,
) -> Result<EnvLockReceiptV1, EnvLockError> {
    let slice: &[[u8; 32]] = match expected_signer {
        Some(k) => std::slice::from_ref(k),
        None => &[],
    };
    verify_env_lock_bundle_inner(repo_root, slice, false)
}

fn verify_env_lock_bundle_inner(
    repo_root: &Path,
    pinned_signers: &[[u8; 32]],
    require_pinned: bool,
) -> Result<EnvLockReceiptV1, EnvLockError> {
    let canon_root = validate_repo_root_dir(repo_root)?;
    let on_disk_lock = read_repo_regular_file_strict(
        repo_root,
        &canon_root,
        ".chinwag/flake.lock",
        MAX_MANIFEST_BYTES,
    )?;
    let parsed_lock: FlakeLockV7 = serde_json::from_slice(&on_disk_lock)
        .map_err(|_| EnvLockError::ReceiptVerification("malformed .chinwag/flake.lock JSON"))?;
    for (node_id, node) in &parsed_lock.nodes {
        if node_id == &parsed_lock.root {
            continue;
        }
        let Some(ref locked) = node.locked else {
            return Err(EnvLockError::ReceiptVerification(
                "non-root flake.lock node missing locked store closure",
            ));
        };
        validate_nix_store_path(&locked.store_path)?;
        let Some(b64_digest) = locked.nar_hash.strip_prefix("sha256-") else {
            return Err(EnvLockError::ReceiptVerification(
                "locked narHash must use sha256-<base64> SRI encoding",
            ));
        };
        let decoded = BASE64_STANDARD
            .decode(b64_digest)
            .map_err(|_| EnvLockError::ReceiptVerification("malformed base64 in locked narHash"))?;
        if decoded.len() != 32 {
            return Err(EnvLockError::ReceiptVerification(
                "locked narHash must decode to 32 bytes",
            ));
        }
    }

    let compiled = compile_workspace_env_lock(repo_root)?;
    if on_disk_lock != compiled.canonical_json.as_bytes() {
        return Err(EnvLockError::LockfileDrift(
            ".chinwag/flake.lock is out of sync with workspace manifests or store closures; run `chinwag env lock`"
                .to_owned(),
        ));
    }
    let on_disk_receipt_bytes = read_repo_regular_file_strict(
        repo_root,
        &canon_root,
        ".chinwag/env-lock.receipt.json",
        MAX_MANIFEST_BYTES,
    )?;
    let receipt: EnvLockReceiptV1 = serde_json::from_slice(&on_disk_receipt_bytes)
        .map_err(|_| EnvLockError::ReceiptVerification("malformed env-lock.receipt.json"))?;
    verify_env_lock_receipt_against_allowlist(
        &receipt,
        &on_disk_lock,
        pinned_signers,
        require_pinned,
    )?;
    if receipt.closure_sha256 != compiled.closure_sha256_hex
        || receipt.node_nar_hashes != compiled.node_nar_hashes
        || receipt.manifests != compiled.manifests
    {
        return Err(EnvLockError::LockfileDrift(
            "closure_sha256, node_nar_hashes, or manifests mismatch between workspace manifests and receipt"
                .to_owned(),
        ));
    }
    Ok(receipt)
}

/// Verifies every store closure node in `<repo_root>/.chinwag/flake.lock` against any realized
/// store object present inside `nix_store_host` using constant-time NAR v1 SHA-256 comparison.
pub fn verify_mounted_store_closures(
    repo_root: &Path,
    nix_store_host: &Path,
) -> Result<(), EnvLockError> {
    let canon_root = validate_repo_root_dir(repo_root)?;
    let lock_bytes = read_repo_regular_file_strict(
        repo_root,
        &canon_root,
        ".chinwag/flake.lock",
        MAX_MANIFEST_BYTES,
    )?;
    let parsed: FlakeLockV7 = serde_json::from_slice(&lock_bytes)
        .map_err(|_| EnvLockError::ReceiptVerification("malformed .chinwag/flake.lock JSON"))?;
    for (node_id, node) in &parsed.nodes {
        if node_id == &parsed.root {
            continue;
        }
        let Some(ref locked) = node.locked else {
            continue;
        };
        validate_nix_store_path(&locked.store_path)?;
        let Some(basename) = locked.store_path.strip_prefix("/nix/store/") else {
            return Err(EnvLockError::ReceiptVerification(
                "invalid locked store_path prefix",
            ));
        };
        let candidate = nix_store_host.join(basename);
        if let Ok(meta) = fs::symlink_metadata(&candidate) {
            if meta.file_type().is_symlink() {
                return Err(EnvLockError::SymlinkForbidden(
                    candidate.display().to_string(),
                ));
            }
            let nar_bytes = serialize_nar_v1(&candidate)?;
            let actual_sri = format!(
                "sha256-{}",
                BASE64_STANDARD.encode(Sha256::digest(&nar_bytes))
            );
            if !bool::from(actual_sri.as_bytes().ct_eq(locked.nar_hash.as_bytes())) {
                return Err(EnvLockError::LockfileDrift(format!(
                    "realized store closure `{}` narHash `{actual_sri}` does not match locked `{}`",
                    candidate.display(),
                    locked.nar_hash
                )));
            }
        }
    }
    Ok(())
}

fn verify_repo_relative_components_no_symlink(
    repo_root: &Path,
    canon_root: &Path,
    rel_path: &str,
) -> Result<PathBuf, EnvLockError> {
    if rel_path.is_empty()
        || rel_path.starts_with('/')
        || rel_path.contains("//")
        || rel_path.chars().any(char::is_control)
    {
        return Err(EnvLockError::ManifestParse {
            path: rel_path.to_owned(),
            detail: "path must be normalized relative UTF-8".to_owned(),
        });
    }
    let mut cursor = repo_root.to_path_buf();
    for comp in Path::new(rel_path).components() {
        match comp {
            Component::Normal(seg) => {
                cursor.push(seg);
                let meta =
                    fs::symlink_metadata(&cursor).map_err(|e| EnvLockError::ManifestParse {
                        path: rel_path.to_owned(),
                        detail: e.to_string(),
                    })?;
                if meta.file_type().is_symlink() {
                    return Err(EnvLockError::ManifestParse {
                        path: rel_path.to_owned(),
                        detail: "symlink component forbidden inside repository root".to_owned(),
                    });
                }
            }
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(EnvLockError::ManifestParse {
                    path: rel_path.to_owned(),
                    detail: "relative `.` or `..` segments forbidden".to_owned(),
                });
            }
        }
    }
    let canon_target = fs::canonicalize(&cursor).map_err(|e| EnvLockError::ManifestParse {
        path: rel_path.to_owned(),
        detail: e.to_string(),
    })?;
    if !canon_target.starts_with(canon_root) {
        return Err(EnvLockError::ManifestParse {
            path: rel_path.to_owned(),
            detail: "resolved path escapes canonical repository root".to_owned(),
        });
    }
    Ok(cursor)
}

fn read_repo_regular_file_strict(
    repo_root: &Path,
    canon_root: &Path,
    rel_path: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, EnvLockError> {
    let full = verify_repo_relative_components_no_symlink(repo_root, canon_root, rel_path)?;
    read_regular_file_nofollow(&full, max_bytes, true).map_err(|e| EnvLockError::ManifestParse {
        path: rel_path.to_owned(),
        detail: e.to_string(),
    })
}

/// Strictly opens `path` with `O_NOFOLLOW`, verifies `RegularFile`, `nlink == 1`, and
/// `size <= MAX_MANIFEST_BYTES` via `fstat` BEFORE reading any bytes.
pub fn read_non_symlink(path: &Path) -> Result<Vec<u8>, EnvLockError> {
    // Reject intermediate directory symlinks (allowing macOS root `/var -> private/var` and `/tmp -> private/tmp`)
    if path.is_absolute() {
        let mut cursor = PathBuf::from("/");
        for (idx, comp) in path.components().enumerate() {
            let Component::Normal(seg) = comp else {
                if matches!(comp, Component::ParentDir | Component::CurDir) {
                    return Err(EnvLockError::Io(
                        "relative segments forbidden in file path".to_owned(),
                    ));
                }
                continue;
            };
            cursor.push(seg);
            let meta =
                fs::symlink_metadata(&cursor).map_err(|e| EnvLockError::Io(e.to_string()))?;
            if meta.file_type().is_symlink() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if idx == 1 && meta.uid() == 0 && (seg == "var" || seg == "tmp") {
                        let target =
                            fs::read_link(&cursor).map_err(|e| EnvLockError::Io(e.to_string()))?;
                        let expected = if seg == "var" {
                            Path::new("private/var")
                        } else {
                            Path::new("private/tmp")
                        };
                        if target == expected {
                            cursor = Path::new("/").join(expected);
                            continue;
                        }
                    }
                }
                return Err(EnvLockError::Io(
                    "refusing to traverse symlink component".to_owned(),
                ));
            }
        }
    }
    read_regular_file_nofollow(path, MAX_MANIFEST_BYTES, true)
}

fn read_regular_file_nofollow(
    path: &Path,
    max_bytes: u64,
    require_single_link: bool,
) -> Result<Vec<u8>, EnvLockError> {
    #[cfg(unix)]
    {
        use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
        let fd = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| EnvLockError::Io(format!("open(O_NOFOLLOW) failed: {e}")))?;
        let stat = fstat(&fd).map_err(|e| EnvLockError::Io(e.to_string()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(EnvLockError::Io(
                "refusing to read non-regular file".to_owned(),
            ));
        }
        if require_single_link && stat.st_nlink != 1 {
            return Err(EnvLockError::Io(format!(
                "refusing hard-linked file (st_nlink={})",
                stat.st_nlink
            )));
        }
        if stat.st_size < 0 || (stat.st_size as u64) > max_bytes {
            return Err(EnvLockError::Io(format!(
                "file size {} exceeds {} byte bound",
                stat.st_size, max_bytes
            )));
        }
        let expected_len = stat.st_size as usize;
        let file = File::from(fd);
        let mut buf = Vec::with_capacity(expected_len);
        file.take(max_bytes + 1)
            .read_to_end(&mut buf)
            .map_err(|e| EnvLockError::Io(e.to_string()))?;
        if (buf.len() as u64) > max_bytes || buf.len() != expected_len {
            return Err(EnvLockError::Io(
                "concurrent file size mutation or bound overflow during read".to_owned(),
            ));
        }
        Ok(buf)
    }
    #[cfg(not(unix))]
    {
        let _ = require_single_link;
        let meta = fs::symlink_metadata(path).map_err(|e| EnvLockError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > max_bytes {
            return Err(EnvLockError::Io("invalid or oversized file".to_owned()));
        }
        fs::read(path).map_err(|e| EnvLockError::Io(e.to_string()))
    }
}

fn read_open_nofollow_for_nar(
    path: &Path,
    max_bytes: u64,
) -> Result<(Vec<u8>, bool), EnvLockError> {
    #[cfg(unix)]
    {
        use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
        let fd = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| EnvLockError::Io(format!("NAR open(O_NOFOLLOW) failed: {e}")))?;
        let stat = fstat(&fd).map_err(|e| EnvLockError::Io(e.to_string()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(EnvLockError::Io("NAR expected regular file".to_owned()));
        }
        if stat.st_size < 0 || (stat.st_size as u64) > max_bytes {
            return Err(EnvLockError::Io("NAR file exceeds 16 MiB bound".to_owned()));
        }
        let executable = (stat.st_mode as u32) & 0o111 != 0;
        let expected_len = stat.st_size as usize;
        let file = File::from(fd);
        let mut buf = Vec::with_capacity(expected_len);
        file.take(max_bytes + 1)
            .read_to_end(&mut buf)
            .map_err(|e| EnvLockError::Io(e.to_string()))?;
        if buf.len() != expected_len {
            return Err(EnvLockError::Io(
                "NAR file mutated concurrently during serialization".to_owned(),
            ));
        }
        Ok((buf, executable))
    }
    #[cfg(not(unix))]
    {
        let data = read_regular_file_nofollow(path, max_bytes, false)?;
        Ok((data, false))
    }
}

/// Atomically writes `bytes` to `target` via an `O_CREAT | O_EXCL | O_NOFOLLOW` temp file
/// with explicit Unix permissions `mode` (`0600` for sensitive bundles, `0644` for repo lockfiles).
pub fn atomic_write_regular_file(
    target: &Path,
    bytes: &[u8],
    mode_bits: u32,
) -> Result<(), EnvLockError> {
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
    let parent_meta = fs::symlink_metadata(parent).map_err(|e| EnvLockError::Io(e.to_string()))?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err(EnvLockError::Io(
            "refusing to write inside symlinked parent directory".to_owned(),
        ));
    }
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| EnvLockError::Io(e.to_string()))?;
    let tmp = parent.join(format!(
        ".chinwag-tmp-{}-{}",
        target.file_name().and_then(|n| n.to_str()).unwrap_or("out"),
        hex::encode(nonce)
    ));
    #[cfg(unix)]
    {
        use rustix::fs::{CWD, Mode, OFlags, openat};
        let mode = Mode::from_bits_truncate(mode_bits as rustix::fs::RawMode);
        let fd = openat(
            CWD,
            &tmp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        )
        .map_err(|e| EnvLockError::Io(e.to_string()))?;
        let mut f = File::from(fd);
        f.write_all(bytes)
            .and_then(|()| f.sync_all())
            .map_err(|e| {
                let _ = fs::remove_file(&tmp);
                EnvLockError::Io(e.to_string())
            })?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode_bits;
        let mut f = fs::OpenOptions::new()
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
    }
    fs::rename(&tmp, target).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        EnvLockError::Io(e.to_string())
    })
}
