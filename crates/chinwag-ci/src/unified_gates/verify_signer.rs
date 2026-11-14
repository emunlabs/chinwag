// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Allowed-signers registry & commit signer verification (`verify-signer`).
//! Enforces strict 1-to-1 bijection (`INV-SOLE-KEYPAIR-PER-SEAT-01`) across
//! OpenSSH `ssh-ed25519` and 64-hex Ed25519 public-key entries.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifySignerReportV1 {
    pub ok: bool,
    pub command: String,
    pub commit: String,
    pub author: String,
    pub allowed_signers_path: String,
    pub allowed_signers_entries_verified: usize,
    pub unique_principals_verified: usize,
    pub git_sig_status: String,
}

/// Parses an `allowed_signers` file and enforces strict 1-to-1 principal <-> Ed25519 key bijection.
pub fn parse_and_validate_allowed_signers(
    raw_signers: &str,
    source_label: &str,
) -> Result<BTreeMap<String, [u8; 32]>, String> {
    let mut principal_to_key: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    let mut key_to_principal: BTreeMap<[u8; 32], String> = BTreeMap::new();

    for (line_idx, line) in raw_signers.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 2 || tokens[0].is_empty() {
            return Err(format!(
                "malformed entry at `{source_label}:{}`",
                line_idx + 1
            ));
        }
        let principal = extract_canonical_principal(&tokens);
        let pubkey_bytes = extract_ed25519_pubkey_from_tokens(&tokens).ok_or_else(|| {
            format!(
                "invalid Ed25519 key material at `{source_label}:{}`",
                line_idx + 1
            )
        })?;

        // Validate canonical non-weak Ed25519 curve point
        let vk = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| {
            format!(
                "invalid Ed25519 public key at `{source_label}:{}`: {e}",
                line_idx + 1
            )
        })?;
        if vk.is_weak() {
            return Err(format!(
                "weak small-order Ed25519 public key rejected at `{source_label}:{}`",
                line_idx + 1
            ));
        }

        if principal_to_key.contains_key(&principal) {
            return Err(format!(
                "duplicate principal `{principal}` at `{source_label}:{}` violates 1-to-1 bijection",
                line_idx + 1
            ));
        }
        if let Some(existing_principal) = key_to_principal.get(&pubkey_bytes) {
            return Err(format!(
                "shared Ed25519 key across principals `{existing_principal}` and `{principal}` at `{source_label}:{}`",
                line_idx + 1
            ));
        }

        principal_to_key.insert(principal.clone(), pubkey_bytes);
        key_to_principal.insert(pubkey_bytes, principal);
    }

    if principal_to_key.is_empty() {
        return Err(format!(
            "`{source_label}` contains 0 valid Ed25519 signer entries"
        ));
    }

    Ok(principal_to_key)
}

fn extract_canonical_principal(tokens: &[&str]) -> String {
    if let Some(alg_idx) = tokens.iter().position(|t| *t == "ssh-ed25519")
        && alg_idx + 3 < tokens.len()
        && !tokens[alg_idx + 3].is_empty()
    {
        return format!("{}#{}", tokens[0], tokens[alg_idx + 3].to_ascii_uppercase());
    }
    tokens[0].to_string()
}

fn extract_ed25519_pubkey_from_tokens(tokens: &[&str]) -> Option<[u8; 32]> {
    for window in tokens.windows(2) {
        if window[0] == "ssh-ed25519" {
            let decoded = STANDARD.decode(window[1]).ok()?;
            // OpenSSH wire format: uint32(11) || "ssh-ed25519" || uint32(32) || <32-byte key>
            const SSH_ED25519_PREFIX: &[u8] = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20";
            if decoded.len() == SSH_ED25519_PREFIX.len() + 32
                && decoded.starts_with(SSH_ED25519_PREFIX)
            {
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded[SSH_ED25519_PREFIX.len()..]);
                return Some(key);
            }
        }
    }
    for token in &tokens[1..] {
        if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
            let decoded = hex::decode(token).ok()?;
            let key: [u8; 32] = decoded.try_into().ok()?;
            return Some(key);
        }
    }
    None
}

/// Runs `verify-signer` against `allowed_signers_path` and `commit`.
pub fn execute_verify_signer(
    allowed_signers_path: &Path,
    commit: &str,
    require_git_sig: bool,
) -> Result<VerifySignerReportV1, String> {
    let trimmed_commit = commit.trim();
    if trimmed_commit.is_empty() || trimmed_commit.starts_with('-') {
        return Err(format!(
            "invalid commit revision `{commit}`: empty or leading `-` option injection is forbidden"
        ));
    }

    let meta = fs::symlink_metadata(allowed_signers_path)
        .map_err(|e| format!("unable to stat `{}`: {e}", allowed_signers_path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(format!(
            "allowed-signers path `{}` must be a regular non-symlink file",
            allowed_signers_path.display()
        ));
    }
    let raw_signers = fs::read_to_string(allowed_signers_path)
        .map_err(|e| format!("unable to read `{}`: {e}", allowed_signers_path.display()))?;
    let label = allowed_signers_path.display().to_string();
    let registry = parse_and_validate_allowed_signers(&raw_signers, &label)?;

    let log_output = Command::new("git")
        .args([
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!(
                "gpg.ssh.allowedSignersFile={}",
                allowed_signers_path.display()
            ),
            "log",
            "-1",
            "--format=%H|%an|%ae|%G?",
            trimmed_commit,
            "--",
        ])
        .output()
        .map_err(|e| format!("failed to spawn `git log` for `{trimmed_commit}`: {e}"))?;
    if !log_output.status.success() {
        return Err(format!(
            "`git log` failed to resolve commit `{trimmed_commit}` (exit status {})",
            log_output.status
        ));
    }
    let formatted = String::from_utf8_lossy(&log_output.stdout)
        .trim()
        .to_string();
    let parts: Vec<&str> = formatted.splitn(4, '|').collect();
    if parts.len() != 4 || parts[0].is_empty() {
        return Err(format!(
            "unexpected `git log` metadata output for `{trimmed_commit}`"
        ));
    }
    let resolved_commit = parts[0].to_string();
    let author = format!("{} <{}>", parts[1], parts[2]);
    let git_sig_status = parts[3].to_string();

    if matches!(git_sig_status.as_str(), "B" | "X" | "Y" | "R") {
        return Err(format!(
            "commit `{resolved_commit}` has invalid/revoked/expired signature (`git_sig_status={git_sig_status}`)"
        ));
    }

    if require_git_sig && git_sig_status != "G" {
        return Err(format!(
            "commit `{resolved_commit}` failed strict SSH signature check (`git_sig_status={git_sig_status}`)"
        ));
    }

    Ok(VerifySignerReportV1 {
        ok: true,
        command: "chinwag-ci verify-signer".to_string(),
        commit: resolved_commit,
        author,
        allowed_signers_path: label,
        allowed_signers_entries_verified: registry.len(),
        unique_principals_verified: registry.len(),
        git_sig_status,
    })
}
