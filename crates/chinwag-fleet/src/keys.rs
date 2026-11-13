// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Strict seat/public-key bijection and private-key filesystem checks.
#![forbid(unsafe_code)]
use crate::{FleetManifest, FleetPolicyError, FleetResult};
use std::{collections::BTreeSet, path::Path};

pub struct KeyBijectionValidator;
impl KeyBijectionValidator {
    pub fn validate(manifest: &FleetManifest, strict: bool) -> FleetResult<()> {
        let fail = |message: String| FleetPolicyError::KeyBijectionFailed(message);
        if !strict
            && manifest.pubkey_map.is_empty()
            && manifest.allowed_signers.is_empty()
            && manifest.private_key_paths.is_empty()
        {
            return Ok(());
        }
        let seats: BTreeSet<_> = manifest.seats.iter().map(|s| &s.id).collect();
        let mapped: BTreeSet<_> = manifest.pubkey_map.keys().collect();
        let allowed: BTreeSet<_> = manifest.allowed_signers.keys().collect();
        if seats != mapped || seats != allowed {
            return Err(fail(
                "every seat must occur exactly once in both pubkey_map and allowed_signers".into(),
            ));
        }
        let mut keys = BTreeSet::new();
        for (seat, text) in &manifest.pubkey_map {
            let key = chinwag_claim::decode_hex_exact::<32>(text)
                .map_err(|_| fail(format!("invalid key for {seat}")))?;
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map_err(|_| fail(format!("invalid Ed25519 key for {seat}")))?;
            if !keys.insert(key) {
                return Err(fail(format!("duplicate key assigned to {seat}")));
            }
            if manifest.allowed_signers.get(seat) != Some(text) {
                return Err(fail(format!("allowed signer disagrees for {seat}")));
            }
        }
        for (seat, path) in &manifest.private_key_paths {
            if !seats.contains(seat) {
                return Err(fail(format!("private key assigned to unknown seat {seat}")));
            }
            let cwd = std::env::current_dir()?;
            let resolved = manifest.resolve_path(path, &cwd);
            validate_private_key_path(&resolved)?;
        }
        Ok(())
    }
}

pub fn validate_private_key_path(path: &Path) -> FleetResult<()> {
    let fail = |text| FleetPolicyError::KeyBijectionFailed(text);
    // Inspect every existing component; checking only the leaf permits parent symlink escapes.
    let mut component_path = std::path::PathBuf::new();
    for component in path.components() {
        component_path.push(component);
        let metadata = std::fs::symlink_metadata(&component_path)?;
        if metadata.file_type().is_symlink() {
            return Err(fail(format!("symlink key path {}", path.display())));
        }
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(fail("private key must be a regular file".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(fail("private key permissions must be 0600".into()));
        }
    }
    Ok(())
}
