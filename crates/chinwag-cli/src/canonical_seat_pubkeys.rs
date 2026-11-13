//! Runtime fleet trust roots. An absent or invalid manifest grants no trust.
#![forbid(unsafe_code)]

use std::{collections::BTreeMap, path::Path};
use subtle::ConstantTimeEq;

pub fn configured_manifest() -> Option<chinwag_fleet::FleetManifest> {
    let cwd = std::env::current_dir().ok()?;
    let path = chinwag_fleet::FleetManifest::discover_path(None, &cwd);
    manifest_at(&path)
}

fn manifest_at(path: &Path) -> Option<chinwag_fleet::FleetManifest> {
    let manifest = chinwag_fleet::FleetManifest::load(path).ok()?;
    chinwag_fleet::KeyBijectionValidator::validate(&manifest, true).ok()?;
    Some(manifest)
}

pub fn configured_seat_pubkeys() -> BTreeMap<String, [u8; 32]> {
    let Some(manifest) = configured_manifest() else {
        return BTreeMap::new();
    };
    manifest_seat_pubkeys(&manifest)
}

pub fn manifest_seat_pubkeys(
    manifest: &chinwag_fleet::FleetManifest,
) -> BTreeMap<String, [u8; 32]> {
    manifest
        .pubkey_map
        .iter()
        .filter_map(|(seat, key)| decode_public_key(key).map(|key| (seat.to_string(), key)))
        .collect()
}

pub fn configured_release_signers() -> Vec<String> {
    configured_manifest()
        .map(|m| m.policy.release_signers)
        .unwrap_or_default()
}

pub fn canonical_seat_pubkey(base_seat: &str) -> Option<[u8; 32]> {
    configured_seat_pubkeys().get(base_seat).copied()
}

pub fn verify_canonical_seat_pubkey(base_seat: &str, public_key: &[u8; 32]) -> bool {
    canonical_seat_pubkey(base_seat).is_some_and(|expected| bool::from(expected.ct_eq(public_key)))
}

fn decode_public_key(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    let mut key = [0; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_configuration_has_no_embedded_trust_roots() {
        let temp = tempfile::TempDir::new().unwrap();
        assert!(manifest_at(&temp.path().join("missing.toml")).is_none());
    }

    #[test]
    fn trust_roots_require_the_exact_manifest_and_both_key_maps() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("fleet.toml");
        let mut manifest = chinwag_fleet::FleetManifest::starter_profile("solo").unwrap();
        let seat = manifest.seats[0].id.clone();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes();
        let encoded = key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        manifest.pubkey_map.insert(seat.clone(), encoded.clone());
        manifest.allowed_signers.insert(seat.clone(), encoded);
        std::fs::write(&path, manifest.to_toml().unwrap()).unwrap();
        let loaded = manifest_at(&path).unwrap();
        assert_eq!(
            manifest_seat_pubkeys(&loaded),
            BTreeMap::from([(seat.to_string(), key)])
        );
        manifest.allowed_signers.clear();
        std::fs::write(&path, manifest.to_toml().unwrap()).unwrap();
        assert!(manifest_at(&path).is_none());
    }
}
