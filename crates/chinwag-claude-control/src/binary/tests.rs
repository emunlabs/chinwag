use super::*;
use crate::StartupPolicyDeclaration;
use std::os::unix::fs::{PermissionsExt, symlink};

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    binary: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let binary = root.join("declared-native-fixture");
        let mut bytes = vec![0u8; 128];
        #[cfg(target_os = "macos")]
        {
            bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
            let arch: u32 = if cfg!(target_arch = "aarch64") {
                0x0100000c
            } else {
                0x01000007
            };
            bytes[4..8].copy_from_slice(&arch.to_le_bytes());
        }
        #[cfg(not(target_os = "macos"))]
        {
            bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
            let arch: u16 = if cfg!(target_arch = "aarch64") {
                183
            } else {
                62
            };
            bytes[18..20].copy_from_slice(&arch.to_le_bytes());
        }
        fs::write(&binary, bytes).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _temporary: temporary,
            root,
            binary,
        }
    }

    fn config(&self) -> WorkConfig {
        let digest = format!("{:x}", Sha256::digest(fs::read(&self.binary).unwrap()));
        WorkConfig::new(
            &self.binary,
            &digest,
            &self.root,
            &self.root.join("journal"),
            StartupPolicyDeclaration::ManagedPolicyProseOnly,
        )
        .unwrap()
    }
}

#[test]
fn declared_native_file_is_hashed_without_executing_it() {
    let fixture = Fixture::new();
    let pin = BinaryPin::open(&fixture.config()).unwrap();
    pin.verify().unwrap();
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 1);
}

#[test]
fn wrong_digest_or_incompatible_native_header_is_rejected() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.sha256 = "0".repeat(64);
    assert!(BinaryPin::open(&config).is_err());
    fs::write(
        &fixture.binary,
        b"#!/bin/sh\nthis fixture is never executed\n",
    )
    .unwrap();
    assert!(BinaryPin::open(&fixture.config()).is_err());
}

#[test]
fn final_symlink_is_not_an_executable_pin() {
    let fixture = Fixture::new();
    let alias = fixture.root.join("alias");
    symlink(&fixture.binary, &alias).unwrap();
    let mut config = fixture.config();
    config.binary = alias;
    assert!(BinaryPin::open(&config).is_err());
}

#[test]
fn executable_mode_must_be_owner_executable_and_not_writable_by_others() {
    let fixture = Fixture::new();
    for mode in [0o600, 0o720, 0o702] {
        fs::set_permissions(&fixture.binary, fs::Permissions::from_mode(mode)).unwrap();
        assert!(BinaryPin::open(&fixture.config()).is_err(), "mode {mode:o}");
    }
}

#[test]
fn replacing_the_name_with_identical_bytes_invalidates_the_pin() {
    let fixture = Fixture::new();
    let pin = BinaryPin::open(&fixture.config()).unwrap();
    let replacement = fixture.root.join("replacement");
    fs::copy(&fixture.binary, &replacement).unwrap();
    fs::rename(&replacement, &fixture.binary).unwrap();
    assert!(pin.verify().is_err());
}

#[test]
fn mutating_held_file_metadata_invalidates_the_pin() {
    let fixture = Fixture::new();
    let pin = BinaryPin::open(&fixture.config()).unwrap();
    fs::set_permissions(&fixture.binary, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(pin.verify().is_err());
}

#[test]
fn size_limit_is_checked_before_reading_a_sparse_file() {
    let fixture = Fixture::new();
    let config = fixture.config();
    OpenOptions::new()
        .write(true)
        .open(&fixture.binary)
        .unwrap()
        .set_len(MAX_BINARY + 1)
        .unwrap();
    assert!(BinaryPin::open(&config).is_err());
}

#[test]
fn selected_directory_is_held_and_cannot_be_substituted_by_a_symlink() {
    let fixture = Fixture::new();
    let selected = fixture.root.join("work");
    fs::create_dir(&selected).unwrap();
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
    let held = work_directory(&selected).unwrap();
    verify_directory(&selected, &held).unwrap();
    let original = fixture.root.join("original-work");
    fs::rename(&selected, &original).unwrap();
    symlink(&original, &selected).unwrap();
    assert!(verify_directory(&selected, &held).is_err());
}
