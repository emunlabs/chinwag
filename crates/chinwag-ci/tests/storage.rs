// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]

use chinwag_ci::storage::{CiphertextClaim, CiphertextStore, StorageError};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};

fn directory() -> (tempfile::TempDir, PathBuf, CiphertextStore) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let store = CiphertextStore::open(&path).unwrap();
    (temp, path, store)
}
fn claim(bytes: &[u8]) -> CiphertextClaim {
    CiphertextClaim {
        sha256: Sha256::digest(bytes).into(),
        bytes: bytes.len() as u64,
    }
}

#[test]
fn persists_and_independently_reads_exact_private_bytes_without_overwriting() {
    let (_temp, path, store) = directory();
    let bytes = vec![0xa5; 1024 * 1024];
    let expected = claim(&bytes);
    let saved = store.persist_ciphertext_claim(expected, &bytes).unwrap();
    assert_eq!(fs::read(path.join(saved.object())).unwrap(), bytes);
    assert_eq!(
        fs::metadata(path.join(saved.object()))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    let observed = store.observe_existing(expected).unwrap();
    assert_eq!(observed.sha256(), saved.sha256());
    assert_eq!(observed.bytes(), bytes.len() as u64);
    let created = serde_json::to_value(&saved).unwrap();
    let existing = serde_json::to_value(&observed).unwrap();
    assert_eq!(created["reopened_same_inode_as_created"], true);
    assert_eq!(existing["reopened_same_inode_as_created"], false);
    assert_eq!(existing["file_and_directory_sync_completed"], true);
    assert!(matches!(
        store.persist_ciphertext_claim(expected, &bytes),
        Err(StorageError::AlreadyExists)
    ));
}

#[test]
fn a_wrong_hash_or_length_creates_nothing() {
    let (_temp, path, store) = directory();
    let bytes = b"test-only untrusted bytes";
    let mut expected = claim(bytes);
    expected.sha256[0] ^= 1;
    assert!(matches!(
        store.persist_ciphertext_claim(expected, bytes),
        Err(StorageError::Claim)
    ));
    let mut expected = claim(bytes);
    expected.bytes += 1;
    assert!(matches!(
        store.persist_ciphertext_claim(expected, bytes),
        Err(StorageError::Claim)
    ));
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

#[test]
fn refuses_symlinked_store_components_and_nonprivate_directory() {
    let (temp, path, _store) = directory();
    let parent = path.parent().unwrap();
    let alias = parent.join(format!("ci-store-alias-{}", std::process::id()));
    symlink(&path, &alias).unwrap();
    assert!(matches!(
        CiphertextStore::open(&alias),
        Err(StorageError::Directory)
    ));
    fs::remove_file(alias).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        CiphertextStore::open(&path),
        Err(StorageError::Directory)
    ));
}

#[test]
fn never_follows_an_existing_object_symlink_or_truncates_its_target() {
    let (_temp, path, store) = directory();
    let bytes = b"test-only ciphertext claim";
    let expected = claim(bytes);
    let outside = path.join("preserve-me");
    fs::write(&outside, b"untouched").unwrap();
    let object = path.join(format!("{}.cwcipher", hex::encode(expected.sha256)));
    symlink(&outside, &object).unwrap();
    assert!(matches!(
        store.persist_ciphertext_claim(expected, bytes),
        Err(StorageError::AlreadyExists)
    ));
    assert!(matches!(
        store.observe_existing(expected),
        Err(StorageError::Readback)
    ));
    assert_eq!(fs::read(outside).unwrap(), b"untouched");
}

#[test]
fn tampered_or_hardlinked_objects_do_not_get_readback_confirmation() {
    let (_temp, path, store) = directory();
    let bytes = b"test-only ciphertext claim";
    let expected = claim(bytes);
    let saved = store.persist_ciphertext_claim(expected, bytes).unwrap();
    let object = path.join(saved.object());
    fs::write(&object, vec![0; bytes.len()]).unwrap();
    assert!(matches!(
        store.observe_existing(expected),
        Err(StorageError::Readback)
    ));
    fs::write(&object, bytes).unwrap();
    fs::hard_link(&object, path.join("second-link")).unwrap();
    assert!(matches!(
        store.observe_existing(expected),
        Err(StorageError::Readback)
    ));
}

#[test]
fn directory_capability_survives_rename_without_following_a_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().canonicalize().unwrap();
    let path = parent.join("store");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let store = CiphertextStore::open(&path).unwrap();
    let moved = parent.join("moved");
    fs::rename(&path, &moved).unwrap();
    fs::create_dir(&path).unwrap();
    let bytes = b"test-only ciphertext claim";
    let saved = store.persist_ciphertext_claim(claim(bytes), bytes).unwrap();
    assert_eq!(fs::read(moved.join(saved.object())).unwrap(), bytes);
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

#[cfg(target_os = "macos")]
#[test]
fn mode_bits_do_not_hide_granting_directory_or_file_acls() {
    fn grant(path: &std::path::Path, ace: &str) {
        let result = std::process::Command::new("/bin/chmod")
            .args(["+a", ace])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "owned temporary ACL fixture creation failed"
        );
    }
    let (_temp, path, store) = directory();
    let bytes = b"test-only ciphertext claim";
    let expected = claim(bytes);
    let saved = store.persist_ciphertext_claim(expected, bytes).unwrap();
    grant(&path.join(saved.object()), "everyone allow read");
    assert_eq!(
        fs::metadata(path.join(saved.object()))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(matches!(
        store.observe_existing(expected),
        Err(StorageError::Readback)
    ));
    grant(
        &path,
        "everyone allow list,search,add_file,file_inherit,directory_inherit",
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert!(matches!(
        CiphertextStore::open(&path),
        Err(StorageError::Directory)
    ));
    let other = b"second test-only ciphertext claim";
    assert!(matches!(
        store.persist_ciphertext_claim(claim(other), other),
        Err(StorageError::Directory)
    ));
    assert!(
        !path
            .join(format!("{}.cwcipher", hex::encode(claim(other).sha256)))
            .exists()
    );
}
