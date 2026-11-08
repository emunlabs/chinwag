// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Explicit operator-owned enrollment only. Configuration and output contain
//! public routing/pins, never seeds. Existing private bundles are never replaced.

use crate::{
    custody::{OwnerCustody, OwnerRole, PublicEnrollment},
    storage::CiphertextStore,
};
#[cfg(target_os = "macos")]
use rustix::fd::AsFd;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_PUBLIC: usize = 16 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfiguration {
    pub version: u16,
    pub role: OwnerRole,
    pub owner_context: [u8; 32],
    pub private_directory: PathBuf,
    pub ciphertext_directory: Option<PathBuf>,
    pub store_id: Option<[u8; 32]>,
}
#[derive(Debug, thiserror::Error)]
#[error(
    "CI owner enrollment refused; preserve existing files and reconcile the original operation"
)]
pub struct OwnerCliError;
#[derive(Serialize)]
pub struct PublicObservation {
    pub classification: &'static str,
    pub public_enrollment_sha256: String,
    pub public_enrollment_bytes: usize,
}
fn private_file(file: &File) -> Result<rustix::fs::Stat, OwnerCliError> {
    let stat = fs::fstat(file).map_err(|_| OwnerCliError)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_size < 0
        || stat.st_size as u64 > MAX_PUBLIC as u64
    {
        return Err(OwnerCliError);
    }
    #[cfg(target_os = "macos")]
    crate::macos_acl::require_absent(file.as_fd()).map_err(|_| OwnerCliError)?;
    Ok(stat)
}
fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, OwnerCliError> {
    serde_json::to_vec(v).map_err(|_| OwnerCliError)
}
fn read_public<T: Serialize + for<'a> Deserialize<'a>>(path: &Path) -> Result<T, OwnerCliError> {
    if !path.is_absolute() || path.extension().is_none_or(|e| e != "json") {
        return Err(OwnerCliError);
    }
    let parent = path.parent().ok_or(OwnerCliError)?;
    let directory = CiphertextStore::open(parent).map_err(|_| OwnerCliError)?;
    let name = path.file_name().ok_or(OwnerCliError)?;
    let file = File::from(
        fs::openat(
            directory.directory(),
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| OwnerCliError)?,
    );
    let initial = private_file(&file)?;
    let mut bytes = Vec::with_capacity(initial.st_size as usize);
    (&file)
        .take(MAX_PUBLIC as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OwnerCliError)?;
    let end = private_file(&file)?;
    let named = fs::statat(directory.directory(), name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| OwnerCliError)?;
    if bytes.len() != initial.st_size as usize
        || end.st_size != initial.st_size
        || end.st_ino != initial.st_ino
        || end.st_dev != initial.st_dev
        || named.st_dev != end.st_dev
        || named.st_ino != end.st_ino
        || named.st_size != end.st_size
    {
        return Err(OwnerCliError);
    }
    directory.check().map_err(|_| OwnerCliError)?;
    let value: T = serde_json::from_slice(&bytes).map_err(|_| OwnerCliError)?;
    if canonical(&value)? != bytes {
        return Err(OwnerCliError);
    }
    Ok(value)
}
fn store(
    config: &OwnerConfiguration,
) -> Result<Option<(CiphertextStore, [u8; 32])>, OwnerCliError> {
    match (&config.ciphertext_directory, config.store_id, config.role) {
        (Some(p), Some(id), OwnerRole::Recipient | OwnerRole::Archive) if id != [0; 32] => Ok(
            Some((CiphertextStore::open(p).map_err(|_| OwnerCliError)?, id)),
        ),
        (None, None, OwnerRole::Admission | OwnerRole::Acu) => Ok(None),
        _ => Err(OwnerCliError),
    }
}
/// All directories must already exist as canonical, private, owner-created
/// namespaces. Public output is reserved before key creation; failed/uncertain
/// operations leave their files intact, and cannot silently initialize again.
pub fn initialize(
    config_path: &Path,
    public_path: &Path,
) -> Result<PublicObservation, OwnerCliError> {
    let config: OwnerConfiguration = read_public(config_path)?;
    if config.version != 1
        || config.owner_context == [0; 32]
        || public_path
            .file_name()
            .is_none_or(|n| n != "public-enrollment.json")
    {
        return Err(OwnerCliError);
    }
    let public_parent = public_path.parent().ok_or(OwnerCliError)?;
    let directory = CiphertextStore::open(public_parent).map_err(|_| OwnerCliError)?;
    let store = store(&config)?;
    // Validate the key namespace before reserving the public result. No reads
    // or hashes of existing private bundle bytes are exposed to this CLI.
    CiphertextStore::open(&config.private_directory).map_err(|_| OwnerCliError)?;
    let mode = Mode::RUSR | Mode::WUSR;
    let fd = fs::openat(
        directory.directory(),
        "public-enrollment.json",
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        mode,
    )
    .map_err(|_| OwnerCliError)?;
    fs::fchmod(&fd, mode).map_err(|_| OwnerCliError)?;
    let mut output = File::from(fd);
    private_file(&output)?;
    let owner = OwnerCustody::create_new(
        &config.private_directory,
        config.role,
        config.owner_context,
        store,
    )
    .map_err(|_| OwnerCliError)?;
    let enrollment = owner.public_enrollment().map_err(|_| OwnerCliError)?;
    let bytes = canonical(&enrollment)?;
    output.write_all(&bytes).map_err(|_| OwnerCliError)?;
    output.sync_all().map_err(|_| OwnerCliError)?;
    let initial = private_file(&output)?;
    fs::fsync(directory.directory()).map_err(|_| OwnerCliError)?;
    let named = fs::statat(
        directory.directory(),
        "public-enrollment.json",
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| OwnerCliError)?;
    if named.st_dev != initial.st_dev
        || named.st_ino != initial.st_ino
        || named.st_size != initial.st_size
    {
        return Err(OwnerCliError);
    }
    let observed: PublicEnrollment = read_public(public_path)?;
    if observed != enrollment {
        return Err(OwnerCliError);
    }
    Ok(observation(&bytes, "OWNER_CREATED_PUBLIC_ENROLLMENT_ONLY"))
}
/// Reopen and compare actual private custody to the operator-pinned PUBLIC
/// enrollment. This proves key continuity, not a native identity or live service.
pub fn verify(config_path: &Path, public_path: &Path) -> Result<PublicObservation, OwnerCliError> {
    let config: OwnerConfiguration = read_public(config_path)?;
    let expected: PublicEnrollment = read_public(public_path)?;
    if config.version != 1 || config.owner_context == [0; 32] {
        return Err(OwnerCliError);
    }
    let owner = OwnerCustody::open_enrolled(
        &config.private_directory,
        config.role,
        config.owner_context,
        store(&config)?,
        &expected,
    )
    .map_err(|_| OwnerCliError)?;
    let actual = owner.public_enrollment().map_err(|_| OwnerCliError)?;
    Ok(observation(
        &canonical(&actual)?,
        "OWNER_CUSTODY_CONTINUITY_ONLY",
    ))
}
fn observation(bytes: &[u8], classification: &'static str) -> PublicObservation {
    PublicObservation {
        classification,
        public_enrollment_sha256: hex::encode(Sha256::digest(bytes)),
        public_enrollment_bytes: bytes.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    fn write<T: Serialize>(path: &Path, v: &T) {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        f.write_all(&canonical(v).unwrap()).unwrap();
    }
    #[test]
    fn public_enrollment_survives_new_cli_lifetimes_and_refuses_reinitialization_or_changed_pins() {
        let d = dir();
        let v = dir();
        let p = d.path().canonicalize().unwrap();
        let vp = v.path().canonicalize().unwrap();
        let config = OwnerConfiguration {
            version: 1,
            role: OwnerRole::Acu,
            owner_context: [19; 32],
            private_directory: vp,
            ciphertext_directory: None,
            store_id: None,
        };
        let cp = p.join("owner-config.json");
        let pp = p.join("public-enrollment.json");
        write(&cp, &config);
        let created = initialize(&cp, &pp).unwrap();
        let verified = verify(&cp, &pp).unwrap();
        assert_eq!(
            created.public_enrollment_sha256,
            verified.public_enrollment_sha256
        );
        assert!(initialize(&cp, &pp).is_err());
        let mut other: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&pp).unwrap()).unwrap();
        let byte = other["Acu"]["signer"][0].as_u64().unwrap();
        other["Acu"]["signer"][0] = serde_json::json!(byte ^ 1);
        std::fs::write(&pp, canonical(&other).unwrap()).unwrap();
        assert!(verify(&cp, &pp).is_err());
    }
    #[test]
    fn malformed_config_and_symlink_public_result_do_not_create_customer_keys() {
        let d = dir();
        let v = dir();
        let p = d.path().canonicalize().unwrap();
        let vp = v.path().canonicalize().unwrap();
        let config = OwnerConfiguration {
            version: 1,
            role: OwnerRole::Admission,
            owner_context: [20; 32],
            private_directory: vp.clone(),
            ciphertext_directory: None,
            store_id: None,
        };
        let cp = p.join("owner-config.json");
        let pp = p.join("public-enrollment.json");
        write(&cp, &config);
        std::os::unix::fs::symlink(&cp, &pp).unwrap();
        assert!(initialize(&cp, &pp).is_err());
        assert_eq!(std::fs::read_dir(&vp).unwrap().count(), 0);
        std::fs::remove_file(&pp).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(initialize(&cp, &pp).is_err());
        assert_eq!(std::fs::read_dir(&vp).unwrap().count(), 0);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&cp, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(initialize(&cp, &pp).is_err());
        assert_eq!(std::fs::read_dir(&vp).unwrap().count(), 0);
    }
}
