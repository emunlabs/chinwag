// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use chinwag_ci::{
    custody::{OwnerRole, PublicEnrollment},
    owner_cli::OwnerConfiguration,
};
use std::{io::Write, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn executable_enrollment_reopens_across_real_process_exit_and_never_replaces_customer_keys() {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let parent = d.path().canonicalize().unwrap();
    let vault = parent.join("role-vault");
    std::fs::create_dir(&vault).unwrap();
    std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cfg = OwnerConfiguration {
        version: 1,
        role: OwnerRole::Admission,
        owner_context: [33; 32],
        private_directory: vault,
        ciphertext_directory: None,
        store_id: None,
    };
    let config = parent.join("owner-config.json");
    let public = parent.join("public-enrollment.json");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&config)
        .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    file.write_all(&serde_json::to_vec(&cfg).unwrap()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let invoke = |action| {
        Command::new(env!("CARGO_BIN_EXE_chinwag-ci"))
            .arg(action)
            .arg(&config)
            .arg(&public)
            .output()
            .unwrap()
    };
    let init = invoke("owner-init");
    assert!(init.status.success());
    assert!(init.stderr.is_empty());
    let init: serde_json::Value = serde_json::from_slice(&init.stdout).unwrap();
    assert_eq!(
        init["classification"],
        "OWNER_CREATED_PUBLIC_ENROLLMENT_ONLY"
    );
    let original_public = std::fs::read(&public).unwrap();
    let enrollment: PublicEnrollment = serde_json::from_slice(&original_public).unwrap();
    assert!(matches!(enrollment, PublicEnrollment::Admission { .. }));
    let verify = invoke("owner-verify");
    assert!(verify.status.success());
    let verify: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(
        init["public_enrollment_sha256"],
        verify["public_enrollment_sha256"]
    );
    let second = invoke("owner-init");
    assert_eq!(second.status.code(), Some(1));
    assert!(second.stdout.is_empty());
    assert_eq!(std::fs::read(&public).unwrap(), original_public);
    assert!(invoke("owner-verify").status.success());
}
