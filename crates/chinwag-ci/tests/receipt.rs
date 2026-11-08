// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]
use chinwag_ci::{
    envelope::{
        self, AcuGateKey, AuthenticatedEnvelope, ClaimedProvenance, Destination, DestinationKey,
        KeyPins, ResponseKey,
    },
    receipt::{self, ReceiptError, ReceiptSigner},
    runner_identity::RunnerIdentity,
    storage::{CiphertextStore, StorageError},
};
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    acu: AcuGateKey,
    recipient: DestinationKey,
    archive: DestinationKey,
    signer_r: ReceiptSigner,
    signer_a: ReceiptSigner,
    runner: RunnerIdentity,
    claims: ClaimedProvenance,
    pins: KeyPins,
    directory_r: tempfile::TempDir,
    directory_a: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let acu = AcuGateKey::generate().unwrap();
        let recipient = DestinationKey::generate(Destination::Recipient).unwrap();
        let archive = DestinationKey::generate(Destination::Archive).unwrap();
        let response_r = ResponseKey::generate(Destination::Recipient).unwrap();
        let response_a = ResponseKey::generate(Destination::Archive).unwrap();
        let directory_r = directory();
        let directory_a = directory();
        let signer_r =
            ReceiptSigner::generate(Destination::Recipient, [21; 32], open(&directory_r)).unwrap();
        let signer_a =
            ReceiptSigner::generate(Destination::Archive, [22; 32], open(&directory_a)).unwrap();
        let acu_signer = RunnerIdentity::generate()
            .unwrap()
            .public_keys()
            .signing_ed25519;
        let pins = KeyPins {
            acu_gate_base: acu.public(),
            recipient_psk: recipient.public(),
            archive_psk: archive.public(),
            recipient_response_base: response_r.public(),
            archive_response_base: response_a.public(),
            acu_signer,
            recipient_receipt_signer: signer_r.public(),
            archive_receipt_signer: signer_a.public(),
        };
        let claims = ClaimedProvenance {
            admission_sha256: [1; 32],
            repository: "example/ci-test".into(),
            repository_id: 42,
            source_commit: [2; 20],
            workflow_ref: "example/ci-test/.github/workflows/ci.yml@refs/heads/test".into(),
            workflow_commit: [3; 20],
            run_id: 100,
            run_attempt: 1,
            initiating_instance: "WORKHORSE#test-instance-1234".into(),
            intent_digest: [4; 32],
            command_profile_sha256: [5; 32],
            delivery_profile_sha256: [6; 32],
            policy_sha256: [7; 32],
            policy_epoch: 1,
        };
        Self {
            acu,
            recipient,
            archive,
            signer_r,
            signer_a,
            runner: RunnerIdentity::generate().unwrap(),
            claims,
            pins,
            directory_r,
            directory_a,
        }
    }
    fn envelope(&self, payload: &[u8]) -> AuthenticatedEnvelope {
        let s = self
            .runner
            .seal_failure(self.claims.clone(), self.pins.clone(), payload)
            .unwrap();
        envelope::authenticate(
            &s.manifest,
            &s.ciphertext,
            &self.claims,
            &self.pins,
            &self.runner.public_keys().signing_ed25519,
        )
        .unwrap()
    }
    fn authenticate(&self, blob: &[u8]) -> AuthenticatedEnvelope {
        let s = envelope::parse_storage_blob(blob).unwrap();
        envelope::authenticate(
            &s.manifest,
            &s.ciphertext,
            &self.claims,
            &self.pins,
            &self.runner.public_keys().signing_ed25519,
        )
        .unwrap()
    }
}
fn open(directory: &tempfile::TempDir) -> CiphertextStore {
    CiphertextStore::open(&directory.path().canonicalize().unwrap()).unwrap()
}
fn directory() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[test]
fn both_signed_receipts_follow_complete_durable_objects_with_recoverable_original_metadata() {
    let f = Fixture::new();
    let payload: Vec<u8> = (0..70000).map(|i| (i % 251) as u8).collect();
    let original = f.envelope(&payload);
    let r = open(&f.directory_r);
    let a = open(&f.directory_a);
    let mut blobs = vec![];
    for (store, signer, role, id, key) in [
        (
            &r,
            &f.signer_r,
            Destination::Recipient,
            [21; 32],
            &f.recipient,
        ),
        (&a, &f.signer_a, Destination::Archive, [22; 32], &f.archive),
    ] {
        let signed = signer.persist(&original).unwrap();
        let verified = receipt::verify(&signed, &original, role, id).unwrap();
        assert!(verified.created_inode_confirmed());
        assert_eq!(verified.envelope_digest(), original.digest());
        assert_eq!(verified.store_id(), &id);
        let blob = store.read_existing(verified.object_claim()).unwrap();
        let from_disk = f.authenticate(&blob);
        assert_eq!(from_disk.digest(), original.digest());
        let gate = f.acu.unwrap_for_authorized_release(&from_disk).unwrap();
        assert_eq!(&*key.open(&from_disk, &gate).unwrap(), &payload);
        blobs.push(blob);
    }
    assert_eq!(blobs[0], blobs[1]);
}

#[test]
fn reconciled_existing_observation_cannot_claim_witnessed_creation_or_rewrite_the_original() {
    let f = Fixture::new();
    let env = f.envelope(b"failure");
    let first = f.signer_r.persist(&env).unwrap();
    let first_verified = receipt::verify(&first, &env, Destination::Recipient, [21; 32]).unwrap();
    assert!(matches!(
        f.signer_r.persist(&env),
        Err(ReceiptError::Storage(StorageError::AlreadyExists))
    ));
    let reconciled = f.signer_r.reconcile_existing(&env).unwrap();
    let verified = receipt::verify(&reconciled, &env, Destination::Recipient, [21; 32]).unwrap();
    assert!(!verified.created_inode_confirmed());
    assert_eq!(
        first_verified.object_claim().sha256,
        verified.object_claim().sha256
    );
    let changed = String::from_utf8(reconciled).unwrap().replace(
        "\"created_inode_confirmed\":false",
        "\"created_inode_confirmed\":true",
    );
    // Preserve canonical field order so this exercises the signature check.
    assert!(receipt::verify(changed.as_bytes(), &env, Destination::Recipient, [21; 32]).is_err());
}

#[test]
fn receipt_role_store_provenance_or_signer_cannot_be_substituted_and_wrong_role_writes_nothing() {
    let f = Fixture::new();
    let env = f.envelope(b"failure");
    let wrong =
        ReceiptSigner::generate(Destination::Recipient, [21; 32], open(&f.directory_r)).unwrap();
    assert!(matches!(wrong.persist(&env), Err(ReceiptError::Rejected)));
    assert_eq!(std::fs::read_dir(f.directory_r.path()).unwrap().count(), 0);
    let signed = f.signer_r.persist(&env).unwrap();
    assert!(receipt::verify(&signed, &env, Destination::Archive, [21; 32]).is_err());
    assert!(receipt::verify(&signed, &env, Destination::Recipient, [22; 32]).is_err());
    let other = f.envelope(b"another failure");
    assert!(receipt::verify(&signed, &other, Destination::Recipient, [21; 32]).is_err());
    let json: serde_json::Value = serde_json::from_slice(&signed).unwrap();
    let signature = json["signature_hex"].as_str().unwrap();
    let mut corrupted = signature.to_owned();
    corrupted.replace_range(0..1, if &signature[..1] == "0" { "1" } else { "0" });
    let changed = String::from_utf8(signed)
        .unwrap()
        .replace(signature, &corrupted);
    assert!(receipt::verify(changed.as_bytes(), &env, Destination::Recipient, [21; 32]).is_err());
}

#[test]
fn storage_container_requires_all_original_parts_and_rejects_unbounded_or_trailing_bytes() {
    let f = Fixture::new();
    let env = f.envelope(b"failure");
    let bytes = env.complete_storage_blob().unwrap();
    for n in [0, 8, 19, 20, bytes.len() - 1] {
        assert!(envelope::parse_storage_blob(&bytes[..n]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(envelope::parse_storage_blob(&trailing).is_err());
    let mut overflow = bytes;
    overflow[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(envelope::parse_storage_blob(&overflow).is_err());
}
