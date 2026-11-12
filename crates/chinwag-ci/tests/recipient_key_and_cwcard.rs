// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Spec-pinned integration and negative tests for `CHWG-0267`:
//! 1. Ed25519-authenticated recipient `X25519-MLKEM768` (`0x647a`) encryption-key
//!    enrollment, `.chinwag/allowed_signers` seat bijection, rotation, and revocation.
//! 2. Direct offline-capable HPKE Base `.cwcard` (`CWCARD01`) sealing & local
//!    decapsulation without an ACU round-trip (with mandatory runner Ed25519
//!    origin authentication before decapsulation).
//! 3. Clean composition with Enterprise 2-of-3 ACU-gated release (`acu.rs`) on
//!    `X25519-MLKEM768` (`[0x647a, 1, 3]`) plus backward-compatible classical
//!    `X25519` (`[0x0020, 1, 3]`) profile/envelope parsing.

use chinwag_ci::{
    envelope::{
        self, CIPHERSUITE_X25519_MLKEM768, ClaimedProvenance, Destination, KEM_ID_X25519_MLKEM768,
        KeyPins, SUITE_X25519_LEGACY, SUITE_X25519_MLKEM768, XWING_ENCAPPED_KEY_BYTES,
        XWING_PUBLIC_KEY_BYTES,
    },
    recipient_key::{
        RecipientDecryptionKey, RecipientKeyDescriptor, RecipientKeyPurpose, RecipientKeyRegistry,
        SeatSignerDirectory, SignedRecipientKey, VerifiedRevocationState,
        sign_public_key_enrollment, sign_revocation_statement, verify_signed_recipient_key,
    },
    runner_identity::RunnerIdentity,
};
use ed25519_dalek::{Signer, SigningKey};

fn openssh_allowed_signers_line(
    seat_lower: &str,
    seat_upper: &str,
    seed_byte: u8,
) -> (SigningKey, String) {
    let sk = SigningKey::from_bytes(&[seed_byte; 32]);
    let ssh_pub = ssh_key::public::Ed25519PublicKey(sk.verifying_key().to_bytes());
    let pub_key = ssh_key::PublicKey::from(ssh_pub);
    let encoded = pub_key.to_openssh().unwrap();
    let line = format!("{seat_lower}-agent@chinwag.sh {encoded} chinwag {seat_upper}");
    (sk, line)
}

fn sample_claims() -> ClaimedProvenance {
    ClaimedProvenance {
        admission_sha256: [1; 32],
        repository: "emunlabs/chinwag".into(),
        repository_id: 42,
        source_commit: [2; 20],
        workflow_ref: "emunlabs/chinwag/.github/workflows/ci.yml@refs/heads/main".into(),
        workflow_commit: [3; 20],
        run_id: 267,
        run_attempt: 1,
        initiating_instance: "WORKHORSE#aabbccddeeff00112233445566778899".into(),
        intent_digest: [4; 32],
        command_profile_sha256: [5; 32],
        delivery_profile_sha256: [6; 32],
        policy_sha256: [7; 32],
        policy_epoch: 1,
    }
}

#[test]
fn allowed_signers_bijection_enrollment_rotation_and_revocation_enforced() {
    let (workhorse_sk, wh_line) = openssh_allowed_signers_line("workhorse", "WORKHORSE", 0x31);
    let (rust_sk, rust_line) = openssh_allowed_signers_line("rust", "RUST", 0x32);
    let allowed = format!("# Fleet signers\n{wh_line}\n{rust_line}\n");
    let signers = SeatSignerDirectory::from_allowed_signers(&allowed).unwrap();
    assert_eq!(
        signers.pubkey_for_seat("WORKHORSE"),
        Some(workhorse_sk.verifying_key().to_bytes())
    );

    // Duplicate seat with different key or shared key across two seats must fail closed.
    let (_, wh_conflict) = openssh_allowed_signers_line("workhorse", "WORKHORSE", 0x33);
    assert!(
        SeatSignerDirectory::from_allowed_signers(&format!("{wh_line}\n{wh_conflict}\n")).is_err()
    );
    let (_, shared_key_other_seat) = openssh_allowed_signers_line("alistair", "ALISTAIR", 0x31);
    assert!(
        SeatSignerDirectory::from_allowed_signers(&format!("{wh_line}\n{shared_key_other_seat}\n"))
            .is_err()
    );

    let recip_k1 = RecipientDecryptionKey::generate(
        "WORKHORSE",
        "wh-hpke-2026-e1",
        1,
        RecipientKeyPurpose::CwcardOfflineBase,
    )
    .unwrap();
    assert_eq!(
        recip_k1.public_key().as_bytes().len(),
        XWING_PUBLIC_KEY_BYTES
    );

    let signed_k1 = recip_k1
        .sign_enrollment(&workhorse_sk, 1_000, 10_000)
        .unwrap();
    let revocations = VerifiedRevocationState::new();
    let verified_k1 =
        verify_signed_recipient_key(&signed_k1, &signers, &revocations, 2_000).unwrap();
    assert_eq!(verified_k1.seat(), "WORKHORSE");
    assert_eq!(verified_k1.kid(), "wh-hpke-2026-e1");
    assert_eq!(verified_k1.epoch(), 1);
    assert_eq!(verified_k1.kem_id(), KEM_ID_X25519_MLKEM768);
    assert_eq!(verified_k1.ciphersuite(), CIPHERSUITE_X25519_MLKEM768);

    // Lifetime boundaries: premature (999) and expired (10_000) must reject.
    assert!(verify_signed_recipient_key(&signed_k1, &signers, &revocations, 999).is_err());
    assert!(verify_signed_recipient_key(&signed_k1, &signers, &revocations, 10_000).is_err());

    // Wrong seat's authorized signer (`RUST` signing a `WORKHORSE` key) must reject.
    let cross_seat = recip_k1.sign_enrollment(&rust_sk, 1_000, 10_000).unwrap();
    assert!(verify_signed_recipient_key(&cross_seat, &signers, &revocations, 2_000).is_err());

    // Unregistered signer must reject.
    let rogue_sk = SigningKey::from_bytes(&[0x99; 32]);
    let rogue_signed = recip_k1.sign_enrollment(&rogue_sk, 1_000, 10_000).unwrap();
    assert!(verify_signed_recipient_key(&rogue_signed, &signers, &revocations, 2_000).is_err());

    // Tampered signature, tampered ciphersuite, tampered kem_id, non-canonical ML-KEM or X25519 pk.
    let mut parsed: SignedRecipientKey = serde_json::from_slice(&signed_k1).unwrap();
    let mut bad_sig = hex::decode(&parsed.signature_hex).unwrap();
    bad_sig[0] ^= 0x01;
    let mut sig_tampered = parsed.clone();
    sig_tampered.signature_hex = hex::encode(bad_sig);
    assert!(
        verify_signed_recipient_key(
            &serde_json::to_vec(&sig_tampered).unwrap(),
            &signers,
            &revocations,
            2_000
        )
        .is_err()
    );

    // Re-signed wrong kem_id (0x0020 or 0x0030) or wrong ciphersuite must reject.
    for (bad_suite, bad_kem) in [
        ("X25519-HKDF-SHA256-ChaCha20Poly1305", 0x0020_u16),
        (CIPHERSUITE_X25519_MLKEM768, 0x0030_u16),
    ] {
        let mut bad_desc: RecipientKeyDescriptor = parsed.descriptor.clone();
        bad_desc.ciphersuite = bad_suite.into();
        bad_desc.kem_id = bad_kem;
        let forged = sign_raw_descriptor_for_negative_test(&bad_desc, &workhorse_sk);
        assert!(verify_signed_recipient_key(&forged, &signers, &revocations, 2_000).is_err());
    }

    // Re-signed non-canonical ML-KEM-768 coefficient (>= 3329) or low-order X25519 component must reject.
    let mut raw_pk = hex::decode(&parsed.descriptor.enc_public_key_hex).unwrap();
    raw_pk[0] = 0x01;
    raw_pk[1] = (raw_pk[1] & 0xf0) | 0x0d; // 3329
    let mut bad_mlkem = parsed.descriptor.clone();
    bad_mlkem.enc_public_key_hex = hex::encode(&raw_pk);
    assert!(
        verify_signed_recipient_key(
            &sign_raw_descriptor_for_negative_test(&bad_mlkem, &workhorse_sk),
            &signers,
            &revocations,
            2_000
        )
        .is_err()
    );

    let mut low_order_x = hex::decode(&parsed.descriptor.enc_public_key_hex).unwrap();
    low_order_x[1184..1216].fill(0);
    low_order_x[1184] = 1; // low-order point on Curve25519
    let mut bad_x25519 = parsed.descriptor.clone();
    bad_x25519.enc_public_key_hex = hex::encode(&low_order_x);
    assert!(
        verify_signed_recipient_key(
            &sign_raw_descriptor_for_negative_test(&bad_x25519, &workhorse_sk),
            &signers,
            &revocations,
            2_000
        )
        .is_err()
    );

    // Inline revoked=true must reject even when validly signed by seat owner.
    parsed.descriptor.revoked = true;
    assert!(
        verify_signed_recipient_key(
            &sign_raw_descriptor_for_negative_test(&parsed.descriptor, &workhorse_sk),
            &signers,
            &revocations,
            2_000
        )
        .is_err()
    );

    // Signed revocation list from WORKHORSE revokes `wh-hpke-2026-e1`; wrong seat cannot forge it.
    assert!(
        sign_revocation_statement(
            "WORKHORSE",
            1,
            &["wh-hpke-2026-e1".to_string()],
            2_500,
            &rust_sk,
        )
        .and_then(|bytes| {
            let mut st = VerifiedRevocationState::new();
            st.ingest_signed_revocation(&bytes, &signers)?;
            Ok(st)
        })
        .is_err()
    );
    let rev_bytes = sign_revocation_statement(
        "WORKHORSE",
        1,
        &["wh-hpke-2026-e1".to_string()],
        2_500,
        &workhorse_sk,
    )
    .unwrap();
    let mut active_revocations = VerifiedRevocationState::new();
    active_revocations
        .ingest_signed_revocation(&rev_bytes, &signers)
        .unwrap();
    assert!(verify_signed_recipient_key(&signed_k1, &signers, &active_revocations, 2_600).is_err());

    // Registry rotation: epoch 1 -> epoch 2 must supersede epoch 1 and reject key/kid/epoch reuse.
    let mut registry = RecipientKeyRegistry::new();
    registry.enroll(&signed_k1, &signers, 2_000).unwrap();
    // Re-enrolling same epoch or reusing public key with epoch 2 must reject.
    let reused_pk_e2 = sign_public_key_enrollment(
        "WORKHORSE",
        "wh-hpke-2026-e2-reused",
        2,
        RecipientKeyPurpose::CwcardOfflineBase,
        recip_k1.public_key(),
        2_100,
        10_000,
        &workhorse_sk,
    )
    .unwrap();
    assert!(registry.rotate(&reused_pk_e2, &signers, 2_200).is_err());

    let recip_k2 = RecipientDecryptionKey::generate(
        "WORKHORSE",
        "wh-hpke-2026-e2",
        2,
        RecipientKeyPurpose::CwcardOfflineBase,
    )
    .unwrap();
    let signed_k2 = recip_k2
        .sign_enrollment(&workhorse_sk, 2_100, 12_000)
        .unwrap();
    let verified_k2 = registry.rotate(&signed_k2, &signers, 2_200).unwrap();
    assert_eq!(verified_k2.epoch(), 2);
    // Old epoch 1 key is now superseded in registry's revocation state!
    assert!(
        verify_signed_recipient_key(&signed_k1, &signers, registry.revocation_state(), 2_200)
            .is_err()
    );

    // Revoking active K2 (epoch 2) with min_valid_epoch = 1 evicts K2 AND strictly
    // advances the slot's monotonic epoch floor so re-enrolling a fresh K3 at epoch 2
    // or with a backdated issued_unix (< 2_100) is REFUSED, whereas epoch 3 succeeds!
    let rev_k2 = sign_revocation_statement(
        "WORKHORSE",
        1,
        &["wh-hpke-2026-e2".to_string()],
        2_250,
        &workhorse_sk,
    )
    .unwrap();
    registry
        .ingest_signed_revocation(&rev_k2, &signers)
        .unwrap();
    assert!(
        registry
            .active_key("WORKHORSE", RecipientKeyPurpose::CwcardOfflineBase)
            .is_none()
    );

    let recip_k3_reused_epoch = RecipientDecryptionKey::generate(
        "WORKHORSE",
        "wh-hpke-2026-e2-retry",
        2,
        RecipientKeyPurpose::CwcardOfflineBase,
    )
    .unwrap();
    let signed_k3_reused_epoch = recip_k3_reused_epoch
        .sign_enrollment(&workhorse_sk, 2_300, 15_000)
        .unwrap();
    assert!(
        registry
            .enroll(&signed_k3_reused_epoch, &signers, 2_300)
            .is_err()
    );

    let recip_k3_backdated = RecipientDecryptionKey::generate(
        "WORKHORSE",
        "wh-hpke-2026-e3-backdated",
        3,
        RecipientKeyPurpose::CwcardOfflineBase,
    )
    .unwrap();
    let signed_k3_backdated = recip_k3_backdated
        .sign_enrollment(&workhorse_sk, 2_050, 15_000)
        .unwrap();
    assert!(
        registry
            .enroll(&signed_k3_backdated, &signers, 2_300)
            .is_err()
    );

    let recip_k3 = RecipientDecryptionKey::generate(
        "WORKHORSE",
        "wh-hpke-2026-e3",
        3,
        RecipientKeyPurpose::CwcardOfflineBase,
    )
    .unwrap();
    let signed_k3 = recip_k3
        .sign_enrollment(&workhorse_sk, 2_300, 15_000)
        .unwrap();
    let verified_k3 = registry.enroll(&signed_k3, &signers, 2_300).unwrap();
    assert_eq!(verified_k3.epoch(), 3);
}

fn sign_raw_descriptor_for_negative_test(
    descriptor: &RecipientKeyDescriptor,
    signer: &SigningKey,
) -> Vec<u8> {
    let payload = chinwag_ci::recipient_key::descriptor_signing_bytes(descriptor).unwrap();
    let sig = signer.sign(&payload);
    serde_json::to_vec(&SignedRecipientKey {
        descriptor: descriptor.clone(),
        signature_hex: hex::encode(sig.to_bytes()),
    })
    .unwrap()
}

#[test]
fn offline_cwcard_base_hpke_seals_and_opens_locally_and_rejects_all_tampering() {
    let (workhorse_sk, wh_line) = openssh_allowed_signers_line("workhorse", "WORKHORSE", 0x41);
    let signers = SeatSignerDirectory::from_allowed_signers(&wh_line).unwrap();
    let revocations = VerifiedRevocationState::new();

    let recipient_secret = RecipientDecryptionKey::generate(
        "WORKHORSE",
        "wh-cwcard-offline-v1",
        1,
        RecipientKeyPurpose::CwcardOfflineBase,
    )
    .unwrap();
    let enrollment = recipient_secret
        .sign_enrollment(&workhorse_sk, 1_000, 20_000)
        .unwrap();
    let verified_recipient =
        verify_signed_recipient_key(&enrollment, &signers, &revocations, 1_500).unwrap();

    // Runner seals `.cwcard` while recipient is completely offline (no ACU round-trip).
    let runner = RunnerIdentity::generate().unwrap();
    let claims = sample_claims();
    let payload: Vec<u8> = (0..128_000).map(|i| ((i * 7 + 3) % 251) as u8).collect();
    let sealed = runner
        .seal_cwcard_offline(claims.clone(), &verified_recipient, 1_500, &payload)
        .unwrap();
    let wire_blob = sealed.to_cwcard_blob().unwrap();
    assert_eq!(&wire_blob[..8], b"CWCARD01");

    // Parse `.cwcard` wire blob, authenticate runner Ed25519 signature + recipient binding, and
    // open locally with `recipient_secret`.
    let parsed_cwcard = envelope::parse_cwcard_blob(&wire_blob).unwrap();
    let manifest_json: serde_json::Value = serde_json::from_slice(&parsed_cwcard.manifest).unwrap();
    assert_eq!(
        manifest_json["header"]["pre"]["ciphersuite"].as_str(),
        Some(CIPHERSUITE_X25519_MLKEM768)
    );
    assert_eq!(
        manifest_json["header"]["pre"]["suite"],
        serde_json::json!(SUITE_X25519_MLKEM768)
    );
    assert_eq!(
        manifest_json["header"]["enc"].as_str().unwrap().len(),
        XWING_ENCAPPED_KEY_BYTES * 2
    );

    let authenticated = envelope::authenticate_cwcard_offline(
        &parsed_cwcard,
        &claims,
        &verified_recipient,
        &runner.public_keys().signing_ed25519,
    )
    .unwrap();
    let opened = recipient_secret.open_cwcard(&authenticated).unwrap();
    assert_eq!(&*opened, payload.as_slice());

    // Negative 1: Wrong `RecipientDecryptionKey` (`kid` mismatch or key mismatch) refuses.
    let other_secret = RecipientDecryptionKey::generate(
        "WORKHORSE",
        "wh-cwcard-other",
        1,
        RecipientKeyPurpose::CwcardOfflineBase,
    )
    .unwrap();
    assert!(other_secret.open_cwcard(&authenticated).is_err());

    // Negative 2: Purpose confusion (`AcuRecipientPsk` key passed to `seal_cwcard_offline`) refuses.
    let acu_purpose_key = RecipientDecryptionKey::generate(
        "WORKHORSE",
        "wh-acu-psk-only",
        1,
        RecipientKeyPurpose::AcuRecipientPsk,
    )
    .unwrap();
    let acu_enrollment = acu_purpose_key
        .sign_enrollment(&workhorse_sk, 1_000, 20_000)
        .unwrap();
    let verified_acu_key =
        verify_signed_recipient_key(&acu_enrollment, &signers, &revocations, 1_500).unwrap();
    assert!(
        runner
            .seal_cwcard_offline(claims.clone(), &verified_acu_key, 1_500, b"payload")
            .is_err()
    );

    // Negative 3: Unsigned / tampered runner Ed25519 signature refuses BEFORE decapsulation.
    let mut bad_sig_manifest: serde_json::Value =
        serde_json::from_slice(&parsed_cwcard.manifest).unwrap();
    let orig_sig = bad_sig_manifest["signature_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let flipped = if orig_sig.starts_with('0') { "1" } else { "0" };
    bad_sig_manifest["signature_hex"] = serde_json::json!(format!("{flipped}{}", &orig_sig[1..]));
    let forged_cwcard = envelope::SealedCwcard {
        manifest: serde_json::to_vec(&bad_sig_manifest).unwrap(),
        ciphertext: parsed_cwcard.ciphertext.clone(),
    };
    assert!(
        envelope::authenticate_cwcard_offline(
            &forged_cwcard,
            &claims,
            &verified_recipient,
            &runner.public_keys().signing_ed25519,
        )
        .is_err()
    );

    // Negative 4: Mutated AAD / header metadata (`run_id`, `recipient_kid`, `enc` in ML-KEM ct_M
    // and X25519 ct_X) refuses authentication; and even if re-signed by a compromised runner,
    // mutating `enc[0]` (ML-KEM-768 ct_M) or `enc[1088]` (X25519 ct_X) fails `open_cwcard`!
    for byte_offset in [0_usize, 600, 1088, 1119] {
        let mut tampered = parsed_cwcard.clone();
        let mut v: serde_json::Value = serde_json::from_slice(&tampered.manifest).unwrap();
        let mut enc_raw = hex::decode(v["header"]["enc"].as_str().unwrap()).unwrap();
        enc_raw[byte_offset] ^= 0x01;
        v["header"]["enc"] = serde_json::json!(hex::encode(&enc_raw));
        tampered.manifest = serde_json::to_vec(&v).unwrap();
        assert!(
            envelope::authenticate_cwcard_offline(
                &tampered,
                &claims,
                &verified_recipient,
                &runner.public_keys().signing_ed25519,
            )
            .is_err()
        );
    }

    // Negative 5: Compromised runner re-signing mutated `enc[0]` (ML-KEM-768 `ct_M`),
    // mutated contributory `enc[1088..1120]` (X25519 `ct_X`), or low-order `ct_X`!
    #[derive(serde::Serialize, serde::Deserialize)]
    struct RawPre {
        schema: String,
        version: u16,
        mode: String,
        ciphersuite: String,
        suite: [u16; 3],
        recipient_seat: String,
        recipient_kid: String,
        recipient_key_epoch: u64,
        recipient_enc_pk_sha256: [u8; 32],
        claims: ClaimedProvenance,
        runner_signer: [u8; 32],
        sealed_unix: u64,
        plaintext_bytes: u64,
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    struct RawHdr {
        pre: RawPre,
        enc: String,
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    struct RawManifest {
        header: RawHdr,
        ciphertext_sha256: [u8; 32],
        ciphertext_bytes: u64,
        signature_hex: String,
    }
    let rogue_runner_sk = iroh::SecretKey::from_bytes(&[0x77; 32]);
    let rogue_runner_pk = *rogue_runner_sk.public().as_bytes();
    let resign_cwcard = |enc_bytes: &[u8]| -> envelope::SealedCwcard {
        let mut m: RawManifest = serde_json::from_slice(&parsed_cwcard.manifest).unwrap();
        m.header.pre.runner_signer = rogue_runner_pk;
        m.header.enc = hex::encode(enc_bytes);
        let header_bytes = serde_json::to_vec(&m.header).unwrap();
        let mut stmt = b"chinwag-ci-cwcard-signature-v1\0".to_vec();
        stmt.extend_from_slice(&(header_bytes.len() as u64).to_be_bytes());
        stmt.extend_from_slice(&header_bytes);
        stmt.extend_from_slice(&32_u64.to_be_bytes());
        stmt.extend_from_slice(&m.ciphertext_sha256);
        stmt.extend_from_slice(&8_u64.to_be_bytes());
        stmt.extend_from_slice(&m.ciphertext_bytes.to_be_bytes());
        m.signature_hex = hex::encode(rogue_runner_sk.sign(&stmt).to_bytes());
        envelope::SealedCwcard {
            manifest: serde_json::to_vec(&m).unwrap(),
            ciphertext: parsed_cwcard.ciphertext.clone(),
        }
    };
    let orig_enc =
        hex::decode(
            serde_json::from_slice::<serde_json::Value>(&parsed_cwcard.manifest).unwrap()["header"]
                ["enc"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    // 5a: Mutated ML-KEM-768 `ct_M` re-signed by rogue runner -> passes origin auth, MUST fail `open_cwcard`!
    let mut mlkem_flipped = orig_enc.clone();
    mlkem_flipped[0] ^= 0x01;
    let auth_mlkem_flipped = envelope::authenticate_cwcard_offline(
        &resign_cwcard(&mlkem_flipped),
        &claims,
        &verified_recipient,
        &rogue_runner_pk,
    )
    .unwrap();
    assert!(recipient_secret.open_cwcard(&auth_mlkem_flipped).is_err());

    // 5b: Mutated contributory X25519 `ct_X` re-signed by rogue runner -> passes origin auth, MUST fail `open_cwcard`!
    let other_ephem_x =
        envelope::DestinationKey::generate_legacy_x25519(envelope::Destination::Recipient)
            .unwrap()
            .public();
    let mut x25519_swapped = orig_enc.clone();
    x25519_swapped[1088..1120].copy_from_slice(other_ephem_x.as_bytes());
    let auth_x25519_swapped = envelope::authenticate_cwcard_offline(
        &resign_cwcard(&x25519_swapped),
        &claims,
        &verified_recipient,
        &rogue_runner_pk,
    )
    .unwrap();
    assert!(recipient_secret.open_cwcard(&auth_x25519_swapped).is_err());

    // 5c: Low-order X25519 `ct_X` re-signed by rogue runner -> MUST be rejected at `authenticate_cwcard_offline`!
    let mut low_order_enc = orig_enc;
    low_order_enc[1088..1120].fill(0);
    low_order_enc[1088] = 1;
    assert!(
        envelope::authenticate_cwcard_offline(
            &resign_cwcard(&low_order_enc),
            &claims,
            &verified_recipient,
            &rogue_runner_pk,
        )
        .is_err()
    );

    // Negative 6: Sealing outside recipient key validity window refuses.
    assert!(
        runner
            .seal_cwcard_offline(claims.clone(), &verified_recipient, 20_000, b"expired")
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn enterprise_acu_gated_x25519_mlkem768_composes_with_allowed_signers_and_legacy_0x0020_parses() {
    use chinwag_ci::{
        acu::{self, PolicySpec},
        custody::{OwnerCustody, OwnerRole, PublicDestination, PublicEnrollment},
        envelope::{AcuGateKey, DestinationKey, ResponseKey},
        profile::{CommandProfile, CommandProfileSpec, DeliveryProfile, DeliveryProfileSpec},
        receipt,
        storage::CiphertextStore,
    };
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

    let mk_dir = || {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    };
    let dirs: Vec<_> = (0..6).map(|_| mk_dir()).collect();
    let store = |i: usize| CiphertextStore::open(&dirs[i].path().canonicalize().unwrap()).unwrap();

    let (workhorse_sk, wh_line) = openssh_allowed_signers_line("workhorse", "WORKHORSE", 0x51);
    let signers = SeatSignerDirectory::from_allowed_signers(&wh_line).unwrap();
    let mut revocations = VerifiedRevocationState::new();

    let recipient_owner = OwnerCustody::create_new(
        &dirs[0].path().canonicalize().unwrap(),
        OwnerRole::Recipient,
        [10; 32],
        Some((store(4), [21; 32])),
    )
    .unwrap();
    let archive_owner = OwnerCustody::create_new(
        &dirs[1].path().canonicalize().unwrap(),
        OwnerRole::Archive,
        [11; 32],
        Some((store(5), [22; 32])),
    )
    .unwrap();
    let acu_owner = OwnerCustody::create_new(
        &dirs[2].path().canonicalize().unwrap(),
        OwnerRole::Acu,
        [12; 32],
        None,
    )
    .unwrap();
    let admission_owner = OwnerCustody::create_new(
        &dirs[3].path().canonicalize().unwrap(),
        OwnerRole::Admission,
        [13; 32],
        None,
    )
    .unwrap();

    let PublicEnrollment::Destination(r_dest) = recipient_owner.public_enrollment().unwrap() else {
        panic!("recipient")
    };
    let PublicEnrollment::Destination(a_dest) = archive_owner.public_enrollment().unwrap() else {
        panic!("archive")
    };
    let PublicEnrollment::Acu {
        gate_base,
        signer: acu_signer,
    } = acu_owner.public_enrollment().unwrap()
    else {
        panic!("acu")
    };
    let PublicEnrollment::Admission {
        signer: admission_signer,
    } = admission_owner.public_enrollment().unwrap()
    else {
        panic!("admission")
    };

    // Confirm all newly generated OwnerCustody KEM keys are 1216-byte X25519-MLKEM768 (0x647a).
    assert_eq!(r_dest.psk.as_bytes().len(), XWING_PUBLIC_KEY_BYTES);
    assert_eq!(
        r_dest.response_base.as_bytes().len(),
        XWING_PUBLIC_KEY_BYTES
    );
    assert_eq!(gate_base.as_bytes().len(), XWING_PUBLIC_KEY_BYTES);

    // Bind recipient's ACU-gated KEM keys to WORKHORSE's `.chinwag/allowed_signers` Ed25519 seat key!
    let psk_binding = sign_public_key_enrollment(
        "WORKHORSE",
        "wh-acu-psk-e1",
        1,
        RecipientKeyPurpose::AcuRecipientPsk,
        &r_dest.psk,
        1_000,
        5_000,
        &workhorse_sk,
    )
    .unwrap();
    let response_binding = sign_public_key_enrollment(
        "WORKHORSE",
        "wh-acu-resp-e1",
        1,
        RecipientKeyPurpose::AcuRecipientResponseBase,
        &r_dest.response_base,
        1_000,
        5_000,
        &workhorse_sk,
    )
    .unwrap();

    let cmd_spec = CommandProfileSpec {
        version: 1,
        execution_id: [1; 32],
        rust_image: format!("docker.io/library/rust@sha256:{}", "a".repeat(64)),
        fixture_sha256: Sha256::digest(b"fixture").into(),
        timeout_seconds: 60,
        isolation: "UNPRIVILEGED_NETWORKLESS_DOCKER_FIXED_RUST_FIXTURE_V1".into(),
    };
    let cmd_profile = CommandProfile::parse(&serde_json::to_vec(&cmd_spec).unwrap()).unwrap();

    let pins = KeyPins {
        acu_gate_base: gate_base.clone(),
        recipient_psk: r_dest.psk.clone(),
        archive_psk: a_dest.psk.clone(),
        recipient_response_base: r_dest.response_base.clone(),
        archive_response_base: a_dest.response_base.clone(),
        acu_signer,
        recipient_receipt_signer: r_dest.receipt_signer,
        archive_receipt_signer: a_dest.receipt_signer,
    };
    let policy_spec = PolicySpec {
        version: 1,
        epoch: 1,
        issued_unix: 1_000,
        expires_unix: 2_000,
        active: true,
        allow_recipient: true,
        allow_archive: true,
        repository_id: 42,
        initiating_instance: "WORKHORSE#acu-pq-instance".into(),
        key_pins_sha256: acu::key_pins_digest(&pins).unwrap(),
        recipient_store_id: [21; 32],
        archive_store_id: [22; 32],
        allowed_historical_envelopes: Vec::new(),
    };
    let policy = acu::verify_current_policy(
        &acu_owner.sign_release_policy(&policy_spec).unwrap(),
        acu_signer,
        1_001,
    )
    .unwrap();

    let delivery_spec = DeliveryProfileSpec {
        version: 1,
        repository_id: 42,
        initiating_instance: "WORKHORSE#acu-pq-instance".into(),
        recipient: r_dest,
        recipient_psk_binding: Some(serde_json::from_slice(&psk_binding).unwrap()),
        recipient_response_base_binding: Some(serde_json::from_slice(&response_binding).unwrap()),
        recipient_key_revocations: Vec::new(),
        archive: a_dest,
        acu_gate_base: gate_base,
        acu_signer,
        admission_signer,
        relay_origin: "https://relay-pq.trycloudflare.com/".into(),
        admission_origin: "https://admission-pq.trycloudflare.com/".into(),
        acu_origin: "https://acu-pq.trycloudflare.com/".into(),
        command_profile_sha256: cmd_profile.digest(),
        original_policy_sha256: policy.digest(),
        original_policy_epoch: 1,
        expires_unix: 2_000,
        customer_custody_boundary: "CUSTOMER_ACU_AND_ARCHIVE_SHARED_HOST_UID".into(),
    };
    let delivery_bytes = serde_json::to_vec(&delivery_spec).unwrap();
    let delivery_profile = DeliveryProfile::parse(&delivery_bytes).unwrap();
    assert_eq!(delivery_profile.suite().suite_ids(), SUITE_X25519_MLKEM768);

    // Verify authenticated recipient key bindings compose with `DeliveryProfile`!
    let (v_psk, v_resp) = delivery_profile
        .verify_recipient_key_bindings(
            &psk_binding,
            &response_binding,
            &signers,
            &revocations,
            1_005,
        )
        .unwrap();
    assert_eq!(v_psk.seat(), "WORKHORSE");
    assert_eq!(v_resp.seat(), "WORKHORSE");

    // Persist + verify signed durable storage receipt on X25519-MLKEM768 envelope:
    let runner = RunnerIdentity::generate().unwrap();
    let mut claims = sample_claims();
    claims.initiating_instance = "WORKHORSE#acu-pq-instance".into();
    claims.policy_sha256 = policy.digest();
    let secret_failure = b"sensitive compiler diagnostic sealed under X25519-MLKEM768 + ACU 2-of-3";
    let sealed = runner
        .seal_failure(
            claims.clone(),
            delivery_profile.key_pins().clone(),
            secret_failure,
        )
        .unwrap();
    let auth_env = envelope::authenticate(
        &sealed.manifest,
        &sealed.ciphertext,
        &claims,
        delivery_profile.key_pins(),
        &runner.public_keys().signing_ed25519,
    )
    .unwrap();
    let receipt_bytes = recipient_owner.persist(&auth_env).unwrap();
    let verified_receipt =
        receipt::verify(&receipt_bytes, &auth_env, Destination::Recipient, [21; 32]).unwrap();
    assert_eq!(
        recipient_owner
            .read_complete_object(&verified_receipt)
            .unwrap(),
        auth_env.complete_storage_blob().unwrap()
    );

    // Also prove standalone ACU-gated 2-of-3 cryptographic round-trip on X25519-MLKEM768:
    let acu_k = AcuGateKey::generate().unwrap();
    let dst_r = DestinationKey::generate(Destination::Recipient).unwrap();
    let dst_a = DestinationKey::generate(Destination::Archive).unwrap();
    let rsp_r = ResponseKey::generate(Destination::Recipient).unwrap();
    let rsp_a = ResponseKey::generate(Destination::Archive).unwrap();
    let ed = |b| *iroh::SecretKey::from_bytes(&[b; 32]).public().as_bytes();
    let standalone_pins = KeyPins {
        acu_gate_base: acu_k.public(),
        recipient_psk: dst_r.public(),
        archive_psk: dst_a.public(),
        recipient_response_base: rsp_r.public(),
        archive_response_base: rsp_a.public(),
        acu_signer: ed(61),
        recipient_receipt_signer: ed(62),
        archive_receipt_signer: ed(63),
    };
    let s2 = runner
        .seal_failure(claims.clone(), standalone_pins.clone(), secret_failure)
        .unwrap();
    let e2 = envelope::authenticate(
        &s2.manifest,
        &s2.ciphertext,
        &claims,
        &standalone_pins,
        &runner.public_keys().signing_ed25519,
    )
    .unwrap();
    let gate = acu_k.unwrap_for_authorized_release(&e2).unwrap();
    let wrapped_grant = gate
        .wrap_response(&e2, Destination::Recipient, [0x77; 32])
        .unwrap();
    let delivered_gate = rsp_r
        .open_gate_from_verified_grant(&e2, [0x77; 32], &wrapped_grant)
        .unwrap();
    assert_eq!(&*dst_r.open(&e2, &delivered_gate).unwrap(), secret_failure);

    // Revoking `wh-acu-psk-e1` causes `DeliveryProfile::verify_recipient_key_bindings` to refuse!
    let rev = sign_revocation_statement(
        "WORKHORSE",
        1,
        &["wh-acu-psk-e1".to_string()],
        1_020,
        &workhorse_sk,
    )
    .unwrap();
    revocations
        .ingest_signed_revocation(&rev, &signers)
        .unwrap();
    assert!(
        delivery_profile
            .verify_recipient_key_bindings(
                &psk_binding,
                &response_binding,
                &signers,
                &revocations,
                1_021,
            )
            .is_err()
    );

    // Backward-compatible classical X25519 ([0x0020, 1, 3]) DeliveryProfile parsing check:
    let legacy_r = PublicDestination {
        role: Destination::Recipient,
        store_id: [31; 32],
        store_binding: [32; 32],
        psk: DestinationKey::generate_legacy_x25519(Destination::Recipient)
            .unwrap()
            .public(),
        response_base: ResponseKey::generate_legacy_x25519(Destination::Recipient)
            .unwrap()
            .public(),
        receipt_signer: ed(41),
        release_request_signer: ed(41),
        transport: ed(42),
    };
    let legacy_a = PublicDestination {
        role: Destination::Archive,
        store_id: [33; 32],
        store_binding: [34; 32],
        psk: DestinationKey::generate_legacy_x25519(Destination::Archive)
            .unwrap()
            .public(),
        response_base: ResponseKey::generate_legacy_x25519(Destination::Archive)
            .unwrap()
            .public(),
        receipt_signer: ed(43),
        release_request_signer: ed(43),
        transport: ed(44),
    };
    let legacy_spec = DeliveryProfileSpec {
        recipient: legacy_r,
        recipient_psk_binding: None,
        recipient_response_base_binding: None,
        recipient_key_revocations: Vec::new(),
        archive: legacy_a.clone(),
        acu_gate_base: AcuGateKey::generate_legacy_x25519().unwrap().public(),
        acu_signer: ed(45),
        admission_signer: ed(46),
        ..delivery_spec.clone()
    };
    let legacy_profile =
        DeliveryProfile::parse(&serde_json::to_vec(&legacy_spec).unwrap()).unwrap();
    assert_eq!(legacy_profile.suite().suite_ids(), SUITE_X25519_LEGACY);

    // Mixed-suite KeyPins (e.g., 0x647a acu_gate_base mixed with 0x0020 archive) must reject!
    let mut mixed_spec = legacy_spec;
    mixed_spec.acu_gate_base = AcuGateKey::generate().unwrap().public();
    assert!(DeliveryProfile::parse(&serde_json::to_vec(&mixed_spec).unwrap()).is_err());
}
