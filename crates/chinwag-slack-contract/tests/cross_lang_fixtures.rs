// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use chinwag_slack_contract::{
    Ed25519KeyPairSigner, KeyFingerprint, VerificationPolicyV1,
    decode_and_verify_dispatch_envelope_bytes, decode_and_verify_signed_beat_bytes,
    sign_blind_slack_beat, sign_coordinator_dispatch_envelope, to_jcs_string,
};
use serde::Deserialize;
use serde_json::Value;

const ROUNDTRIP_JSON: &str = include_str!("vectors/cross-lang-roundtrip-vectors.json");
const ADVERSARIAL_JSON: &str = include_str!("vectors/adversarial-vectors.json");

#[derive(Deserialize)]
struct TrustedKeysDoc {
    k1_ci: KeyFingerprint,
    k1_daemon: KeyFingerprint,
    k1_admin_passkey: KeyFingerprint,
    k2_coordinator: KeyFingerprint,
}

#[derive(Deserialize)]
struct RoundtripVector {
    id: String,
    expected_beat_jcs: String,
    expected_beat_digest: String,
    expected_receipt_jcs: String,
    envelope: Value,
}

#[derive(Deserialize)]
struct RoundtripSuite {
    trusted_keys: TrustedKeysDoc,
    vectors: Vec<RoundtripVector>,
}

#[derive(Deserialize)]
struct AdversarialCase {
    id: String,
    payload: Value,
}

#[derive(Deserialize)]
struct AdversarialSuite {
    signed_beat_rejections: Vec<AdversarialCase>,
    dispatch_envelope_rejections: Vec<AdversarialCase>,
}

fn seed_from_label(label: &str) -> [u8; 32] {
    let full = format!("TEST_ONLY:CHWG_0253:{label}");
    *blake3::hash(full.as_bytes()).as_bytes()
}

#[test]
fn verifies_typescript_generated_jcs_blake3_and_ed25519_vectors_bit_for_bit() {
    let suite: RoundtripSuite = serde_json::from_str(ROUNDTRIP_JSON).unwrap();

    let k1_ci = Ed25519KeyPairSigner::from_seed_bytes(&seed_from_label("K1_CI_OIDC"));
    let k1_daemon = Ed25519KeyPairSigner::from_seed_bytes(&seed_from_label("K1_DEV_SEAT"));
    let k1_admin = Ed25519KeyPairSigner::from_seed_bytes(&seed_from_label("K1_ORG_ADMIN_PASSKEY"));
    let k2_coord = Ed25519KeyPairSigner::from_seed_bytes(&seed_from_label("K2_COORDINATOR"));

    assert_eq!(k1_ci.public_fingerprint(), suite.trusted_keys.k1_ci);
    assert_eq!(k1_daemon.public_fingerprint(), suite.trusted_keys.k1_daemon);
    assert_eq!(
        k1_admin.public_fingerprint(),
        suite.trusted_keys.k1_admin_passkey
    );
    assert_eq!(
        k2_coord.public_fingerprint(),
        suite.trusted_keys.k2_coordinator
    );

    let policy = VerificationPolicyV1 {
        trusted_k1_keys: Some(vec![suite.trusted_keys.k1_ci, suite.trusted_keys.k1_daemon]),
        trusted_k2_keys: Some(vec![suite.trusted_keys.k2_coordinator]),
        trusted_admin_passkey_keys: Some(vec![suite.trusted_keys.k1_admin_passkey]),
        ..VerificationPolicyV1::default()
    };

    assert_eq!(suite.vectors.len(), 3);
    for vec_case in &suite.vectors {
        let raw_bytes = serde_json::to_vec(&vec_case.envelope).unwrap();
        let (decoded, verified_digest) =
            decode_and_verify_dispatch_envelope_bytes(&raw_bytes, &policy)
                .unwrap_or_else(|e| panic!("vector {} failed verification: {e}", vec_case.id));

        assert_eq!(
            verified_digest.to_prefixed_string(),
            vec_case.expected_beat_digest,
            "BLAKE3 digest mismatch on {}",
            vec_case.id
        );
        assert_eq!(
            to_jcs_string(&decoded.signed_beat.beat).unwrap(),
            vec_case.expected_beat_jcs,
            "RFC 8785 JCS beat mismatch on {}",
            vec_case.id
        );
        assert_eq!(
            to_jcs_string(&decoded.receipt).unwrap(),
            vec_case.expected_receipt_jcs,
            "RFC 8785 JCS receipt mismatch on {}",
            vec_case.id
        );

        // Deterministic Ed25519 re-sign parity against TypeScript node:crypto
        let signer = if decoded.signed_beat.beat.k1_key_id == k1_ci.public_fingerprint() {
            &k1_ci
        } else {
            &k1_daemon
        };
        let (_, rust_resigned_beat) =
            sign_blind_slack_beat(signer, decoded.signed_beat.beat.clone()).unwrap();
        assert_eq!(
            rust_resigned_beat.k1_signature, decoded.signed_beat.k1_signature,
            "Deterministic K1 Ed25519 signature mismatch on {}",
            vec_case.id
        );

        let rust_resigned_env = sign_coordinator_dispatch_envelope(
            &k2_coord,
            rust_resigned_beat,
            decoded.receipt.clone(),
            &policy,
        )
        .unwrap();
        assert_eq!(
            rust_resigned_env.k2_signature, decoded.k2_signature,
            "Deterministic K2 Ed25519 signature mismatch on {}",
            vec_case.id
        );
    }
}

#[test]
fn rejects_all_malicious_and_adversarial_fixture_vectors_fail_closed() {
    let suite: AdversarialSuite = serde_json::from_str(ADVERSARIAL_JSON).unwrap();
    let policy = VerificationPolicyV1::default();

    assert_eq!(suite.signed_beat_rejections.len(), 13);
    for case in &suite.signed_beat_rejections {
        let raw = serde_json::to_vec(&case.payload).unwrap();
        let res = decode_and_verify_signed_beat_bytes(&raw, &policy);
        assert!(
            res.is_err(),
            "adversarial signed beat {} unexpectedly succeeded!",
            case.id
        );
    }

    assert_eq!(suite.dispatch_envelope_rejections.len(), 1);
    for case in &suite.dispatch_envelope_rejections {
        let raw = serde_json::to_vec(&case.payload).unwrap();
        let res = decode_and_verify_dispatch_envelope_bytes(&raw, &policy);
        assert!(
            res.is_err(),
            "adversarial dispatch envelope {} unexpectedly succeeded!",
            case.id
        );
    }
}
