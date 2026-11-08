// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

use chinwag_ci::intent::{IntentError, IntentVerification, verify_original};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const INITIATOR: &str = "WORKHORSE#test-instance-1234";
const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn key() -> SigningKey {
    SigningKey::from_bytes(&hex::decode(SEED).unwrap().try_into().unwrap())
}

#[test]
fn rfc8032_section_7_1_test_1_known_answer_precedes_application_fixtures() {
    // Public, published RFC test material; never an operator/agent private key.
    let public = VerifyingKey::from_bytes(
        &hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let signature = Signature::from_slice(
        &hex::decode(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
            "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ))
        .unwrap(),
    )
    .unwrap();
    public.verify_strict(b"", &signature).unwrap();
    assert!(public.verify_strict(b"changed", &signature).is_err());
}

fn body() -> Value {
    json!({
        "schema":"chinwag.ci-dispatch-intent.v1",
        "repository":"example/ci-test", "repository_id":42,
        "source_commit":"ab".repeat(20),
        "workflow_ref":"example/ci-test/.github/workflows/ci-é.yml@refs/heads/test",
        "workflow_commit":"bc".repeat(20),
        "recipient_instance":INITIATOR,
        "delivery_profile_sha256":"cd".repeat(32),
        "command_sha256":"de".repeat(32), "nonce":"ef".repeat(32),
        "expires_unix":1100
    })
}

fn original(body: &str) -> Value {
    let key = key();
    let public = hex::encode(key.verifying_key().to_bytes());
    let digest = hex::encode(Sha256::digest(format!(
        "chinwag-bus-v1|1000|#eng|{INITIATOR}|{public}|GEMINI-PM#test-instance-5678|CHWG-CI-TEST|{body}"
    )));
    let id = format!("bus-1000-{}", &digest[..8]);
    let fields = [
        id.as_str(),
        "1000",
        INITIATOR,
        "GEMINI-PM#test-instance-5678",
        "#eng",
        "CHWG-CI-TEST",
        body,
    ];
    let signed = format!(
        "chinwag-bus-sig-v2|{}",
        fields
            .iter()
            .map(|s| format!("{}:{s}", s.len()))
            .collect::<Vec<_>>()
            .join("|")
    );
    json!({"id":id,"ts_unix":1000,"sender":INITIATOR,"sender_endpoint_id":public,
        "to":"GEMINI-PM#test-instance-5678","room":"#eng","task_id":"CHWG-CI-TEST",
        "body":body,"digest_sha256":digest,"pubkey_ed25519":public,
        "signature_ed25519":hex::encode(key.sign(signed.as_bytes()).to_bytes()),
        "sig_verified":false,"seq":123})
}

fn expected(now_unix: u64) -> IntentVerification<'static> {
    IntentVerification {
        initiator_instance: INITIATOR,
        initiator_public_key: key().verifying_key().to_bytes(),
        admission_addressee: "GEMINI-PM#test-instance-5678",
        task_id: "CHWG-CI-TEST",
        room: "#eng",
        now_unix,
    }
}

#[test]
fn verifies_exact_native_original_and_utf8_byte_lengths() {
    let value = original(&body().to_string());
    let verified = verify_original(&serde_json::to_vec(&value).unwrap(), expected(1001)).unwrap();
    assert_eq!(verified.initiating_instance(), INITIATOR);
    assert_eq!(verified.spec().repository_id, 42);
    assert_eq!(verified.original_id(), value["id"].as_str().unwrap());
    assert_eq!(
        hex::encode(verified.original_digest()),
        value["digest_sha256"]
    );
}

#[test]
fn a_valid_signature_for_another_admission_recipient_does_not_grant_scope() {
    let bytes = serde_json::to_vec(&original(&body().to_string())).unwrap();
    for destination in [
        "OTHER#test-instance-5678",
        "GEMINI-PM",
        "ALL#test-instance-5678",
        "GEMINI-PM#test-instance-5678,OTHER#test-instance-1234",
        "",
    ] {
        let mut other = expected(1001);
        other.admission_addressee = destination;
        assert!(matches!(
            verify_original(&bytes, other),
            Err(IntentError::Scope)
        ));
    }
}

#[test]
fn forged_sig_verified_metadata_cannot_admit_a_changed_body() {
    let mut value = original(&body().to_string());
    value["body"] = json!("attacker changed the failure recipient");
    value["sig_verified"] = json!(true);
    assert!(matches!(
        verify_original(&serde_json::to_vec(&value).unwrap(), expected(1001)),
        Err(IntentError::Authentication)
    ));
}

#[test]
fn changing_transport_identity_or_expected_agent_is_refused() {
    let mut value = original(&body().to_string());
    value["sender_endpoint_id"] = json!("aa".repeat(32));
    assert!(matches!(
        verify_original(&serde_json::to_vec(&value).unwrap(), expected(1001)),
        Err(IntentError::Scope)
    ));
    let mut other = expected(1001);
    other.initiator_instance = "OTHER#test-instance-1234";
    assert!(matches!(
        verify_original(
            &serde_json::to_vec(&original(&body().to_string())).unwrap(),
            other
        ),
        Err(IntentError::Scope)
    ));
}

#[test]
fn signature_success_does_not_override_expiry_or_a_different_recipient() {
    let bytes = serde_json::to_vec(&original(&body().to_string())).unwrap();
    for now in [999, 1100, 1101] {
        assert!(matches!(
            verify_original(&bytes, expected(now)),
            Err(IntentError::Lifetime)
        ));
    }
    let mut spec = body();
    spec["recipient_instance"] = json!("OTHER#test-instance-1234");
    assert!(matches!(
        verify_original(
            &serde_json::to_vec(&original(&spec.to_string())).unwrap(),
            expected(1001)
        ),
        Err(IntentError::Scope)
    ));
}

#[test]
fn duplicate_or_unknown_intent_fields_are_refused_even_when_signed() {
    let text = body().to_string();
    let duplicate = format!(
        "{},\"nonce\":\"{}\"}}",
        &text[..text.len() - 1],
        "aa".repeat(32)
    );
    assert!(matches!(
        verify_original(
            &serde_json::to_vec(&original(&duplicate)).unwrap(),
            expected(1001)
        ),
        Err(IntentError::Format)
    ));
    let mut spec = body();
    spec["auto_execute"] = json!(true);
    assert!(matches!(
        verify_original(
            &serde_json::to_vec(&original(&spec.to_string())).unwrap(),
            expected(1001)
        ),
        Err(IntentError::Format)
    ));
}

#[test]
fn wrong_scope_digest_and_unbounded_input_fail_closed() {
    let mut value = original(&body().to_string());
    value["digest_sha256"] = json!("00".repeat(32));
    assert!(matches!(
        verify_original(&serde_json::to_vec(&value).unwrap(), expected(1001)),
        Err(IntentError::Authentication)
    ));
    let value = original(&body().to_string());
    let mut scope = expected(1001);
    scope.task_id = "OTHER-TASK";
    assert!(matches!(
        verify_original(&serde_json::to_vec(&value).unwrap(), scope),
        Err(IntentError::Scope)
    ));
    assert!(matches!(
        verify_original(&vec![b' '; 32769], expected(1001)),
        Err(IntentError::Format)
    ));
}

#[test]
fn signed_ambiguous_workflow_paths_and_excess_lifetime_are_refused() {
    for workflow in [
        "example/ci-test/.github/workflows/@refs/heads/",
        "example/ci-test/.github/workflows/../ci.yml@refs/heads/main",
        "example/ci-test/.github/workflows/ci.yml@refs/heads/main@extra",
        "example/ci-test/.github/workflows/ci.yml@refs/heads/main/../other",
    ] {
        let mut spec = body();
        spec["workflow_ref"] = json!(workflow);
        assert!(matches!(
            verify_original(
                &serde_json::to_vec(&original(&spec.to_string())).unwrap(),
                expected(1001)
            ),
            Err(IntentError::Scope)
        ));
    }
    let mut spec = body();
    spec["expires_unix"] = json!(4601);
    assert!(matches!(
        verify_original(
            &serde_json::to_vec(&original(&spec.to_string())).unwrap(),
            expected(1001)
        ),
        Err(IntentError::Lifetime)
    ));
}

#[test]
fn signed_id_and_native_recipient_cannot_be_rewritten() {
    for (field, value) in [
        ("id", "bus-1000-deadbeef"),
        ("to", "OTHER#different-instance"),
    ] {
        let mut message = original(&body().to_string());
        message[field] = json!(value);
        assert!(matches!(
            verify_original(&serde_json::to_vec(&message).unwrap(), expected(1001)),
            Err(IntentError::Authentication)
        ));
    }
}

#[test]
fn invalid_expected_addresses_are_not_normalized_into_authority() {
    let message = serde_json::to_vec(&original(&body().to_string())).unwrap();
    for invalid in [
        "ALL#instance",
        "_SEAT#instance",
        "@WORKHORSE#test-instance-1234",
        "WORKHORSE",
    ] {
        let mut scope = expected(1001);
        scope.initiator_instance = invalid;
        assert!(matches!(
            verify_original(&message, scope),
            Err(IntentError::Scope)
        ));
    }
}
