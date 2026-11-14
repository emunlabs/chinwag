// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Canonical zero-source Slack beat contract (`BlindSlackBeatV1`), RFC 8785 JCS serializer,
//! `OrgAdminPasskeyAttestationV1` rich-symbol gate, and `K1 + K2` Ed25519 verification.

pub mod jcs;
pub mod mrkdwn;
pub mod signing;
pub mod types;

pub use jcs::{to_jcs_bytes, to_jcs_string};
pub use mrkdwn::{escape_slack_mrkdwn, is_forbidden_control_or_bidi, validate_safe_display_token};
pub use signing::{
    Ed25519KeyPairSigner, K1_BEAT_DOMAIN, K1_PASSKEY_GRANT_DOMAIN, K2_DISPATCH_DOMAIN,
    VerificationPolicyV1, decode_and_verify_dispatch_envelope_bytes,
    decode_and_verify_signed_beat_bytes, decode_bounded_json, domain_separated_jcs_signing_input,
    sign_blind_slack_beat, sign_coordinator_dispatch_envelope, sign_passkey_attestation,
    verify_ed25519_strict, verify_k1_and_k2_envelope, verify_passkey_attestation,
    verify_signed_blind_slack_beat,
};
pub use types::{
    ApprovedHttpsUrl, ApprovedSymbolsV1, AuthorizationRef, BeatSourceV1, BlindEvidenceV1,
    BlindSlackBeatV1, BlindSummaryV1, CanonicalU64, CiProviderV1, CiRemediationStepV1,
    CoordinatorDispatchReceiptBodyV1, DeliveryStepV1, Digest32, EventId, HpkeSuiteV1,
    KeyFingerprint, LedgerActionV1, MAX_SLACK_BEAT_BYTES, OpaqueOperationId, OpaqueOrgId,
    OpaqueRef, OrgAdminPasskeyAttestationV1, PairSessionStepV1, PolicyHoldStepV1, QueueStatusV1,
    SCHEMA_VERSION_V1, SceneProgressV1, Signature64, SignedBlindSlackBeatV1,
    SignedSlackDispatchEnvelopeV1, SlackMetadataV1, UnsignedPasskeyAttestationV1,
};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    #[error("payload size {0} exceeds 32 KiB BlindSlackBeatV1 limit")]
    PayloadTooLarge(usize),
    #[error("schema rejected malformed or unknown field")]
    SchemaRejected,
    #[error("unsupported schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("canonical u64 must be a canonical base-10 decimal string")]
    InvalidCanonicalU64,
    #[error("invalid digest format")]
    InvalidDigest,
    #[error("invalid Ed25519 public key format")]
    InvalidPublicKey,
    #[error("invalid Ed25519 signature format")]
    InvalidSignature,
    #[error("invalid approved HTTPS URL")]
    InvalidUrl,
    #[error("invalid bounded field: {0}")]
    InvalidField(&'static str),
    #[error("RFC 8785 JCS canonicalization failed")]
    Canonicalization,
    #[error("Slack injection, control character, or bidi override detected")]
    InjectionOrBidiDetected,
    #[error("forbidden environment variable interpolation detected")]
    EnvInterpolationForbidden,
    #[error("banned legacy copy term detected")]
    BannedCopyTerm,
    #[error("secret token prefix or high-entropy secret detected")]
    SecretMaterialDetected,
    #[error("plaintext source bytes must be zero")]
    NonZeroPlaintextBytes,
    #[error("non-zero credit debit forbidden during laptop sleep, quote, reserve, or void")]
    NonZeroCreditsDuringLaptopSleep,
    #[error("passkey disclosure grant org_id does not match beat org_id")]
    PasskeyGrantOrgMismatch,
    #[error("passkey disclosure grant has expired")]
    PasskeyGrantExpired,
    #[error("signer key does not match declared key fingerprint")]
    SignerKeyMismatch,
    #[error("signer key is not in configured trust policy")]
    UntrustedSignerKey,
    #[error("Ed25519 strict signature verification failed")]
    SignatureVerificationFailed,
    #[error("K2 receipt beat_digest does not match K1 beat digest")]
    ReceiptBeatDigestMismatch,
    #[error("K2 receipt org_id or event_id does not match K1 beat")]
    ReceiptIdentityMismatch,
    #[error("dispatch_audience host is outside configured policy")]
    DisallowedDispatchAudience,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed(label: &[u8]) -> [u8; 32] {
        *blake3::hash(label).as_bytes()
    }

    fn sample_strict_beat(k1: &Ed25519KeyPairSigner) -> BlindSlackBeatV1 {
        BlindSlackBeatV1 {
            schema_version: 1,
            event_id: EventId::parse("ev_01JCHINWAG418_01").unwrap(),
            org_id: OpaqueOrgId::parse("org_01JCHINWAG8899AABBCCDD").unwrap(),
            operation_id: OpaqueOperationId::parse("op_ci_run_418").unwrap(),
            source: BeatSourceV1::Ci {
                provider: CiProviderV1::GithubActions,
                runner_lease_ref: OpaqueRef::parse("lease_gha_9981").unwrap(),
                run_ref: OpaqueRef::parse("run_418").unwrap(),
                shard_ref: Some(OpaqueRef::parse("shard_01").unwrap()),
            },
            source_sequence: CanonicalU64::new(12),
            attempt: 1,
            occurred_at_ms: CanonicalU64::new(1_794_400_012_000),
            progress: SceneProgressV1::CiRemediation {
                step: CiRemediationStepV1::Passed,
            },
            evidence: BlindEvidenceV1 {
                cwcard_digest: Digest32::from_bytes(*blake3::hash(b"sealed_cwcard_418").as_bytes()),
                hpke_suite: HpkeSuiteV1::X25519MlKem768HkdfSha256ChaCha20Poly1305,
                sealed_locator_ref: Some(OpaqueRef::parse("obj_cwcard_418").unwrap()),
                policy_gate_id: Some(OpaqueRef::parse("WP-04").unwrap()),
                tombstone_id: None,
                ed25519_attestation_count: 2,
                plaintext_source_bytes: 0,
            },
            metadata: SlackMetadataV1::StrictZk {
                summary: BlindSummaryV1 {
                    queue_status: QueueStatusV1::TerminalGreen,
                    specs_passed: 148,
                    specs_total: 148,
                    gates_passed: 6,
                    gates_total: 6,
                    loc_added: 14,
                    loc_removed: 3,
                    command_exit_code: Some(0),
                    duration_ms: CanonicalU64::new(19_400),
                    est_minutes_saved: 18,
                    credits_charged: CanonicalU64::new(50),
                    credit_receipt_ref: Some(OpaqueRef::parse("lrcpt_418_commit").unwrap()),
                },
            },
            authorization_ref: AuthorizationRef::parse("auth_bind_01JCHINWAG").unwrap(),
            k1_key_id: k1.public_fingerprint(),
        }
    }

    #[test]
    fn signs_and_verifies_strict_zk_and_k2_dispatch_envelope() {
        let k1 = Ed25519KeyPairSigner::from_seed_bytes(&test_seed(b"TEST_ONLY:K1"));
        let k2 = Ed25519KeyPairSigner::from_seed_bytes(&test_seed(b"TEST_ONLY:K2"));
        let policy = VerificationPolicyV1::default();

        let beat = sample_strict_beat(&k1);
        let (beat_digest, signed_beat) = sign_blind_slack_beat(&k1, beat).unwrap();

        let receipt = CoordinatorDispatchReceiptBodyV1 {
            schema_version: 1,
            dispatch_id: OpaqueRef::parse("disp_418_12").unwrap(),
            beat_digest: beat_digest.clone(),
            org_id: OpaqueOrgId::parse("org_01JCHINWAG8899AABBCCDD").unwrap(),
            event_id: EventId::parse("ev_01JCHINWAG418_01").unwrap(),
            coordinator_sequence: CanonicalU64::new(42),
            ledger_receipt_ref: OpaqueRef::parse("lrcpt_418_commit").unwrap(),
            ledger_action: LedgerActionV1::Commit,
            credits_charged: CanonicalU64::new(50),
            remaining_credits: CanonicalU64::new(450),
            authorization_epoch: CanonicalU64::new(1),
            destination_binding_ref: OpaqueRef::parse("dest_slack_T01TENANTA1").unwrap(),
            dispatch_audience: ApprovedHttpsUrl::parse(
                "https://slack.chinwag.sh/api/slack/receipts",
            )
            .unwrap(),
            dispatched_at_ms: CanonicalU64::new(1_794_400_012_250),
            k2_key_id: k2.public_fingerprint(),
        };

        let envelope =
            sign_coordinator_dispatch_envelope(&k2, signed_beat, receipt, &policy).unwrap();
        let bytes = to_jcs_bytes(&envelope).unwrap();
        let (decoded, verified_digest) =
            decode_and_verify_dispatch_envelope_bytes(&bytes, &policy).unwrap();
        assert_eq!(verified_digest, beat_digest);
        assert_eq!(decoded.signed_beat.beat.progress.step_number(), 12);
    }

    #[test]
    fn enforces_passkey_bound_rich_symbols_and_rejects_expired_or_wrong_org_grants() {
        let k1 = Ed25519KeyPairSigner::from_seed_bytes(&test_seed(b"TEST_ONLY:K1_DEV"));
        let admin = Ed25519KeyPairSigner::from_seed_bytes(&test_seed(b"TEST_ONLY:ADMIN_PASSKEY"));

        let grant = UnsignedPasskeyAttestationV1 {
            schema_version: 1,
            org_id: OpaqueOrgId::parse("org_01JCHINWAG8899AABBCCDD").unwrap(),
            disclosure_grant_ref: OpaqueRef::parse("grant_rich_01").unwrap(),
            config_digest: Digest32::from_bytes(*blake3::hash(b"workflow_yaml").as_bytes()),
            webauthn_credential_id: OpaqueRef::parse("cred_fido2_yubikey_01").unwrap(),
            authorization_epoch: CanonicalU64::new(1),
            expires_at_ms: CanonicalU64::new(1_795_000_000_000),
            admin_k1_pubkey: admin.public_fingerprint(),
        };
        let attestation = sign_passkey_attestation(&admin, grant.clone()).unwrap();

        let mut beat = sample_strict_beat(&k1);
        beat.progress = SceneProgressV1::Delivery {
            step: DeliveryStepV1::Gating,
        };
        let summary = match &beat.metadata {
            SlackMetadataV1::StrictZk { summary } => summary.clone(),
            SlackMetadataV1::RichSymbols { summary, .. } => summary.clone(),
        };
        beat.metadata = SlackMetadataV1::RichSymbols {
            summary: summary.clone(),
            symbols: Box::new(ApprovedSymbolsV1 {
                repo_label: Some("acme/core".to_owned()),
                branch_label: Some("feat/jwt-clock-skew".to_owned()),
                symbol_label: Some("jwt.rs:142 · verify_clock_skew".to_owned()),
                pr_number: Some(418),
                approved_pr_url: Some(
                    ApprovedHttpsUrl::parse("https://github.com/acme/core/pull/418").unwrap(),
                ),
                short_revision: Some("4d8e91b".to_owned()),
                gate_display_name: Some("Visual Geometry & Copy Gate".to_owned()),
            }),
            passkey_attestation: Box::new(attestation),
        };

        let (_, signed) = sign_blind_slack_beat(&k1, beat.clone()).unwrap();
        // Default policy without explicit trusted_admin_passkey_keys MUST fail closed!
        assert_eq!(
            verify_signed_blind_slack_beat(&signed, &VerificationPolicyV1::default()).unwrap_err(),
            ContractError::UntrustedSignerKey
        );

        let rich_policy = VerificationPolicyV1 {
            trusted_admin_passkey_keys: Some(vec![admin.public_fingerprint()]),
            now_ms: Some(1_794_500_000_000),
            expected_authorization_epoch: Some(1),
            ..VerificationPolicyV1::default()
        };
        verify_signed_blind_slack_beat(&signed, &rich_policy).unwrap();

        // Wall-clock expiry (`now_ms >= grant.expires_at_ms`) fails closed even when `occurred_at_ms` is older!
        assert_eq!(
            verify_signed_blind_slack_beat(
                &signed,
                &VerificationPolicyV1 {
                    now_ms: Some(1_795_000_000_000),
                    ..rich_policy.clone()
                },
            )
            .unwrap_err(),
            ContractError::PasskeyGrantExpired
        );

        // Stale authorization_epoch fails closed!
        assert_eq!(
            verify_signed_blind_slack_beat(
                &signed,
                &VerificationPolicyV1 {
                    expected_authorization_epoch: Some(2),
                    ..rich_policy
                },
            )
            .unwrap_err(),
            ContractError::UntrustedSignerKey
        );

        // Expired passkey grant fails closed
        let mut expired_grant = grant;
        expired_grant.expires_at_ms = CanonicalU64::new(1_794_400_000_000);
        let expired_att = sign_passkey_attestation(&admin, expired_grant).unwrap();
        let mut bad_beat = beat;
        if let SlackMetadataV1::RichSymbols {
            passkey_attestation,
            ..
        } = &mut bad_beat.metadata
        {
            **passkey_attestation = expired_att;
        }
        assert_eq!(
            sign_blind_slack_beat(&k1, bad_beat).unwrap_err(),
            ContractError::PasskeyGrantExpired
        );
    }

    #[test]
    fn rejects_unknown_diff_or_source_fields_at_every_nested_level_and_caps_32kib() {
        let k1 = Ed25519KeyPairSigner::from_seed_bytes(&test_seed(b"TEST_ONLY:K1"));
        let beat = sample_strict_beat(&k1);
        let (_, signed) = sign_blind_slack_beat(&k1, beat).unwrap();
        let mut val = serde_json::to_value(&signed).unwrap();

        // 1. Inject unexpected field at beat root
        let mut root_inject = val.clone();
        root_inject["beat"]["diff"] = serde_json::json!("@@ -1,3 +1,3 @@ -secret");
        let raw_root = serde_json::to_vec(&root_inject).unwrap();
        assert_eq!(
            decode_and_verify_signed_beat_bytes(&raw_root, &VerificationPolicyV1::default())
                .unwrap_err(),
            ContractError::SchemaRejected
        );

        // 2. Inject unexpected field inside nested evidence
        let mut ev_inject = val.clone();
        ev_inject["beat"]["evidence"]["source_code"] = serde_json::json!("fn leak() {}");
        let raw_ev = serde_json::to_vec(&ev_inject).unwrap();
        assert_eq!(
            decode_and_verify_signed_beat_bytes(&raw_ev, &VerificationPolicyV1::default())
                .unwrap_err(),
            ContractError::SchemaRejected
        );

        // 3. Inject unexpected field inside internally-tagged source enum
        val["beat"]["source"]["raw_log"] = serde_json::json!("stack trace");
        let raw_src = serde_json::to_vec(&val).unwrap();
        assert_eq!(
            decode_and_verify_signed_beat_bytes(&raw_src, &VerificationPolicyV1::default())
                .unwrap_err(),
            ContractError::SchemaRejected
        );

        // 4. Reject > 32 KiB payload before JSON parse
        let oversized = vec![b' '; MAX_SLACK_BEAT_BYTES + 1];
        assert_eq!(
            decode_and_verify_signed_beat_bytes(&oversized, &VerificationPolicyV1::default())
                .unwrap_err(),
            ContractError::PayloadTooLarge(MAX_SLACK_BEAT_BYTES + 1)
        );
    }

    #[test]
    fn blocks_slack_mentions_bidi_overrides_tribunal_copy_and_non_canonical_u64() {
        assert_eq!(
            CanonicalU64::parse_decimal("01").unwrap_err(),
            ContractError::InvalidCanonicalU64
        );
        assert_eq!(
            validate_safe_display_token("alert <!channel> pwned", 64).unwrap_err(),
            ContractError::InjectionOrBidiDetected
        );
        assert_eq!(
            validate_safe_display_token("spoof\u{202E}txt.exe", 64).unwrap_err(),
            ContractError::InjectionOrBidiDetected
        );
        assert_eq!(
            validate_safe_display_token("Enters Tribunal Review", 64).unwrap_err(),
            ContractError::BannedCopyTerm
        );
        assert_eq!(
            escape_slack_mrkdwn("<!channel> \u{202E}*bold* <https://evil|click>", 80),
            "&lt;!channel&gt; \\*bold\\* &lt;https://evil|click&gt;"
        );
    }

    #[test]
    fn enforces_cross_lang_parity_on_duplicate_keys_float_ints_null_optionals_and_safe_jcs_ints() {
        let k1 = Ed25519KeyPairSigner::from_seed_bytes(&test_seed(b"TEST_ONLY:K1"));
        let beat = sample_strict_beat(&k1);
        let (_, signed) = sign_blind_slack_beat(&k1, beat).unwrap();
        let raw_json = serde_json::to_string(&signed).unwrap();

        // 1. Duplicate JSON key fails closed
        let dup_json = raw_json.replacen(
            "\"event_id\":\"",
            "\"event_id\":\"ev_shadow_01\",\"event_id\":\"",
            1,
        );
        assert_eq!(
            decode_and_verify_signed_beat_bytes(
                dup_json.as_bytes(),
                &VerificationPolicyV1::default()
            )
            .unwrap_err(),
            ContractError::SchemaRejected
        );

        // 2. Float literal 1.0 on integer field fails closed
        let float_json = raw_json.replacen("\"attempt\":1", "\"attempt\":1.0", 1);
        assert_eq!(
            decode_and_verify_signed_beat_bytes(
                float_json.as_bytes(),
                &VerificationPolicyV1::default()
            )
            .unwrap_err(),
            ContractError::SchemaRejected
        );

        // 3. Explicit null on optional field fails closed (matching TypeScript)
        let mut with_null = serde_json::to_value(&signed).unwrap();
        with_null["beat"]["evidence"]["tombstone_id"] = serde_json::Value::Null;
        assert_eq!(
            decode_and_verify_signed_beat_bytes(
                &serde_json::to_vec(&with_null).unwrap(),
                &VerificationPolicyV1::default(),
            )
            .unwrap_err(),
            ContractError::SchemaRejected
        );

        // 4. Multi-byte UTF-8 URL > 512 bytes fails closed
        let long_url = format!("https://chinwag.sh/p/{}", "é".repeat(252));
        assert_eq!(
            ApprovedHttpsUrl::parse(long_url).unwrap_err(),
            ContractError::InvalidUrl
        );

        // 5. Unsafe integer > 2^53 - 1 fails JCS canonicalization
        assert_eq!(
            to_jcs_string(&9_007_199_254_740_992_u64).unwrap_err(),
            ContractError::Canonicalization
        );

        // 6. UTF-8 BOM (0xEF 0xBB 0xBF) prefix fails closed (matching TypeScript TextDecoder ignoreBOM: true)
        let mut bom_bytes = vec![0xef, 0xbb, 0xbf];
        bom_bytes.extend_from_slice(raw_json.as_bytes());
        assert_eq!(
            decode_and_verify_signed_beat_bytes(&bom_bytes, &VerificationPolicyV1::default())
                .unwrap_err(),
            ContractError::SchemaRejected
        );

        // 7. All 8 compressed Ed25519 torsion encodings fail verify_ed25519_strict on both A and R
        let eight_torsion_hex = [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        ];
        let valid_pub = k1.public_fingerprint();
        for hex_pt in eight_torsion_hex {
            let torsion_pub = KeyFingerprint::parse_prefixed(&format!("ed25519:{hex_pt}")).unwrap();
            let torsion_sig =
                Signature64::parse_prefixed(&format!("ed25519:{hex_pt}{}", "00".repeat(32)))
                    .unwrap();
            assert_eq!(
                verify_ed25519_strict(&torsion_pub, b"msg", &torsion_sig).unwrap_err(),
                ContractError::SignatureVerificationFailed
            );
            assert_eq!(
                verify_ed25519_strict(&valid_pub, b"msg", &torsion_sig).unwrap_err(),
                ContractError::SignatureVerificationFailed
            );
        }

        // 8. Secret-prefix literals constructed via concat!() fail closed at runtime without contiguous scanner triggers
        for tok in [
            concat!("xoxb-", "1234567890-fake-token"),
            concat!("ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
        ] {
            assert_eq!(
                validate_safe_display_token(tok, 128).unwrap_err(),
                ContractError::SecretMaterialDetected
            );
        }
    }
}
