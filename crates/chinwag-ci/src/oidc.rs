// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic GitHub OIDC verification. Keys MUST be obtained from the fixed
//! issuer's JWKS over normally verified HTTPS by the admitted caller. A token
//! cannot select its own URL/key. This module performs no networking, K2 issuance,
//! replay storage, proof of possession, or execution authorization.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{BigUint, RsaPublicKey, pkcs1v15, signature::Verifier, traits::PublicKeyParts};
use serde::{
    Deserialize,
    de::{self, MapAccess, Visitor},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};

pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const GITHUB_JWKS: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const MAX_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum OidcError {
    #[error("OIDC input is malformed or exceeds its bound")]
    Format,
    #[error("OIDC algorithm or issuer key is not approved")]
    Key,
    #[error("OIDC RS256 signature is invalid")]
    Signature,
    #[error("OIDC claims do not match the exact admitted workflow execution")]
    Scope,
    #[error("OIDC token is not currently within its finite validity interval")]
    Lifetime,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Jwk {
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    usage: String,
    kid: String,
    n: String,
    e: String,
    #[serde(rename = "x5c")]
    _certificate_chain: Option<Vec<String>>,
    #[serde(rename = "x5t")]
    _certificate_thumbprint: Option<String>,
    key_ops: Option<Vec<String>>,
}

pub struct IssuerKeys {
    keys: Vec<(String, RsaPublicKey)>,
}

fn b64(value: &str) -> Result<Vec<u8>, OidcError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| OidcError::Format)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(OidcError::Format);
    }
    Ok(decoded)
}

fn valid_kid(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

impl IssuerKeys {
    /// This parser does not authenticate a fetched key set. The caller must pin
    /// GITHUB_JWKS and its normal TLS validation; never use token-provided keys.
    pub fn from_fixed_issuer_jwks(json: &[u8]) -> Result<Self, OidcError> {
        if json.len() > 64 * 1024 {
            return Err(OidcError::Format);
        }
        let set: JwkSet = serde_json::from_slice(json).map_err(|_| OidcError::Format)?;
        if set.keys.is_empty() || set.keys.len() > 8 {
            return Err(OidcError::Key);
        }
        let mut keys = Vec::new();
        for jwk in set.keys {
            if jwk.kty != "RSA"
                || jwk.alg != "RS256"
                || jwk.usage != "sig"
                || !valid_kid(&jwk.kid)
                || jwk
                    .key_ops
                    .as_ref()
                    .is_some_and(|ops| ops.as_slice() != ["verify"])
                || keys.iter().any(|(kid, _)| kid == &jwk.kid)
                || jwk.n.len() > 700
                || jwk.e.len() > 8
            {
                return Err(OidcError::Key);
            }
            let n = b64(&jwk.n)?;
            let e = b64(&jwk.e)?;
            if n.first() == Some(&0) || e != [1, 0, 1] {
                return Err(OidcError::Key);
            }
            let key = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
                .map_err(|_| OidcError::Key)?;
            if !(2048..=4096).contains(&key.n().bits()) {
                return Err(OidcError::Key);
            }
            keys.push((jwk.kid, key));
        }
        Ok(Self { keys })
    }
}

/// Duplicate top-level JOSE headers or claims must not be collapsed by JSON
/// Value into a last-wins object. Unknown signed claims are retained as data.
struct UniqueObject(BTreeMap<String, Value>);
impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = UniqueObject;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object with unique field names")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let mut fields = BTreeMap::new();
                while let Some((key, value)) = input.next_entry::<String, Value>()? {
                    if fields.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate OIDC field"));
                    }
                }
                Ok(UniqueObject(fields))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
    #[serde(rename = "x5t")]
    _certificate_thumbprint: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    repository_id: String,
    repository_owner_id: String,
    run_id: String,
    run_attempt: String,
    actor_id: String,
    sha: String,
    workflow_ref: String,
    workflow_sha: String,
    event_name: String,
    jti: String,
    iat: u64,
    nbf: u64,
    exp: u64,
}

/// Obtain expected run/actor IDs from the trusted dispatch API response and
/// current run metadata. A public signed intent alone must not let the first
/// unrelated workflow claim it. Audience must commit to the original intent,
/// runner public keys and delivery policy; verify runner PoP separately.
pub struct ExpectedWorkflow<'a> {
    pub audience: &'a str,
    pub subject: &'a str,
    pub repository_id: u64,
    pub repository_owner_id: u64,
    pub run_id: u64,
    pub run_attempt: u32,
    pub actor_id: u64,
    pub source_commit: &'a str,
    pub workflow_ref: &'a str,
    pub workflow_commit: &'a str,
    /// Caller clock observation, not a K2/hardware-trusted-time attestation.
    pub now_unix: u64,
}

pub struct VerifiedWorkflow {
    run_id: u64,
    run_attempt: u32,
    token_id: String,
    expires_unix: u64,
    audience: String,
    subject: String,
    repository_id: u64,
    repository_owner_id: u64,
    actor_id: u64,
    source_commit: String,
    workflow_ref: String,
    workflow_commit: String,
    token_sha256: [u8; 32],
    issued_unix: u64,
    not_before_unix: u64,
}
impl VerifiedWorkflow {
    pub fn run_id(&self) -> u64 {
        self.run_id
    }
    pub fn run_attempt(&self) -> u32 {
        self.run_attempt
    }
    pub fn token_id(&self) -> &str {
        &self.token_id
    }
    pub fn expires_unix(&self) -> u64 {
        self.expires_unix
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn repository_id(&self) -> u64 {
        self.repository_id
    }
    pub fn repository_owner_id(&self) -> u64 {
        self.repository_owner_id
    }
    pub fn actor_id(&self) -> u64 {
        self.actor_id
    }
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }
    pub fn workflow_ref(&self) -> &str {
        &self.workflow_ref
    }
    pub fn workflow_commit(&self) -> &str {
        &self.workflow_commit
    }
    pub fn token_sha256(&self) -> &[u8; 32] {
        &self.token_sha256
    }
    pub fn issued_unix(&self) -> u64 {
        self.issued_unix
    }
    pub fn not_before_unix(&self) -> u64 {
        self.not_before_unix
    }
}

fn same_number(value: &str, expected: u64) -> bool {
    expected > 0 && value == expected.to_string()
}

fn verify_rs256(key: &RsaPublicKey, input: &[u8], signature: &[u8]) -> Result<(), OidcError> {
    // Explicit OID-prefixed SHA256 DigestInfo. From<PublicKey> instead selects
    // the unprefixed verifier, which is not the named RS256 construction.
    pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(key.clone())
        .verify(
            input,
            &pkcs1v15::Signature::try_from(signature).map_err(|_| OidcError::Signature)?,
        )
        .map_err(|_| OidcError::Signature)
}

pub fn verify_token(
    token: &str,
    keys: &IssuerKeys,
    expected: ExpectedWorkflow<'_>,
) -> Result<VerifiedWorkflow, OidcError> {
    if token.len() > MAX_TOKEN_BYTES || !token.is_ascii() {
        return Err(OidcError::Format);
    }
    let mut parts = token.split('.');
    let (Some(protected), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(OidcError::Format);
    };
    let header: UniqueObject =
        serde_json::from_slice(&b64(protected)?).map_err(|_| OidcError::Format)?;
    let header: Header =
        serde_json::from_value(serde_json::to_value(header.0).map_err(|_| OidcError::Format)?)
            .map_err(|_| OidcError::Format)?;
    if header.alg != "RS256" || header.typ != "JWT" || !valid_kid(&header.kid) {
        return Err(OidcError::Key);
    }
    let key = keys
        .keys
        .iter()
        .find(|(kid, _)| kid == &header.kid)
        .map(|(_, key)| key)
        .ok_or(OidcError::Key)?;
    verify_rs256(
        key,
        format!("{protected}.{payload}").as_bytes(),
        &b64(signature)?,
    )?;
    let claims: UniqueObject =
        serde_json::from_slice(&b64(payload)?).map_err(|_| OidcError::Format)?;
    let claims: Claims =
        serde_json::from_value(serde_json::to_value(claims.0).map_err(|_| OidcError::Format)?)
            .map_err(|_| OidcError::Format)?;
    if claims.iss != GITHUB_ISSUER
        || expected.audience.is_empty()
        || expected.subject.is_empty()
        || claims.aud != expected.audience
        || claims.sub != expected.subject
        || !same_number(&claims.repository_id, expected.repository_id)
        || !same_number(&claims.repository_owner_id, expected.repository_owner_id)
        || !same_number(&claims.run_id, expected.run_id)
        || !same_number(&claims.run_attempt, u64::from(expected.run_attempt))
        || !same_number(&claims.actor_id, expected.actor_id)
        || claims.sha != expected.source_commit
        || claims.workflow_ref != expected.workflow_ref
        || claims.workflow_sha != expected.workflow_commit
        || claims.event_name != "workflow_dispatch"
        || claims.jti.is_empty()
        || claims.jti.len() > 256
        || claims.jti.chars().any(char::is_control)
    {
        return Err(OidcError::Scope);
    }
    if claims.iat > expected.now_unix
        || claims.nbf > expected.now_unix
        || claims.exp <= expected.now_unix
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > 600
        || claims.nbf > claims.exp
    {
        return Err(OidcError::Lifetime);
    }
    Ok(VerifiedWorkflow {
        run_id: expected.run_id,
        run_attempt: expected.run_attempt,
        token_id: claims.jti,
        expires_unix: claims.exp,
        audience: claims.aud,
        subject: claims.sub,
        repository_id: expected.repository_id,
        repository_owner_id: expected.repository_owner_id,
        actor_id: expected.actor_id,
        source_commit: claims.sha,
        workflow_ref: claims.workflow_ref,
        workflow_commit: claims.workflow_sha,
        token_sha256: Sha256::digest(token.as_bytes()).into(),
        issued_unix: claims.iat,
        not_before_unix: claims.nbf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{
        RsaPrivateKey,
        signature::{SignatureEncoding, Signer},
    };
    use serde_json::json;
    use std::sync::OnceLock;

    const AUD: &str = "urn:chinwag:ci-admission:v1:test-binding";
    const SUBJECT: &str = "repo:example/ci-test:ref:refs/heads/test";

    #[test]
    fn rfc7515_appendix_a2_rs256_known_answer() {
        let vector: Value = serde_json::from_str(include_str!(
            "../tests/vectors/rfc7515-a2-rs256-public.json"
        ))
        .unwrap();
        let jwk = &vector["jwk"];
        let key = RsaPublicKey::new(
            BigUint::from_bytes_be(&b64(jwk["n"].as_str().unwrap()).unwrap()),
            BigUint::from_bytes_be(&b64(jwk["e"].as_str().unwrap()).unwrap()),
        )
        .unwrap();
        let token = vector["compact_jws"].as_str().unwrap();
        let (input, signature) = token.rsplit_once('.').unwrap();
        let signature = b64(signature).unwrap();
        verify_rs256(&key, input.as_bytes(), &signature).unwrap();
        assert_eq!(
            verify_rs256(&key, b"changed", &signature),
            Err(OidcError::Signature)
        );
        // This published example is not a GitHub identity or an admission.
    }

    fn key() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap())
    }

    fn keys() -> IssuerKeys {
        let key = key().to_public_key();
        IssuerKeys::from_fixed_issuer_jwks(&serde_json::to_vec(&json!({"keys":[{
            "kty":"RSA","alg":"RS256","use":"sig","kid":"fixture-key",
            "n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())
        }]})).unwrap()).unwrap()
    }

    fn claims() -> Value {
        json!({"iss":GITHUB_ISSUER,"aud":AUD,"sub":SUBJECT,
            "repository_id":"42","repository_owner_id":"7","run_id":"100","run_attempt":"1","actor_id":"9",
            "sha":"ab".repeat(20),"workflow_ref":"example/ci-test/.github/workflows/ci.yml@refs/heads/test",
            "workflow_sha":"bc".repeat(20),"event_name":"workflow_dispatch",
            "jti":"test-token-id","iat":1000,"nbf":1000,"exp":1300})
    }

    fn expected() -> ExpectedWorkflow<'static> {
        ExpectedWorkflow {
            audience: AUD,
            subject: SUBJECT,
            repository_id: 42,
            repository_owner_id: 7,
            run_id: 100,
            run_attempt: 1,
            actor_id: 9,
            source_commit: "abababababababababababababababababababab",
            workflow_ref: "example/ci-test/.github/workflows/ci.yml@refs/heads/test",
            workflow_commit: "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc",
            now_unix: 1001,
        }
    }

    fn issue_raw(header: &str, claims: &str) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signer = pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(key().clone());
        let signature: pkcs1v15::Signature = signer.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_vec()))
    }

    fn header() -> Value {
        json!({"alg":"RS256","typ":"JWT","kid":"fixture-key"})
    }
    fn issue(claims: &Value) -> String {
        issue_raw(&header().to_string(), &claims.to_string())
    }

    #[test]
    fn verifies_signature_and_actual_execution_scope_without_issuing_a_lease() {
        let verified = verify_token(&issue(&claims()), &keys(), expected()).unwrap();
        assert_eq!(verified.run_id(), 100);
        assert_eq!(verified.run_attempt(), 1);
        assert_eq!(verified.token_id(), "test-token-id");
        assert_eq!(verified.expires_unix(), 1300);
        assert_eq!(verified.audience(), AUD);
        assert_eq!(verified.repository_id(), 42);
        assert_eq!(verified.source_commit(), expected().source_commit);
    }

    #[test]
    fn issuer_audience_subject_run_attempt_and_workflow_cannot_be_substituted() {
        for (field, value) in [
            ("iss", "https://attacker.invalid"),
            ("aud", "another-intent"),
            ("sub", "repo:other/repo"),
            ("repository_id", "43"),
            ("repository_owner_id", "8"),
            ("run_id", "101"),
            ("run_attempt", "2"),
            ("actor_id", "10"),
            ("sha", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
            (
                "workflow_ref",
                "other/repo/.github/workflows/ci.yml@refs/heads/main",
            ),
            ("workflow_sha", "dededededededededededededededededededede"),
            ("event_name", "pull_request_target"),
        ] {
            let mut claims = claims();
            claims[field] = json!(value);
            assert!(
                matches!(
                    verify_token(&issue(&claims), &keys(), expected()),
                    Err(OidcError::Scope)
                ),
                "{field}"
            );
        }
    }

    #[test]
    fn token_signature_algorithm_kid_or_self_selected_url_cannot_bypass_verification() {
        let token = issue(&claims());
        let (input, signature) = token.rsplit_once('.').unwrap();
        let mut bytes = b64(signature).unwrap();
        bytes[0] ^= 1;
        assert!(matches!(
            verify_token(
                &format!("{input}.{}", URL_SAFE_NO_PAD.encode(bytes)),
                &keys(),
                expected()
            ),
            Err(OidcError::Signature)
        ));
        for alg in ["none", "HS256", "PS256"] {
            let mut head = header();
            head["alg"] = json!(alg);
            assert!(matches!(
                verify_token(
                    &issue_raw(&head.to_string(), &claims().to_string()),
                    &keys(),
                    expected()
                ),
                Err(OidcError::Key)
            ));
        }
        let mut head = header();
        head["jku"] = json!("https://attacker.invalid/key");
        assert!(matches!(
            verify_token(
                &issue_raw(&head.to_string(), &claims().to_string()),
                &keys(),
                expected()
            ),
            Err(OidcError::Format)
        ));
        let mut head = header();
        head["kid"] = json!("different-key");
        assert!(matches!(
            verify_token(
                &issue_raw(&head.to_string(), &claims().to_string()),
                &keys(),
                expected()
            ),
            Err(OidcError::Key)
        ));
    }

    #[test]
    fn duplicate_signed_claims_and_headers_are_refused() {
        let text = claims().to_string();
        let duplicate = format!("{},\"run_id\":\"100\"}}", &text[..text.len() - 1]);
        assert!(matches!(
            verify_token(
                &issue_raw(&header().to_string(), &duplicate),
                &keys(),
                expected()
            ),
            Err(OidcError::Format)
        ));
        let duplicate = r#"{"alg":"RS256","alg":"RS256","typ":"JWT","kid":"fixture-key"}"#;
        assert!(matches!(
            verify_token(&issue_raw(duplicate, &text), &keys(), expected()),
            Err(OidcError::Format)
        ));
    }

    #[test]
    fn finite_validity_never_accepts_expired_or_future_tokens() {
        for (field, value) in [("exp", 1001), ("iat", 1002), ("nbf", 1002), ("exp", 1601)] {
            let mut claims = claims();
            claims[field] = json!(value);
            assert!(
                matches!(
                    verify_token(&issue(&claims), &keys(), expected()),
                    Err(OidcError::Lifetime)
                ),
                "{field}"
            );
        }
    }

    #[test]
    fn key_set_duplicates_unknown_fields_and_short_moduli_are_refused() {
        let key = key().to_public_key();
        let jwk = json!({"kty":"RSA","alg":"RS256","use":"sig","kid":"fixture-key",
            "n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())});
        assert!(matches!(
            IssuerKeys::from_fixed_issuer_jwks(
                &serde_json::to_vec(&json!({"keys":[jwk,jwk]})).unwrap()
            ),
            Err(OidcError::Key)
        ));
        let mut short = jwk.clone();
        short["n"] = json!(URL_SAFE_NO_PAD.encode([0xff; 16]));
        assert!(
            IssuerKeys::from_fixed_issuer_jwks(
                &serde_json::to_vec(&json!({"keys":[short]})).unwrap()
            )
            .is_err()
        );
        let mut private_field = jwk.clone();
        private_field["d"] = json!("not-an-issuer-public-field");
        assert!(matches!(
            IssuerKeys::from_fixed_issuer_jwks(
                &serde_json::to_vec(&json!({"keys":[private_field]})).unwrap()
            ),
            Err(OidcError::Format)
        ));
    }

    fn dispatch_intent(profile: &str) -> crate::intent::VerifiedIntent {
        use ed25519_dalek::{Signer, SigningKey};
        let signer = SigningKey::from_bytes(&[0x31; 32]); // ephemeral test-only identity
        let public = hex::encode(signer.verifying_key().to_bytes());
        let sender = "WORKHORSE#test-instance-1234";
        let body=json!({"schema":"chinwag.ci-dispatch-intent.v1","repository":"example/ci-test","repository_id":42,
            "source_commit":"ab".repeat(20),"workflow_ref":expected().workflow_ref,"workflow_commit":"bc".repeat(20),
            "recipient_instance":sender,"delivery_profile_sha256":profile.repeat(32),"command_sha256":"de".repeat(32),
            "nonce":"ef".repeat(32),"expires_unix":1100}).to_string();
        let to = "GEMINI-PM#test-instance-5678";
        let digest = hex::encode(Sha256::digest(format!(
            "chinwag-bus-v1|1000|#eng|{sender}|{public}|{to}|CHWG-CI-TEST|{body}"
        )));
        let id = format!("bus-1000-{}", &digest[..8]);
        let fields = [
            id.as_str(),
            "1000",
            sender,
            to,
            "#eng",
            "CHWG-CI-TEST",
            &body,
        ];
        let input = format!(
            "chinwag-bus-sig-v2|{}",
            fields
                .iter()
                .map(|s| format!("{}:{s}", s.len()))
                .collect::<Vec<_>>()
                .join("|")
        );
        let original = json!({"id":id,"ts_unix":1000,"sender":sender,"sender_endpoint_id":public,"pubkey_ed25519":public,
            "to":to,"room":"#eng","task_id":"CHWG-CI-TEST","body":body,"digest_sha256":digest,
            "signature_ed25519":hex::encode(signer.sign(input.as_bytes()).to_bytes())});
        crate::intent::verify_original(
            &serde_json::to_vec(&original).unwrap(),
            crate::intent::IntentVerification {
                initiator_instance: sender,
                initiator_public_key: signer.verifying_key().to_bytes(),
                admission_addressee: to,
                task_id: "CHWG-CI-TEST",
                room: "#eng",
                now_unix: 1001,
            },
        )
        .unwrap()
    }

    fn runner_keys() -> crate::runner_binding::RunnerPublicKeys {
        let public = |seed| {
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes()
        };
        crate::runner_binding::RunnerPublicKeys {
            signing_ed25519: public(0x55),
            agent_transport_ed25519: public(0x66),
            archive_transport_ed25519: public(0x77),
        }
    }

    fn workflow_for(audience: &str) -> VerifiedWorkflow {
        let mut claims = claims();
        claims["aud"] = json!(audience);
        verify_token(
            &issue(&claims),
            &keys(),
            ExpectedWorkflow {
                audience,
                ..expected()
            },
        )
        .unwrap()
    }

    fn pop_signature(
        intent: &crate::intent::VerifiedIntent,
        workflow: &VerifiedWorkflow,
        keys: crate::runner_binding::RunnerPublicKeys,
        challenge: [u8; 32],
    ) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let payload =
            crate::runner_binding::proof_payload(intent, workflow, keys, challenge).unwrap();
        ed25519_dalek::SigningKey::from_bytes(&[0x55; 32])
            .sign(&payload)
            .to_bytes()
    }

    #[test]
    fn runner_pop_joins_verified_native_intent_and_oidc_execution_scope() {
        use crate::runner_binding::{audience_for, verify_runner_proof};
        let intent = dispatch_intent("cd");
        let keys = runner_keys();
        let challenge = [0x88; 32];
        let audience = audience_for(&intent, keys, challenge, 100, 1).unwrap();
        let workflow = workflow_for(&audience);
        let signature = pop_signature(&intent, &workflow, keys, challenge);
        let binding =
            verify_runner_proof(intent, workflow, keys, challenge, signature, 1001).unwrap();
        assert_eq!(
            binding.initiating_instance(),
            "WORKHORSE#test-instance-1234"
        );
        assert_eq!(binding.run_id(), 100);
        assert_eq!(binding.run_attempt(), 1);
        assert_eq!(binding.expires_unix(), 1100);
        assert_eq!(binding.signing_public_key(), &keys.signing_ed25519);
        assert_eq!(binding.audience(), audience);
    }

    #[test]
    fn opaque_iroh_job_signer_interoperates_with_strict_admission_verification() {
        use crate::{
            runner_binding::{BindingError, audience_for, verify_runner_proof},
            runner_identity::RunnerIdentity,
        };
        let identity = RunnerIdentity::generate().unwrap();
        let public = identity.public_keys();
        let intent = dispatch_intent("cd");
        let challenge = [0x88; 32];
        let audience = audience_for(&intent, public, challenge, 100, 1).unwrap();
        let workflow = workflow_for(&audience);
        let signature = identity
            .sign_admission(&intent, &workflow, challenge)
            .unwrap();
        // Production Iroh signing and strict Dalek verification use their real
        // independent APIs; this is not a predeclared fixture signature.
        let verified =
            verify_runner_proof(intent, workflow, public, challenge, signature, 1001).unwrap();
        assert_eq!(verified.signing_public_key(), &public.signing_ed25519);
        assert_eq!(verified.audience(), audience);
        let other_identity = RunnerIdentity::generate().unwrap();
        assert!(matches!(
            other_identity.sign_admission(
                &dispatch_intent("cd"),
                &workflow_for(&audience),
                challenge
            ),
            Err(crate::runner_identity::IdentityError::Binding(
                BindingError::Scope
            ))
        ));
    }

    #[test]
    fn valid_independent_layers_cannot_be_mixed_with_another_intent_key_or_challenge() {
        use crate::runner_binding::{BindingError, audience_for, verify_runner_proof};
        let intent = dispatch_intent("cd");
        let keys = runner_keys();
        let challenge = [0x88; 32];
        let audience = audience_for(&intent, keys, challenge, 100, 1).unwrap();
        let workflow = workflow_for(&audience);
        let signature = pop_signature(&intent, &workflow, keys, challenge);
        assert!(matches!(
            verify_runner_proof(
                dispatch_intent("ce"),
                workflow_for(&audience),
                keys,
                challenge,
                signature,
                1001
            ),
            Err(BindingError::Scope)
        ));
        let mut other = keys;
        other.archive_transport_ed25519 = ed25519_dalek::SigningKey::from_bytes(&[0x79; 32])
            .verifying_key()
            .to_bytes();
        assert!(matches!(
            verify_runner_proof(
                dispatch_intent("cd"),
                workflow_for(&audience),
                other,
                challenge,
                signature,
                1001
            ),
            Err(BindingError::Scope)
        ));
        assert!(matches!(
            verify_runner_proof(
                dispatch_intent("cd"),
                workflow_for(&audience),
                keys,
                [0x89; 32],
                signature,
                1001
            ),
            Err(BindingError::Scope)
        ));
    }

    #[test]
    fn runner_pop_rejects_another_token_bad_signature_expiry_and_duplicate_transport_keys() {
        use crate::runner_binding::{BindingError, audience_for, verify_runner_proof};
        let intent = dispatch_intent("cd");
        let keys = runner_keys();
        let challenge = [0x88; 32];
        let audience = audience_for(&intent, keys, challenge, 100, 1).unwrap();
        let workflow = workflow_for(&audience);
        let signature = pop_signature(&intent, &workflow, keys, challenge);
        let mut claims = claims();
        claims["aud"] = json!(audience);
        claims["jti"] = json!("a-different-valid-token");
        let other = verify_token(
            &issue(&claims),
            &self::keys(),
            ExpectedWorkflow {
                audience: &audience,
                ..expected()
            },
        )
        .unwrap();
        assert!(matches!(
            verify_runner_proof(
                dispatch_intent("cd"),
                other,
                keys,
                challenge,
                signature,
                1001
            ),
            Err(BindingError::Signature)
        ));
        let mut bad = signature;
        bad[0] ^= 1;
        assert!(matches!(
            verify_runner_proof(
                dispatch_intent("cd"),
                workflow_for(&audience),
                keys,
                challenge,
                bad,
                1001
            ),
            Err(BindingError::Signature)
        ));
        assert!(matches!(
            verify_runner_proof(
                dispatch_intent("cd"),
                workflow_for(&audience),
                keys,
                challenge,
                signature,
                1100
            ),
            Err(BindingError::Lifetime)
        ));
        let mut duplicate = keys;
        duplicate.archive_transport_ed25519 = duplicate.agent_transport_ed25519;
        assert!(matches!(
            audience_for(&intent, duplicate, challenge, 100, 1),
            Err(BindingError::Input)
        ));
        for alias in [keys.agent_transport_ed25519, keys.archive_transport_ed25519] {
            let mut duplicate_signer = keys;
            duplicate_signer.signing_ed25519 = alias;
            assert!(matches!(
                audience_for(&intent, duplicate_signer, challenge, 100, 1),
                Err(BindingError::Input)
            ));
        }
        assert!(matches!(
            audience_for(&intent, keys, [0; 32], 100, 1),
            Err(BindingError::Input)
        ));
    }

    #[test]
    fn a_verified_workflow_cannot_be_rejoined_before_its_not_before_time() {
        use crate::runner_binding::{BindingError, audience_for, verify_runner_proof};
        let intent = dispatch_intent("cd");
        let keys = runner_keys();
        let challenge = [0x88; 32];
        let audience = audience_for(&intent, keys, challenge, 100, 1).unwrap();
        let mut claims = claims();
        claims["aud"] = json!(audience);
        claims["nbf"] = json!(1050);
        let workflow = verify_token(
            &issue(&claims),
            &self::keys(),
            ExpectedWorkflow {
                audience: &audience,
                now_unix: 1050,
                ..expected()
            },
        )
        .unwrap();
        let signature = pop_signature(&intent, &workflow, keys, challenge);
        assert!(matches!(
            verify_runner_proof(intent, workflow, keys, challenge, signature, 1001),
            Err(BindingError::Lifetime)
        ));
    }
}
