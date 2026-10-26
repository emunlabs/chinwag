//! Claim reply parsing and one-shot request preparation.
//!
//! The receipt signature covers the receipt and its request binding.
//! `disposition` is the server's reported classification, not part of that
//! signature. This module cannot prove which handler emitted it, or that a
//! lease is active. A fixed-origin TLS boundary is still required later.
//! Neither reply type is a write permit.

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use super::{
    ClaimError, ClaimPolicy, MAX_JSON_BYTES, ObservedTime, SignedClaimReceipt, SignedClaimRequest,
    parse_signed_receipt,
};

/// Outer reply cap: a fully escaped inner receipt plus the envelope.
pub const MAX_REPLY_BODY_BYTES: usize = 6 * MAX_JSON_BYTES + 128;

/// One serialization of a signed request. Retry uses these bytes unchanged.
#[derive(Clone, Debug)]
pub struct PreparedClaim {
    signed: SignedClaimRequest,
    request_json: String,
    request_sha256: [u8; 32],
    wire_sha256: [u8; 32],
}

impl PreparedClaim {
    /// Authenticates the key declared in the request, not a pinned membership.
    pub fn from_signed(signed: SignedClaimRequest) -> Result<Self, ClaimError> {
        let request_sha256 = signed.request_sha256()?;
        let actor_id = super::decode_hex_exact::<32>(&signed.request.actor)?;
        let actor = VerifyingKey::from_bytes(&actor_id).map_err(|_| ClaimError::Identity)?;
        signed.verify_actor(&actor)?;
        let request_json = serde_json::to_string(&signed).map_err(|_| ClaimError::Malformed)?;
        if request_json.len() > MAX_JSON_BYTES {
            return Err(ClaimError::InputTooLarge);
        }
        Ok(Self {
            signed,
            wire_sha256: super::sha256(request_json.as_bytes()),
            request_json,
            request_sha256,
        })
    }

    /// Restore an original packet without serializing, signing, or restamping it.
    /// This authenticates its declared actor, not room membership or freshness.
    pub fn from_request_json_exact(bytes: &[u8]) -> Result<Self, ClaimError> {
        if bytes.len() > MAX_JSON_BYTES {
            return Err(ClaimError::InputTooLarge);
        }
        let request_json = std::str::from_utf8(bytes).map_err(|_| ClaimError::Malformed)?;
        let signed = super::parse_signed_request(bytes)?;
        let actor_id = super::decode_hex_exact::<32>(&signed.request.actor)?;
        let actor = VerifyingKey::from_bytes(&actor_id).map_err(|_| ClaimError::Identity)?;
        signed.verify_actor(&actor)?;
        let request_sha256 = signed.request_sha256()?;
        Ok(Self {
            signed,
            request_json: request_json.to_owned(),
            request_sha256,
            wire_sha256: super::sha256(bytes),
        })
    }

    pub fn request_json(&self) -> &str {
        &self.request_json
    }

    pub fn signed(&self) -> &SignedClaimRequest {
        &self.signed
    }

    pub fn request_sha256(&self) -> &[u8; 32] {
        &self.request_sha256
    }

    pub fn wire_sha256(&self) -> &[u8; 32] {
        &self.wire_sha256
    }
}

/// Binding-only reply. No current policy, session, or clock is required.
///
/// ```compile_fail,E0599
/// fn no_current(reply: chinwag_claim::reply::HistoricalReply) {
///     reply.check_current(&chinwag_claim::ClaimPolicy::default(), 0, 0, "");
/// }
/// ```
///
/// ```compile_fail,E0308
/// fn no_promotion(reply: chinwag_claim::reply::HistoricalReply) {
///     let _ = chinwag_claim::reply::ParsedClaimReply::FreshlyStored(reply);
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalReply {
    inner: AuthenticatedReply,
}

impl HistoricalReply {
    pub fn receipt_json(&self) -> &str {
        &self.inner.receipt_json
    }

    pub fn receipt(&self) -> &SignedClaimReceipt {
        &self.inner.receipt
    }

    pub fn receipt_json_sha256(&self) -> &[u8; 32] {
        &self.inner.receipt_json_sha256
    }
}

/// Freshly stored classification. `check_current` is not a write permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreshReply {
    inner: AuthenticatedReply,
}

impl FreshReply {
    pub fn receipt_json(&self) -> &str {
        &self.inner.receipt_json
    }

    pub fn receipt(&self) -> &SignedClaimReceipt {
        &self.inner.receipt
    }

    pub fn receipt_json_sha256(&self) -> &[u8; 32] {
        &self.inner.receipt_json_sha256
    }

    /// Caller-supplied clock, watermark, session, and policy. This does not
    /// observe a live session or persist the watermark, and `Ok(())` grants nothing.
    pub fn check_current(
        &self,
        policy: &ClaimPolicy,
        now: u64,
        watermark: u64,
        current_session: &str,
    ) -> Result<(), ClaimError> {
        ObservedTime::at(watermark)?.observe(now)?;
        let receipt = &self.inner.receipt.receipt;
        if now < receipt.issued || now >= receipt.expiry {
            return Err(ClaimError::Ttl);
        }
        if current_session != receipt.session {
            return Err(ClaimError::Mismatch);
        }
        policy.authorize(receipt.pr, &receipt.files)
    }
}

/// Reported classification after binding. Not a lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedClaimReply {
    Historical(HistoricalReply),
    FreshlyStored(FreshReply),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedReply {
    receipt_json: String,
    receipt: SignedClaimReceipt,
    receipt_json_sha256: [u8; 32],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyEnvelope {
    disposition: ReportedDisposition,
    receipt_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReportedDisposition {
    FreshlyStored,
    OutcomeResolution,
}

pub fn parse_claim_reply(
    body: &[u8],
    expected: &SignedClaimRequest,
    actor: &VerifyingKey,
    coordinator: &VerifyingKey,
) -> Result<ParsedClaimReply, ClaimError> {
    if body.len() > MAX_REPLY_BODY_BYTES {
        return Err(ClaimError::InputTooLarge);
    }
    let envelope: ReplyEnvelope =
        serde_json::from_slice(body).map_err(|_| ClaimError::Malformed)?;
    if envelope.receipt_json.len() > MAX_JSON_BYTES {
        return Err(ClaimError::InputTooLarge);
    }
    let receipt = parse_signed_receipt(envelope.receipt_json.as_bytes())?;
    receipt.verify_binding(expected, actor, coordinator)?;
    let inner = AuthenticatedReply {
        receipt_json_sha256: super::sha256(envelope.receipt_json.as_bytes()),
        receipt,
        receipt_json: envelope.receipt_json,
    };
    Ok(match envelope.disposition {
        ReportedDisposition::OutcomeResolution => {
            ParsedClaimReply::Historical(HistoricalReply { inner })
        }
        ReportedDisposition::FreshlyStored => ParsedClaimReply::FreshlyStored(FreshReply { inner }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ClaimRequestUnsigned, MAX_JSON_BYTES, Pr, SigningKey, encode_hex, receipt_revision_for,
        sha256,
    };

    const SAMPLE: &str = "crates/chinwag-claim/src/lib.rs";

    struct Fixture {
        actor: SigningKey,
        coordinator: SigningKey,
        signed: SignedClaimRequest,
        receipt_json: String,
        receipt: SignedClaimReceipt,
    }

    fn fixture() -> Fixture {
        let actor = SigningKey::from_bytes(&[7u8; 32]);
        let coordinator = SigningKey::from_bytes(&[9u8; 32]);
        let signed = ClaimRequestUnsigned {
            claim_id: encode_hex(&[0x11; 32]),
            actor: encode_hex(actor.verifying_key().as_bytes()),
            session: encode_hex(&[0x22; 32]),
            nonce: encode_hex(&[0x33; 32]),
            pr: Pr::Pr01,
            files: vec![SAMPLE.to_string()],
            expected_revision: 0,
            issued: 1_700_000_000,
            expiry: 1_700_000_120,
        }
        .sign(&actor)
        .unwrap();
        let receipt = crate::ClaimReceiptUnsigned {
            claim_id: signed.request.claim_id.clone(),
            actor: signed.request.actor.clone(),
            session: signed.request.session.clone(),
            pr: signed.request.pr,
            files: signed.request.files.clone(),
            revision: receipt_revision_for(signed.request.expected_revision).unwrap(),
            issued: signed.request.issued,
            expiry: signed.request.expiry,
            request_sha256: signed.request_sha256_hex().unwrap(),
            coordinator: encode_hex(coordinator.verifying_key().as_bytes()),
        }
        .sign(&coordinator)
        .unwrap();
        let receipt_json = format!(
            "{{\n  \"receipt\": {},\n  \"signature\": \"{}\"\n}}",
            serde_json::to_string(&receipt.receipt).unwrap(),
            receipt.signature
        );
        Fixture {
            actor,
            coordinator,
            signed,
            receipt_json,
            receipt,
        }
    }

    fn envelope(disposition: &str, receipt_json: &str) -> Vec<u8> {
        format!(
            "{{\"disposition\":{},\"receipt_json\":{}}}",
            serde_json::to_string(disposition).unwrap(),
            serde_json::to_string(receipt_json).unwrap()
        )
        .into_bytes()
    }

    fn historical(body: &[u8], fix: &Fixture) -> HistoricalReply {
        match parse_claim_reply(
            body,
            &fix.signed,
            &fix.actor.verifying_key(),
            &fix.coordinator.verifying_key(),
        )
        .unwrap()
        {
            ParsedClaimReply::Historical(reply) => reply,
            ParsedClaimReply::FreshlyStored(_) => panic!("reported fresh"),
        }
    }

    fn fresh(body: &[u8], fix: &Fixture) -> FreshReply {
        match parse_claim_reply(
            body,
            &fix.signed,
            &fix.actor.verifying_key(),
            &fix.coordinator.verifying_key(),
        )
        .unwrap()
        {
            ParsedClaimReply::FreshlyStored(reply) => reply,
            ParsedClaimReply::Historical(_) => panic!("reported historical"),
        }
    }

    fn allowing() -> ClaimPolicy {
        let mut policy = ClaimPolicy::default();
        policy.allow(Pr::Pr01, SAMPLE).unwrap();
        policy
    }

    #[test]
    fn prepared_claim_keeps_one_serialization_for_the_declared_key() {
        let fix = fixture();
        let prepared = PreparedClaim::from_signed(fix.signed.clone()).unwrap();
        let again = serde_json::to_string(&fix.signed).unwrap();
        assert_eq!(prepared.request_json(), again);
        assert_eq!(prepared.wire_sha256(), &sha256(again.as_bytes()));
        assert_eq!(
            prepared.request_sha256(),
            &fix.signed.request_sha256().unwrap()
        );
        assert_eq!(prepared.signed(), &fix.signed);
        let mut broken = fix.signed.clone();
        let last = broken.signature.pop().unwrap();
        broken.signature.push(if last == 'a' { 'b' } else { 'a' });
        assert_eq!(
            PreparedClaim::from_signed(broken).unwrap_err(),
            ClaimError::Signature
        );
    }

    #[test]
    fn exact_restore_retains_whitespace_with_same_canonical_hash_and_original_nonce() {
        let fix = fixture();
        let compact = PreparedClaim::from_signed(fix.signed.clone()).unwrap();
        let spaced = format!("\n{}\n", serde_json::to_string_pretty(&fix.signed).unwrap());
        let restored = PreparedClaim::from_request_json_exact(spaced.as_bytes()).unwrap();
        assert_eq!(restored.request_json().as_bytes(), spaced.as_bytes());
        assert_eq!(restored.signed(), compact.signed());
        assert_eq!(restored.request_sha256(), compact.request_sha256());
        assert_ne!(restored.wire_sha256(), compact.wire_sha256());
        assert_eq!(restored.wire_sha256(), &sha256(spaced.as_bytes()));
        let recovered =
            PreparedClaim::from_request_json_exact(restored.request_json().as_bytes()).unwrap();
        assert_eq!(recovered.request_json(), spaced);
        assert_eq!(recovered.wire_sha256(), restored.wire_sha256());
        assert_eq!(recovered.signed().request.nonce, fix.signed.request.nonce);
    }

    #[test]
    fn exact_restore_rejects_oversize_utf8_duplicates_unknown_fields_and_bad_signature() {
        assert_eq!(
            PreparedClaim::from_request_json_exact(&vec![b' '; MAX_JSON_BYTES + 1]).unwrap_err(),
            ClaimError::InputTooLarge
        );
        assert_eq!(
            PreparedClaim::from_request_json_exact(&[0xff]).unwrap_err(),
            ClaimError::Malformed
        );
        let fix = fixture();
        let request = serde_json::to_string(&fix.signed.request).unwrap();
        let signature = serde_json::to_string(&fix.signed.signature).unwrap();
        let duplicate = format!(
            "{{\"request\":{request},\"signature\":{signature},\"signature\":{signature}}}"
        );
        assert_eq!(
            PreparedClaim::from_request_json_exact(duplicate.as_bytes()).unwrap_err(),
            ClaimError::Malformed
        );
        let unknown = format!("{{\"request\":{request},\"signature\":{signature},\"extra\":true}}");
        assert_eq!(
            PreparedClaim::from_request_json_exact(unknown.as_bytes()).unwrap_err(),
            ClaimError::Malformed
        );
        let mut forged = fix.signed;
        let last = forged.signature.pop().unwrap();
        forged.signature.push(if last == 'a' { 'b' } else { 'a' });
        assert_eq!(
            PreparedClaim::from_request_json_exact(&serde_json::to_vec(&forged).unwrap())
                .unwrap_err(),
            ClaimError::Signature
        );
    }

    #[test]
    fn stale_historical_binding_ignores_empty_policy_and_keeps_exact_text() {
        let fix = fixture();
        let body = envelope("outcome_resolution", &fix.receipt_json);
        let reply = historical(&body, &fix);
        assert_eq!(reply.receipt_json(), fix.receipt_json);
        assert_eq!(reply.receipt(), &fix.receipt);
        assert_eq!(
            reply.receipt_json_sha256(),
            &sha256(fix.receipt_json.as_bytes())
        );
        assert_ne!(
            reply.receipt_json(),
            serde_json::to_string(reply.receipt()).unwrap()
        );
    }

    #[test]
    fn forged_fresh_label_is_only_a_reported_classification() {
        let fix = fixture();
        let reply = fresh(&envelope("freshly_stored", &fix.receipt_json), &fix);
        assert_eq!(reply.receipt_json(), fix.receipt_json);
        assert_eq!(
            reply.check_current(
                &ClaimPolicy::default(),
                1_700_000_060,
                1_700_000_000,
                &fix.signed.request.session,
            ),
            Err(ClaimError::PolicyDenied)
        );
        assert_eq!(
            reply.check_current(
                &allowing(),
                1_700_000_060,
                1_700_000_000,
                &fix.signed.request.session,
            ),
            Ok(())
        );
    }

    #[test]
    fn fresh_time_session_and_rollback_fail_closed() {
        let fix = fixture();
        let reply = fresh(&envelope("freshly_stored", &fix.receipt_json), &fix);
        let session = fix.signed.request.session.as_str();
        let policy = allowing();
        assert_eq!(
            reply.check_current(&policy, 1_700_000_050, 1_700_000_100, session),
            Err(ClaimError::ClockRollback)
        );
        assert_eq!(
            reply.check_current(&policy, 1_699_999_999, 1_699_999_999, session),
            Err(ClaimError::Ttl)
        );
        assert_eq!(
            reply.check_current(&policy, 1_700_000_120, 1_700_000_000, session),
            Err(ClaimError::Ttl)
        );
        assert_eq!(
            reply.check_current(&policy, 1_700_000_060, 1_700_000_000, "other-session"),
            Err(ClaimError::Mismatch)
        );
        assert_eq!(
            reply.check_current(&policy, crate::MAX_SAFE_UNIX + 1, 0, session),
            Err(ClaimError::Overflow)
        );
    }

    #[test]
    fn binding_rejects_bad_signatures_and_changed_scope() {
        let fix = fixture();
        let other = SigningKey::from_bytes(&[3u8; 32]);
        let body = envelope("outcome_resolution", &fix.receipt_json);
        assert_eq!(
            parse_claim_reply(
                &body,
                &fix.signed,
                &other.verifying_key(),
                &fix.coordinator.verifying_key(),
            ),
            Err(ClaimError::Identity)
        );
        assert_eq!(
            parse_claim_reply(
                &body,
                &fix.signed,
                &fix.actor.verifying_key(),
                &other.verifying_key(),
            ),
            Err(ClaimError::Pin)
        );
        let mut request = fix.signed.clone();
        let last = request.signature.pop().unwrap();
        request.signature.push(if last == 'a' { 'b' } else { 'a' });
        assert_eq!(
            parse_claim_reply(
                &body,
                &request,
                &fix.actor.verifying_key(),
                &fix.coordinator.verifying_key(),
            ),
            Err(ClaimError::Signature)
        );
        let mut bad = fix.receipt.clone();
        let last = bad.signature.pop().unwrap();
        bad.signature.push(if last == 'a' { 'b' } else { 'a' });
        assert_eq!(
            parse_claim_reply(
                &envelope("outcome_resolution", &serde_json::to_string(&bad).unwrap()),
                &fix.signed,
                &fix.actor.verifying_key(),
                &fix.coordinator.verifying_key(),
            ),
            Err(ClaimError::Signature)
        );

        let mut hash = fix.receipt.receipt.clone();
        hash.request_sha256 = encode_hex(&[0xab; 32]);
        let hash = hash.sign(&fix.coordinator).unwrap();
        assert_eq!(
            err_historical(&serde_json::to_string(&hash).unwrap(), &fix),
            ClaimError::Mismatch
        );
        let mut path = fix.receipt.receipt.clone();
        path.files = vec!["crates/chinwag-seed/src/lib.rs".to_string()];
        let path = path.sign(&fix.coordinator).unwrap();
        assert_eq!(
            err_historical(&serde_json::to_string(&path).unwrap(), &fix),
            ClaimError::Mismatch
        );
        let mut pr = fix.receipt.receipt.clone();
        pr.pr = Pr::Pr02;
        let pr = pr.sign(&fix.coordinator).unwrap();
        assert_eq!(
            err_historical(&serde_json::to_string(&pr).unwrap(), &fix),
            ClaimError::Mismatch
        );
        let mut revision = fix.receipt.receipt.clone();
        revision.revision = 2;
        let revision = revision.sign(&fix.coordinator).unwrap();
        assert_eq!(
            err_historical(&serde_json::to_string(&revision).unwrap(), &fix),
            ClaimError::Revision
        );
    }

    fn err_historical(receipt_json: &str, fix: &Fixture) -> ClaimError {
        parse_claim_reply(
            &envelope("outcome_resolution", receipt_json),
            &fix.signed,
            &fix.actor.verifying_key(),
            &fix.coordinator.verifying_key(),
        )
        .unwrap_err()
    }

    #[test]
    fn envelope_bounds_duplicates_and_unknown_fields() {
        let fix = fixture();
        assert_eq!(
            parse_claim_reply(
                &vec![b'x'; MAX_REPLY_BODY_BYTES + 1],
                &fix.signed,
                &fix.actor.verifying_key(),
                &fix.coordinator.verifying_key(),
            ),
            Err(ClaimError::InputTooLarge)
        );
        let huge = "x".repeat(MAX_JSON_BYTES + 1);
        assert!(envelope("outcome_resolution", &huge).len() <= MAX_REPLY_BODY_BYTES);
        assert_eq!(err_historical(&huge, &fix), ClaimError::InputTooLarge);
        let quoted = serde_json::to_string(&fix.receipt_json).unwrap();
        let duplicate_disposition = format!(
            "{{\"disposition\":\"freshly_stored\",\"disposition\":\"outcome_resolution\",\"receipt_json\":{quoted}}}"
        );
        assert_eq!(
            parse_claim_reply(
                duplicate_disposition.as_bytes(),
                &fix.signed,
                &fix.actor.verifying_key(),
                &fix.coordinator.verifying_key(),
            ),
            Err(ClaimError::Malformed)
        );
        let duplicate_receipt = format!(
            "{{\"receipt_json\":{quoted},\"disposition\":\"outcome_resolution\",\"receipt_json\":{quoted}}}"
        );
        assert_eq!(
            parse_claim_reply(
                duplicate_receipt.as_bytes(),
                &fix.signed,
                &fix.actor.verifying_key(),
                &fix.coordinator.verifying_key(),
            ),
            Err(ClaimError::Malformed)
        );
        let unknown = format!(
            "{{\"disposition\":\"outcome_resolution\",\"receipt_json\":{quoted},\"lease\":true}}"
        );
        assert_eq!(
            parse_claim_reply(
                unknown.as_bytes(),
                &fix.signed,
                &fix.actor.verifying_key(),
                &fix.coordinator.verifying_key(),
            ),
            Err(ClaimError::Malformed)
        );
        assert_eq!(
            err_historical("{\"receipt\":1}", &fix),
            ClaimError::Malformed
        );
        assert_eq!(
            parse_claim_reply(
                &envelope("lease", &fix.receipt_json),
                &fix.signed,
                &fix.actor.verifying_key(),
                &fix.coordinator.verifying_key(),
            ),
            Err(ClaimError::Malformed)
        );
        let duplicate_inner = format!(
            "{{\"receipt\":{},\"signature\":\"{}\",\"signature\":\"{}\"}}",
            serde_json::to_string(&fix.receipt.receipt).unwrap(),
            fix.receipt.signature,
            fix.receipt.signature,
        );
        assert_eq!(
            err_historical(&duplicate_inner, &fix),
            ClaimError::Malformed
        );
        let mut value = serde_json::to_value(&fix.receipt).unwrap();
        value["extra"] = serde_json::json!(true);
        assert_eq!(
            err_historical(&serde_json::to_string(&value).unwrap(), &fix),
            ClaimError::Malformed
        );
    }
}
