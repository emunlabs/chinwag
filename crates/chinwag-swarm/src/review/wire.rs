//! Bounded, untrusted review replies. Decoding never establishes a review.

use super::{SignedReview, Statement};
use iroh::EndpointId;
use iroh_blobs::Hash;
use serde::{Deserialize, Serialize};

pub const MAX_REVIEW_BYTES: usize = 2048;
const SCHEMA: &str = "chinwag-review-reply/v2";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("review reply is not a bounded v2 object")]
    Wire,
    #[error(transparent)]
    Metadata(#[from] super::Error),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewWire {
    schema: String,
    run: String,
    oid: String,
    tree: String,
    bundle: [u8; 32],
    test_digest: [u8; 32],
    verdict_digest: [u8; 32],
    reviewer: [u8; 32],
    signature: Vec<u8>,
}

pub fn encode(review: &SignedReview) -> Result<Vec<u8>, Error> {
    let statement = &review.statement;
    let wire = ReviewWire {
        schema: SCHEMA.to_owned(),
        run: statement.run.clone(),
        oid: statement.oid.clone(),
        tree: statement.tree.clone(),
        bundle: *statement.bundle.as_bytes(),
        test_digest: statement.test_digest,
        verdict_digest: statement.verdict_digest,
        reviewer: *review.reviewer.as_bytes(),
        signature: review.signature_bytes().to_vec(),
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| Error::Wire)?;
    if bytes.len() > MAX_REVIEW_BYTES {
        return Err(Error::Wire);
    }
    Ok(bytes)
}

/// Return an unverified claim. The caller must separately use
/// `SignedReview::verify` with its pinned reviewer and expected statement.
/// That signature check authenticates bytes; the workflow still needs the
/// actual independent Cargo output and model verdict behind their digests.
///
/// ```compile_fail
/// use chinwag_swarm::review::{VerifiedReview, wire};
/// let verified: VerifiedReview = wire::decode(b"{}").unwrap();
/// ```
pub fn decode(bytes: &[u8]) -> Result<SignedReview, Error> {
    if bytes.is_empty() || bytes.len() > MAX_REVIEW_BYTES {
        return Err(Error::Wire);
    }
    let wire: ReviewWire = serde_json::from_slice(bytes).map_err(|_| Error::Wire)?;
    if wire.schema != SCHEMA {
        return Err(Error::Wire);
    }
    let signature: [u8; 64] = wire.signature.try_into().map_err(|_| Error::Wire)?;
    let reviewer = EndpointId::from_bytes(&wire.reviewer).map_err(|_| Error::Wire)?;
    let statement = Statement::passed(
        &wire.run,
        &wire.oid,
        &wire.tree,
        Hash::from_bytes(wire.bundle),
        wire.test_digest,
        wire.verdict_digest,
    )?;
    Ok(SignedReview::from_parts(statement, reviewer, signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{identity::Identity, review::Error as ReviewError};
    use serde_json::{Value, json};

    fn expected(width: usize, run: char) -> Statement {
        Statement::passed(
            &run.to_string().repeat(64),
            &"1".repeat(width),
            &"2".repeat(width),
            Hash::new(b"synthetic bundle"),
            [3; 32],
            [4; 32],
        )
        .unwrap()
    }

    fn fixture(width: usize) -> (Identity, Statement, Vec<u8>) {
        let architect = Identity::test_identity([0x11; 32]);
        let statement = expected(width, 'c');
        let bytes = encode(&SignedReview::sign(statement.clone(), &architect)).unwrap();
        (architect, statement, bytes)
    }

    fn edited(bytes: &[u8], edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(bytes).unwrap();
        edit(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn both_git_formats_roundtrip_then_require_explicit_signature_verification() {
        for width in [40, 64] {
            let (architect, statement, bytes) = fixture(width);
            assert!(bytes.len() <= MAX_REVIEW_BYTES);
            let unverified = decode(&bytes).unwrap();
            let verified = unverified
                .verify(architect.endpoint_id(), &statement)
                .unwrap();
            assert_eq!(verified.statement(), &statement);
            assert_eq!(verified.reviewer(), architect.endpoint_id());
        }
    }

    #[test]
    fn rewriting_wire_and_expected_run_cannot_rebind_an_old_signature() {
        let (architect, _, bytes) = fixture(40);
        let bytes = edited(&bytes, |v| v["run"] = json!("d".repeat(64)));
        let unverified = decode(&bytes).unwrap();
        assert!(matches!(
            unverified.verify(architect.endpoint_id(), &expected(40, 'd')),
            Err(ReviewError::Signature)
        ));
    }

    #[test]
    fn rewriting_candidate_or_evidence_and_expected_values_cannot_preserve_signature() {
        let (architect, original, bytes) = fixture(40);
        for field in ["oid", "tree", "bundle", "test_digest", "verdict_digest"] {
            let mut statement = original.clone();
            let changed = edited(&bytes, |v| match field {
                "oid" => {
                    statement.oid = "5".repeat(40);
                    v[field] = json!(statement.oid);
                }
                "tree" => {
                    statement.tree = "6".repeat(40);
                    v[field] = json!(statement.tree);
                }
                "bundle" => {
                    statement.bundle = Hash::from_bytes([7; 32]);
                    v[field] = json!(vec![7; 32]);
                }
                "test_digest" => {
                    statement.test_digest = [8; 32];
                    v[field] = json!(vec![8; 32]);
                }
                "verdict_digest" => {
                    statement.verdict_digest = [9; 32];
                    v[field] = json!(vec![9; 32]);
                }
                _ => unreachable!(),
            });
            assert!(matches!(
                decode(&changed)
                    .unwrap()
                    .verify(architect.endpoint_id(), &statement),
                Err(ReviewError::Signature)
            ));
        }
    }

    #[test]
    fn wrong_reviewer_and_wrong_signature_have_distinct_refusals() {
        let (architect, statement, bytes) = fixture(40);
        let other = Identity::test_identity([0x22; 32]);
        let changed = edited(&bytes, |v| {
            v["reviewer"] = json!(other.endpoint_id().as_bytes())
        });
        assert!(matches!(
            decode(&changed)
                .unwrap()
                .verify(architect.endpoint_id(), &statement),
            Err(ReviewError::Reviewer)
        ));
        let other_signature = SignedReview::sign(statement.clone(), &other).signature_bytes();
        let changed = edited(&bytes, |v| v["signature"] = json!(other_signature.to_vec()));
        assert!(matches!(
            decode(&changed)
                .unwrap()
                .verify(architect.endpoint_id(), &statement),
            Err(ReviewError::Signature)
        ));
    }

    #[test]
    fn an_unmodified_claim_with_a_different_expected_statement_refuses_evidence() {
        let (architect, _, bytes) = fixture(40);
        assert!(matches!(
            decode(&bytes)
                .unwrap()
                .verify(architect.endpoint_id(), &expected(40, 'd')),
            Err(ReviewError::Evidence)
        ));
    }

    #[test]
    fn old_schema_or_old_canonical_domain_cannot_pass_v2() {
        let (architect, statement, bytes) = fixture(40);
        let old_schema = edited(&bytes, |v| v["schema"] = json!("chinwag-review-reply/v1"));
        assert!(matches!(decode(&old_schema), Err(Error::Wire)));
        let old_bytes = String::from_utf8(statement.canonical_bytes())
            .unwrap()
            .replacen("chinwag-review/v2\n", "chinwag-review/v1\n", 1)
            .replace(&format!("run={}\n", statement.run()), "");
        let old_signature = architect.secret_key().sign(old_bytes.as_bytes()).to_bytes();
        let old_signed = edited(&bytes, |v| v["signature"] = json!(old_signature.to_vec()));
        assert!(matches!(
            decode(&old_signed)
                .unwrap()
                .verify(architect.endpoint_id(), &statement),
            Err(ReviewError::Signature)
        ));
    }

    #[test]
    fn direct_serde_decode_rejects_unknown_duplicate_and_escaped_duplicate_fields() {
        let (_, _, bytes) = fixture(40);
        let text = String::from_utf8(bytes.clone()).unwrap();
        for extra in [
            "\"extra\":0,",
            "\"run\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",",
            "\"r\\u0075n\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",",
        ] {
            let malformed = format!("{{{extra}{}", &text[1..]);
            assert!(matches!(decode(malformed.as_bytes()), Err(Error::Wire)));
        }
        for malformed in [
            b"".as_slice(),
            b"null",
            b"[]",
            b"{",
            b"{}",
            b"{\"schema\":true}",
        ] {
            assert!(matches!(decode(malformed), Err(Error::Wire)));
        }
        let mut trailing = bytes;
        trailing.extend_from_slice(b"{}");
        assert!(matches!(decode(&trailing), Err(Error::Wire)));
    }

    #[test]
    fn exact_array_widths_numeric_types_and_metadata_are_required() {
        let (_, _, bytes) = fixture(40);
        for field in [
            "bundle",
            "test_digest",
            "verdict_digest",
            "reviewer",
            "signature",
        ] {
            let width = if field == "signature" { 64 } else { 32 };
            for value in [
                json!(vec![0; width - 1]),
                json!(vec![0; width + 1]),
                json!("not bytes"),
                json!(vec![256; width]),
                json!(vec![-1; width]),
            ] {
                let changed = edited(&bytes, |v| v[field] = value);
                assert!(matches!(decode(&changed), Err(Error::Wire)));
            }
        }
        for value in [
            "c".repeat(63),
            "c".repeat(65),
            "C".repeat(64),
            "z".repeat(64),
        ] {
            let changed = edited(&bytes, |v| v["run"] = json!(value));
            assert!(matches!(
                decode(&changed),
                Err(Error::Metadata(ReviewError::Run))
            ));
        }
        for (oid, tree) in [
            ("1".repeat(64), "2".repeat(40)),
            ("1".repeat(40), "2".repeat(64)),
            ("A".repeat(40), "2".repeat(40)),
            ("HEAD".to_owned(), "2".repeat(40)),
        ] {
            let changed = edited(&bytes, |v| {
                v["oid"] = json!(oid);
                v["tree"] = json!(tree);
            });
            assert!(matches!(
                decode(&changed),
                Err(Error::Metadata(ReviewError::ObjectId))
            ));
        }
    }

    #[test]
    fn the_byte_cap_is_checked_before_deserializing() {
        let (architect, statement, mut bytes) = fixture(64);
        bytes.resize(MAX_REVIEW_BYTES, b' ');
        decode(&bytes)
            .unwrap()
            .verify(architect.endpoint_id(), &statement)
            .unwrap();
        bytes.push(b' ');
        assert!(matches!(decode(&bytes), Err(Error::Wire)));
        assert!(matches!(
            decode(&vec![b' '; MAX_REVIEW_BYTES + 1]),
            Err(Error::Wire)
        ));
    }
}
