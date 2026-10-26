//! Luggage tag for one bundle offer.
//!
//! `decode_for` checks the byte cap, the schema, the pinned run, and the pinned
//! candidate. It does not authenticate the sender and it does not grant
//! membership, a write, a review, or a seal. The caller has to receive the
//! bytes on the existing pinned two-actor data plane during a fresh room
//! session and has to pass the expected run and candidate. This module adds
//! no signing key.

use crate::bundle::{BundleExpectation, GitCandidate};
use serde::{Deserialize, Serialize};

pub const MAX_OFFER_BYTES: usize = 2048;
const SCHEMA: &str = "chinwag-bundle-offer/v1";
pub const MAX_ACK_BYTES: usize = 2048;
const ACK_SCHEMA: &str = "chinwag-bundle-bytes-received/v1";

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("bundle offer bytes are not a bounded v1 object")]
    Wire,
    #[error("bundle offer run is not the pinned 64-hex id")]
    Run,
    #[error("bundle offer candidate does not match the pinned candidate")]
    Candidate,
    #[error("byte receipt does not match the pinned offer")]
    Receipt,
    #[error(transparent)]
    Metadata(#[from] crate::bundle::Error),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferWire {
    schema: String,
    run: String,
    oid: String,
    tree: String,
    builder: [u8; 32],
    blake3: [u8; 32],
    size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleOffer {
    run: String,
    expected: BundleExpectation,
}

/// A byte-receipt claim, not authentication, a disk save, Git verification,
/// Cargo, a model verdict, or seal authority. The receiver checks actual bytes
/// before encoding; the sender must separately require its pinned transport
/// peer and a fresh session before accepting a decoded claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleBytesAck {
    offer: BundleOffer,
}

impl BundleBytesAck {
    pub fn from_received_bytes(offer: &BundleOffer, bytes: &[u8]) -> Result<Self, Error> {
        offer.expected.matches_blob(bytes)?;
        Ok(Self {
            offer: offer.clone(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let expected = &self.offer.expected;
        let wire = OfferWire {
            schema: ACK_SCHEMA.into(),
            run: self.offer.run.clone(),
            oid: expected.oid().into(),
            tree: expected.tree().into(),
            builder: expected.builder(),
            blake3: expected.hash(),
            size: expected.size(),
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| Error::Wire)?;
        if bytes.len() > MAX_ACK_BYTES {
            return Err(Error::Wire);
        }
        Ok(bytes)
    }

    /// Parse an untrusted peer claim bound to every field of the expected
    /// offer. This does not independently observe that peer's receipt.
    pub fn decode_for(bytes: &[u8], expected: &BundleOffer) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_ACK_BYTES {
            return Err(Error::Wire);
        }
        let wire: OfferWire = serde_json::from_slice(bytes).map_err(|_| Error::Wire)?;
        if wire.schema != ACK_SCHEMA {
            return Err(Error::Wire);
        }
        let bundle = &expected.expected;
        if wire.run != expected.run
            || wire.oid != bundle.oid()
            || wire.tree != bundle.tree()
            || wire.builder != bundle.builder()
            || wire.blake3 != bundle.hash()
            || wire.size != bundle.size()
        {
            return Err(Error::Receipt);
        }
        Ok(Self {
            offer: expected.clone(),
        })
    }
}

pub(crate) fn run_id(run: &str) -> Result<(), Error> {
    if run.len() == 64
        && run
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(Error::Run)
    }
}

impl BundleOffer {
    pub fn new(run: &str, expected: BundleExpectation) -> Result<Self, Error> {
        run_id(run)?;
        Ok(Self {
            run: run.to_owned(),
            expected,
        })
    }

    pub fn run(&self) -> &str {
        &self.run
    }

    pub fn expectation(&self) -> &BundleExpectation {
        &self.expected
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let wire = OfferWire {
            schema: SCHEMA.to_owned(),
            run: self.run.clone(),
            oid: self.expected.oid().to_owned(),
            tree: self.expected.tree().to_owned(),
            builder: self.expected.builder(),
            blake3: self.expected.hash(),
            size: self.expected.size(),
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| Error::Wire)?;
        if bytes.len() > MAX_OFFER_BYTES {
            Err(Error::Wire)
        } else {
            Ok(bytes)
        }
    }

    pub fn decode_for(bytes: &[u8], run: &str, candidate: &GitCandidate) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_OFFER_BYTES {
            return Err(Error::Wire);
        }
        run_id(run)?;
        let wire: OfferWire = serde_json::from_slice(bytes).map_err(|_| Error::Wire)?;
        if wire.schema != SCHEMA {
            return Err(Error::Wire);
        }
        if wire.run != run {
            return Err(Error::Run);
        }
        let parsed = GitCandidate::new(&wire.oid, &wire.tree, wire.builder)?;
        if &parsed != candidate {
            return Err(Error::Candidate);
        }
        let expected =
            BundleExpectation::from_candidate(candidate.clone(), wire.blake3, wire.size)?;
        Ok(Self {
            run: run.to_owned(),
            expected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_receipt_requires_actual_matching_bytes_and_roundtrips_both_git_formats() {
        let payload = b"codec fixture bytes, not a Git or Cargo proof";
        for width in [40, 64] {
            let (run, candidate, _) = pinned(width, payload.len() as u64);
            let expected = BundleExpectation::from_candidate(
                candidate.clone(),
                *blake3::hash(payload).as_bytes(),
                payload.len() as u64,
            )
            .unwrap();
            let offer = BundleOffer::new(&run, expected).unwrap();
            assert!(BundleBytesAck::from_received_bytes(&offer, b"wrong length").is_err());
            assert!(BundleBytesAck::from_received_bytes(&offer, &vec![0; payload.len()]).is_err());
            let ack = BundleBytesAck::from_received_bytes(&offer, payload).unwrap();
            let bytes = ack.encode().unwrap();
            assert!(bytes.len() <= MAX_ACK_BYTES);
            assert_eq!(BundleBytesAck::decode_for(&bytes, &offer).unwrap(), ack);
            assert!(BundleBytesAck::decode_for(&offer.encode().unwrap(), &offer).is_err());
            assert!(BundleOffer::decode_for(&bytes, &run, &candidate).is_err());
        }
    }

    #[test]
    fn byte_receipt_rejects_every_changed_binding_and_ambiguous_or_oversized_wire() {
        let payload = b"checked bytes";
        let (run, candidate, _) = pinned(40, payload.len() as u64);
        let expected = BundleExpectation::from_candidate(
            candidate,
            *blake3::hash(payload).as_bytes(),
            payload.len() as u64,
        )
        .unwrap();
        let offer = BundleOffer::new(&run, expected).unwrap();
        let bytes = BundleBytesAck::from_received_bytes(&offer, payload)
            .unwrap()
            .encode()
            .unwrap();
        for (field, value) in [
            ("run", serde_json::json!("d".repeat(64))),
            ("oid", serde_json::json!("f".repeat(40))),
            ("tree", serde_json::json!("e".repeat(40))),
            ("builder", serde_json::json!(vec![9u8; 32])),
            ("blake3", serde_json::json!(vec![8u8; 32])),
            ("size", serde_json::json!(payload.len() + 1)),
        ] {
            assert_eq!(
                BundleBytesAck::decode_for(&edited(&bytes, |v| v[field] = value), &offer),
                Err(Error::Receipt),
                "{field}"
            );
        }
        for schema in ["chinwag-bundle-offer/v1", "chinwag-bundle-verified/v1"] {
            assert_eq!(
                BundleBytesAck::decode_for(
                    &edited(&bytes, |v| v["schema"] = serde_json::json!(schema)),
                    &offer
                ),
                Err(Error::Wire)
            );
        }
        for invalid in [
            b"".to_vec(),
            b"{".to_vec(),
            vec![b'x'; MAX_ACK_BYTES + 1],
            edited(&bytes, |v| v["cargo_passed"] = serde_json::json!(true)),
            edited(&bytes, |v| v["size"] = serde_json::json!("13")),
        ] {
            assert_eq!(
                BundleBytesAck::decode_for(&invalid, &offer),
                Err(Error::Wire)
            );
        }
        for key in ["run", "\\u0072un"] {
            let mut duplicate = format!("{{\"{key}\":\"{run}\",").into_bytes();
            duplicate.extend_from_slice(&bytes[1..]);
            assert_eq!(
                BundleBytesAck::decode_for(&duplicate, &offer),
                Err(Error::Wire)
            );
        }
    }

    fn pinned(width: usize, size: u64) -> (String, GitCandidate, BundleExpectation) {
        let (oid, tree, run) = if width == 64 {
            ("ab".repeat(32), "cd".repeat(32), "e".repeat(64))
        } else {
            ("a".repeat(40), "b".repeat(40), "c".repeat(64))
        };
        let candidate = GitCandidate::new(&oid, &tree, [4; 32]).unwrap();
        let expected = BundleExpectation::from_candidate(candidate.clone(), [6; 32], size).unwrap();
        (run, candidate, expected)
    }

    fn edited(bytes: &[u8], change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        change(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn sha1_and_sha256_tags_roundtrip_the_same_hash_and_size() {
        for (width, size) in [(40usize, 20u64), (64, 100)] {
            let (run, candidate, expected) = pinned(width, size);
            let offer = BundleOffer::new(&run, expected.clone()).unwrap();
            let bytes = offer.encode().unwrap();
            assert!(bytes.len() <= MAX_OFFER_BYTES);
            let decoded = BundleOffer::decode_for(&bytes, &run, &candidate).unwrap();
            assert_eq!(decoded.run(), run);
            assert_eq!(decoded.expectation(), &expected);
            assert_eq!(decoded.expectation().hash(), expected.hash());
            assert_eq!(decoded.expectation().size(), expected.size());
            assert_eq!(
                decoded.expectation().object_format(),
                expected.object_format()
            );
        }
    }

    #[test]
    fn run_shape_rejects_uppercase_and_short_ids() {
        let (_, _, expected) = pinned(40, 20);
        assert_eq!(
            BundleOffer::new(&"A".repeat(64), expected.clone()),
            Err(Error::Run)
        );
        assert_eq!(
            BundleOffer::new(&"c".repeat(63), expected.clone()),
            Err(Error::Run)
        );
        assert_eq!(BundleOffer::new(&"g".repeat(64), expected), Err(Error::Run));
    }

    #[test]
    fn decode_rejects_a_tag_that_is_not_the_pinned_offer() {
        let (run, candidate, expected) = pinned(40, 20);
        let bytes = BundleOffer::new(&run, expected).unwrap().encode().unwrap();
        assert_eq!(
            BundleOffer::decode_for(&bytes, &"A".repeat(64), &candidate),
            Err(Error::Run)
        );
        assert_eq!(
            BundleOffer::decode_for(&bytes, &"d".repeat(64), &candidate),
            Err(Error::Run)
        );
        let other =
            GitCandidate::new(&"f".repeat(40), candidate.tree(), candidate.builder()).unwrap();
        assert_eq!(
            BundleOffer::decode_for(&bytes, &run, &other),
            Err(Error::Candidate)
        );
        let builder = GitCandidate::new(candidate.oid(), candidate.tree(), [9; 32]).unwrap();
        assert_eq!(
            BundleOffer::decode_for(&bytes, &run, &builder),
            Err(Error::Candidate)
        );
        assert_eq!(
            BundleOffer::decode_for(b"", &run, &candidate),
            Err(Error::Wire)
        );
        assert_eq!(
            BundleOffer::decode_for(&vec![b'x'; MAX_OFFER_BYTES + 1], &run, &candidate),
            Err(Error::Wire)
        );
        assert_eq!(
            BundleOffer::decode_for(b"{", &run, &candidate),
            Err(Error::Wire)
        );
        assert_eq!(
            BundleOffer::decode_for(
                &edited(&bytes, |value| {
                    value["schema"] = serde_json::json!("chinwag-bundle-offer/v2");
                }),
                &run,
                &candidate,
            ),
            Err(Error::Wire)
        );
        assert_eq!(
            BundleOffer::decode_for(
                &edited(&bytes, |value| value["extra"] = serde_json::json!(1)),
                &run,
                &candidate,
            ),
            Err(Error::Wire)
        );
        assert_eq!(
            BundleOffer::decode_for(
                &edited(&bytes, |value| value["size"] = serde_json::json!(0)),
                &run,
                &candidate,
            ),
            Err(Error::Metadata(crate::bundle::Error::Size))
        );
        assert_eq!(
            BundleOffer::decode_for(
                &edited(&bytes, |value| {
                    value["size"] = serde_json::json!(crate::bundle::MAX_BUNDLE_BYTES as u64 + 1);
                }),
                &run,
                &candidate,
            ),
            Err(Error::Metadata(crate::bundle::Error::Size))
        );
        for prefix in [
            br#"{"schema":"chinwag-bundle-offer/v1","#.as_slice(),
            br#"{"\u0073chema":"chinwag-bundle-offer/v1","#.as_slice(),
        ] {
            let mut duplicate = Vec::with_capacity(prefix.len() + bytes.len());
            duplicate.extend_from_slice(prefix);
            duplicate.extend_from_slice(&bytes[1..]);
            assert!(serde_json::from_slice::<OfferWire>(&duplicate).is_err());
            assert_eq!(
                BundleOffer::decode_for(&duplicate, &run, &candidate),
                Err(Error::Wire)
            );
        }
    }
}
