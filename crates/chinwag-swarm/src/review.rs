//! Stage-0 peer-review claims bound to an exact candidate and its evidence.
//!
//! Verification proves who signed these bytes. It does not run Cargo, obtain a
//! model verdict, authorize a branch update, or establish Genesis acceptance.

pub mod wire;

use iroh::{EndpointId, Signature};
use iroh_blobs::Hash;

use crate::identity::Identity;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the review run must be 64 lowercase hexadecimal characters")]
    Run,
    #[error("review object ids must be full lowercase hex using one Git object format")]
    ObjectId,
    #[error("the review was not signed by the pinned reviewer")]
    Reviewer,
    #[error("the review does not match the expected candidate evidence")]
    Evidence,
    #[error("the review signature is invalid")]
    Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Statement {
    run: String,
    oid: String,
    tree: String,
    bundle: Hash,
    test_digest: [u8; 32],
    verdict_digest: [u8; 32],
}

fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64)
        && oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Statement {
    /// Describe a passed peer review. The workflow must supply digests of the
    /// actual independent test output and the actual approved model verdict.
    pub fn passed(
        run: &str,
        oid: &str,
        tree: &str,
        bundle: Hash,
        test_digest: [u8; 32],
        verdict_digest: [u8; 32],
    ) -> Result<Self, Error> {
        if run.len() != 64 || !valid_oid(run) {
            return Err(Error::Run);
        }
        if !valid_oid(oid) || !valid_oid(tree) || oid.len() != tree.len() {
            return Err(Error::ObjectId);
        }
        Ok(Self {
            run: run.to_owned(),
            oid: oid.to_owned(),
            tree: tree.to_owned(),
            bundle,
            test_digest,
            verdict_digest,
        })
    }

    pub fn run(&self) -> &str {
        &self.run
    }

    pub fn source_oid(&self) -> &str {
        &self.oid
    }
    pub fn source_tree(&self) -> &str {
        &self.tree
    }
    pub fn bundle_hash(&self) -> Hash {
        self.bundle
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "chinwag-review/v2\nrepo=emunlabs/chinwag\nrun={}\noid={}\ntree={}\nbundle_blake3={}\ntest_result=pass\ntest_sha256={}\nverdict_sha256={}\n",
            self.run, self.oid, self.tree, hex(self.bundle.as_bytes()), hex(&self.test_digest), hex(&self.verdict_digest)
        ).into_bytes()
    }
}

pub struct SignedReview {
    statement: Statement,
    reviewer: EndpointId,
    signature: Signature,
}

/// Only successful strict signature and evidence verification constructs this
/// type. Downstream publication still has its own policy and acceptance gate.
pub struct VerifiedReview {
    statement: Statement,
    reviewer: EndpointId,
}

impl SignedReview {
    pub fn sign(statement: Statement, identity: &Identity) -> Self {
        let signature = identity.secret_key().sign(&statement.canonical_bytes());
        Self {
            statement,
            reviewer: identity.endpoint_id(),
            signature,
        }
    }

    /// Parse an untrusted wire claim; this constructor grants no verification.
    pub fn from_parts(statement: Statement, reviewer: EndpointId, signature: [u8; 64]) -> Self {
        Self {
            statement,
            reviewer,
            signature: Signature::from_bytes(&signature),
        }
    }

    pub fn signature_bytes(&self) -> [u8; 64] {
        self.signature.to_bytes()
    }

    pub fn verify(
        &self,
        pinned_reviewer: EndpointId,
        expected: &Statement,
    ) -> Result<VerifiedReview, Error> {
        if self.reviewer != pinned_reviewer {
            return Err(Error::Reviewer);
        }
        if &self.statement != expected {
            return Err(Error::Evidence);
        }
        pinned_reviewer
            .verify(&self.statement.canonical_bytes(), &self.signature)
            .map_err(|_| Error::Signature)?;
        Ok(VerifiedReview {
            statement: self.statement.clone(),
            reviewer: self.reviewer,
        })
    }
}

impl VerifiedReview {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn reviewer(&self) -> EndpointId {
        self.reviewer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement() -> Statement {
        Statement::passed(
            &"c".repeat(64),
            &"1".repeat(40),
            &"2".repeat(40),
            Hash::new(b"synthetic bundle"),
            [3; 32],
            [4; 32],
        )
        .unwrap()
    }

    #[test]
    fn only_the_pinned_git_and_iroh_identity_can_verify_a_review() {
        let architect = Identity::test_identity([0x11; 32]);
        let other = Identity::test_identity([0x22; 32]);
        let statement = statement();
        let signed = SignedReview::sign(statement.clone(), &architect);
        let verified = signed.verify(architect.endpoint_id(), &statement).unwrap();
        assert_eq!(
            verified.reviewer().as_bytes(),
            &architect.ssh_public_bytes()
        );
        assert_eq!(verified.statement(), &statement);
        assert!(matches!(
            signed.verify(other.endpoint_id(), &statement),
            Err(Error::Reviewer)
        ));
        let forged = SignedReview::from_parts(
            statement.clone(),
            architect.endpoint_id(),
            SignedReview::sign(statement.clone(), &other).signature_bytes(),
        );
        assert!(matches!(
            forged.verify(architect.endpoint_id(), &statement),
            Err(Error::Signature)
        ));
    }

    #[test]
    fn every_candidate_and_evidence_field_is_authenticated() {
        let architect = Identity::test_identity([0x11; 32]);
        let original = statement();
        let signed = SignedReview::sign(original.clone(), &architect);
        let mut variants = Vec::new();
        let mut run = original.clone();
        run.run = "d".repeat(64);
        variants.push(run);
        let mut oid = original.clone();
        oid.oid = "5".repeat(40);
        variants.push(oid);
        let mut tree = original.clone();
        tree.tree = "6".repeat(40);
        variants.push(tree);
        let mut bundle = original.clone();
        bundle.bundle = Hash::new(b"different bundle");
        variants.push(bundle);
        let mut tests = original.clone();
        tests.test_digest = [7; 32];
        variants.push(tests);
        let mut verdict = original.clone();
        verdict.verdict_digest = [8; 32];
        variants.push(verdict);
        for changed in variants {
            assert!(matches!(
                signed.verify(architect.endpoint_id(), &changed),
                Err(Error::Evidence)
            ));
            let altered_wire = SignedReview::from_parts(
                changed.clone(),
                architect.endpoint_id(),
                signed.signature_bytes(),
            );
            assert!(matches!(
                altered_wire.verify(architect.endpoint_id(), &changed),
                Err(Error::Signature)
            ));
        }
        let bytes = original.canonical_bytes();
        assert!(bytes.starts_with(b"chinwag-review/v2\nrepo=emunlabs/chinwag\n"));
        assert!(bytes.ends_with(b"\n"));
        assert!(bytes.len() < 1024);
    }

    #[test]
    fn object_ids_are_full_unambiguous_and_use_the_same_hash_format() {
        for oid in [
            "HEAD",
            "../main",
            "1\n2",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(matches!(
                Statement::passed(
                    &"c".repeat(64),
                    oid,
                    &"2".repeat(40),
                    Hash::new(b"bundle"),
                    [3; 32],
                    [4; 32]
                ),
                Err(Error::ObjectId)
            ));
        }
        assert!(
            Statement::passed(
                &"c".repeat(64),
                &"1".repeat(64),
                &"2".repeat(64),
                Hash::new(b"bundle"),
                [3; 32],
                [4; 32]
            )
            .is_ok()
        );
        assert!(matches!(
            Statement::passed(
                &"c".repeat(64),
                &"1".repeat(64),
                &"2".repeat(40),
                Hash::new(b"bundle"),
                [3; 32],
                [4; 32]
            ),
            Err(Error::ObjectId)
        ));
    }
    #[test]
    fn run_is_exact_lowercase_hex_and_part_of_the_statement() {
        for run in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "é".repeat(32),
        ] {
            assert!(matches!(
                Statement::passed(
                    &run,
                    &"1".repeat(40),
                    &"2".repeat(40),
                    Hash::new(b"bundle"),
                    [3; 32],
                    [4; 32]
                ),
                Err(Error::Run)
            ));
        }
        assert_eq!(statement().run(), "c".repeat(64));
        let bytes = statement().canonical_bytes();
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains(&format!("\nrun={}\n", "c".repeat(64)))
        );
    }
}
