//! Immutable bundle expectation: object ids, BLAKE3, and one ed25519 signer line.
//!
//! Operator data only. This is not a review, a Cargo result, a write lease, or membership.
//! Git intake and directories stay outside this module. There is no child process here.

pub const MAX_BUNDLE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SIGNER_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitCandidate {
    oid: String,
    tree: String,
    builder: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleExpectation {
    candidate: GitCandidate,
    hash: [u8; 32],
    size: u64,
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("bundle object ids must be full lowercase hex of one width")]
    Candidate,
    #[error("bundle size is outside 1..=32MiB")]
    Size,
    #[error("bundle bytes do not match the expected BLAKE3 hash")]
    Hash,
    #[error("allowed signer line is not the expected ed25519 key")]
    Signer,
}

fn object_id(value: &str) -> Result<(), Error> {
    if matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(Error::Candidate)
    }
}

impl GitCandidate {
    pub fn new(oid: &str, tree: &str, builder: [u8; 32]) -> Result<Self, Error> {
        object_id(oid)?;
        object_id(tree)?;
        if oid.len() != tree.len() {
            return Err(Error::Candidate);
        }
        Ok(Self {
            oid: oid.to_owned(),
            tree: tree.to_owned(),
            builder,
        })
    }

    pub fn oid(&self) -> &str {
        &self.oid
    }

    pub fn tree(&self) -> &str {
        &self.tree
    }

    pub fn builder(&self) -> [u8; 32] {
        self.builder
    }

    pub fn object_format(&self) -> &'static str {
        if self.oid.len() == 64 {
            "sha256"
        } else {
            "sha1"
        }
    }

    pub fn signer_snapshot(&self, text: &str) -> Result<String, Error> {
        let line = one_signer_line(text)?;
        let mut fields = line.split_whitespace();
        let principal = fields.next().ok_or(Error::Signer)?;
        let algorithm = fields.next().ok_or(Error::Signer)?;
        let encoded = fields.next().ok_or(Error::Signer)?;
        if fields.next().is_some() || !principal_ok(principal) || algorithm != "ssh-ed25519" {
            return Err(Error::Signer);
        }
        let parsed = ssh_key::PublicKey::from_openssh(&format!("{algorithm} {encoded}"))
            .map_err(|_| Error::Signer)?;
        if parsed
            .key_data()
            .ed25519()
            .is_some_and(|key| key.0 == self.builder)
        {
            Ok(format!("{principal} {algorithm} {encoded}\n"))
        } else {
            Err(Error::Signer)
        }
    }
}

impl BundleExpectation {
    pub fn new(
        oid: &str,
        tree: &str,
        hash: [u8; 32],
        size: u64,
        builder: [u8; 32],
    ) -> Result<Self, Error> {
        Self::from_candidate(GitCandidate::new(oid, tree, builder)?, hash, size)
    }

    pub fn from_candidate(
        candidate: GitCandidate,
        hash: [u8; 32],
        size: u64,
    ) -> Result<Self, Error> {
        if !(1..=MAX_BUNDLE_BYTES as u64).contains(&size) {
            return Err(Error::Size);
        }
        Ok(Self {
            candidate,
            hash,
            size,
        })
    }

    pub fn candidate(&self) -> &GitCandidate {
        &self.candidate
    }

    pub fn oid(&self) -> &str {
        self.candidate.oid()
    }

    pub fn tree(&self) -> &str {
        self.candidate.tree()
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn builder(&self) -> [u8; 32] {
        self.candidate.builder()
    }

    pub fn object_format(&self) -> &'static str {
        self.candidate.object_format()
    }

    pub fn matches_blob(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
            return Err(Error::Size);
        }
        if u64::try_from(bytes.len()).ok() != Some(self.size) {
            return Err(Error::Size);
        }
        if blake3::hash(bytes).as_bytes() != &self.hash {
            return Err(Error::Hash);
        }
        Ok(())
    }

    pub fn signer_snapshot(&self, text: &str) -> Result<String, Error> {
        self.candidate.signer_snapshot(text)
    }
}

fn one_signer_line(text: &str) -> Result<&str, Error> {
    if text.len() > MAX_SIGNER_BYTES || text.bytes().any(|byte| byte == b'\r') {
        return Err(Error::Signer);
    }
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.is_empty() || body.as_bytes().contains(&b'\n') {
        Err(Error::Signer)
    } else {
        Ok(body)
    }
}

fn principal_ok(principal: &str) -> bool {
    !principal.is_empty()
        && principal
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILDER: [u8; 32] = [
        223, 118, 118, 168, 104, 15, 6, 241, 205, 219, 81, 167, 147, 190, 154, 7, 160, 208, 34, 99,
        140, 178, 94, 190, 104, 29, 212, 35, 40, 134, 121, 49,
    ];
    const BUILDER_LINE: &str = "builder-agent@chinwag.sh ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN92dqhoDwbxzdtRp5O+mgeg0CJjjLJevmgd1CMohnkx";
    const ARCHITECT_LINE: &str = "architect-agent@chinwag.sh ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGPkT7tQVOBzB5OyvmHa8gO5EsfMV3f4brv+X3OwlsPQ";
    const BUILDER_KEY: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIN92dqhoDwbxzdtRp5O+mgeg0CJjjLJevmgd1CMohnkx";

    fn expectation(width: usize, size: u64) -> BundleExpectation {
        BundleExpectation::new(
            &"a".repeat(width),
            &"b".repeat(width),
            [9; 32],
            size,
            BUILDER,
        )
        .unwrap()
    }

    #[test]
    fn widths_select_object_format_and_bounds_reject() {
        assert_eq!(expectation(40, 1).object_format(), "sha1");
        assert_eq!(
            expectation(64, MAX_BUNDLE_BYTES as u64).object_format(),
            "sha256"
        );
        assert_eq!(expectation(40, 1).builder(), BUILDER);
        assert_eq!(expectation(40, 1).hash(), [9; 32]);
        let hash = [9; 32];
        for oid in [
            "HEAD",
            "../main",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "abcdef\n",
            "--upload-pack=evil",
            "deadbeef^{commit}",
        ] {
            assert_eq!(
                BundleExpectation::new(oid, &"b".repeat(40), hash, 1, BUILDER),
                Err(Error::Candidate)
            );
        }
        assert_eq!(
            BundleExpectation::new(&"a".repeat(39), &"b".repeat(40), hash, 1, BUILDER),
            Err(Error::Candidate)
        );
        assert_eq!(
            BundleExpectation::new(&"a".repeat(64), &"b".repeat(40), hash, 1, BUILDER),
            Err(Error::Candidate)
        );
        assert_eq!(
            BundleExpectation::new(&"a".repeat(40), &"b".repeat(40), hash, 0, BUILDER),
            Err(Error::Size)
        );
        assert_eq!(
            BundleExpectation::new(
                &"a".repeat(40),
                &"b".repeat(40),
                hash,
                MAX_BUNDLE_BYTES as u64 + 1,
                BUILDER,
            ),
            Err(Error::Size)
        );
    }

    #[test]
    fn matches_blob_requires_exact_size_then_blake3() {
        let bytes = b"tiny-bundle";
        let hash = *blake3::hash(bytes).as_bytes();
        let expectation = BundleExpectation::new(
            &"c".repeat(40),
            &"d".repeat(40),
            hash,
            bytes.len() as u64,
            BUILDER,
        )
        .unwrap();
        assert_eq!(expectation.matches_blob(bytes), Ok(()));
        let mut flipped = *bytes;
        flipped[0] ^= 1;
        assert_eq!(expectation.matches_blob(&flipped), Err(Error::Hash));
        assert_eq!(
            expectation.matches_blob(&bytes[..bytes.len() - 1]),
            Err(Error::Size)
        );
        assert_eq!(expectation.matches_blob(b""), Err(Error::Size));
        assert_eq!(
            expectation.matches_blob(&vec![0; MAX_BUNDLE_BYTES + 1]),
            Err(Error::Size)
        );
    }

    #[test]
    fn signer_snapshot_keeps_only_the_expected_builder_line() {
        let expectation = expectation(40, 1);
        let canonical = format!("{BUILDER_LINE}\n");
        assert_eq!(
            expectation.signer_snapshot(BUILDER_LINE).unwrap(),
            canonical
        );
        assert_eq!(expectation.signer_snapshot(&canonical).unwrap(), canonical);
        let rejected = [
            ARCHITECT_LINE.to_owned(),
            format!("cert-authority {BUILDER_LINE}"),
            format!("{BUILDER_LINE}\n{BUILDER_LINE}\n"),
            format!("{BUILDER_LINE} # note"),
            format!("* ssh-ed25519 {BUILDER_KEY}"),
            format!("builder-agent@chinwag.sh ssh-ed25519-cert-v01@openssh.com {BUILDER_KEY}"),
            format!("builder-agent@chinwag.sh,other ssh-ed25519 {BUILDER_KEY}"),
            format!("{BUILDER_LINE}\r\n"),
            "# comment\n".to_owned(),
            "\n".to_owned(),
            String::new(),
        ];
        for line in &rejected {
            assert_eq!(expectation.signer_snapshot(line), Err(Error::Signer));
        }
    }

    #[test]
    fn git_candidate_is_checked_before_any_bundle_bytes() {
        let candidate = GitCandidate::new(&"ab".repeat(32), &"cd".repeat(32), BUILDER).unwrap();
        assert_eq!(candidate.object_format(), "sha256");
        assert_eq!(candidate.builder(), BUILDER);
        assert_eq!(
            candidate.signer_snapshot(BUILDER_LINE).unwrap(),
            format!("{BUILDER_LINE}\n")
        );
        assert_eq!(
            candidate.signer_snapshot(ARCHITECT_LINE),
            Err(Error::Signer)
        );
        assert_eq!(
            GitCandidate::new("HEAD", &"b".repeat(40), BUILDER),
            Err(Error::Candidate)
        );
        let expectation =
            BundleExpectation::from_candidate(candidate.clone(), [7; 32], 12).unwrap();
        assert_eq!(expectation.candidate(), &candidate);
        assert_eq!(expectation.oid(), candidate.oid());
        assert_eq!(expectation.tree(), candidate.tree());
        assert_eq!(expectation.hash(), [7; 32]);
        assert_eq!(expectation.size(), 12);
        assert_eq!(
            BundleExpectation::from_candidate(candidate.clone(), [7; 32], 0),
            Err(Error::Size)
        );
        assert_eq!(
            BundleExpectation::from_candidate(candidate, [7; 32], MAX_BUNDLE_BYTES as u64 + 1),
            Err(Error::Size)
        );
    }
}
