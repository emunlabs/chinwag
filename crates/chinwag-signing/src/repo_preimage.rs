//! Optional validation constraints. These observations grant no owner or cleanup authority.
use super::Receipt;

/// Require the original transaction to capture the supplied configuration preimage.
/// The original lock and transaction still establish all actual install/release authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigPreimageConstraint {
    repo: (i32, u64),
    git: (i32, u64),
    config: (i32, u64),
    sha256: [u8; 32],
}
impl ConfigPreimageConstraint {
    /// A restriction only; callers cannot turn these observations into a transaction.
    pub fn new(repo: (i32, u64), git: (i32, u64), config: (i32, u64), sha256: [u8; 32]) -> Self {
        Self {
            repo,
            git,
            config,
            sha256,
        }
    }
    pub(super) fn accepts(&self, actual: &Receipt) -> bool {
        self.repo == (actual.repo_dev, actual.repo_ino)
            && self.git == (actual.git_dev, actual.git_ino)
            && self.config == (actual.config_dev, actual.config_ino)
            && self.sha256 == actual.snapshot_sha256
    }
}
