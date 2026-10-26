#![forbid(unsafe_code)]

use ssh_key::{PrivateKey, private::Ed25519Keypair};
use zeroize::Zeroizing;

#[cfg(unix)]
mod storage;
#[cfg(unix)]
pub use storage::PrivateDirectory;

const MAX_KEY_BYTES: usize = 16_384;

/// Secret material has no Debug, Clone, or byte-export interface.
pub struct SigningSecret {
    private: PrivateKey,
    public: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Entropy,
    Proof,
    Directory,
    Name,
    Exists,
    Create,
    /// Creation succeeded. A file or directory may remain; do not overwrite or retry it.
    CreatedButUnconfirmed,
    Open,
    File,
    Read,
    Format,
    PublicMismatch,
}

impl Error {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Entropy => "signing_entropy",
            Self::Proof => "signing_proof",
            Self::Directory => "signing_directory",
            Self::Name => "signing_name",
            Self::Exists => "signing_exists",
            Self::Create => "signing_create",
            Self::CreatedButUnconfirmed => "signing_created_but_unconfirmed",
            Self::Open => "signing_open",
            Self::File => "signing_file",
            Self::Read => "signing_read",
            Self::Format => "signing_format",
            Self::PublicMismatch => "signing_public_mismatch",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.code())
    }
}

impl std::error::Error for Error {}

mod proof;
pub use proof::GitNamespaceProof;

/// Validate the existing supported SSH signing principal grammar without key generation.
#[cfg(unix)]
pub fn validate_principal(value: &str) -> Result<(), Error> {
    fn label(value: &str, local: bool) -> bool {
        !value.is_empty()
            && !value.starts_with('.')
            && !value.ends_with('.')
            && !value.contains("..")
            && !value.starts_with('-')
            && !value.ends_with('-')
            && value.chars().all(|char| {
                char.is_ascii_alphanumeric()
                    || char == '.'
                    || char == '-'
                    || (local && (char == '_' || char == '+'))
            })
    }
    let mut parts = value.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None)
            if label(local, true) && label(domain, false) && domain.contains('.') =>
        {
            Ok(())
        }
        _ => Err(Error::Name),
    }
}

#[cfg(unix)]
fn allowed_signers_line(principal: &str, secret: &SigningSecret) -> Result<String, Error> {
    validate_principal(principal)?;
    if principal.len() > MAX_KEY_BYTES {
        return Err(Error::Format);
    }
    let public = secret.public_openssh()?;
    let parts: Vec<_> = public.split_ascii_whitespace().collect();
    if parts.len() != 2
        || parts[0] != "ssh-ed25519"
        || public != format!("{} {}", parts[0], parts[1])
    {
        return Err(Error::Format);
    }
    let line = format!("{principal} namespaces=\"git\" {public}\n");
    if line.len() > MAX_KEY_BYTES {
        return Err(Error::Format);
    }
    Ok(line)
}

impl SigningSecret {
    /// Obtain a seed from the operating system. Any entropy error fails closed.
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with(getrandom::fill)
    }

    fn generate_with(
        fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
    ) -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        fill(&mut seed[..]).map_err(|_| Error::Entropy)?;
        Ok(Self::from_seed(seed))
    }

    /// The caller supplies entropy. This primitive does not generate a seed.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        let pair = Ed25519Keypair::from_seed(&seed);
        let public = pair.public.0;
        Self {
            private: PrivateKey::from(pair),
            public,
        }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }

    pub fn public_openssh(&self) -> Result<String, Error> {
        self.private
            .public_key()
            .to_openssh()
            .map_err(|_| Error::Format)
    }

    #[cfg(unix)]
    fn from_encoded(encoded: &[u8], expected: &[u8; 32]) -> Result<Self, Error> {
        let private = PrivateKey::from_openssh(encoded).map_err(|_| Error::Format)?;
        if private.is_encrypted() {
            return Err(Error::Format);
        }
        let pair = private.key_data().ed25519().ok_or(Error::Format)?;
        let seed = Zeroizing::new(pair.private.to_bytes());
        let derived = Ed25519Keypair::from_seed(&seed);
        if derived.public.0 != pair.public.0 || &pair.public.0 != expected {
            return Err(Error::PublicMismatch);
        }
        let public = pair.public.0;
        Ok(Self { private, public })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_entropy_failure_returns_no_signer() {
        let result = SigningSecret::generate_with(|seed| {
            assert_eq!(seed.len(), 32);
            seed[..16].fill(0xA5);
            Err(getrandom::Error::UNSUPPORTED)
        });
        assert!(matches!(result, Err(Error::Entropy)));
        assert_eq!(Error::Entropy.to_string(), "signing_entropy");
    }

    #[test]
    fn complete_entropy_is_used_for_the_signing_identity() {
        let key = SigningSecret::generate_with(|seed| {
            assert_eq!(seed.len(), 32);
            seed.fill(0xA5);
            Ok(())
        })
        .unwrap();
        let expected = SigningSecret::from_seed(Zeroizing::new([0xA5; 32]));
        assert_eq!(key.public_bytes(), expected.public_bytes());
    }
}

#[cfg(target_os = "macos")]
mod repo;
#[cfg(target_os = "macos")]
pub use repo::{ConfigPreimageConstraint, ConfigTransaction, Receipt, RepoSigningRequest, TxState};

#[cfg(target_os = "macos")]
mod init;
#[cfg(target_os = "macos")]
pub use init::{InitCoordinator, InitFailure, InitMaterial, InitPaths, InitProgress, InitReceipt};
