use std::{fs::File, io::Read, path::Path};

use iroh::{EndpointId, SecretKey};
use ssh_key::PrivateKey;
use zeroize::Zeroizing;

const MAX_KEY_FILE_BYTES: u64 = 16_384;

/// The same Ed25519 seed encoded by the Git OpenSSH signing file.
/// No second transport key is generated. Secret-bearing types have no Debug.
pub struct Identity {
    key: SecretKey,
    public: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("cannot read the SSH signing key")]
    Read,
    #[error("SSH signing key must be a private regular file no larger than 16 KiB")]
    File,
    #[error("an unencrypted Ed25519 OpenSSH signing key is required")]
    Format,
    #[error("SSH and iroh public identities do not match")]
    Mismatch,
}

impl Identity {
    pub fn from_ssh_signing_file(path: &Path) -> Result<Self, IdentityError> {
        let file = File::open(path).map_err(|_| IdentityError::Read)?;
        let metadata = file.metadata().map_err(|_| IdentityError::Read)?;
        if !metadata.is_file() || metadata.len() > MAX_KEY_FILE_BYTES {
            return Err(IdentityError::File);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.permissions().mode() & 0o077 != 0
                || metadata.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(IdentityError::File);
            }
        }
        let mut encoded = Zeroizing::new(Vec::new());
        file.take(MAX_KEY_FILE_BYTES + 1)
            .read_to_end(&mut encoded)
            .map_err(|_| IdentityError::Read)?;
        if encoded.len() as u64 > MAX_KEY_FILE_BYTES {
            return Err(IdentityError::File);
        }
        let parsed =
            PrivateKey::from_openssh(encoded.as_slice()).map_err(|_| IdentityError::Format)?;
        if parsed.is_encrypted() {
            return Err(IdentityError::Format);
        }
        let pair = parsed.key_data().ed25519().ok_or(IdentityError::Format)?;
        let seed = Zeroizing::new(pair.private.to_bytes());
        let key = SecretKey::from_bytes(&seed);
        let public = pair.public.0;
        if key.public().as_bytes() != &public {
            return Err(IdentityError::Mismatch);
        }
        Ok(Self { key, public })
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.key.public()
    }

    pub fn ssh_public_bytes(&self) -> [u8; 32] {
        self.public
    }

    /// Sign only a validated claim for this identity. No secret or general
    /// signing capability leaves the identity boundary.
    pub fn sign_claim(
        &self,
        request: chinwag_claim::ClaimRequestUnsigned,
    ) -> Result<chinwag_claim::SignedClaimRequest, chinwag_claim::ClaimError> {
        request.validate()?;
        let actor: String = self
            .public
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if request.actor != actor {
            return Err(chinwag_claim::ClaimError::Identity);
        }
        let bytes = request.canonical_bytes()?;
        let signature = self.key.sign(&bytes).to_bytes();
        Ok(chinwag_claim::SignedClaimRequest {
            request,
            signature: signature.iter().map(|byte| format!("{byte:02x}")).collect(),
        })
    }

    pub(crate) fn secret_key(&self) -> SecretKey {
        self.key.clone()
    }

    pub fn iroh_secret_key(&self) -> SecretKey {
        self.key.clone()
    }

    #[cfg(test)]
    pub(crate) fn test_identity(seed: [u8; 32]) -> Self {
        let key = SecretKey::from_bytes(&seed);
        Self {
            public: *key.public().as_bytes(),
            key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{LineEnding, private::Ed25519Keypair};

    #[test]
    fn openssh_and_iroh_share_the_same_seed_and_reject_public_key_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let pair = Ed25519Keypair::from_seed(&[0x11; 32]);
        let expected = pair.public.0;
        let key = PrivateKey::from(pair);
        key.write_openssh_file(&path, LineEnding::LF).unwrap();
        let identity = Identity::from_ssh_signing_file(&path).unwrap();
        assert_eq!(identity.endpoint_id().as_bytes(), &expected);
        assert_eq!(identity.ssh_public_bytes(), expected);
        let public_path = directory.path().join("public");
        key.public_key().write_openssh_file(&public_path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&public_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            Identity::from_ssh_signing_file(&public_path),
            Err(IdentityError::Format)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                Identity::from_ssh_signing_file(&path),
                Err(IdentityError::File)
            ));
        }
    }
    fn claim_for(identity: &Identity) -> chinwag_claim::ClaimRequestUnsigned {
        chinwag_claim::ClaimRequestUnsigned {
            claim_id: "88".repeat(32),
            actor: identity
                .ssh_public_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            session: "22".repeat(32),
            nonce: "33".repeat(32),
            pr: chinwag_claim::Pr::Pr01,
            files: vec!["crates/chinwag-seed/src/main.rs".to_owned()],
            expected_revision: 0,
            issued: 1000,
            expiry: 1060,
        }
    }

    #[test]
    fn typed_claim_signature_uses_transport_identity_and_rejects_another_actor() {
        let identity = Identity::test_identity([0x11; 32]);
        let signed = identity.sign_claim(claim_for(&identity)).unwrap();
        let public = ed25519_dalek::VerifyingKey::from_bytes(&identity.ssh_public_bytes()).unwrap();
        signed.verify_actor(&public).unwrap();
        assert_eq!(identity.endpoint_id().as_bytes(), public.as_bytes());
        let other = Identity::test_identity([0x12; 32]);
        assert_eq!(
            identity.sign_claim(claim_for(&other)),
            Err(chinwag_claim::ClaimError::Identity)
        );
    }

    #[test]
    fn typed_claim_signature_rejects_protected_paths_and_bad_nonce_before_signing() {
        let identity = Identity::test_identity([0x11; 32]);
        let mut request = claim_for(&identity);
        request.files = vec![".git/config".to_owned()];
        assert_eq!(
            identity.sign_claim(request),
            Err(chinwag_claim::ClaimError::PathRejected)
        );
        let mut request = claim_for(&identity);
        request.nonce = "not-a-nonce".to_owned();
        assert_eq!(
            identity.sign_claim(request),
            Err(chinwag_claim::ClaimError::Noncanonical)
        );
    }
}
