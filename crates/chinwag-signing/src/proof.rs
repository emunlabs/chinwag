use ssh_key::{HashAlg, LineEnding};

use super::{Error, SigningSecret};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitNamespaceProof {
    pub public: [u8; 32],
    pub public_openssh: String,
    pub namespace: &'static str,
    pub challenge: &'static str,
    pub armored: String,
}

impl SigningSecret {
    pub fn prove_git_namespace(&self) -> Result<GitNamespaceProof, Error> {
        const NAMESPACE: &str = "git";
        const CHALLENGE: &str = "chinwag-signing-selftest-v1";
        let signature = self
            .private
            .sign(NAMESPACE, HashAlg::Sha512, CHALLENGE.as_bytes())
            .map_err(|_| Error::Proof)?;
        self.private
            .public_key()
            .verify(NAMESPACE, CHALLENGE.as_bytes(), &signature)
            .map_err(|_| Error::Proof)?;
        let armored = signature.to_pem(LineEnding::LF).map_err(|_| Error::Proof)?;
        let public_openssh = self.public_openssh().map_err(|_| Error::Proof)?;
        Ok(GitNamespaceProof {
            public: self.public_bytes(),
            public_openssh,
            namespace: NAMESPACE,
            challenge: CHALLENGE,
            armored,
        })
    }
}
