use chinwag_signing::{GitNamespaceProof, SigningSecret};
use ssh_key::{PublicKey, SshSig};
use zeroize::Zeroizing;

const NAMESPACE: &str = "git";
const CHALLENGE: &str = "chinwag-signing-selftest-v1";

fn seed(byte: u8) -> SigningSecret {
    SigningSecret::from_seed(Zeroizing::new([byte; 32]))
}

#[test]
fn a5_proof_verifies_through_an_independent_parser() {
    let secret = seed(0xA5);
    let proof: GitNamespaceProof = secret.prove_git_namespace().unwrap();
    assert_eq!(proof.public, secret.public_bytes());
    assert_eq!(proof.public_openssh, secret.public_openssh().unwrap());
    assert_eq!(proof.namespace, NAMESPACE);
    assert_eq!(proof.challenge, CHALLENGE);
    assert!(proof.armored.starts_with("-----BEGIN SSH SIGNATURE-----\n"));
    let public = PublicKey::from_openssh(&proof.public_openssh).unwrap();
    let signature = SshSig::from_pem(&proof.armored).unwrap();
    public
        .verify(NAMESPACE, CHALLENGE.as_bytes(), &signature)
        .unwrap();
}

#[test]
fn independent_verifier_rejects_wrong_key_challenge_and_namespace() {
    let proof = seed(0xA5).prove_git_namespace().unwrap();
    let public = PublicKey::from_openssh(&proof.public_openssh).unwrap();
    let signature = SshSig::from_pem(&proof.armored).unwrap();
    let wrong = PublicKey::from_openssh(&seed(0xA6).public_openssh().unwrap()).unwrap();
    assert!(
        wrong
            .verify(NAMESPACE, CHALLENGE.as_bytes(), &signature)
            .is_err()
    );
    assert!(
        public
            .verify(NAMESPACE, b"chinwag-signing-selftest-v2", &signature)
            .is_err()
    );
    assert!(
        public
            .verify("not-git", CHALLENGE.as_bytes(), &signature)
            .is_err()
    );
}
