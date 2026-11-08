// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Fresh workload identities live only inside this job process. No Debug,
//! Clone, serialization, seed export, existing-key loading or arbitrary-message
//! signing interface is provided. Enrollment/authority remains a separate gate.

use crate::{
    intent::VerifiedIntent,
    oidc::VerifiedWorkflow,
    runner_binding::{self, BindingError, RunnerPublicKeys},
    transport::{CiPair, TransferError},
};
use iroh::{EndpointId, SecretKey};
use zeroize::Zeroizing;

pub struct RunnerIdentity {
    signer: SecretKey,
    agent_transport: Option<SecretKey>,
    archive_transport: Option<SecretKey>,
    public: RunnerPublicKeys,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("CI workload identity entropy is unavailable")]
    Entropy,
    #[error("CI transport identity has already been used for a bind attempt")]
    AlreadyBound,
    #[error(transparent)]
    Binding(#[from] BindingError),
    #[error(transparent)]
    Transport(#[from] TransferError),
}

impl RunnerIdentity {
    pub fn generate() -> Result<Self, IdentityError> {
        Self::generate_with(getrandom::fill)
    }

    fn generate_with(
        mut fill: impl FnMut(&mut [u8]) -> Result<(), getrandom::Error>,
    ) -> Result<Self, IdentityError> {
        let mut make = || {
            let mut seed = Zeroizing::new([0_u8; 32]);
            fill(&mut seed[..]).map_err(|_| IdentityError::Entropy)?;
            Ok::<_, IdentityError>(SecretKey::from_bytes(&seed))
        };
        let signer = make()?;
        let agent = make()?;
        let archive = make()?;
        if signer.public() == agent.public()
            || signer.public() == archive.public()
            || agent.public() == archive.public()
        {
            return Err(IdentityError::Entropy);
        }
        let public = RunnerPublicKeys {
            signing_ed25519: *signer.public().as_bytes(),
            agent_transport_ed25519: *agent.public().as_bytes(),
            archive_transport_ed25519: *archive.public().as_bytes(),
        };
        Ok(Self {
            signer,
            agent_transport: Some(agent),
            archive_transport: Some(archive),
            public,
        })
    }

    pub fn public_keys(&self) -> RunnerPublicKeys {
        self.public
    }

    /// Signs only the typed admission PoP domain for THIS job's public keys.
    /// This is not a coordinator K2 or permission to execute/repair a task.
    pub fn sign_admission(
        &self,
        intent: &VerifiedIntent,
        workflow: &VerifiedWorkflow,
        challenge: [u8; 32],
    ) -> Result<[u8; 64], IdentityError> {
        let payload = runner_binding::proof_payload(intent, workflow, self.public, challenge)?;
        Ok(self.signer.sign(&payload).to_bytes())
    }

    /// A transport key is consumed before bind, even if the attempt fails or is
    /// cancelled. Never start two endpoints with one identity on the same relay,
    /// or silently regenerate/re-enroll after an uncertain attempt.
    pub async fn bind_agent_pair(
        &mut self,
        peer: EndpointId,
        selected: &str,
        approved: &str,
    ) -> Result<CiPair, IdentityError> {
        let key = self
            .agent_transport
            .take()
            .ok_or(IdentityError::AlreadyBound)?;
        Ok(CiPair::bind(key, peer, selected, approved).await?)
    }

    pub async fn bind_archive_pair(
        &mut self,
        peer: EndpointId,
        selected: &str,
        approved: &str,
    ) -> Result<CiPair, IdentityError> {
        let key = self
            .archive_transport
            .take()
            .ok_or(IdentityError::AlreadyBound)?;
        Ok(CiPair::bind(key, peer, selected, approved).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entropy_failure_never_returns_a_partial_or_reused_identity() {
        let mut calls = 0;
        let result = RunnerIdentity::generate_with(|seed| {
            calls += 1;
            seed[..16].fill(calls as u8);
            if calls == 2 {
                Err(getrandom::Error::UNSUPPORTED)
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(IdentityError::Entropy)));
        assert_eq!(calls, 2);
        assert!(matches!(
            RunnerIdentity::generate_with(|seed| {
                seed.fill(1);
                Ok(())
            }),
            Err(IdentityError::Entropy)
        ));
    }

    #[tokio::test]
    async fn a_failed_bind_cannot_create_a_second_endpoint_with_the_same_key() {
        let mut identity = RunnerIdentity::generate().unwrap();
        let public = identity.public_keys();
        let self_peer = EndpointId::from_bytes(&public.agent_transport_ed25519).unwrap();
        // A self peer is rejected before any network bind/relay operation.
        assert!(matches!(
            identity
                .bind_agent_pair(
                    self_peer,
                    "https://owned.invalid/",
                    "https://owned.invalid/"
                )
                .await,
            Err(IdentityError::Transport(TransferError::Policy))
        ));
        assert!(matches!(
            identity
                .bind_agent_pair(
                    self_peer,
                    "https://owned.invalid/",
                    "https://owned.invalid/"
                )
                .await,
            Err(IdentityError::AlreadyBound)
        ));
        assert_eq!(
            identity.public_keys().signing_ed25519,
            public.signing_ed25519
        );
    }
}
