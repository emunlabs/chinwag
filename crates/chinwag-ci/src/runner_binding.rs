// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Join independently verified origin and GitHub evidence with runner key PoP.
//! This is not K2, replay consumption, task-start or repair authorization. The
//! server must issue and consume the exact fresh challenge atomically. Claimed
//! transport keys additionally require their actual native TLS handshakes.

use crate::{intent::VerifiedIntent, oidc::VerifiedWorkflow};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub struct RunnerPublicKeys {
    pub signing_ed25519: [u8; 32],
    pub agent_transport_ed25519: [u8; 32],
    pub archive_transport_ed25519: [u8; 32],
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    #[error("invalid runner public keys, challenge, or execution identifiers")]
    Input,
    #[error("runner proof combines different intent, policy, keys, or workflow execution")]
    Scope,
    #[error("runner signing-key proof of possession is invalid")]
    Signature,
    #[error("runner evidence is outside its finite validity interval")]
    Lifetime,
}

fn validate(
    keys: RunnerPublicKeys,
    challenge: &[u8; 32],
    run_id: u64,
    attempt: u32,
) -> Result<(), BindingError> {
    if *challenge == [0; 32]
        || run_id == 0
        || attempt == 0
        || keys.agent_transport_ed25519 == keys.archive_transport_ed25519
        || keys.signing_ed25519 == keys.agent_transport_ed25519
        || keys.signing_ed25519 == keys.archive_transport_ed25519
    {
        return Err(BindingError::Input);
    }
    for key in [
        keys.signing_ed25519,
        keys.agent_transport_ed25519,
        keys.archive_transport_ed25519,
    ] {
        if VerifyingKey::from_bytes(&key)
            .map_err(|_| BindingError::Input)?
            .is_weak()
        {
            return Err(BindingError::Input);
        }
    }
    Ok(())
}

fn fields(domain: &str, values: &[String]) -> Vec<u8> {
    format!(
        "{domain}|{}",
        values
            .iter()
            .map(|value| format!("{}:{value}", value.len()))
            .collect::<Vec<_>>()
            .join("|")
    )
    .into_bytes()
}

/// Audience requested from GitHub BEFORE the token is issued. GitHub signs the
/// audience string but does not validate this application commitment itself.
pub fn audience_for(
    intent: &VerifiedIntent,
    keys: RunnerPublicKeys,
    challenge: [u8; 32],
    run_id: u64,
    attempt: u32,
) -> Result<String, BindingError> {
    validate(keys, &challenge, run_id, attempt)?;
    let bytes = fields(
        "chinwag-ci-runner-audience-v1",
        &[
            intent.original_id().into(),
            hex::encode(intent.original_digest()),
            intent.initiating_instance().into(),
            intent.spec().repository_id.to_string(),
            intent.spec().source_commit.clone(),
            intent.spec().workflow_ref.clone(),
            intent.spec().workflow_commit.clone(),
            intent.spec().delivery_profile_sha256.clone(),
            intent.spec().command_sha256.clone(),
            hex::encode(keys.signing_ed25519),
            hex::encode(keys.agent_transport_ed25519),
            hex::encode(keys.archive_transport_ed25519),
            hex::encode(challenge),
            run_id.to_string(),
            attempt.to_string(),
        ],
    );
    Ok(format!(
        "urn:chinwag:ci-runner:v1:{}",
        hex::encode(Sha256::digest(bytes))
    ))
}

/// Domain-separated data the ephemeral runner signs. A client may verify its
/// own issuer token before signing; the server independently verifies it against
/// trusted dispatch metadata and must not accept the client's verification flag.
pub fn proof_payload(
    intent: &VerifiedIntent,
    workflow: &VerifiedWorkflow,
    keys: RunnerPublicKeys,
    challenge: [u8; 32],
) -> Result<Vec<u8>, BindingError> {
    if workflow.repository_id() != intent.spec().repository_id
        || workflow.source_commit() != intent.spec().source_commit
        || workflow.workflow_ref() != intent.spec().workflow_ref
        || workflow.workflow_commit() != intent.spec().workflow_commit
        || workflow.audience()
            != audience_for(
                intent,
                keys,
                challenge,
                workflow.run_id(),
                workflow.run_attempt(),
            )?
    {
        return Err(BindingError::Scope);
    }
    Ok(fields(
        "chinwag-ci-runner-pop-v1",
        &[
            workflow.audience().into(),
            hex::encode(workflow.token_sha256()),
            intent.original_id().into(),
            hex::encode(intent.original_digest()),
            workflow.run_id().to_string(),
            workflow.run_attempt().to_string(),
        ],
    ))
}

pub struct VerifiedRunnerBinding {
    initiating_instance: String,
    intent_digest: [u8; 32],
    token_sha256: [u8; 32],
    token_id: String,
    audience: String,
    run_id: u64,
    attempt: u32,
    expires_unix: u64,
    keys: RunnerPublicKeys,
}

impl VerifiedRunnerBinding {
    pub fn initiating_instance(&self) -> &str {
        &self.initiating_instance
    }
    pub fn intent_digest(&self) -> &[u8; 32] {
        &self.intent_digest
    }
    pub fn token_sha256(&self) -> &[u8; 32] {
        &self.token_sha256
    }
    pub fn token_id(&self) -> &str {
        &self.token_id
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn run_id(&self) -> u64 {
        self.run_id
    }
    pub fn run_attempt(&self) -> u32 {
        self.attempt
    }
    pub fn expires_unix(&self) -> u64 {
        self.expires_unix
    }
    pub fn signing_public_key(&self) -> &[u8; 32] {
        &self.keys.signing_ed25519
    }
    pub fn claimed_agent_transport_key(&self) -> &[u8; 32] {
        &self.keys.agent_transport_ed25519
    }
    pub fn claimed_archive_transport_key(&self) -> &[u8; 32] {
        &self.keys.archive_transport_ed25519
    }
}

pub fn verify_runner_proof(
    intent: VerifiedIntent,
    workflow: VerifiedWorkflow,
    keys: RunnerPublicKeys,
    challenge: [u8; 32],
    signature: [u8; 64],
    now_unix: u64,
) -> Result<VerifiedRunnerBinding, BindingError> {
    let expires_unix = intent.spec().expires_unix.min(workflow.expires_unix());
    if now_unix < intent.issued_unix()
        || now_unix < workflow.issued_unix()
        || now_unix < workflow.not_before_unix()
        || now_unix >= expires_unix
    {
        return Err(BindingError::Lifetime);
    }
    let payload = proof_payload(&intent, &workflow, keys, challenge)?;
    VerifyingKey::from_bytes(&keys.signing_ed25519)
        .map_err(|_| BindingError::Input)?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| BindingError::Signature)?;
    Ok(VerifiedRunnerBinding {
        initiating_instance: intent.initiating_instance().into(),
        intent_digest: *intent.original_digest(),
        token_sha256: *workflow.token_sha256(),
        token_id: workflow.token_id().into(),
        audience: workflow.audience().into(),
        run_id: workflow.run_id(),
        attempt: workflow.run_attempt(),
        expires_unix,
        keys,
    })
}
