// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Fixed-origin GitHub evidence reads, never workflow dispatch or auth repair.
//! TrustedDispatch values must come from the operator's authenticated dispatch
//! response/profile, not a run chosen by the incoming JWT or an API list order.

use crate::{
    intent::VerifiedIntent,
    oidc::{ExpectedWorkflow, GITHUB_JWKS, IssuerKeys},
};
use reqwest::{Client, Url};
use rustls_platform_verifier::BuilderVerifierExt;
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;
pub const REQUEST_BOUND: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("GitHub evidence TLS configuration is unavailable")]
    Tls,
    #[error("GitHub evidence request failed")]
    Network,
    #[error("GitHub evidence request exceeded its deadline")]
    Timeout,
    #[error("GitHub evidence endpoint returned HTTP status {0}")]
    Status(u16),
    #[error("GitHub evidence response is malformed or exceeds its bound")]
    Response,
    #[error("GitHub execution does not match the trusted dispatch and original intent")]
    Scope,
}
pub struct GithubEvidenceClient {
    client: Client,
}
fn network_error(error: reqwest::Error) -> EvidenceError {
    if error.is_timeout() {
        EvidenceError::Timeout
    } else {
        EvidenceError::Network
    }
}
#[derive(Clone, Copy)]
pub struct TrustedDispatch {
    pub run_id: u64,
    pub run_attempt: u32,
    pub repository_owner_id: u64,
    pub actor_id: u64,
    pub workflow_id: u64,
}
pub struct VerifiedRun {
    expected: TrustedDispatch,
    repository_id: u64,
    source_commit: String,
    workflow_ref: String,
    workflow_commit: String,
    subject: String,
}
impl VerifiedRun {
    pub fn expected_oidc<'a>(&'a self, audience: &'a str, now_unix: u64) -> ExpectedWorkflow<'a> {
        ExpectedWorkflow {
            audience,
            subject: &self.subject,
            repository_id: self.repository_id,
            repository_owner_id: self.expected.repository_owner_id,
            run_id: self.expected.run_id,
            run_attempt: self.expected.run_attempt,
            actor_id: self.expected.actor_id,
            source_commit: &self.source_commit,
            workflow_ref: &self.workflow_ref,
            workflow_commit: &self.workflow_commit,
            now_unix,
        }
    }
}
#[derive(Deserialize)]
struct Actor {
    id: u64,
}
#[derive(Deserialize)]
struct Repository {
    id: u64,
    full_name: String,
    owner: Actor,
}
#[derive(Deserialize)]
struct Run {
    id: u64,
    run_attempt: u32,
    workflow_id: u64,
    event: String,
    status: String,
    conclusion: Option<String>,
    head_sha: String,
    head_branch: String,
    path: String,
    actor: Actor,
    repository: Repository,
    head_repository: Repository,
}

pub(crate) fn normal_https_client() -> Result<Client, EvidenceError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| EvidenceError::Tls)?
    .with_platform_verifier()
    .map_err(|_| EvidenceError::Tls)?
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Client::builder()
        .tls_backend_preconfigured(tls)
        .http1_only()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .user_agent("chinwag-ci-evidence/1")
        .connect_timeout(Duration::from_secs(5))
        .timeout(REQUEST_BOUND)
        .build()
        .map_err(|_| EvidenceError::Network)
}
fn run_url(repository: &str, run_id: u64) -> Result<Url, EvidenceError> {
    let Some((owner, repo)) = repository.split_once('/') else {
        return Err(EvidenceError::Scope);
    };
    if run_id == 0
        || [owner, repo].iter().any(|p| {
            p.is_empty()
                || p.len() > 100
                || *p == "."
                || *p == ".."
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return Err(EvidenceError::Scope);
    }
    let mut url = Url::parse("https://api.github.com/").map_err(|_| EvidenceError::Scope)?;
    url.path_segments_mut()
        .map_err(|_| EvidenceError::Scope)?
        .extend(["repos", owner, repo, "actions", "runs", &run_id.to_string()]);
    Ok(url)
}
impl GithubEvidenceClient {
    pub fn new() -> Result<Self, EvidenceError> {
        Ok(Self {
            client: normal_https_client()?,
        })
    }
    async fn get(&self, url: Url, max_bytes: usize) -> Result<Vec<u8>, EvidenceError> {
        timeout(REQUEST_BOUND, async {
            let mut response = self
                .client
                .get(url.clone())
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2026-03-10")
                .send()
                .await
                .map_err(network_error)?;
            if response.url() != &url {
                return Err(EvidenceError::Scope);
            }
            if response.status().as_u16() != 200 {
                return Err(EvidenceError::Status(response.status().as_u16()));
            }
            if response
                .content_length()
                .is_some_and(|n| n > max_bytes as u64)
            {
                return Err(EvidenceError::Response);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(network_error)? {
                if chunk.len() > max_bytes.saturating_sub(bytes.len()) {
                    return Err(EvidenceError::Response);
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| EvidenceError::Timeout)?
    }
    /// Fresh, fixed public issuer route; no token-selected URL or ambient token.
    pub async fn issuer_keys(&self) -> Result<IssuerKeys, EvidenceError> {
        let bytes = self
            .get(
                Url::parse(GITHUB_JWKS).map_err(|_| EvidenceError::Scope)?,
                64 * 1024,
            )
            .await?;
        IssuerKeys::from_fixed_issuer_jwks(&bytes).map_err(|_| EvidenceError::Response)
    }
    pub async fn verify_dispatch_run(
        &self,
        intent: &VerifiedIntent,
        dispatch: TrustedDispatch,
    ) -> Result<VerifiedRun, EvidenceError> {
        let bytes = self
            .get(
                run_url(&intent.spec().repository, dispatch.run_id)?,
                512 * 1024,
            )
            .await?;
        verify_run(&bytes, intent, dispatch)
    }
}
pub(crate) fn verify_run(
    bytes: &[u8],
    intent: &VerifiedIntent,
    dispatch: TrustedDispatch,
) -> Result<VerifiedRun, EvidenceError> {
    if bytes.len() > 512 * 1024 {
        return Err(EvidenceError::Response);
    }
    let run: Run = serde_json::from_slice(bytes).map_err(|_| EvidenceError::Response)?;
    let spec = intent.spec();
    let (path, reference) = spec
        .workflow_ref
        .split_once('@')
        .ok_or(EvidenceError::Scope)?;
    let path = path
        .strip_prefix(&format!("{}/", spec.repository))
        .ok_or(EvidenceError::Scope)?;
    let branch = reference
        .strip_prefix("refs/heads/")
        .ok_or(EvidenceError::Scope)?;
    if dispatch.run_id == 0
        || dispatch.run_attempt == 0
        || dispatch.repository_owner_id == 0
        || dispatch.actor_id == 0
        || dispatch.workflow_id == 0

        || run.id != dispatch.run_id
        || run.run_attempt != dispatch.run_attempt
        || run.workflow_id != dispatch.workflow_id
        || run.event != "workflow_dispatch"

        || run.status  !=  "in_progress"
        || run.conclusion.is_some()

        || run.head_sha != spec.source_commit
        || run.head_branch != branch
        || run.path != path
        || run.actor.id != dispatch.actor_id

        || run.repository.id != spec.repository_id
        || run.repository.owner.id != dispatch.repository_owner_id
        || run.repository.full_name != spec.repository

        || run.head_repository.id != spec.repository_id
        || run.head_repository.full_name != spec.repository
        || run.head_repository.owner.id != dispatch.repository_owner_id
        // This MVP executes its workflow from the same admitted branch commit.
        // Reusable or differently sourced workflows require their own schema.

        || spec.workflow_commit != spec.source_commit
    {
        return Err(EvidenceError::Scope);
    }
    Ok(VerifiedRun {
        expected: dispatch,
        repository_id: spec.repository_id,
        source_commit: spec.source_commit.clone(),
        workflow_ref: spec.workflow_ref.clone(),
        workflow_commit: spec.workflow_commit.clone(),
        subject: format!("repo:{}:ref:{reference}", spec.repository),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn urls_are_fixed_origin_and_cannot_insert_an_authority_or_query() {
        assert_eq!(
            run_url("example/ci-test", 100).unwrap().as_str(),
            "https://api.github.com/repos/example/ci-test/actions/runs/100"
        );
        for repo in [
            "https://evil.invalid/repo",
            "example/../other",
            "example/repo?query",
            "example//repo",
            "example/%2f",
        ] {
            assert!(run_url(repo, 100).is_err());
        }
        assert!(run_url("example/ci-test", 0).is_err());
    }
    #[test]
    fn explicit_tls_client_uses_normal_platform_trust_without_global_provider_mutation() {
        GithubEvidenceClient::new().unwrap();
        GithubEvidenceClient::new().unwrap();
    }
}
