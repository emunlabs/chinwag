// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! A Linux Actions job's complete finite capture and dual native delivery.
//! Only fixed public result metadata reaches Actions stdout. Tokens, raw logs,
//! captured command data and decrypted plaintext never do.
use crate::{
    authorization,
    envelope::Destination,
    execution,
    github::GithubEvidenceClient,
    oidc, preparation, receipt,
    runner_identity::RunnerIdentity,
    runtime::{
        self, AdmitRequest, BootstrapRequest, ChallengeResponse, Dispatch, Job, Plan, RuntimeError,
        Scope,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, RuntimeError>;
fn ck<T, E>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|_| RuntimeError)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfiguration {
    pub version: u16,
    pub admission_origin: String,
    pub bootstrap_hint: [u8; 32],
    pub expected_scope: Scope,
    pub expected_oidc_subject: String,
    pub dispatch: Dispatch,
    pub checkout: PathBuf,
}
#[derive(Serialize)]
pub struct RunnerObservation {
    pub classification: &'static str,
    pub run_id: u64,
    pub run_attempt: u32,
    pub envelope_digest: [u8; 32],
    pub complete_object_sha256: [u8; 32],
    pub complete_object_bytes: u64,
    pub raw_output_complete: bool,
    pub eligible_for_green: bool,
    pub recipient_receipt: serde_json::Value,
    pub archive_receipt: serde_json::Value,
    pub recipient_path: crate::transport::SelectedRelayWitness,
    pub archive_path: crate::transport::SelectedRelayWitness,
}
fn origin_ok(origin: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(origin) else {
        return false;
    };
    u.scheme() == "https"
        && u.username().is_empty()
        && u.password().is_none()
        && u.port_or_known_default() == Some(443)
        && u.path() == "/"
        && u.query().is_none()
        && u.fragment().is_none()
        && u.as_str() == origin
        && u.host_str()
            .is_some_and(|h| h.ends_with(".trycloudflare.com") || h.ends_with(".workers.dev"))
}
fn own_oidc_url(raw: &str, audience: &str) -> Result<reqwest::Url> {
    let mut url = ck(reqwest::Url::parse(raw))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.fragment().is_some()
        || !url
            .host_str()
            .is_some_and(|h| h.ends_with(".actions.githubusercontent.com") && !h.starts_with('.'))
        || url.query_pairs().any(|(k, _)| k == "audience")
    {
        return Err(RuntimeError);
    }
    url.query_pairs_mut().append_pair("audience", audience);
    Ok(url)
}
async fn own_oidc(client: &reqwest::Client, audience: &str) -> Result<Zeroizing<String>> {
    // Only this hosted job's two explicitly named runtime variables are read.
    // No environment scan or long-lived account/seat key exists in the VM.
    let raw = Zeroizing::new(ck(std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL"))?);
    let bearer = Zeroizing::new(ck(std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))?);
    let url = own_oidc_url(&raw, audience)?;
    let mut response = ck(client
        .get(url.clone())
        .bearer_auth(bearer.as_str())
        .send()
        .await)?;
    if response.url() != &url
        || response.status() != reqwest::StatusCode::OK
        || response.content_length().is_some_and(|n| n > 32 * 1024)
    {
        return Err(RuntimeError);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(b) = ck(response.chunk().await)? {
        if b.len() > 32768usize.saturating_sub(bytes.len()) {
            return Err(RuntimeError);
        }
        bytes.extend_from_slice(&b)
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Token {
        value: String,
    }
    let token: Token = ck(serde_json::from_slice(&bytes))?;
    if token.value.len() > 16 * 1024 || token.value.is_empty() {
        return Err(RuntimeError);
    }
    Ok(Zeroizing::new(token.value))
}
fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    ck(serde_json::to_vec(v))
}
async fn post<T: Serialize>(
    c: &reqwest::Client,
    origin: &str,
    path: &str,
    v: &T,
) -> Result<Vec<u8>> {
    runtime::request_bytes(
        c,
        reqwest::Method::POST,
        &format!("{origin}{path}"),
        Some(ser(v)?),
        128 * 1024,
    )
    .await
}
/// Return 1 for a fully delivered red workload, 0 only for a fully delivered
/// eligible green workload. Any missing admission/receipt/closure stays held.
pub async fn run(path: &Path) -> Result<(RunnerObservation, bool)> {
    if !cfg!(target_os = "linux") {
        return Err(RuntimeError);
    }
    let config: RunnerConfiguration = ck(crate::owner_cli::read_public(path))?;
    if config.version != 1
        || !origin_ok(&config.admission_origin)
        || config.bootstrap_hint == [0; 32]
    {
        return Err(RuntimeError);
    }
    let mut identity = ck(RunnerIdentity::generate())?;
    let keys = identity.public_keys();
    let job = Job {
        run_id: config.dispatch.run_id,
        run_attempt: config.dispatch.run_attempt,
        signing: keys.signing_ed25519,
        agent_transport: keys.agent_transport_ed25519,
        archive_transport: keys.archive_transport_ed25519,
    };
    let client = ck(crate::github::normal_https_client())?;
    let bootstrap_audience = runtime::bootstrap_audience(config.bootstrap_hint, &job)?;
    let bootstrap_token = own_oidc(&client, &bootstrap_audience).await?;
    let boot = BootstrapRequest {
        job: job.clone(),
        token: bootstrap_token.to_string(),
    };
    let plan_bytes = post(&client, &config.admission_origin, "v1/bootstrap", &boot).await?;
    let plan: Plan = ck(serde_json::from_slice(&plan_bytes))?;
    if plan.scope != config.expected_scope
        || plan.expected_oidc_subject != config.expected_oidc_subject
        || plan.bootstrap_hint != config.bootstrap_hint
    {
        return Err(RuntimeError);
    }
    let profiles = plan.profiles()?;
    if profiles.delivery().spec().admission_origin != config.admission_origin {
        return Err(RuntimeError);
    }
    let fixture = ck(preparation::prepare(&profiles, &config.checkout).await)?;
    let image = ck(execution::prepare_image(profiles.command(), &fixture).await)?;
    // Status GET is read-only; no publication/challenge/admission retry. The
    // finite preparation window lets the original operators enroll exact keys.
    let end = tokio::time::Instant::now() + Duration::from_secs(600);
    loop {
        let url = format!("{}v1/ready", config.admission_origin);
        let response = ck(client.get(&url).send().await)?;
        if response.status() == reqwest::StatusCode::OK {
            break;
        }
        if response.status() != reqwest::StatusCode::TOO_EARLY || tokio::time::Instant::now() >= end
        {
            return Err(RuntimeError);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    // Image preparation and original-owner enrollment can outlive the first
    // credential. Obtain a fresh token for this new challenge operation.
    drop(boot);
    drop(bootstrap_token);
    let fresh_bootstrap = own_oidc(&client, &bootstrap_audience).await?;
    let boot = BootstrapRequest {
        job: job.clone(),
        token: fresh_bootstrap.to_string(),
    };
    let challenge: ChallengeResponse = ck(serde_json::from_slice(
        &post(&client, &config.admission_origin, "v1/challenge", &boot).await?,
    ))?;
    let token = own_oidc(&client, &challenge.audience).await?;
    let intent = plan.intent()?;
    let evidence = ck(GithubEvidenceClient::new())?;
    let (run, jwks) = tokio::join!(
        evidence.verify_dispatch_run(&intent, config.dispatch.trusted()),
        evidence.issuer_keys()
    );
    let run = ck(run)?;
    let jwks = ck(jwks)?;
    let mut expected = run.expected_oidc(&challenge.audience, runtime::now()?);
    expected.subject = &config.expected_oidc_subject;
    let workflow = ck(oidc::verify_token(&token, &jwks, expected))?;
    let signature = ck(identity.sign_admission(&intent, &workflow, challenge.nonce))?;
    let admit = AdmitRequest {
        job: job.clone(),
        token: token.to_string(),
        nonce: challenge.nonce,
        signature_hex: hex::encode(signature),
    };
    let certificate = post(&client, &config.admission_origin, "v1/admit", &admit).await?;
    drop(admit);
    drop(token);
    drop(boot);
    drop(fresh_bootstrap);
    let d = profiles.delivery().spec();
    let admission = ck(ck(authorization::verify_historical_certificate(
        &certificate,
        d.admission_signer,
    ))?
    .require_current(runtime::now()?))?;
    ck(profiles.validate_admission(&admission, &job.registered(), runtime::now()?))?;
    let captured =
        ck(execution::execute(&profiles, fixture, &image, &admission, &job.registered()).await)?;
    let green = captured.eligible_for_green();
    let complete = captured.output_is_complete();
    let plaintext = ck(captured.plaintext_for_sealing())?;
    let claims =
        ck(admission.expected_provenance(d.original_policy_sha256, d.original_policy_epoch))?;
    let sealed =
        ck(identity.seal_failure(claims, profiles.delivery().key_pins().clone(), &plaintext))?;
    drop(plaintext);
    let bound = ck(profiles.authenticate_current_artifact(
        &certificate,
        sealed,
        &job.registered(),
        runtime::now()?,
    ))?;
    let wire = ck(bound.complete_storage_blob())?;
    let blob = ck(bound.complete_admitted_blob())?;
    let archive_peer = ck(iroh::EndpointId::from_bytes(&d.archive.transport))?;
    let agent_peer = ck(iroh::EndpointId::from_bytes(&d.recipient.transport))?;
    let archive = ck(identity
        .bind_archive_pair(archive_peer, &d.relay_origin, &d.relay_origin)
        .await)?;
    let agent = match identity
        .bind_agent_pair(agent_peer, &d.relay_origin, &d.relay_origin)
        .await
    {
        Ok(pair) => pair,
        Err(_) => {
            archive.close().await;
            return Err(RuntimeError);
        }
    };
    // Archive first, so its durable object is available to ACU when Root
    // requests its independent P grant after receiving the same original.
    let transfer = async {
        let a = ck(archive
            .send(&certificate, &wire, Duration::from_secs(60))
            .await)?;
        ck(receipt::verify_native_admitted(
            &a.unverified_receipt,
            &bound,
            Destination::Archive,
            d.archive.store_id,
            &d.relay_origin,
        ))?;
        let r = ck(agent
            .send(&certificate, &wire, Duration::from_secs(60))
            .await)?;
        ck(receipt::verify_native_admitted(
            &r.unverified_receipt,
            &bound,
            Destination::Recipient,
            d.recipient.store_id,
            &d.relay_origin,
        ))?;
        Ok::<_, RuntimeError>((a, r))
    }
    .await;
    archive.close().await;
    agent.close().await;
    let (a, r) = transfer?;
    // Receipt-only completion: the complete encrypted failure has already gone
    // directly over native Iroh/Cloudflare to BOTH stores. This POST carries no
    // payload and confers no read, agent-start or repair authority.
    let completion = crate::delivery_barrier::DualDeliveryRequest {
        version: 1,
        run_id: job.run_id,
        run_attempt: job.run_attempt,
        envelope_digest: *bound.digest(),
        object: crate::storage::CiphertextClaim {
            sha256: Sha256::digest(&blob).into(),
            bytes: blob.len() as u64,
        },
        recipient_receipt_hex: hex::encode(&r.unverified_receipt),
        archive_receipt_hex: hex::encode(&a.unverified_receipt),
        recipient_path: r.path_after.clone(),
        archive_path: a.path_after.clone(),
    };
    // Exactly one POST; a lost reply stays held and never replays the original.
    let _ = post(
        &client,
        &config.admission_origin,
        "v1/delivery-complete",
        &completion,
    )
    .await?;
    Ok((
        RunnerObservation {
            classification: "SAME_SIGNED_ADMITTED_ENCRYPTED_ORIGINAL_VERIFIED_DURABLE_AT_BOTH_SELECTED_CF_DESTINATIONS",
            run_id: job.run_id,
            run_attempt: job.run_attempt,
            envelope_digest: *bound.digest(),
            complete_object_sha256: Sha256::digest(&blob).into(),
            complete_object_bytes: blob.len() as u64,
            raw_output_complete: complete,
            eligible_for_green: green,
            recipient_receipt: ck(serde_json::from_slice(&r.unverified_receipt))?,
            archive_receipt: ck(serde_json::from_slice(&a.unverified_receipt))?,
            recipient_path: r.path_after,
            archive_path: a.path_after,
        },
        green,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_oidc_endpoint_cannot_export_bearer_to_arbitrary_or_confused_host() {
        assert!(
            own_oidc_url(
                "https://runner.actions.githubusercontent.com/a?api-version=2",
                "aud"
            )
            .is_ok()
        );
        for u in [
            "http://runner.actions.githubusercontent.com/a",
            "https://actions.githubusercontent.com.evil.invalid/a",
            "https://runner.actions.githubusercontent.com:444/a",
            "https://user@runner.actions.githubusercontent.com/a",
            "https://runner.actions.githubusercontent.com/a#a",
            "https://runner.actions.githubusercontent.com/a?audience=preselected",
        ] {
            assert!(own_oidc_url(u, "aud").is_err())
        }
    }
}
