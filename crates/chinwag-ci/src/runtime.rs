// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Finite, operator-owned CI jobs. Public HTTP never returns plaintext logs.
//! A native intent and an independently registered GitHub dispatch are required.
use crate::{
    acu,
    admission::{AdmissionLedger, AdmissionOutcome},
    authorization,
    custody::{OwnerCustody, PublicDestination, PublicEnrollment},
    envelope::{self, Destination},
    github::{GithubEvidenceClient, TrustedDispatch},
    intent::{self, IntentVerification, VerifiedIntent},
    oidc, owner_cli,
    profile::{BoundProfiles, DeliveryProfile, RegisteredJob},
    runner_binding::{self, RunnerPublicKeys},
    storage::{CiphertextClaim, CiphertextStore},
    transport::TransferError,
};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use zeroize::Zeroize;
#[derive(Debug, thiserror::Error)]
#[error("CI runtime refused or ended with unconfirmed evidence; preserve its original operation")]
pub struct RuntimeError;
type Result<T> = std::result::Result<T, RuntimeError>;
fn checked<T, E>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|_| RuntimeError)
}
pub(crate) fn now() -> Result<u64> {
    checked(SystemTime::now().duration_since(UNIX_EPOCH)).map(|d| d.as_secs())
}
fn json<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    checked(serde_json::to_vec(v))
}
fn decode<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Result<T> {
    if b.len() > 128 * 1024 {
        return Err(RuntimeError);
    }
    checked(serde_json::from_slice(b))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerFiles {
    pub config: PathBuf,
    pub public: PathBuf,
}
impl OwnerFiles {
    fn open(&self) -> Result<OwnerCustody> {
        checked(owner_cli::open_owner(&self.config, &self.public))
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub instance: String,
    pub public_key: [u8; 32],
    pub addressee: String,
    pub task_id: String,
    pub room: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub version: u16,
    pub scope: Scope,
    pub native_original: String,
    pub command_profile: String,
    pub delivery_profile: String,
    pub expected_oidc_subject: String,
    pub bootstrap_hint: [u8; 32],
}
impl Plan {
    pub(crate) fn intent(&self) -> Result<VerifiedIntent> {
        if self.version != 1
            || self.bootstrap_hint == [0; 32]
            || self.expected_oidc_subject.is_empty()
            || self.expected_oidc_subject.len() > 1024
        {
            return Err(RuntimeError);
        }
        checked(intent::verify_original(
            self.native_original.as_bytes(),
            IntentVerification {
                initiator_instance: &self.scope.instance,
                initiator_public_key: self.scope.public_key,
                admission_addressee: &self.scope.addressee,
                task_id: &self.scope.task_id,
                room: &self.scope.room,
                now_unix: now()?,
            },
        ))
    }
    pub(crate) fn profiles(&self) -> Result<BoundProfiles> {
        checked(BoundProfiles::resolve(
            &self.intent()?,
            self.command_profile.as_bytes(),
            self.delivery_profile.as_bytes(),
            now()?,
        ))
    }
    fn delivery(&self) -> Result<DeliveryProfile> {
        checked(DeliveryProfile::parse(self.delivery_profile.as_bytes()))
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub run_id: u64,
    pub run_attempt: u32,
    pub signing: [u8; 32],
    pub agent_transport: [u8; 32],
    pub archive_transport: [u8; 32],
}
impl Job {
    pub(crate) fn keys(&self) -> RunnerPublicKeys {
        RunnerPublicKeys {
            signing_ed25519: self.signing,
            agent_transport_ed25519: self.agent_transport,
            archive_transport_ed25519: self.archive_transport,
        }
    }
    pub(crate) fn registered(&self) -> RegisteredJob {
        RegisteredJob {
            run_id: self.run_id,
            run_attempt: self.run_attempt,
            keys: self.keys(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dispatch {
    pub run_id: u64,
    pub run_attempt: u32,
    pub repository_owner_id: u64,
    pub actor_id: u64,
    pub workflow_id: u64,
}
impl Dispatch {
    pub(crate) fn trusted(&self) -> TrustedDispatch {
        TrustedDispatch {
            run_id: self.run_id,
            run_attempt: self.run_attempt,
            repository_owner_id: self.repository_owner_id,
            actor_id: self.actor_id,
            workflow_id: self.workflow_id,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfiguration {
    pub version: u16,
    pub listen: std::net::SocketAddr,
    pub lifetime_seconds: u64,
    pub plan: PathBuf,
    pub dispatch: PathBuf,
    pub registered_job: PathBuf,
    pub relay_ready: PathBuf,
    pub recipient: OwnerFiles,
    pub admission: OwnerFiles,
    pub ledger: PathBuf,
    pub output_directory: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudioConfiguration {
    pub version: u16,
    pub listen: std::net::SocketAddr,
    pub lifetime_seconds: u64,
    pub plan: PathBuf,
    pub registered_job: PathBuf,
    pub archive: OwnerFiles,
    pub acu: OwnerFiles,
    pub release_ledger: PathBuf,
    pub current_policy: PathBuf,
    pub output_directory: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BootstrapRequest {
    pub job: Job,
    pub token: String,
}
impl Drop for BootstrapRequest {
    fn drop(&mut self) {
        self.token.zeroize()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChallengeResponse {
    pub nonce: [u8; 32],
    pub audience: String,
    pub expires_unix: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmitRequest {
    pub job: Job,
    pub token: String,
    pub nonce: [u8; 32],
    pub signature_hex: String,
}
impl Drop for AdmitRequest {
    fn drop(&mut self) {
        self.token.zeroize()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseRequest {
    pub object: CiphertextClaim,
    pub signed_request_hex: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactObservation {
    pub classification: String,
    pub role: Destination,
    pub object: CiphertextClaim,
    pub envelope_digest: [u8; 32],
    pub admission_sha256: [u8; 32],
    pub run_id: u64,
    pub run_attempt: u32,
    pub plaintext_sha256: [u8; 32],
    pub plaintext_bytes: u64,
    pub fully_read: bool,
}

/// Own exclusive private file, anchored to an already admitted directory. This
/// helper never overwrites or creates parent namespaces and never logs content.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use rustix::fs::{self, AtFlags, Mode, OFlags};
    let dir = checked(CiphertextStore::open(path.parent().ok_or(RuntimeError)?))?;
    let name = path.file_name().ok_or(RuntimeError)?;
    let fd = checked(fs::openat(
        dir.directory(),
        name,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ))?;
    checked(fs::fchmod(&fd, Mode::RUSR | Mode::WUSR))?;
    let mut f = File::from(fd);
    checked(f.write_all(bytes))?;
    checked(f.sync_all())?;
    let st = checked(fs::fstat(&f))?;
    let named = checked(fs::statat(dir.directory(), name, AtFlags::SYMLINK_NOFOLLOW))?;
    if st.st_dev != named.st_dev
        || st.st_ino != named.st_ino
        || st.st_size != bytes.len() as i64
        || st.st_nlink != 1
    {
        return Err(RuntimeError);
    }
    checked(fs::fsync(dir.directory()))?;
    checked(dir.check())
}
fn read<T: Serialize + for<'a> Deserialize<'a>>(p: &Path) -> Result<T> {
    checked(owner_cli::read_public(p))
}
fn register(path: &Path, job: &Job) -> Result<()> {
    if path.try_exists().map_err(|_| RuntimeError)? {
        if read::<Job>(path)? != *job {
            return Err(RuntimeError);
        }
        Ok(())
    } else {
        write_new(path, &json(job)?)
    }
}
pub(crate) fn bootstrap_audience(hint: [u8; 32], job: &Job) -> Result<String> {
    Ok(format!(
        "urn:chinwag:ci-bootstrap:v1:{}",
        hex::encode(Sha256::digest(
            [b"chinwag-ci-bootstrap-v1\0".as_slice(), &hint, &json(job)?].concat()
        ))
    ))
}
async fn verify_workflow(
    plan: &Plan,
    dispatch: &Dispatch,
    job: &Job,
    token: &str,
    audience: &str,
) -> Result<oidc::VerifiedWorkflow> {
    if job.run_id != dispatch.run_id || job.run_attempt != dispatch.run_attempt {
        return Err(RuntimeError);
    }
    let intent = plan.intent()?;
    let client = checked(GithubEvidenceClient::new())?;
    let (run, keys) = tokio::join!(
        client.verify_dispatch_run(&intent, dispatch.trusted()),
        client.issuer_keys()
    );
    let run = checked(run)?;
    let keys = checked(keys)?;
    let mut expected = run.expected_oidc(audience, now()?);
    // Exact subject is operator-pinned from repository OIDC configuration, never
    // decoded from the incoming JWT. All run/repository/workflow checks remain.
    expected.subject = &plan.expected_oidc_subject;
    checked(oidc::verify_token(token, &keys, expected))
}
fn same_enrollment(owner: &OwnerCustody, d: &PublicDestination) -> Result<()> {
    if checked(owner.public_enrollment())? != PublicEnrollment::Destination(d.clone()) {
        return Err(RuntimeError);
    }
    Ok(())
}
struct RootState {
    stop: Arc<AtomicBool>,
    config: RootConfiguration,
    admission: OwnerCustody,
    ledger: Mutex<AdmissionLedger>,
    recipient_online: AtomicBool,
}
async fn bootstrap(State(s): State<Arc<RootState>>, body: Bytes) -> impl IntoResponse {
    let result = async {
        let request: BootstrapRequest = decode(&body)?;
        let plan: Plan = read(&s.config.plan)?;
        let dispatch: Dispatch = read(&s.config.dispatch)?;
        let audience = bootstrap_audience(plan.bootstrap_hint, &request.job)?;
        verify_workflow(&plan, &dispatch, &request.job, &request.token, &audience).await?;
        plan.profiles()?
            .validate_registered_job(&request.job.registered())
            .map_err(|_| RuntimeError)?;
        register(&s.config.registered_job, &request.job)?;
        json(&plan)
    }
    .await;
    http_result(result)
}
fn is_ready(s: &RootState, job: &Job) -> Result<()> {
    if s.stop.load(Ordering::Acquire)
        || !s.recipient_online.load(Ordering::Acquire)
        || read::<Job>(&s.config.registered_job)? != *job
        || read::<Job>(&s.config.relay_ready)? != *job
    {
        return Err(RuntimeError);
    }
    Ok(())
}
async fn readiness(State(s): State<Arc<RootState>>) -> impl IntoResponse {
    let ready = read::<Job>(&s.config.registered_job).and_then(|j| is_ready(&s, &j));
    if ready.is_ok() {
        (StatusCode::OK, "CI_EXACT_OWNER_PAIR_READY")
    } else {
        (StatusCode::TOO_EARLY, "CI_OWNERS_PENDING")
    }
}
async fn challenge(State(s): State<Arc<RootState>>, body: Bytes) -> impl IntoResponse {
    let result = async {
        let r: BootstrapRequest = decode(&body)?;
        is_ready(&s, &r.job)?;
        let plan: Plan = read(&s.config.plan)?;
        let dispatch: Dispatch = read(&s.config.dispatch)?;
        verify_workflow(
            &plan,
            &dispatch,
            &r.job,
            &r.token,
            &bootstrap_audience(plan.bootstrap_hint, &r.job)?,
        )
        .await?;
        let intent = plan.intent()?;
        let t = now()?;
        let exp = intent.spec().expires_unix.min(t + 300);
        let c = checked(s.ledger.lock().await.issue(
            &intent,
            r.job.keys(),
            r.job.run_id,
            r.job.run_attempt,
            t,
            exp,
        ))?;
        json(&ChallengeResponse {
            nonce: c.nonce,
            audience: c.audience,
            expires_unix: c.expires_unix,
        })
    }
    .await;
    http_result(result)
}
async fn admit(State(s): State<Arc<RootState>>, body: Bytes) -> impl IntoResponse {
    let result = async {
        let r: AdmitRequest = decode(&body)?;
        is_ready(&s, &r.job)?;
        let plan: Plan = read(&s.config.plan)?;
        let dispatch: Dispatch = read(&s.config.dispatch)?;
        let intent = plan.intent()?;
        let audience = checked(runner_binding::audience_for(
            &intent,
            r.job.keys(),
            r.nonce,
            r.job.run_id,
            r.job.run_attempt,
        ))?;
        let workflow = verify_workflow(&plan, &dispatch, &r.job, &r.token, &audience).await?;
        let signature: [u8; 64] = checked(checked(hex::decode(&r.signature_hex))?.try_into())?;
        let binding = checked(runner_binding::verify_runner_proof(
            intent,
            workflow,
            r.job.keys(),
            r.nonce,
            signature,
            now()?,
        ))?;
        let admission = checked(s.ledger.lock().await.consume(&binding, r.nonce, now()?))?;
        let record = match admission {
            AdmissionOutcome::NewlyCommitted(a) | AdmissionOutcome::ReconciledOriginal(a) => a,
        };
        checked(s.admission.certify_admission(&record))
    }
    .await;
    http_result(result)
}
fn http_result(result: Result<Vec<u8>>) -> (StatusCode, Vec<u8>) {
    match result {
        Ok(b) => (StatusCode::OK, b),
        Err(_) => (StatusCode::FORBIDDEN, b"CI_OPERATION_HELD".to_vec()),
    }
}
fn validate_server(
    version: u16,
    addr: std::net::SocketAddr,
    lifetime: u64,
    outputs: &Path,
) -> Result<()> {
    if version != 1
        || !addr.ip().is_loopback()
        || addr.port() == 0
        || !(30..=3600).contains(&lifetime)
    {
        return Err(RuntimeError);
    }
    checked(CiphertextStore::open(outputs)).map(|_| ())
}
async fn wait_stop(stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
async fn finite_shutdown(seconds: u64, stop: Arc<AtomicBool>) {
    tokio::select! {_=tokio::time::sleep(Duration::from_secs(seconds))=>{},_=tokio::signal::ctrl_c()=>{}}
    stop.store(true, Ordering::Release);
}
static INFLIGHT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);
async fn request_deadline(request: axum::extract::Request, next: Next) -> Response {
    request_deadline_at(request, next, Duration::from_secs(25)).await
}
async fn request_deadline_at(
    request: axum::extract::Request,
    next: Next,
    limit: Duration,
) -> Response {
    let Ok(_permit) = INFLIGHT.try_acquire() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "CI_BUSY").into_response();
    };
    match tokio::time::timeout(limit, next.run(request)).await {
        Ok(r) => r,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "CI_REQUEST_DEADLINE").into_response(),
    }
}
struct OnlineGuard<'a>(Option<&'a AtomicBool>);
impl Drop for OnlineGuard<'_> {
    fn drop(&mut self) {
        if let Some(flag) = self.0 {
            flag.store(false, Ordering::Release);
        }
    }
}

// Keep independent owner, identity, output and lifetime inputs explicit.
#[allow(clippy::too_many_arguments)]
async fn receive(
    owner: &mut OwnerCustody,
    plan: &Plan,
    job: &Job,
    role: Destination,
    seconds: u64,
    outputs: &Path,
    stop: &AtomicBool,
    online: Option<&AtomicBool>,
) -> Result<ArtifactObservation> {
    let profiles = plan.profiles()?;
    let d = profiles.delivery().spec();
    let destination = match role {
        Destination::Recipient => &d.recipient,
        Destination::Archive => &d.archive,
    };
    same_enrollment(owner, destination)?;
    let peer = match role {
        Destination::Recipient => job.agent_transport,
        Destination::Archive => job.archive_transport,
    };
    let pair = checked(
        owner
            .bind_destination_pair(
                checked(iroh::EndpointId::from_bytes(&peer))?,
                &d.relay_origin,
                &d.relay_origin,
            )
            .await,
    )?;
    if let Some(online) = online {
        online.store(true, Ordering::Release);
    }
    let online_guard = OnlineGuard(online);
    let mut observation = None;
    let operation = pair.receive_once(Duration::from_secs(seconds), |claim| {
        let result: Result<Vec<u8>> = (|| {
            let sealed = checked(envelope::parse_storage_blob(&claim.ciphertext))?;
            let bound = checked(profiles.authenticate_current_artifact(
                &claim.manifest,
                sealed,
                &job.registered(),
                now()?,
            ))?;
            let reply = checked(owner.persist_native_admitted(&bound, &claim, &d.relay_origin))?;
            let blob = checked(bound.complete_admitted_blob())?;
            observation = Some((
                CiphertextClaim {
                    sha256: Sha256::digest(&blob).into(),
                    bytes: blob.len() as u64,
                },
                *bound.digest(),
                bound.claims().admission_sha256,
            ));
            Ok(reply)
        })();
        async move { result.map_err(|_| TransferError::Application) }
    });
    let transfer = tokio::select! {r=operation=>r,_=wait_stop(stop)=>Err(TransferError::Deadline)};
    drop(online_guard);
    pair.close().await;
    checked(transfer)?;
    let (object, envelope_digest, admission_sha256) = observation.ok_or(RuntimeError)?;
    let native = checked(owner.read_native_receipt(object))?;
    let stored = recover(owner, profiles.delivery(), role, object)?;
    checked(crate::receipt::verify_native_admitted(
        &native,
        &stored,
        role,
        destination.store_id,
        &d.relay_origin,
    ))?;
    write_new(&outputs.join("native-ingress-receipt.json"), &native)?;
    let obs = ArtifactObservation {
        classification: "SIGNED_NATIVE_COMPLETE_ADMITTED_CIPHERTEXT_STORED_NOT_YET_READ".into(),
        role,
        object,
        envelope_digest,
        admission_sha256,
        run_id: job.run_id,
        run_attempt: job.run_attempt,
        plaintext_sha256: [0; 32],
        plaintext_bytes: 0,
        fully_read: false,
    };
    write_new(
        &outputs.join("native-storage-observation.json"),
        &json(&obs)?,
    )?;
    Ok(obs)
}
fn recover(
    owner: &OwnerCustody,
    delivery: &DeliveryProfile,
    role: Destination,
    object: CiphertextClaim,
) -> Result<authorization::AdmissionBoundEnvelope> {
    let (blob, receipt) = checked(owner.read_admitted_object(object))?;
    let d = delivery.spec();
    let dest = match role {
        Destination::Recipient => &d.recipient,
        Destination::Archive => &d.archive,
    };
    same_enrollment(owner, dest)?;
    checked(authorization::recover_stored_admitted_envelope(
        &blob,
        &receipt,
        d.admission_signer,
        delivery.key_pins(),
        d.original_policy_sha256,
        d.original_policy_epoch,
        role,
        dest.store_id,
    ))
    .map(|(e, _)| e)
}
#[allow(clippy::too_many_arguments)]
fn qualified_output(
    owner: &OwnerCustody,
    envelope: &authorization::AdmissionBoundEnvelope,
    policy: &acu::CurrentPolicy,
    profile: &crate::profile::CommandProfile,
    request: &[u8],
    grant: &[u8],
    mut obs: ArtifactObservation,
    outputs: &Path,
) -> Result<ArtifactObservation> {
    let grant = checked(acu::verify_grant(grant, request, envelope, policy, now()?))?;
    let plaintext = checked(owner.open_payload_from_grant(envelope, &grant, policy, now()?))?;
    // Parse and traverse the complete sealed capture before recording qualified
    // read. Content is untrusted evidence, never instructions or repair authority.
    crate::capture_read::validate(&plaintext, envelope, profile)?;
    obs.plaintext_sha256 = Sha256::digest(&plaintext).into();
    obs.plaintext_bytes = plaintext.len() as u64;
    obs.fully_read = true;
    obs.classification =
        "OWNER_AUTHORIZED_FULL_DECRYPTED_CAPTURE_READ_NOT_TASK_START_OR_REPAIR_AUTHORITY".into();
    write_new(&outputs.join("qualified-plaintext.json"), &plaintext)?;
    write_new(
        &outputs.join("qualified-read-observation.json"),
        &json(&obs)?,
    )?;
    Ok(obs)
}
async fn recipient_read(
    owner: &OwnerCustody,
    plan: &Plan,
    obs: ArtifactObservation,
    outputs: &Path,
) -> Result<ArtifactObservation> {
    let delivery = plan.delivery()?;
    let e = recover(owner, &delivery, Destination::Recipient, obs.object)?;
    let client = checked(crate::github::normal_https_client())?;
    let policy_bytes = request_bytes(
        &client,
        reqwest::Method::GET,
        &format!("{}v1/policy", delivery.spec().acu_origin),
        None,
        128 * 1024,
    )
    .await?;
    let policy = checked(acu::verify_current_policy(
        &policy_bytes,
        delivery.spec().acu_signer,
        now()?,
    ))?;
    let t = now()?;
    let request = checked(owner.create_release_request(
        &e,
        &policy,
        t,
        (t + 120).min(policy.expires_unix()),
    ))?;
    let body = json(&ReleaseRequest {
        object: obs.object,
        signed_request_hex: hex::encode(&request),
    })?;
    // Exactly one release POST. Uncertain outcomes are preserved, not retried.
    let grant = request_bytes(
        &client,
        reqwest::Method::POST,
        &format!("{}v1/release", delivery.spec().acu_origin),
        Some(body),
        128 * 1024,
    )
    .await?;
    let current_bytes = request_bytes(
        &client,
        reqwest::Method::GET,
        &format!("{}v1/policy", delivery.spec().acu_origin),
        None,
        128 * 1024,
    )
    .await?;
    let current = checked(acu::verify_current_policy(
        &current_bytes,
        delivery.spec().acu_signer,
        now()?,
    ))?;
    qualified_output(
        owner,
        &e,
        &current,
        &checked(crate::profile::CommandProfile::parse(
            plan.command_profile.as_bytes(),
        ))?,
        &request,
        &grant,
        obs,
        outputs,
    )
}
/// Finite root admission HTTP and one exact registered recipient endpoint. No
/// process is spawned for another seat; all children are joined before return.
pub async fn serve_root(path: &Path) -> Result<()> {
    let config: RootConfiguration = read(path)?;
    validate_server(
        config.version,
        config.listen,
        config.lifetime_seconds,
        &config.output_directory,
    )?;
    let mut recipient = config.recipient.open()?;
    let admission = config.admission.open()?;
    let plan: Plan = read(&config.plan)?;
    let d = plan.delivery()?;
    if checked(admission.public_enrollment())?
        != (PublicEnrollment::Admission {
            signer: d.spec().admission_signer,
        })
    {
        return Err(RuntimeError);
    }
    same_enrollment(&recipient, &d.spec().recipient)?;
    let listener = checked(tokio::net::TcpListener::bind(config.listen).await)?;
    let state = Arc::new(RootState {
        stop: Arc::new(AtomicBool::new(false)),
        ledger: Mutex::new(checked(AdmissionLedger::open(&config.ledger))?),
        config,
        admission,
        recipient_online: AtomicBool::new(false),
    });
    let app = Router::new()
        .route("/v1/bootstrap", post(bootstrap))
        .route("/v1/ready", get(readiness))
        .route("/v1/challenge", post(challenge))
        .route("/v1/admit", post(admit))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn(request_deadline))
        .with_state(state.clone());
    let s = state.clone();
    let receiver = async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(s.config.lifetime_seconds);
        let job = loop {
            if let Ok(j) = read::<Job>(&s.config.registered_job) {
                break j;
            }
            if s.stop.load(Ordering::Acquire) || tokio::time::Instant::now() >= deadline {
                return Err(RuntimeError);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        let plan: Plan = read(&s.config.plan)?;
        // This readiness flag means the exact receiver owner is about to bind;
        // selected-relay readiness still requires actual transfer witnesses.
        let seconds = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .as_secs()
            .min(1800);
        let obs = receive(
            &mut recipient,
            &plan,
            &job,
            Destination::Recipient,
            seconds,
            &s.config.output_directory,
            &s.stop,
            Some(&s.recipient_online),
        )
        .await?;
        s.recipient_online.store(false, Ordering::Release);
        recipient_read(&recipient, &plan, obs, &s.config.output_directory)
            .await
            .map(|_| ())
    };
    let server = axum::serve(listener, app).with_graceful_shutdown(finite_shutdown(
        state.config.lifetime_seconds,
        state.stop.clone(),
    ));
    let server = tokio::time::timeout(
        Duration::from_secs(state.config.lifetime_seconds + 30),
        std::future::IntoFuture::into_future(server),
    );
    let (http, receipt) = tokio::join!(server, receiver);
    checked(checked(http)?)?;
    receipt
}
struct StudioState {
    stop: Arc<AtomicBool>,
    config: StudioConfiguration,
    archive: Arc<Mutex<OwnerCustody>>,
    acu: OwnerCustody,
    ledger: Mutex<acu::ReleaseLedger>,
}
async fn policy_get(State(s): State<Arc<StudioState>>) -> impl IntoResponse {
    http_result((|| {
        let raw = read_raw(&s.config.current_policy, 128 * 1024)?;
        checked(acu::verify_current_policy(&raw, acu_pin(&s.acu)?, now()?))?;
        Ok(raw)
    })())
}
fn acu_pin(owner: &OwnerCustody) -> Result<[u8; 32]> {
    match checked(owner.public_enrollment())? {
        PublicEnrollment::Acu { signer, .. } => Ok(signer),
        _ => Err(RuntimeError),
    }
}
fn read_raw(path: &Path, max: usize) -> Result<Vec<u8>> {
    use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
    let dir = checked(CiphertextStore::open(path.parent().ok_or(RuntimeError)?))?;
    let name = path.file_name().ok_or(RuntimeError)?;
    let f = File::from(checked(fs::openat(
        dir.directory(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ))?);
    let st = checked(fs::fstat(&f))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
        || st.st_uid != rustix::process::geteuid().as_raw()
        || st.st_nlink != 1
        || st.st_mode & 0o7777 != 0o600
        || st.st_size < 1
        || st.st_size as usize > max
    {
        return Err(RuntimeError);
    }
    #[cfg(target_os = "macos")]
    {
        use rustix::fd::AsFd;
        checked(crate::macos_acl::require_absent(f.as_fd()))?;
    }
    let mut bytes = Vec::new();
    checked((&f).take(max as u64 + 1).read_to_end(&mut bytes))?;
    let end = checked(fs::fstat(&f))?;
    let named = checked(fs::statat(dir.directory(), name, AtFlags::SYMLINK_NOFOLLOW))?;
    if bytes.len() != st.st_size as usize
        || end.st_size != st.st_size
        || end.st_ino != named.st_ino
        || end.st_dev != named.st_dev
        || named.st_size != end.st_size
    {
        return Err(RuntimeError);
    }
    checked(dir.check())?;
    Ok(bytes)
}
async fn release(State(s): State<Arc<StudioState>>, body: Bytes) -> impl IntoResponse {
    let result = (|| {
        let r: ReleaseRequest = decode(&body)?;
        Ok(r)
    })();
    let result = match result {
        Ok(r) => {
            async {
                let plan: Plan = read(&s.config.plan)?;
                let d = plan.delivery()?;
                let archive = s.archive.lock().await;
                let e = recover(&archive, &d, Destination::Archive, r.object)?;
                let policy = checked(acu::verify_current_policy(
                    &read_raw(&s.config.current_policy, 128 * 1024)?,
                    acu_pin(&s.acu)?,
                    now()?,
                ))?;
                let request = checked(hex::decode(r.signed_request_hex))?;
                checked(
                    s.ledger
                        .lock()
                        .await
                        .release(&s.acu, &e, &policy, &request, now()?),
                )
            }
            .await
        }
        Err(e) => Err(e),
    };
    http_result(result)
}
pub async fn serve_studio(path: &Path) -> Result<()> {
    let config: StudioConfiguration = read(path)?;
    validate_server(
        config.version,
        config.listen,
        config.lifetime_seconds,
        &config.output_directory,
    )?;
    let plan: Plan = read(&config.plan)?;
    let job: Job = read(&config.registered_job)?;
    let d = plan.delivery()?;
    let archive = Arc::new(Mutex::new(config.archive.open()?));
    let acu = config.acu.open()?;
    same_enrollment(&*archive.lock().await, &d.spec().archive)?;
    if checked(acu.public_enrollment())?
        != (PublicEnrollment::Acu {
            gate_base: d.spec().acu_gate_base,
            signer: d.spec().acu_signer,
        })
    {
        return Err(RuntimeError);
    }
    let listener = checked(tokio::net::TcpListener::bind(config.listen).await)?;
    let ledger = checked(acu::ReleaseLedger::open(
        &config.release_ledger,
        d.spec().acu_signer,
        d.spec().admission_signer,
    ))?;
    let state = Arc::new(StudioState {
        stop: Arc::new(AtomicBool::new(false)),
        config,
        archive,
        acu,
        ledger: Mutex::new(ledger),
    });
    let app = Router::new()
        .route("/v1/policy", get(policy_get))
        .route("/v1/release", post(release))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn(request_deadline))
        .with_state(state.clone());
    let s = state.clone();
    let receiver = async move {
        let obs = receive(
            &mut *s.archive.lock().await,
            &plan,
            &job,
            Destination::Archive,
            s.config.lifetime_seconds.min(1800),
            &s.config.output_directory,
            &s.stop,
            None,
        )
        .await?;
        let archive = s.archive.lock().await;
        let e = recover(&archive, &d, Destination::Archive, obs.object)?;
        let p = checked(acu::verify_current_policy(
            &read_raw(&s.config.current_policy, 128 * 1024)?,
            acu_pin(&s.acu)?,
            now()?,
        ))?;
        let t = now()?;
        let request =
            checked(archive.create_release_request(&e, &p, t, (t + 120).min(p.expires_unix())))?;
        let grant = checked(s.ledger.lock().await.release(&s.acu, &e, &p, &request, t))?;
        let current = checked(acu::verify_current_policy(
            &read_raw(&s.config.current_policy, 128 * 1024)?,
            acu_pin(&s.acu)?,
            now()?,
        ))?;
        qualified_output(
            &archive,
            &e,
            &current,
            &checked(crate::profile::CommandProfile::parse(
                plan.command_profile.as_bytes(),
            ))?,
            &request,
            &grant,
            obs,
            &s.config.output_directory,
        )
        .map(|_| ())
    };
    let server = axum::serve(listener, app).with_graceful_shutdown(finite_shutdown(
        state.config.lifetime_seconds,
        state.stop.clone(),
    ));
    let server = tokio::time::timeout(
        Duration::from_secs(state.config.lifetime_seconds + 30),
        std::future::IntoFuture::into_future(server),
    );
    let (http, receipt) = tokio::join!(server, receiver);
    checked(checked(http)?)?;
    receipt
}
pub fn sign_policy(
    owner_config: &Path,
    public: &Path,
    spec_path: &Path,
    output: &Path,
) -> Result<()> {
    let owner = checked(owner_cli::open_owner(owner_config, public))?;
    let spec: acu::PolicySpec = read(spec_path)?;
    let bytes = checked(owner.sign_release_policy(&spec))?;
    write_new(output, &bytes)
}
pub(crate) async fn request_bytes(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    body: Option<Vec<u8>>,
    max: usize,
) -> Result<Vec<u8>> {
    let url = checked(reqwest::Url::parse(url))?;
    let mut req = client.request(method, url.clone());
    if let Some(body) = body {
        req = req.header("Content-Type", "application/json").body(body)
    }
    let mut response = checked(req.send().await)?;
    if response.url() != &url
        || response.status() != reqwest::StatusCode::OK
        || response.content_length().is_some_and(|n| n > max as u64)
    {
        return Err(RuntimeError);
    }
    let mut bytes = Vec::new();
    while let Some(b) = checked(response.chunk().await)? {
        if b.len() > max.saturating_sub(bytes.len()) {
            return Err(RuntimeError);
        }
        bytes.extend_from_slice(&b)
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn receiver_readiness_clears_on_all_scope_exits() {
        let flag = AtomicBool::new(true);
        {
            let _guard = OnlineGuard(Some(&flag));
            assert!(flag.load(Ordering::Acquire));
        }
        assert!(!flag.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn an_incomplete_http_body_is_bounded_before_extraction() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/body",
                post(|_b: Bytes| async { "UNEXPECTED_COMPLETE_BODY" }),
            )
            .layer(middleware::from_fn(|r, n| {
                request_deadline_at(r, n, Duration::from_millis(50))
            }));
        let server = tokio::spawn(std::future::IntoFuture::into_future(axum::serve(
            listener, app,
        )));
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n")
            .await
            .unwrap();
        let mut bytes = [0; 2048];
        let response = tokio::time::timeout(Duration::from_secs(2), client.read(&mut bytes)).await;
        client.shutdown().await.unwrap();
        server.abort();
        let _ = server.await;
        let n = response.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&bytes[..n]).starts_with("HTTP/1.1 408"));
    }
}
