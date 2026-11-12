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
    owner_lifecycle::OwnerBudget,
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
use zeroize::{Zeroize, Zeroizing};
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error(
        "CI runtime refused or ended with unconfirmed evidence; preserve its original operation"
    )]
    Refused,
    #[error("{0}")]
    Http(HttpFailure),
    #[error("{0}")]
    Evidence(crate::github::EvidenceError),
    #[error("CI original coding-agent custody requires reconciliation")]
    AgentHeld(crate::idle_agent::IdleAgentError),
}
impl RuntimeError {
    pub fn into_held(self) -> Option<crate::agent_process::HeldAgent> {
        match self {
            Self::AgentHeld(e) => e.into_held(),
            Self::Refused | Self::Http(_) | Self::Evidence(_) => None,
        }
    }
}
impl From<crate::execution::ExecutionError> for RuntimeError {
    fn from(_: crate::execution::ExecutionError) -> Self {
        Self::Refused
    }
}
/// Fixed categories only. Never retain or format a reqwest error, URL, body,
/// token, header or upstream message in an operational diagnostic.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum HttpFailure {
    #[error("HTTP request timed out")]
    Timeout,
    #[error("HTTP connection failed")]
    Connect,
    #[error("HTTP body transfer failed")]
    Body,
    #[error("HTTP network request failed")]
    Network,
    #[error("HTTP endpoint returned status {0}")]
    Status(u16),
    #[error("HTTP response refused")]
    Response,
}
impl HttpFailure {
    pub(crate) fn classify(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else if error.is_connect() {
            Self::Connect
        } else if error.is_body() || error.is_decode() {
            Self::Body
        } else {
            Self::Network
        }
    }
}
pub(crate) type Result<T> = std::result::Result<T, RuntimeError>;
fn checked<T, E>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|_| RuntimeError::Refused)
}
pub(crate) fn now() -> Result<u64> {
    checked(SystemTime::now().duration_since(UNIX_EPOCH)).map(|d| d.as_secs())
}
fn json<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    checked(serde_json::to_vec(v))
}
fn decode<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Result<T> {
    if b.len() > 128 * 1024 {
        return Err(RuntimeError::Refused);
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
    pub(crate) fn pinned_seat_signers(&self) -> Result<crate::recipient_key::SeatSignerDirectory> {
        if self.version != 1
            || self.bootstrap_hint == [0; 32]
            || self.expected_oidc_subject.is_empty()
            || self.expected_oidc_subject.len() > 1024
            || !intent::qualified_instance(&self.scope.instance)
        {
            return Err(RuntimeError::Refused);
        }
        let (seat, _) = self
            .scope
            .instance
            .split_once('#')
            .ok_or(RuntimeError::Refused)?;
        checked(
            crate::recipient_key::SeatSignerDirectory::from_pinned_seats(&[(
                seat,
                self.scope.public_key,
            )]),
        )
    }
    pub(crate) fn intent(&self) -> Result<VerifiedIntent> {
        if self.version != 1
            || self.bootstrap_hint == [0; 32]
            || self.expected_oidc_subject.is_empty()
            || self.expected_oidc_subject.len() > 1024
        {
            return Err(RuntimeError::Refused);
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
    #[cfg(test)]
    pub(crate) fn profiles(&self) -> Result<BoundProfiles> {
        self.profiles_with_revocations(&crate::recipient_key::VerifiedRevocationState::new())
    }
    pub(crate) fn profiles_with_revocations(
        &self,
        revocations: &crate::recipient_key::VerifiedRevocationState,
    ) -> Result<BoundProfiles> {
        checked(BoundProfiles::resolve_with_revocations(
            &self.intent()?,
            self.command_profile.as_bytes(),
            self.delivery_profile.as_bytes(),
            revocations,
            now()?,
        ))
    }
    #[cfg(test)]
    pub(crate) fn delivery(&self) -> Result<DeliveryProfile> {
        self.delivery_with_revocations(&crate::recipient_key::VerifiedRevocationState::new())
    }
    pub(crate) fn delivery_with_revocations(
        &self,
        revocations: &crate::recipient_key::VerifiedRevocationState,
    ) -> Result<DeliveryProfile> {
        let signers = self.pinned_seat_signers()?;
        let d = checked(DeliveryProfile::parse(self.delivery_profile.as_bytes()))?;
        if d.spec().initiating_instance != self.scope.instance {
            return Err(RuntimeError::Refused);
        }
        checked(d.verify_authenticated_recipient_keys(&signers, revocations, now()?))?;
        Ok(d)
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_agent: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_revocations: Option<PathBuf>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_revocations: Option<PathBuf>,
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
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use rustix::fs::{self, AtFlags, Mode, OFlags};
    let dir = checked(CiphertextStore::open(
        path.parent().ok_or(RuntimeError::Refused)?,
    ))?;
    let name = path.file_name().ok_or(RuntimeError::Refused)?;
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
        return Err(RuntimeError::Refused);
    }
    checked(fs::fsync(dir.directory()))?;
    checked(dir.check())
}
fn read<T: Serialize + for<'a> Deserialize<'a>>(p: &Path) -> Result<T> {
    checked(owner_cli::read_public(p))
}
pub(crate) fn load_revocation_statements(
    path: Option<&Path>,
    plan: &Plan,
) -> Result<(
    Vec<crate::recipient_key::SignedRecipientKeyRevocation>,
    crate::recipient_key::VerifiedRevocationState,
)> {
    let mut state = crate::recipient_key::VerifiedRevocationState::new();
    let Some(path) = path else {
        return Ok((Vec::new(), state));
    };
    let statements: Vec<crate::recipient_key::SignedRecipientKeyRevocation> = read(path)?;
    let signers = plan.pinned_seat_signers()?;
    for rev in &statements {
        checked(state.ingest_signed_revocation_struct(rev, &signers))?;
    }
    Ok((statements, state))
}
pub(crate) fn load_revocations(
    path: Option<&Path>,
    plan: &Plan,
) -> Result<crate::recipient_key::VerifiedRevocationState> {
    load_revocation_statements(path, plan).map(|(_, state)| state)
}
fn register(path: &Path, job: &Job) -> Result<()> {
    if path.try_exists().map_err(|_| RuntimeError::Refused)? {
        if read::<Job>(path)? != *job {
            return Err(RuntimeError::Refused);
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
    trace: Option<&crate::http_diagnostics::Request>,
) -> Result<oidc::VerifiedWorkflow> {
    use crate::http_diagnostics::Phase;
    if job.run_id != dispatch.run_id || job.run_attempt != dispatch.run_attempt {
        return Err(RuntimeError::Refused);
    }
    let intent = plan.intent()?;
    let client = checked(GithubEvidenceClient::new())?;
    if let Some(t) = trace {
        t.phase(Phase::ClientPrepared);
    }
    let run = async {
        if let Some(t) = trace {
            t.phase(Phase::RunStarted);
        }
        let r = client
            .verify_dispatch_run(&intent, dispatch.trusted())
            .await
            .map_err(RuntimeError::Evidence);
        if let Some(t) = trace {
            t.result(Phase::RunCompleted, &r);
        }
        r
    };
    let keys = async {
        if let Some(t) = trace {
            t.phase(Phase::KeysStarted);
        }
        let r = client.issuer_keys().await.map_err(RuntimeError::Evidence);
        if let Some(t) = trace {
            t.result(Phase::KeysCompleted, &r);
        }
        r
    };
    let (run, keys) = tokio::join!(run, keys);
    let run = run?;
    let keys = keys?;
    let mut expected = run.expected_oidc(audience, now()?);
    // Exact subject is operator-pinned from repository OIDC configuration, never
    // decoded from the incoming JWT. All run/repository/workflow checks remain.
    expected.subject = &plan.expected_oidc_subject;
    if let Some(t) = trace {
        t.phase(Phase::OidcStarted);
    }
    let verified = checked(oidc::verify_token(token, &keys, expected));
    if let Some(t) = trace {
        t.result(Phase::OidcCompleted, &verified);
    }
    verified
}
fn same_enrollment(owner: &OwnerCustody, d: &PublicDestination) -> Result<()> {
    if checked(owner.public_enrollment())? != PublicEnrollment::Destination(d.clone()) {
        return Err(RuntimeError::Refused);
    }
    Ok(())
}
struct RootState {
    stop: Arc<AtomicBool>,
    config: RootConfiguration,
    admission: OwnerCustody,
    ledger: Mutex<AdmissionLedger>,
    diagnostics: crate::http_diagnostics::Diagnostics,
    recipient_online: AtomicBool,
    recipient: Arc<Mutex<OwnerCustody>>,
    dual_delivery: Mutex<Option<crate::delivery_barrier::VerifiedDualDelivery>>,
    dual_changed: tokio::sync::Notify,
}

async fn delivery_complete(State(s): State<Arc<RootState>>, body: Bytes) -> impl IntoResponse {
    let result = async {
        let request: crate::delivery_barrier::DualDeliveryRequest = decode(&body)?;
        let plan: Plan = read(&s.config.plan)?;
        let revocations = load_revocations(s.config.recipient_revocations.as_deref(), &plan)?;
        let profiles = plan.profiles_with_revocations(&revocations)?;
        let job: Job = read(&s.config.registered_job)?;
        let owner = s.recipient.lock().await;
        let e = recover(
            &owner,
            profiles.delivery(),
            Destination::Recipient,
            request.object,
        )?;
        let proof = checked(crate::delivery_barrier::verify(
            &request,
            &e,
            &profiles,
            &job.registered(),
            now()?,
        ))?;
        drop(owner);
        let mut slot = s.dual_delivery.lock().await;
        let post_wait_revocations =
            load_revocations(s.config.recipient_revocations.as_deref(), &plan)?;
        checked(profiles.reverify_recipient_keys(
            &plan.pinned_seat_signers()?,
            &post_wait_revocations,
            now()?,
        ))?;
        if let Some(prior) = slot.as_ref() {
            if prior.receipt_set_digest() != proof.receipt_set_digest() {
                return Err(RuntimeError::Refused);
            }
        } else {
            write_new(
                &s.config
                    .output_directory
                    .join("verified-dual-delivery-v1.json"),
                &json(&proof)?,
            )?;
            write_new(
                &s.config
                    .output_directory
                    .join("dual-delivery-receipts-v1.json"),
                &json(&request)?,
            )?;
            *slot = Some(proof.clone());
            s.dual_changed.notify_one();
        }
        json(&proof)
    }
    .await;
    http_result(result)
}

async fn wait_dual(
    s: &RootState,
    obs: &ArtifactObservation,
    budget: &OwnerBudget,
) -> Result<crate::delivery_barrier::VerifiedDualDelivery> {
    loop {
        if let Some(proof) = s.dual_delivery.lock().await.clone() {
            if !proof.matches(obs.run_id, obs.run_attempt, obs.envelope_digest, obs.object) {
                return Err(RuntimeError::Refused);
            }
            return Ok(proof);
        }
        tokio::select! { _=s.dual_changed.notified()=>{}, _=budget.work_stopped()=>return Err(RuntimeError::Refused) }
    }
}
async fn bootstrap(State(s): State<Arc<RootState>>, body: Bytes) -> impl IntoResponse {
    let result = async {
        let request: BootstrapRequest = decode(&body)?;
        let plan: Plan = read(&s.config.plan)?;
        let dispatch: Dispatch = read(&s.config.dispatch)?;
        let audience = bootstrap_audience(plan.bootstrap_hint, &request.job)?;
        verify_workflow(
            &plan,
            &dispatch,
            &request.job,
            &request.token,
            &audience,
            None,
        )
        .await?;
        let revocations = load_revocations(s.config.recipient_revocations.as_deref(), &plan)?;
        plan.profiles_with_revocations(&revocations)?
            .validate_registered_job(&request.job.registered())
            .map_err(|_| RuntimeError::Refused)?;
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
        return Err(RuntimeError::Refused);
    }
    let plan: Plan = read(&s.config.plan)?;
    let revocations = load_revocations(s.config.recipient_revocations.as_deref(), &plan)?;
    let _ = plan.delivery_with_revocations(&revocations)?;
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
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationStatusRequest {
    pub nonce: [u8; 32],
}
async fn revocations_status(State(s): State<Arc<RootState>>, body: Bytes) -> impl IntoResponse {
    http_result((|| {
        let r: RevocationStatusRequest = decode(&body)?;
        let plan: Plan = read(&s.config.plan)?;
        let intent = plan.intent()?;
        let (statements, _) =
            load_revocation_statements(s.config.recipient_revocations.as_deref(), &plan)?;
        checked(
            s.admission
                .certify_revocation_status(&intent, r.nonce, statements),
        )
    })())
}
async fn challenge(State(s): State<Arc<RootState>>, body: Bytes) -> impl IntoResponse {
    use crate::http_diagnostics::Phase;
    let trace = s.diagnostics.request();
    trace.phase(Phase::Entered);
    let result = async {
        let r: BootstrapRequest = decode(&body)?;
        trace.phase(Phase::Decoded);
        is_ready(&s, &r.job)?;
        trace.phase(Phase::Ready);
        let plan: Plan = read(&s.config.plan)?;
        let dispatch: Dispatch = read(&s.config.dispatch)?;
        trace.phase(Phase::ConfigurationRead);
        verify_workflow(
            &plan,
            &dispatch,
            &r.job,
            &r.token,
            &bootstrap_audience(plan.bootstrap_hint, &r.job)?,
            Some(&trace),
        )
        .await?;
        trace.phase(Phase::WorkflowVerified);
        trace.phase(Phase::LedgerWait);
        let mut ledger = s.ledger.lock().await;
        let revocations = load_revocations(s.config.recipient_revocations.as_deref(), &plan)?;
        let _ = plan.profiles_with_revocations(&revocations)?;
        let intent = plan.intent()?;
        let t = now()?;
        let exp = intent.spec().expires_unix.min(t + 300);
        trace.phase(Phase::LedgerIssue);
        let c = checked(ledger.issue(
            &intent,
            r.job.keys(),
            r.job.run_id,
            r.job.run_attempt,
            t,
            exp,
        ))?;
        drop(ledger);
        trace.phase(Phase::LedgerIssued);
        json(&ChallengeResponse {
            nonce: c.nonce,
            audience: c.audience,
            expires_unix: c.expires_unix,
        })
    }
    .await;
    trace.result(
        if result.is_ok() {
            Phase::ResponseReady
        } else {
            Phase::Held
        },
        &result,
    );
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
        let workflow = verify_workflow(&plan, &dispatch, &r.job, &r.token, &audience, None).await?;
        let signature: [u8; 64] = checked(checked(hex::decode(&r.signature_hex))?.try_into())?;
        let binding = checked(runner_binding::verify_runner_proof(
            intent,
            workflow,
            r.job.keys(),
            r.nonce,
            signature,
            now()?,
        ))?;
        let mut ledger = s.ledger.lock().await;
        let revocations = load_revocations(s.config.recipient_revocations.as_deref(), &plan)?;
        let _ = plan.profiles_with_revocations(&revocations)?;
        let admission = checked(ledger.consume(&binding, r.nonce, now()?))?;
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
        return Err(RuntimeError::Refused);
    }
    checked(CiphertextStore::open(outputs)).map(|_| ())
}
static INFLIGHT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);
pub(crate) const OWNER_HANDLER_BOUND: Duration = Duration::from_secs(25);
pub(crate) const OWNER_POST_BOUND: Duration = Duration::from_secs(30);
async fn request_deadline(request: axum::extract::Request, next: Next) -> Response {
    request_deadline_at(request, next, OWNER_HANDLER_BOUND).await
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
    revocations_path: Option<&Path>,
    job: &Job,
    role: Destination,
    budget: &OwnerBudget,
    outputs: &Path,
    online: Option<&AtomicBool>,
) -> Result<ArtifactObservation> {
    let initial_revocations = load_revocations(revocations_path, plan)?;
    let profiles = plan.profiles_with_revocations(&initial_revocations)?;
    let pinned_signers = plan.pinned_seat_signers()?;
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
    let bind = async {
        checked(
            owner
                .bind_destination_pair(
                    checked(iroh::EndpointId::from_bytes(&peer))?,
                    &d.relay_origin,
                    &d.relay_origin,
                )
                .await,
        )
    };
    let pair = budget.bind(bind, |pair| pair.close()).await?;
    if let Some(online) = online {
        online.store(true, Ordering::Release);
    }
    let online_guard = OnlineGuard(online);
    let mut observation = None;
    let remaining = budget
        .work_until
        .saturating_duration_since(tokio::time::Instant::now())
        .min(Duration::from_secs(1800));
    let operation = pair.receive_once(remaining, |claim| {
        let result: Result<Vec<u8>> = (|| {
            let live_revocations = load_revocations(revocations_path, plan)?;
            let t = now()?;
            checked(profiles.reverify_recipient_keys(&pinned_signers, &live_revocations, t))?;
            let sealed = checked(envelope::parse_storage_blob(&claim.ciphertext))?;
            let bound = checked(profiles.authenticate_current_artifact(
                &claim.manifest,
                sealed,
                &job.registered(),
                t,
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
    let transfer =
        tokio::select! {r=operation=>r,_=budget.work_stopped()=>Err(TransferError::Deadline)};
    drop(online_guard);
    budget.finish_close(pair.close()).await?;
    checked(transfer)?;
    let (object, envelope_digest, admission_sha256) = observation.ok_or(RuntimeError::Refused)?;
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
struct QualifiedCapture {
    observation: ArtifactObservation,
    verified: crate::capture_read::VerifiedCapture,
    plaintext: Zeroizing<Vec<u8>>,
    read_authorization: crate::agent_read::ReadAuthorization,
}

#[allow(clippy::too_many_arguments)]
fn qualified_output(
    owner: &OwnerCustody,
    plan: &Plan,
    revocations_path: Option<&Path>,
    envelope: &authorization::AdmissionBoundEnvelope,
    policy: &acu::CurrentPolicy,
    profile: &crate::profile::CommandProfile,
    request: &[u8],
    grant: &[u8],
    mut obs: ArtifactObservation,
    outputs: &Path,
) -> Result<QualifiedCapture> {
    let grant = checked(acu::verify_grant(grant, request, envelope, policy, now()?))?;
    let plaintext = checked(owner.open_payload_from_grant(envelope, &grant, policy, now()?))?;
    // Parse and traverse the complete sealed capture before recording qualified
    // read. Content is untrusted evidence, never instructions or repair authority.
    let verified = crate::capture_read::validate(&plaintext, envelope, profile)?;
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
    write_new(
        &outputs.join("qualified-command-outcome.json"),
        &json(&serde_json::json!({
            "classification": "AUTHORIZED_CAPTURE_OUTCOME_NOT_WAKE_OR_REPAIR_AUTHORITY",
            "outcome": verified.outcome(),
            "failed": verified.failed(),
        }))?,
    )?;
    Ok(QualifiedCapture {
        observation: obs,
        verified,
        plaintext,
        read_authorization: crate::agent_read::ReadAuthorization::qualified_for_plan(
            grant.expires_unix(),
            policy,
            plan.clone(),
            revocations_path.map(Path::to_path_buf),
        ),
    })
}
async fn recipient_read(
    owner: &OwnerCustody,
    plan: &Plan,
    revocations_path: Option<&Path>,
    obs: ArtifactObservation,
    outputs: &Path,
) -> Result<QualifiedCapture> {
    let initial_revocations = load_revocations(revocations_path, plan)?;
    let delivery = plan.delivery_with_revocations(&initial_revocations)?;
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
    let pre_request_revocations = load_revocations(revocations_path, plan)?;
    let _ = plan.delivery_with_revocations(&pre_request_revocations)?;
    let t = now()?;
    let policy = checked(acu::verify_current_policy(
        &policy_bytes,
        delivery.spec().acu_signer,
        t,
    ))?;
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
    let pre_open_revocations = load_revocations(revocations_path, plan)?;
    let _ = plan.delivery_with_revocations(&pre_open_revocations)?;
    let current = checked(acu::verify_current_policy(
        &current_bytes,
        delivery.spec().acu_signer,
        now()?,
    ))?;
    qualified_output(
        owner,
        plan,
        revocations_path,
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
/// process is spawned for another seat. Only successful closure is clean; an
/// unconfirmed bind/close returns held and the CLI parent observes worker exit.
pub async fn serve_root(path: &Path) -> Result<()> {
    let config: RootConfiguration = read(path)?;
    validate_server(
        config.version,
        config.listen,
        config.lifetime_seconds,
        &config.output_directory,
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    let budget = OwnerBudget::new(Duration::from_secs(config.lifetime_seconds), stop.clone());
    let recipient = config.recipient.open()?;
    let admission = config.admission.open()?;
    let plan: Plan = read(&config.plan)?;
    let startup_revocations = load_revocations(config.recipient_revocations.as_deref(), &plan)?;
    let d = plan.delivery_with_revocations(&startup_revocations)?;
    if checked(admission.public_enrollment())?
        != (PublicEnrollment::Admission {
            signer: d.spec().admission_signer,
        })
    {
        return Err(RuntimeError::Refused);
    }
    same_enrollment(&recipient, &d.spec().recipient)?;
    let listener = checked(tokio::net::TcpListener::bind(config.listen).await)?;
    let state = Arc::new(RootState {
        stop,
        ledger: Mutex::new(checked(AdmissionLedger::open(&config.ledger))?),
        diagnostics: crate::http_diagnostics::Diagnostics::best_effort(&config.output_directory),
        config,
        admission,
        recipient_online: AtomicBool::new(false),
        recipient: Arc::new(Mutex::new(recipient)),
        dual_delivery: Mutex::new(None),
        dual_changed: tokio::sync::Notify::new(),
    });
    let app = Router::new()
        .route("/v1/bootstrap", post(bootstrap))
        .route("/v1/ready", get(readiness))
        .route("/v1/revocations", post(revocations_status))
        .route("/v1/challenge", post(challenge))
        .route("/v1/admit", post(admit))
        .route("/v1/delivery-complete", post(delivery_complete))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn(request_deadline))
        .with_state(state.clone());
    let s = state.clone();
    let receiver_budget = budget.clone();
    let receiver = async move {
        let job = loop {
            if let Ok(j) = read::<Job>(&s.config.registered_job) {
                break j;
            }
            if receiver_budget.stopped() {
                return Err(RuntimeError::Refused);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        let plan: Plan = read(&s.config.plan)?;
        // Readiness is set only after the exact owner bind actually completes.
        let obs = {
            let mut owner = s.recipient.lock().await;
            receive(
                &mut owner,
                &plan,
                s.config.recipient_revocations.as_deref(),
                &job,
                Destination::Recipient,
                &receiver_budget,
                &s.config.output_directory,
                Some(&s.recipient_online),
            )
            .await?
        };
        s.recipient_online.store(false, Ordering::Release);
        // Both signed native storage proofs precede the CURRENT ACU request.
        // Release the owner mutex while waiting so the receipt-only HTTP
        // handler can independently reopen this already-native stored object.
        let dual = wait_dual(&s, &obs, &receiver_budget).await?;
        let recipient = s.recipient.lock().await;
        let qualified = tokio::select! {
            result = recipient_read(&recipient, &plan, s.config.recipient_revocations.as_deref(), obs, &s.config.output_directory) => result,
            _ = receiver_budget.work_stopped() => Err(RuntimeError::Refused),
        }?;
        if let Some(agent) = &s.config.idle_agent {
            let wake_revocations =
                load_revocations(s.config.recipient_revocations.as_deref(), &plan)?;
            let envelope = recover(
                &recipient,
                &plan.delivery_with_revocations(&wake_revocations)?,
                Destination::Recipient,
                qualified.observation.object,
            )?;
            let command = checked(crate::profile::CommandProfile::parse(
                plan.command_profile.as_bytes(),
            ))?;
            drop(recipient);
            crate::idle_agent::wake(
                agent,
                crate::idle_agent::QualifiedWake {
                    plan: &plan,
                    recipient_revocations: s.config.recipient_revocations.as_deref(),
                    envelope: &envelope,
                    verified: &qualified.verified,
                    plaintext: &qualified.plaintext,
                    observation: &qualified.observation,
                    command_profile: &command,
                    budget: &receiver_budget,
                    dual: &dual,
                    read_authorization: &qualified.read_authorization,
                },
            )
            .await
            .map_err(RuntimeError::AgentHeld)?;
        }
        Ok(())
    };
    run_owner(listener, app, budget, receiver).await
}
async fn run_owner<F: std::future::Future<Output = Result<()>>>(
    listener: tokio::net::TcpListener,
    app: Router,
    budget: OwnerBudget,
    receiver: F,
) -> Result<()> {
    let shutdown = async {
        tokio::select! {
            _ = budget.work_stopped() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
        budget.stop();
    };
    let receiver = async {
        let result = receiver.await;
        if result.is_err() {
            budget.stop();
        }
        result
    };
    let server = async {
        let result = crate::owner_http::serve(listener, app, budget.clone()).await;
        if result.is_err() {
            budget.stop();
        }
        result
    };
    let (http, receipt, ()) = tokio::join!(server, receiver, shutdown);
    owner_outcome(http, receipt)
}
pub(crate) fn owner_outcome(http: Result<()>, receipt: Result<()>) -> Result<()> {
    // A separate HTTP error must never drop the receiver's original custody.
    match receipt {
        Err(e @ RuntimeError::AgentHeld(_)) => Err(e),
        other => {
            http?;
            other
        }
    }
}

struct StudioState {
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
        _ => Err(RuntimeError::Refused),
    }
}
fn read_raw(path: &Path, max: usize) -> Result<Vec<u8>> {
    use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
    let dir = checked(CiphertextStore::open(
        path.parent().ok_or(RuntimeError::Refused)?,
    ))?;
    let name = path.file_name().ok_or(RuntimeError::Refused)?;
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
        return Err(RuntimeError::Refused);
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
        return Err(RuntimeError::Refused);
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
                let request = checked(hex::decode(r.signed_request_hex))?;
                let archive = s.archive.lock().await;
                let mut ledger = s.ledger.lock().await;
                let plan: Plan = read(&s.config.plan)?;
                let revocations =
                    load_revocations(s.config.recipient_revocations.as_deref(), &plan)?;
                let d = plan.delivery_with_revocations(&revocations)?;
                let e = recover(&archive, &d, Destination::Archive, r.object)?;
                let t = now()?;
                let policy = checked(acu::verify_current_policy(
                    &read_raw(&s.config.current_policy, 128 * 1024)?,
                    acu_pin(&s.acu)?,
                    t,
                ))?;
                checked(ledger.release(&s.acu, &e, &policy, &request, t))
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
    let startup_revocations = load_revocations(config.recipient_revocations.as_deref(), &plan)?;
    let d = plan.delivery_with_revocations(&startup_revocations)?;
    let stop = Arc::new(AtomicBool::new(false));
    let budget = OwnerBudget::new(Duration::from_secs(config.lifetime_seconds), stop.clone());
    let archive = Arc::new(Mutex::new(config.archive.open()?));
    let acu = config.acu.open()?;
    same_enrollment(&*archive.lock().await, &d.spec().archive)?;
    if checked(acu.public_enrollment())?
        != (PublicEnrollment::Acu {
            gate_base: d.spec().acu_gate_base.clone(),
            signer: d.spec().acu_signer,
        })
    {
        return Err(RuntimeError::Refused);
    }
    let listener = checked(tokio::net::TcpListener::bind(config.listen).await)?;
    let ledger = checked(acu::ReleaseLedger::open(
        &config.release_ledger,
        d.spec().acu_signer,
        d.spec().admission_signer,
    ))?;
    let state = Arc::new(StudioState {
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
    let receiver_budget = budget.clone();
    let receiver = async move {
        let obs = receive(
            &mut *s.archive.lock().await,
            &plan,
            s.config.recipient_revocations.as_deref(),
            &job,
            Destination::Archive,
            &receiver_budget,
            &s.config.output_directory,
            None,
        )
        .await?;
        let archive = s.archive.lock().await;
        let mut ledger = s.ledger.lock().await;
        let pre_release_revocations =
            load_revocations(s.config.recipient_revocations.as_deref(), &plan)?;
        let d = plan.delivery_with_revocations(&pre_release_revocations)?;
        let e = recover(&archive, &d, Destination::Archive, obs.object)?;
        let t = now()?;
        let p = checked(acu::verify_current_policy(
            &read_raw(&s.config.current_policy, 128 * 1024)?,
            acu_pin(&s.acu)?,
            t,
        ))?;
        let request =
            checked(archive.create_release_request(&e, &p, t, (t + 120).min(p.expires_unix())))?;
        let grant = checked(ledger.release(&s.acu, &e, &p, &request, t))?;
        drop(ledger);
        let pre_open_revocations =
            load_revocations(s.config.recipient_revocations.as_deref(), &plan)?;
        let _ = plan.delivery_with_revocations(&pre_open_revocations)?;
        let current = checked(acu::verify_current_policy(
            &read_raw(&s.config.current_policy, 128 * 1024)?,
            acu_pin(&s.acu)?,
            now()?,
        ))?;
        qualified_output(
            &archive,
            &plan,
            s.config.recipient_revocations.as_deref(),
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
    run_owner(listener, app, budget, receiver).await
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
    request_bytes_inner(client, method, url, body, max, None).await
}
/// The server may spend its whole handler budget before returning a refusal.
/// Leave a bounded network margin instead of racing that work with a shorter
/// client deadline. This does not retry a POST or renew admission authority.
pub(crate) async fn request_owner_post(
    client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
    max: usize,
) -> Result<Vec<u8>> {
    request_bytes_inner(
        client,
        reqwest::Method::POST,
        url,
        Some(body),
        max,
        Some(OWNER_POST_BOUND),
    )
    .await
}
async fn request_bytes_inner(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    body: Option<Vec<u8>>,
    max: usize,
    bound: Option<Duration>,
) -> Result<Vec<u8>> {
    let url = checked(reqwest::Url::parse(url))?;
    let mut req = client.request(method, url.clone());
    if let Some(bound) = bound {
        req = req.timeout(bound);
    }
    if let Some(body) = body {
        req = req.header("Content-Type", "application/json").body(body)
    }
    let mut response = req
        .send()
        .await
        .map_err(|e| RuntimeError::Http(HttpFailure::classify(&e)))?;
    if response.url() != &url || response.content_length().is_some_and(|n| n > max as u64) {
        return Err(RuntimeError::Http(HttpFailure::Response));
    }
    if response.status() != reqwest::StatusCode::OK {
        return Err(RuntimeError::Http(HttpFailure::Status(
            response.status().as_u16(),
        )));
    }
    let mut bytes = Vec::new();
    while let Some(b) = response
        .chunk()
        .await
        .map_err(|e| RuntimeError::Http(HttpFailure::classify(&e)))?
    {
        if b.len() > max.saturating_sub(bytes.len()) {
            return Err(RuntimeError::Http(HttpFailure::Response));
        }
        bytes.extend_from_slice(&b)
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn http_fixture_client(bound: Duration) -> reqwest::Client {
        // The local HTTP fixture still needs an explicit provider when the
        // dependency enables rustls-no-provider. Never mutate the global one.
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .timeout(bound)
            .build()
            .unwrap()
    }
    #[tokio::test]
    async fn owner_post_can_return_a_bounded_server_result_after_client_default_expires() {
        assert!(OWNER_POST_BOUND >= OWNER_HANDLER_BOUND + Duration::from_secs(5));
        assert!(OWNER_HANDLER_BOUND > crate::github::REQUEST_BOUND);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            tokio::time::sleep(Duration::from_millis(60)).await;
            stream
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let client = http_fixture_client(Duration::from_millis(20));
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            request_owner_post(
                &client,
                &format!("http://{addr}/owned"),
                b"{}".to_vec(),
                4096,
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        server.await.unwrap();
        // The actual server result arrives after the shorter default; no retry.
        assert!(matches!(
            error,
            RuntimeError::Http(HttpFailure::Status(403))
        ));
    }
    #[tokio::test]
    async fn http_refusal_reports_only_numeric_status_not_response_or_url() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 34\r\nConnection: close\r\n\r\nTOKEN_NONCE_AND_UPSTREAM_SENTINEL_42").await.unwrap();
        });
        let error = request_bytes(
            &http_fixture_client(Duration::from_secs(2)),
            reqwest::Method::GET,
            &format!("http://{addr}/TOKEN_NONCE_AND_UPSTREAM_SENTINEL_42"),
            None,
            4096,
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert!(matches!(
            error,
            RuntimeError::Http(HttpFailure::Status(403))
        ));
        assert_eq!(error.to_string(), "HTTP endpoint returned status 403");
        assert!(!format!("{error:?}").contains("SENTINEL"));
    }
    #[tokio::test]
    async fn http_timeout_discards_reqwest_url_and_keeps_fixed_category() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let client = http_fixture_client(Duration::from_millis(25));
        let error = request_bytes(
            &client,
            reqwest::Method::GET,
            &format!("http://{addr}/PRIVATE_TOKEN_SENTINEL"),
            None,
            4096,
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert!(matches!(error, RuntimeError::Http(HttpFailure::Timeout)));
        assert_eq!(error.to_string(), "HTTP request timed out");
        assert!(!format!("{error:?}").contains("SENTINEL"));
    }
    #[tokio::test]
    async fn truncated_http_body_has_body_category_without_retaining_content() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nBODY_TOKEN_SENTINEL").await.unwrap();
        });
        let error = request_bytes(
            &http_fixture_client(Duration::from_secs(2)),
            reqwest::Method::GET,
            &format!("http://{addr}/PRIVATE_TOKEN_SENTINEL"),
            None,
            4096,
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert!(matches!(error, RuntimeError::Http(HttpFailure::Body)));
        assert_eq!(error.to_string(), "HTTP body transfer failed");
        assert!(!format!("{error:?}").contains("SENTINEL"));
    }
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
        let budget = OwnerBudget::test(Duration::from_millis(150), Duration::from_millis(150));
        let server = tokio::spawn(crate::owner_http::serve(listener, app, budget));
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n")
            .await
            .unwrap();
        let mut bytes = [0; 2048];
        let response = tokio::time::timeout(Duration::from_secs(2), client.read(&mut bytes)).await;
        client.shutdown().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
        let n = response.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&bytes[..n]).starts_with("HTTP/1.1 408"));
    }
    #[test]
    fn plan_enforces_pinned_seat_signer_and_live_revocation_file() {
        use crate::{
            envelope::{AcuGateKey, DestinationKey, ResponseKey},
            intent::IntentSpec,
            profile::{CommandProfileSpec, DeliveryProfileSpec},
            recipient_key::{
                RecipientKeyPurpose, SignedRecipientKeyRevocation,
                sign_public_key_enrollment_descriptor, sign_revocation_statement,
            },
        };
        use ed25519_dalek::Signer;
        use std::os::unix::fs::PermissionsExt;

        let t = now().unwrap();
        let ed = |n| *iroh::SecretKey::from_bytes(&[n; 32]).public().as_bytes();
        let seat_sk = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
        let cmd_spec = CommandProfileSpec {
            version: 1,
            execution_id: [1; 32],
            rust_image: format!("docker.io/library/rust@sha256:{}", "a".repeat(64)),
            fixture_sha256: Sha256::digest(b"fixture").into(),
            timeout_seconds: 60,
            isolation: "UNPRIVILEGED_NETWORKLESS_DOCKER_FIXED_RUST_FIXTURE_V1".into(),
        };
        let cmd_bytes = serde_json::to_vec(&cmd_spec).unwrap();
        let cmd_digest: [u8; 32] = Sha256::digest(&cmd_bytes).into();

        let recipient = PublicDestination {
            role: Destination::Recipient,
            store_id: [2; 32],
            store_binding: [3; 32],
            psk: DestinationKey::generate(Destination::Recipient)
                .unwrap()
                .public(),
            response_base: ResponseKey::generate(Destination::Recipient)
                .unwrap()
                .public(),
            receipt_signer: ed(4),
            release_request_signer: ed(4),
            transport: ed(5),
        };
        let psk_bind = sign_public_key_enrollment_descriptor(
            "WORKHORSE",
            "wh-runtime-psk-e1",
            1,
            RecipientKeyPurpose::AcuRecipientPsk,
            &recipient.psk,
            t.saturating_sub(60),
            t + 3_600,
            &seat_sk,
        )
        .unwrap();
        let resp_bind = sign_public_key_enrollment_descriptor(
            "WORKHORSE",
            "wh-runtime-resp-e1",
            1,
            RecipientKeyPurpose::AcuRecipientResponseBase,
            &recipient.response_base,
            t.saturating_sub(60),
            t + 3_600,
            &seat_sk,
        )
        .unwrap();
        let archive = PublicDestination {
            role: Destination::Archive,
            store_id: [6; 32],
            store_binding: [7; 32],
            psk: DestinationKey::generate(Destination::Archive)
                .unwrap()
                .public(),
            response_base: ResponseKey::generate(Destination::Archive)
                .unwrap()
                .public(),
            receipt_signer: ed(8),
            release_request_signer: ed(8),
            transport: ed(9),
        };
        let deliv_spec = DeliveryProfileSpec {
            version: 1,
            repository_id: 42,
            initiating_instance: "WORKHORSE#runtime-test".into(),
            recipient,
            recipient_psk_binding: Some(psk_bind),
            recipient_response_base_binding: Some(resp_bind),
            recipient_key_revocations: Vec::new(),
            archive,
            acu_gate_base: AcuGateKey::generate().unwrap().public(),
            acu_signer: ed(10),
            admission_signer: ed(11),
            relay_origin: "https://relay-rt.trycloudflare.com/".into(),
            admission_origin: "https://admission-rt.trycloudflare.com/".into(),
            acu_origin: "https://acu-rt.trycloudflare.com/".into(),
            command_profile_sha256: cmd_digest,
            original_policy_sha256: [12; 32],
            original_policy_epoch: 1,
            expires_unix: t + 1_800,
            customer_custody_boundary: "CUSTOMER_ACU_AND_ARCHIVE_SHARED_HOST_UID".into(),
        };
        let deliv_bytes = serde_json::to_vec(&deliv_spec).unwrap();
        let deliv_digest: [u8; 32] = Sha256::digest(&deliv_bytes).into();

        let intent_spec = IntentSpec {
            schema: "chinwag.ci-dispatch-intent.v1".into(),
            repository: "emunlabs/chinwag".into(),
            repository_id: 42,
            source_commit: hex::encode([13; 20]),
            workflow_ref:
                "emunlabs/chinwag/.github/workflows/chinwag-core-ci-and-merge.yml@refs/heads/main"
                    .into(),
            workflow_commit: hex::encode([13; 20]),
            recipient_instance: "WORKHORSE#runtime-test".into(),
            delivery_profile_sha256: hex::encode(deliv_digest),
            command_sha256: hex::encode(cmd_digest),
            nonce: hex::encode([14; 32]),
            expires_unix: t + 900,
        };
        let body = serde_json::to_string(&intent_spec).unwrap();
        let id = "bus-runtime-test";
        let sender = "WORKHORSE#runtime-test";
        let to = "ADMISSION#runtime-test";
        let room = "#eng";
        let task = "CHWG-0267";
        let key_hex = hex::encode(seat_sk.verifying_key().to_bytes());
        let ts_str = t.to_string();
        let signed = format!(
            "chinwag-bus-sig-v2|{}",
            [id, ts_str.as_str(), sender, to, room, task, body.as_str()]
                .map(|s| format!("{}:{s}", s.len()))
                .join("|")
        );
        let digest = hex::encode(Sha256::digest(
            format!("chinwag-bus-v1|{t}|{room}|{sender}|{key_hex}|{to}|{task}|{body}").as_bytes(),
        ));
        let original = serde_json::json!({
            "id": id,
            "ts_unix": t,
            "sender": sender,
            "sender_endpoint_id": key_hex,
            "to": to,
            "room": room,
            "task_id": task,
            "body": body,
            "digest_sha256": digest,
            "pubkey_ed25519": key_hex,
            "signature_ed25519": hex::encode(seat_sk.sign(signed.as_bytes()).to_bytes()),
        });
        let plan = Plan {
            version: 1,
            scope: Scope {
                instance: sender.into(),
                public_key: seat_sk.verifying_key().to_bytes(),
                addressee: to.into(),
                task_id: task.into(),
                room: room.into(),
            },
            native_original: serde_json::to_string(&original).unwrap(),
            command_profile: String::from_utf8(cmd_bytes).unwrap(),
            delivery_profile: String::from_utf8(deliv_bytes).unwrap(),
            expected_oidc_subject: "repo:emunlabs/chinwag:ref:refs/heads/main".into(),
            bootstrap_hint: [15; 32],
        };

        // Valid Plan resolves both profiles() and delivery() cleanly:
        let initial_profiles = plan.profiles().unwrap();
        let signers = plan.pinned_seat_signers().unwrap();
        let (empty_statements, empty_rev) = load_revocation_statements(None, &plan).unwrap();
        assert!(empty_statements.is_empty());
        assert!(
            initial_profiles
                .reverify_recipient_keys(&signers, &empty_rev, t)
                .is_ok()
        );
        assert!(plan.delivery().is_ok());

        // Mismatched scope.public_key causes Plan::delivery() to fail closed even without intent():
        let mut wrong_pin_plan = plan.clone();
        wrong_pin_plan.scope.public_key = ed(99);
        assert!(wrong_pin_plan.delivery().is_err());

        // Mid-flight live signed revocation update loaded via load_revocation_statements causes
        // already-resolved BoundProfiles::reverify_recipient_keys AND fresh Plan resolution to refuse:
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let canonical_dir = dir.path().canonicalize().unwrap();
        let rev_path = canonical_dir.join("revocations.json");
        let rev_raw =
            sign_revocation_statement("WORKHORSE", 1, &["wh-runtime-psk-e1".into()], t, &seat_sk)
                .unwrap();
        let rev_struct: SignedRecipientKeyRevocation = serde_json::from_slice(&rev_raw).unwrap();
        write_new(&rev_path, &serde_json::to_vec(&vec![rev_struct]).unwrap()).unwrap();

        let (statements, loaded) = load_revocation_statements(Some(&rev_path), &plan).unwrap();
        assert_eq!(statements.len(), 1);
        assert!(
            initial_profiles
                .reverify_recipient_keys(&signers, &loaded, t)
                .is_err()
        );
        assert!(plan.profiles_with_revocations(&loaded).is_err());
        assert!(plan.delivery_with_revocations(&loaded).is_err());

        // Forged / wrong-signer revocation statement in revocations file fails closed:
        let bad_rev_path = canonical_dir.join("bad-revocations.json");
        write_new(&bad_rev_path, &serde_json::to_vec(&statements).unwrap()).unwrap();
        assert!(load_revocation_statements(Some(&bad_rev_path), &wrong_pin_plan).is_err());

        // Challenge-bound admission-signed live revocation status (/v1/revocations) round-trips
        // and rejects nonce replay, wrong admission signer, wrong intent digest, or stripped JSON:
        let adm_secret = iroh::SecretKey::from_bytes(&[42_u8; 32]);
        let adm_pin = *adm_secret.public().as_bytes();
        let intent = plan.intent().unwrap();
        let nonce = [77_u8; 32];
        let signed_empty = crate::authorization::certify_revocation_status(
            &intent,
            nonce,
            Vec::new(),
            &adm_secret,
        )
        .unwrap();
        let mut runner_rev = crate::recipient_key::VerifiedRevocationState::new();
        assert!(
            crate::authorization::verify_revocation_status(
                &signed_empty,
                adm_pin,
                *intent.original_digest(),
                &plan.scope.instance,
                nonce,
                &signers,
                &mut runner_rev,
            )
            .is_ok()
        );
        // Replaying with a different challenge nonce fails closed:
        assert!(
            crate::authorization::verify_revocation_status(
                &signed_empty,
                adm_pin,
                *intent.original_digest(),
                &plan.scope.instance,
                [78_u8; 32],
                &signers,
                &mut runner_rev,
            )
            .is_err()
        );
        // Wrong admission signer pin fails closed:
        assert!(
            crate::authorization::verify_revocation_status(
                &signed_empty,
                ed(91),
                *intent.original_digest(),
                &plan.scope.instance,
                nonce,
                &signers,
                &mut runner_rev,
            )
            .is_err()
        );
        // Signed non-empty revocation status propagates into runner's grow-only state and refuses profiles:
        let nonce2 = [79_u8; 32];
        let signed_revoked = crate::authorization::certify_revocation_status(
            &intent,
            nonce2,
            statements,
            &adm_secret,
        )
        .unwrap();
        assert!(
            crate::authorization::verify_revocation_status(
                &signed_revoked,
                adm_pin,
                *intent.original_digest(),
                &plan.scope.instance,
                nonce2,
                &signers,
                &mut runner_rev,
            )
            .is_ok()
        );
        assert!(
            initial_profiles
                .reverify_recipient_keys(&signers, &runner_rev, t)
                .is_err()
        );
        // Even if a subsequent status returns empty statements, runner's grow-only state stays revoked:
        let nonce3 = [80_u8; 32];
        let signed_after = crate::authorization::certify_revocation_status(
            &intent,
            nonce3,
            Vec::new(),
            &adm_secret,
        )
        .unwrap();
        assert!(
            crate::authorization::verify_revocation_status(
                &signed_after,
                adm_pin,
                *intent.original_digest(),
                &plan.scope.instance,
                nonce3,
                &signers,
                &mut runner_rev,
            )
            .is_ok()
        );
        assert!(
            initial_profiles
                .reverify_recipient_keys(&signers, &runner_rev, t)
                .is_err()
        );

        // Repeated cumulative multi-entry snapshots `[r1(t1), r2(t2)]` (`t1 < t2`) for retired
        // keys refresh idempotently across multiple runner phases without rejecting `r1(t1)`:
        let r1: SignedRecipientKeyRevocation = serde_json::from_slice(
            &sign_revocation_statement("WORKHORSE", 1, &["wh-retired-1".into()], t - 20, &seat_sk)
                .unwrap(),
        )
        .unwrap();
        let r2: SignedRecipientKeyRevocation = serde_json::from_slice(
            &sign_revocation_statement("WORKHORSE", 1, &["wh-retired-2".into()], t - 10, &seat_sk)
                .unwrap(),
        )
        .unwrap();
        let mut cumulative_rev = crate::recipient_key::VerifiedRevocationState::new();
        for n in [[81_u8; 32], [82_u8; 32], [83_u8; 32]] {
            let snap = crate::authorization::certify_revocation_status(
                &intent,
                n,
                vec![r1.clone(), r2.clone()],
                &adm_secret,
            )
            .unwrap();
            assert!(
                crate::authorization::verify_revocation_status(
                    &snap,
                    adm_pin,
                    *intent.original_digest(),
                    &plan.scope.instance,
                    n,
                    &signers,
                    &mut cumulative_rev,
                )
                .is_ok()
            );
            assert!(
                initial_profiles
                    .reverify_recipient_keys(&signers, &cumulative_rev, t)
                    .is_ok()
            );
        }

        // ReadAuthorization::qualified_for_plan enforces live recipient revocations after ACU
        // policy fetch (`current_until`), refusing wake/spawn/FIFO read once revoked:
        let acu_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(acu_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let acu_canon = acu_dir.path().canonicalize().unwrap();
        let acu_owner =
            OwnerCustody::create_new(&acu_canon, crate::custody::OwnerRole::Acu, [55; 32], None)
                .unwrap();
        let acu_pin = match acu_owner.public_enrollment().unwrap() {
            PublicEnrollment::Acu { signer, .. } => signer,
            _ => unreachable!(),
        };
        let pol_spec = acu::PolicySpec {
            version: 1,
            epoch: 1,
            issued_unix: t - 10,
            expires_unix: t + 900,
            active: true,
            allow_recipient: true,
            allow_archive: true,
            repository_id: 42,
            initiating_instance: plan.scope.instance.clone(),
            key_pins_sha256: [33; 32],
            recipient_store_id: [1; 32],
            archive_store_id: [6; 32],
            allowed_historical_envelopes: Vec::new(),
        };
        let pol_raw = acu_owner.sign_release_policy(&pol_spec).unwrap();
        let cur_pol = acu::verify_current_policy(&pol_raw, acu_pin, t).unwrap();
        let live_rev_path = canonical_dir.join("wake-live-revocations.json");
        write_new(&live_rev_path, b"[]").unwrap();
        let read_auth = crate::agent_read::ReadAuthorization::qualified_for_plan(
            t + 600,
            &cur_pol,
            plan.clone(),
            Some(live_rev_path.clone()),
        );
        let monotonic = tokio::time::Instant::now();
        assert!(
            read_auth
                .current_until(
                    &pol_raw,
                    crate::agent_deadline::Sample::fixture(monotonic, t)
                )
                .is_ok()
        );
        let live_rev_tmp = canonical_dir.join("wake-live-revocations.tmp");
        write_new(&live_rev_tmp, &std::fs::read(&rev_path).unwrap()).unwrap();
        std::fs::rename(&live_rev_tmp, &live_rev_path).unwrap();
        assert!(
            read_auth
                .current_until(
                    &pol_raw,
                    crate::agent_deadline::Sample::fixture(monotonic, t)
                )
                .is_err()
        );

        // Profile carrying an older embedded revocation `r1(t1)` composes cleanly with a
        // newer live external revocation snapshot containing only `r2(t2)` (`t2 > t1`) when
        // both revoke retired keys and the active profile keys remain valid:
        let mut deliv_with_r1 = deliv_spec.clone();
        deliv_with_r1.recipient_key_revocations = vec![r1];
        let deliv_with_r1_bytes = serde_json::to_vec(&deliv_with_r1).unwrap();
        let parsed_deliv_with_r1 = DeliveryProfile::parse(&deliv_with_r1_bytes).unwrap();
        let mut newer_external_only = crate::recipient_key::VerifiedRevocationState::new();
        newer_external_only
            .ingest_signed_revocation_struct(&r2, &signers)
            .unwrap();
        assert!(
            parsed_deliv_with_r1
                .verify_authenticated_recipient_keys(&signers, &newer_external_only, t)
                .is_ok()
        );
    }
}
