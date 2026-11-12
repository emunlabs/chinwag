// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! One Linux hosted-job container lifecycle. No raw-output echo, shell-derived
//! arguments, unrelated container adoption, automatic publication or repair.
//! Actual Docker execution is required; parser tests are not that proof.

use crate::{
    CaptureLimits, CapturedRun, ProcessOutcome, UnverifiedRunContext,
    authorization::CurrentAdmission,
    preparation::PreparedFixture,
    profile::{BoundProfiles, CommandProfile, RegisteredJob},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};
use zeroize::Zeroizing;
// Four successful 10s cleanup controls + capture's 2s reap + closure margin.
const CLOSE_RESERVE_SECONDS: u64 = 45;

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("CI isolated workload execution requires the admitted Linux hosted runner")]
    Platform,
    #[error("CI execution no longer matches its current admission, fixture or image")]
    Scope,
    #[error("CI owned container control is unavailable, unbounded or unknown; no readiness claim")]
    Control,
    #[error("CI container name already exists; no foreign container is adopted or removed")]
    Existing,
}
pub struct ImageReady {
    command_profile: [u8; 32],
}
#[derive(Serialize)]
pub struct ContainerLifecycle {
    pub classification: &'static str,
    pub owned_container_id: Option<String>,
    pub absent_after_observed_successful_control: bool,
    pub removed_by_owner: bool,
}
/// No Debug: raw failure output is only serialized for cryptographic sealing.
#[derive(Serialize)]
pub struct IsolatedCapturedRun {
    schema: &'static str,
    provenance: &'static str,
    admission_sha256: [u8; 32],
    command_profile_sha256: [u8; 32],
    fixture_sha256: [u8; 32],
    image: String,
    captured: CapturedRun,
    lifecycle: ContainerLifecycle,
    completed_unix: Option<u64>,
    completed_within_admission: bool,
}
impl IsolatedCapturedRun {
    pub fn eligible_for_green(&self) -> bool {
        self.captured.output_is_complete()
            && matches!(self.captured.outcome(), ProcessOutcome::Exited { code: 0 })
            && self
                .captured
                .observed_child_exit()
                .is_some_and(|e| e.code == Some(0) && e.signal.is_none())
            && self.lifecycle.absent_after_observed_successful_control
            && self.lifecycle.owned_container_id.is_some()
            && self.completed_within_admission
    }
    pub fn output_is_complete(&self) -> bool {
        self.captured.output_is_complete()
    }
    pub fn plaintext_for_sealing(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        serde_json::to_vec(self).map(Zeroizing::new)
    }
}
fn now() -> Result<u64, ExecutionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ExecutionError::Scope)
}
fn docker(profile: &CommandProfile, args: &[String]) -> Command {
    let mut c = Command::new("/usr/bin/docker");
    c.env_clear()
        .envs(profile.parent_environment())
        .current_dir("/")
        .args(args);
    c
}
async fn observed_control(
    profile: &CommandProfile,
    args: &[String],
    limit: usize,
    bound: Duration,
) -> Result<Vec<u8>, ExecutionError> {
    let mut c = docker(profile, args);
    let mut child = c
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| ExecutionError::Control)?;
    let mut out = child
        .stdout
        .take()
        .ok_or(ExecutionError::Control)?
        .take(limit as u64 + 1);
    let mut err = child
        .stderr
        .take()
        .ok_or(ExecutionError::Control)?
        .take(limit as u64 + 1);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = timeout(bound, async {
        let (_, _, status) = tokio::try_join!(
            out.read_to_end(&mut stdout),
            err.read_to_end(&mut stderr),
            child.wait()
        )?;
        Ok::<_, std::io::Error>(status)
    })
    .await;
    match result {
        Ok(Ok(status))
            if status.success()
                && stdout.len() <= limit
                && stderr.len() <= limit
                && (args.first().is_some_and(|s| s == "pull") || stderr.is_empty()) =>
        {
            Ok(stdout)
        }
        _ => {
            let _ = child.start_kill();
            let _ = timeout(Duration::from_secs(5), child.wait()).await;
            Err(ExecutionError::Control)
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageObservation {
    os: String,
    architecture: String,
    repo_digests: Vec<String>,
}
fn image_matches(bytes: &[u8], profile: &CommandProfile) -> bool {
    let Ok(image) = serde_json::from_slice::<ImageObservation>(bytes) else {
        return false;
    };
    let Some(digest) = profile
        .spec()
        .rust_image
        .strip_prefix("docker.io/library/rust@")
    else {
        return false;
    };
    image.os == "linux"
        && image.architecture == "amd64"
        && image.repo_digests.len() <= 32
        && image.repo_digests.iter().any(|d| {
            [
                format!("rust@{digest}"),
                format!("docker.io/library/rust@{digest}"),
                format!("library/rust@{digest}"),
            ]
            .contains(d)
        })
}
/// Before the short final admission lease. Pull only the exact public image
/// through the newly empty Docker config, then verify platform and digest.
pub async fn prepare_image(
    profile: &CommandProfile,
    fixture: &PreparedFixture,
) -> Result<ImageReady, ExecutionError> {
    if !cfg!(target_os = "linux") {
        return Err(ExecutionError::Platform);
    }
    fixture
        .verify_unchanged(profile)
        .map_err(|_| ExecutionError::Scope)?;
    if fixture.path() != profile.execution_directory() {
        return Err(ExecutionError::Scope);
    }
    observed_control(
        profile,
        &[
            "pull".into(),
            "--platform".into(),
            "linux/amd64".into(),
            profile.spec().rust_image.clone(),
        ],
        1024 * 1024,
        Duration::from_secs(180),
    )
    .await?;
    let evidence=observed_control(profile,&["image".into(),"inspect".into(),"--format".into(),"{\"os\":{{json .Os}},\"architecture\":{{json .Architecture}},\"repo_digests\":{{json .RepoDigests}}}".into(),profile.spec().rust_image.clone()],16384,Duration::from_secs(10)).await?;
    if !image_matches(&evidence, profile) {
        return Err(ExecutionError::Scope);
    }
    Ok(ImageReady {
        command_profile: profile.digest(),
    })
}
fn container_id(bytes: &[u8]) -> Result<Option<String>, ExecutionError> {
    let value = std::str::from_utf8(bytes).map_err(|_| ExecutionError::Control)?;
    if value.is_empty() {
        return Ok(None);
    }
    let value = value.strip_suffix('\n').ok_or(ExecutionError::Control)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ExecutionError::Control);
    }
    Ok(Some(value.into()))
}
async fn listed(
    profile: &CommandProfile,
    filter: String,
) -> Result<Option<String>, ExecutionError> {
    let bytes = observed_control(
        profile,
        &[
            "container".into(),
            "ls".into(),
            "--all".into(),
            "--no-trunc".into(),
            "--filter".into(),
            filter,
            "--format".into(),
            "{{.ID}}".into(),
        ],
        4096,
        Duration::from_secs(10),
    )
    .await?;
    container_id(&bytes)
}
async fn cleanup(
    profile: &CommandProfile,
    recorded: Option<&str>,
) -> Result<ContainerLifecycle, ExecutionError> {
    let id = recorded.ok_or(ExecutionError::Control)?.to_string();
    let Some(listed_id) = listed(profile, format!("id={id}")).await? else {
        return Ok(ContainerLifecycle {
            classification: "SUCCESSFUL_OWNER_LIST_OBSERVED_ABSENT",
            owned_container_id: Some(id),
            absent_after_observed_successful_control: true,
            removed_by_owner: false,
        });
    };
    if listed_id != id {
        return Err(ExecutionError::Control);
    }
    let bytes = observed_control(
        profile,
        &[
            "container".into(),
            "inspect".into(),
            "--format".into(),
            "{{json .Config.Labels}}".into(),
            id.clone(),
        ],
        16384,
        Duration::from_secs(10),
    )
    .await?;
    let labels: BTreeMap<String, String> =
        serde_json::from_slice(&bytes).map_err(|_| ExecutionError::Control)?;
    if labels.get("io.chinwag.ci.execution") != Some(&hex::encode(profile.spec().execution_id)) {
        return Err(ExecutionError::Control);
    }
    let removed = observed_control(
        profile,
        &[
            "container".into(),
            "rm".into(),
            "--force".into(),
            id.clone(),
        ],
        4096,
        Duration::from_secs(10),
    )
    .await?;
    if container_id(&removed)?.as_ref() != Some(&id)
        || listed(profile, format!("id={id}")).await?.is_some()
    {
        return Err(ExecutionError::Control);
    }
    Ok(ContainerLifecycle {
        classification: "OWN_LABEL_MATCHED_REMOVAL_AND_SUCCESSFUL_ABSENCE_OBSERVATION",
        owned_container_id: Some(id),
        absent_after_observed_successful_control: true,
        removed_by_owner: true,
    })
}
fn recorded_id(fixture: &PreparedFixture) -> Option<String> {
    use rustix::fs::{self, FileType, Mode, OFlags};
    use std::{fs::File, io::Read};
    // Public, task-owned CID metadata only, not a process/argv/key scan.
    let root = crate::storage::CiphertextStore::open(fixture.path()).ok()?;
    let fd = fs::openat(
        root.directory(),
        "container-id",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let s = fs::fstat(&fd).ok()?;
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_uid != rustix::process::geteuid().as_raw()
        || s.st_nlink != 1
        || ![0o600, 0o644].contains(&(s.st_mode & 0o7777))
        || s.st_size < 64
        || s.st_size > 65
    {
        return None;
    }
    let mut bytes = Vec::new();
    File::from(fd).take(66).read_to_end(&mut bytes).ok()?;
    if bytes.len() == 64 {
        bytes.push(b'\n');
    }
    container_id(&bytes).ok().flatten()
}
fn verify_pre_spawn_invariants(
    profiles: &BoundProfiles,
    fixture: &PreparedFixture,
    admission: &CurrentAdmission,
    job: &RegisteredJob,
    signers: &crate::recipient_key::SeatSignerDirectory,
    revocations: &crate::recipient_key::VerifiedRevocationState,
    verified_now: u64,
) -> Result<(), ExecutionError> {
    let profile = profiles.command();
    profiles
        .reverify_recipient_keys(signers, revocations, verified_now)
        .map_err(|_| ExecutionError::Scope)?;
    profiles
        .validate_admission(admission, job, verified_now)
        .map_err(|_| ExecutionError::Scope)?;
    fixture
        .verify_unchanged(profile)
        .map_err(|_| ExecutionError::Scope)?;
    if verified_now
        .saturating_add(profile.spec().timeout_seconds)
        .saturating_add(CLOSE_RESERVE_SECONDS)
        >= admission.record().expires_unix
    {
        return Err(ExecutionError::Scope);
    }
    Ok(())
}

async fn run_post_listing_pre_spawn_gate<'a, E, F>(
    profiles: &BoundProfiles,
    fixture: &PreparedFixture,
    admission: &CurrentAdmission,
    job: &RegisteredJob,
    signers: &crate::recipient_key::SeatSignerDirectory,
    pre_spawn_revocations: F,
    now_fn: fn() -> Result<u64, ExecutionError>,
) -> Result<(), E>
where
    E: From<ExecutionError>,
    F: std::future::Future<Output = Result<&'a crate::recipient_key::VerifiedRevocationState, E>>,
{
    let revocations = pre_spawn_revocations.await?;
    let verified_now = now_fn().map_err(E::from)?;
    verify_pre_spawn_invariants(
        profiles,
        fixture,
        admission,
        job,
        signers,
        revocations,
        verified_now,
    )
    .map_err(E::from)
}

/// Actual execution only after complete issuer/intent/run/job-key matching,
/// post-listing live recipient-revocation reverification, and enough CURRENT
/// lease for capture+control closure. Cleanup failure is sealed as UNKNOWN and
/// is never eligible for green or a repeated workload send.
pub async fn execute<'a, E, F>(
    profiles: &BoundProfiles,
    fixture: PreparedFixture,
    image: &ImageReady,
    admission: &CurrentAdmission,
    job: &RegisteredJob,
    signers: &crate::recipient_key::SeatSignerDirectory,
    pre_spawn_revocations: F,
) -> Result<IsolatedCapturedRun, E>
where
    E: From<ExecutionError>,
    F: std::future::Future<Output = Result<&'a crate::recipient_key::VerifiedRevocationState, E>>,
{
    if !cfg!(target_os = "linux") {
        return Err(ExecutionError::Platform.into());
    }
    let profile = profiles.command();
    if image.command_profile != profile.digest() || fixture.path() != profile.execution_directory()
    {
        return Err(ExecutionError::Scope.into());
    }
    fixture
        .verify_unchanged(profile)
        .map_err(|_| E::from(ExecutionError::Scope))?;
    let initial_now = now().map_err(E::from)?;
    profiles
        .validate_admission(admission, job, initial_now)
        .map_err(|_| E::from(ExecutionError::Scope))?;
    let r = admission.record();
    if initial_now
        .saturating_add(profile.spec().timeout_seconds)
        .saturating_add(CLOSE_RESERVE_SECONDS)
        >= r.expires_unix
    {
        return Err(ExecutionError::Scope.into());
    }
    if listed(profile, format!("name=^/{}$", profile.container_name()))
        .await
        .map_err(E::from)?
        .is_some()
    {
        return Err(ExecutionError::Existing.into());
    }
    // Container-listing await completed; execute the caller's live revocation
    // refresh and synchronously recheck recipient-key revocations, current
    // admission, exact public fixture, and remaining lease immediately before
    // Command::spawn() inside capture.
    run_post_listing_pre_spawn_gate(
        profiles,
        &fixture,
        admission,
        job,
        signers,
        pre_spawn_revocations,
        now,
    )
    .await?;
    let context = UnverifiedRunContext {
        repository: r.spec.repository.clone(),
        source_commit: r.spec.source_commit.clone(),
        workflow_ref: r.spec.workflow_ref.clone(),
        run_id: r.run_id,
        run_attempt: r.run_attempt,
        job: "chinwag-ci-proof".into(),
        initiating_intent_sha256: hex::encode(r.intent_digest),
    };
    let captured = crate::capture(
        &mut profile.build_command(),
        context,
        CaptureLimits {
            bytes_per_stream: crate::MAX_STREAM_BYTES,
            deadline: Duration::from_secs(profile.spec().timeout_seconds),
        },
    )
    .await;
    let staging_still_matches = fixture.verify_unchanged(profile).is_ok();
    let recorded = if staging_still_matches {
        recorded_id(&fixture)
    } else {
        None
    };
    // A public name/label alone never authorizes removal. This invocation's
    // own CID, held in its fresh private staging, must match BEFORE cleanup.
    let cleanup = cleanup(profile, recorded.as_deref()).await;
    let captured = captured.map_err(|_| E::from(ExecutionError::Control))?;
    let mut lifecycle = cleanup.unwrap_or(ContainerLifecycle {
        classification: "OWNED_CONTAINER_CLOSE_UNKNOWN_DO_NOT_REPEAT",
        owned_container_id: None,
        absent_after_observed_successful_control: false,
        removed_by_owner: false,
    });
    if !staging_still_matches {
        lifecycle.absent_after_observed_successful_control = false;
    }
    if let (Some(observed), Some(recorded)) = (&lifecycle.owned_container_id, &recorded)
        && observed != recorded
    {
        lifecycle.absent_after_observed_successful_control = false;
    }
    if lifecycle.owned_container_id.is_none() {
        lifecycle.owned_container_id = recorded;
    }
    let completed_unix = now().ok();
    let completed_within_admission =
        completed_unix.is_some_and(|t| t >= r.usable_from_unix && t < r.expires_unix);
    Ok(IsolatedCapturedRun {
        schema: "chinwag.ci-isolated-capture.v1",
        provenance: "GITHUB_ADMITTED_JOB_SOFTWARE_REPORT_NOT_HARDWARE_ATTESTATION",
        admission_sha256: *admission.digest(),
        command_profile_sha256: profile.digest(),
        fixture_sha256: fixture.fixture_digest(),
        image: profile.spec().rust_image.clone(),
        captured,
        lifecycle,
        completed_unix,
        completed_within_admission,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::CommandProfileSpec;
    fn profile() -> CommandProfile {
        CommandProfile::parse(
            &serde_json::to_vec(&CommandProfileSpec {
                version: 1,
                execution_id: [1; 32],
                rust_image: format!("docker.io/library/rust@sha256:{}", "a".repeat(64)),
                fixture_sha256: [2; 32],
                timeout_seconds: 60,
                isolation: "UNPRIVILEGED_NETWORKLESS_DOCKER_FIXED_RUST_FIXTURE_V1".into(),
            })
            .unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn absence_requires_clean_empty_output_and_container_ids_are_exact_not_prefixes_or_errors() {
        assert!(container_id(b"").unwrap().is_none());
        let id = "a".repeat(64);
        assert_eq!(
            container_id(format!("{id}\n").as_bytes()).unwrap(),
            Some(id)
        );
        for bad in [
            b"Error response from daemon\n".as_slice(),
            b"\n",
            b"123abc\n",
            b"null",
            b"SIGTERM",
            b"0\n",
        ] {
            assert!(container_id(bad).is_err());
        }
        assert!(
            container_id(format!("{}\n{}\n", "a".repeat(64), "b".repeat(64)).as_bytes()).is_err()
        );
    }
    #[test]
    fn actual_image_observation_must_match_exact_manifest_digest_os_and_architecture() {
        let p = profile();
        let good = serde_json::json!({"os":"linux","architecture":"amd64","repo_digests":[format!("rust@sha256:{}","a".repeat(64))]});
        assert!(image_matches(&serde_json::to_vec(&good).unwrap(), &p));
        for (field, value) in [
            ("os", serde_json::json!("darwin")),
            ("architecture", serde_json::json!("arm64")),
            (
                "repo_digests",
                serde_json::json!([format!("rust@sha256:{}", "b".repeat(64))]),
            ),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(!image_matches(&serde_json::to_vec(&bad).unwrap(), &p));
        }
        assert!(!image_matches(b"[]", &p));
    }

    #[tokio::test]
    async fn post_listing_pre_spawn_gate_refuses_active_key_revocation_and_preserves_caller_errors()
    {
        use crate::{
            admission::{AdmissionRecord, CommittedAdmission},
            authorization,
            custody::{OwnerCustody, OwnerRole, PublicDestination, PublicEnrollment},
            envelope::{AcuGateKey, Destination, DestinationKey, ResponseKey},
            intent::{self, IntentSpec, IntentVerification},
            preparation,
            profile::DeliveryProfileSpec,
            recipient_key::{
                RecipientKeyPurpose, SeatSignerDirectory, VerifiedRevocationState,
                sign_public_key_enrollment_descriptor, sign_revocation_statement,
            },
            runner_identity::RunnerIdentity,
            runtime::{HttpFailure, RuntimeError},
        };
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let vault = dir.path().join("admission");
        std::fs::create_dir(&vault).unwrap();
        std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = OwnerCustody::create_new(
            &vault.canonicalize().unwrap(),
            OwnerRole::Admission,
            [17; 32],
            None,
        )
        .unwrap();
        let PublicEnrollment::Admission { signer: issuer } = owner.public_enrollment().unwrap()
        else {
            panic!("issuer")
        };

        let fixture_bytes = b"#[test] fn ok() {}";
        let cmd_spec = CommandProfileSpec {
            version: 1,
            execution_id: [41; 32],
            rust_image: format!("docker.io/library/rust@sha256:{}", "a".repeat(64)),
            fixture_sha256: Sha256::digest(fixture_bytes).into(),
            timeout_seconds: 60,
            isolation: "UNPRIVILEGED_NETWORKLESS_DOCKER_FIXED_RUST_FIXTURE_V1".into(),
        };
        let cb = serde_json::to_vec(&cmd_spec).unwrap();
        let cp = CommandProfile::parse(&cb).unwrap();

        let ed = |n| *iroh::SecretKey::from_bytes(&[n; 32]).public().as_bytes();
        let seat_sk = SigningKey::from_bytes(&[12; 32]);
        let signers = SeatSignerDirectory::from_pinned_seats(&[(
            "WORKHORSE",
            seat_sk.verifying_key().to_bytes(),
        )])
        .unwrap();
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
        let psk_binding = sign_public_key_enrollment_descriptor(
            "WORKHORSE",
            "wh-exec-psk-e1",
            1,
            RecipientKeyPurpose::AcuRecipientPsk,
            &recipient.psk,
            900,
            2_000,
            &seat_sk,
        )
        .unwrap();
        let response_binding = sign_public_key_enrollment_descriptor(
            "WORKHORSE",
            "wh-exec-resp-e1",
            1,
            RecipientKeyPurpose::AcuRecipientResponseBase,
            &recipient.response_base,
            900,
            2_000,
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
            initiating_instance: "WORKHORSE#exec-fixture".into(),
            recipient,
            recipient_psk_binding: Some(psk_binding),
            recipient_response_base_binding: Some(response_binding),
            recipient_key_revocations: Vec::new(),
            archive,
            acu_gate_base: AcuGateKey::generate().unwrap().public(),
            acu_signer: ed(10),
            admission_signer: issuer,
            relay_origin: "https://relay-fixture.trycloudflare.com/".into(),
            admission_origin: "https://admission-fixture.trycloudflare.com/".into(),
            acu_origin: "https://acu-fixture.trycloudflare.com/".into(),
            command_profile_sha256: cp.digest(),
            original_policy_sha256: [11; 32],
            original_policy_epoch: 1,
            expires_unix: 1600,
            customer_custody_boundary: "CUSTOMER_ACU_AND_ARCHIVE_SHARED_HOST_UID".into(),
        };
        let db = serde_json::to_vec(&deliv_spec).unwrap();
        let deliv_hash: [u8; 32] = Sha256::digest(&db).into();
        let key_hex = hex::encode(seat_sk.verifying_key().to_bytes());
        let intent_spec = IntentSpec {
            schema: "chinwag.ci-dispatch-intent.v1".into(),
            repository: "example/ci-test".into(),
            repository_id: 42,
            source_commit: hex::encode([13; 20]),
            workflow_ref: "example/ci-test/.github/workflows/ci.yml@refs/heads/review".into(),
            workflow_commit: hex::encode([13; 20]),
            recipient_instance: "WORKHORSE#exec-fixture".into(),
            delivery_profile_sha256: hex::encode(deliv_hash),
            command_sha256: hex::encode(cp.digest()),
            nonce: hex::encode([18; 32]),
            expires_unix: 1500,
        };
        let body = serde_json::to_string(&intent_spec).unwrap();
        let id = "bus-exec-test";
        let sender = "WORKHORSE#exec-fixture";
        let to = "ADMISSION#exec-fixture";
        let room = "#eng";
        let task = "CHWG-CI-EXEC";
        let signed = format!(
            "chinwag-bus-sig-v2|{}",
            [id, "1000", sender, to, room, task, &body]
                .map(|s| format!("{}:{s}", s.len()))
                .join("|")
        );
        let digest = hex::encode(Sha256::digest(
            format!("chinwag-bus-v1|1000|{room}|{sender}|{key_hex}|{to}|{task}|{body}").as_bytes(),
        ));
        let original = serde_json::json!({
            "id": id,
            "ts_unix": 1000,
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
        let verified_intent = intent::verify_original(
            &serde_json::to_vec(&original).unwrap(),
            IntentVerification {
                initiator_instance: sender,
                initiator_public_key: seat_sk.verifying_key().to_bytes(),
                admission_addressee: to,
                task_id: task,
                room,
                now_unix: 1001,
            },
        )
        .unwrap();
        let bound = BoundProfiles::resolve(&verified_intent, &cb, &db, 1001).unwrap();
        let staging_path = dir.path().canonicalize().unwrap().join("staging");
        let fixture =
            preparation::materialize(&cp, bound.intended_source(), fixture_bytes, &staging_path)
                .unwrap();

        let runner = RunnerIdentity::generate().unwrap();
        let keys = runner.public_keys();
        let admitted = CommittedAdmission::synthetic_fixture(AdmissionRecord {
            spec: verified_intent.spec().clone(),
            initiating_instance: verified_intent.initiating_instance().into(),
            intent_digest: *verified_intent.original_digest(),
            token_sha256: [19; 32],
            issuer_jti_sha256: [20; 32],
            audience: "fixture".into(),
            run_id: 100,
            run_attempt: 1,
            signing_key: keys.signing_ed25519,
            agent_transport_key: keys.agent_transport_ed25519,
            archive_transport_key: keys.archive_transport_ed25519,
            usable_from_unix: 1000,
            expires_unix: 1300,
        });
        let certificate = owner.certify_admission(&admitted).unwrap();
        let current = authorization::verify_historical_certificate(&certificate, issuer)
            .unwrap()
            .require_current(1001)
            .unwrap();
        let registered = RegisteredJob {
            run_id: 100,
            run_attempt: 1,
            keys,
        };

        let mut live_revocations = VerifiedRevocationState::new();
        // 1. Clean live revocation state after listing await succeeds.
        {
            let rev_ref = &mut live_revocations;
            run_post_listing_pre_spawn_gate(
                &bound,
                &fixture,
                &current,
                &registered,
                &signers,
                async move {
                    tokio::task::yield_now().await;
                    Ok::<&VerifiedRevocationState, RuntimeError>(rev_ref)
                },
                || Ok(1005),
            )
            .await
            .unwrap();
        }

        // 2. Upstream caller error (e.g. HTTP failure on POST /v1/revocations) is preserved.
        let http_err = run_post_listing_pre_spawn_gate(
            &bound,
            &fixture,
            &current,
            &registered,
            &signers,
            async {
                tokio::task::yield_now().await;
                Err::<&VerifiedRevocationState, RuntimeError>(RuntimeError::Http(
                    HttpFailure::Status(503),
                ))
            },
            || Ok(1005),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            http_err,
            RuntimeError::Http(HttpFailure::Status(503))
        ));

        // 3. Active-key revocation arriving during the async listing / refresh window
        // causes synchronous pre-spawn refusal before capture is reached.
        let rev_bytes = sign_revocation_statement(
            "WORKHORSE",
            2,
            &["wh-exec-psk-e1".to_string()],
            1004,
            &seat_sk,
        )
        .unwrap();
        let signers_ref = &signers;
        let rev_ref = &mut live_revocations;
        let scope_err = run_post_listing_pre_spawn_gate(
            &bound,
            &fixture,
            &current,
            &registered,
            &signers,
            async move {
                tokio::task::yield_now().await;
                rev_ref
                    .ingest_signed_revocation(&rev_bytes, signers_ref)
                    .unwrap();
                Ok::<&VerifiedRevocationState, ExecutionError>(rev_ref)
            },
            || Ok(1005),
        )
        .await
        .unwrap_err();
        assert!(matches!(scope_err, ExecutionError::Scope));
    }
}
