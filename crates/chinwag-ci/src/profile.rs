// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Immutable canonical public profiles, resolved by the initiating native
//! original's exact digests. Profiles grant no remediation or capture by
//! themselves. The runner must first complete independently bound admission.

use crate::{
    CommandEvidence, authorization,
    custody::PublicDestination,
    envelope::{self, Destination, KemPublicKey, KemSuite, KeyPins},
    intent::VerifiedIntent,
    recipient_key::{
        RecipientKeyPurpose, SeatSignerDirectory, VerifiedRecipientKey, VerifiedRevocationState,
        valid_seat, verify_signed_recipient_key,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf};
use tokio::process::Command;

#[derive(Debug, thiserror::Error)]
#[error("CI immutable profile is malformed, changed or outside the intended scope")]
pub struct ProfileError;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandProfileSpec {
    pub version: u16,
    pub execution_id: [u8; 32],
    pub rust_image: String,
    pub fixture_sha256: [u8; 32],
    pub timeout_seconds: u64,
    pub isolation: String,
}
pub struct CommandProfile {
    spec: CommandProfileSpec,
    digest: [u8; 32],
}
pub struct VerifiedFixture {
    bytes: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryProfileSpec {
    pub version: u16,
    pub repository_id: u64,
    pub initiating_instance: String,
    pub recipient: PublicDestination,
    pub archive: PublicDestination,
    pub acu_gate_base: KemPublicKey,
    pub acu_signer: [u8; 32],
    pub admission_signer: [u8; 32],
    pub relay_origin: String,
    pub admission_origin: String,
    pub acu_origin: String,
    pub command_profile_sha256: [u8; 32],
    pub original_policy_sha256: [u8; 32],
    pub original_policy_epoch: u64,
    pub expires_unix: u64,
    pub customer_custody_boundary: String,
}
pub struct DeliveryProfile {
    spec: DeliveryProfileSpec,
    digest: [u8; 32],
    keys: KeyPins,
}
pub struct BoundProfiles {
    command: CommandProfile,
    delivery: DeliveryProfile,
    intent: crate::intent::IntentSpec,
    intent_digest: [u8; 32],
    initiating_instance: String,
}
/// From the owner's independently registered exact run/controller, not fields
/// copied from the envelope or incoming certificate being checked.
pub struct RegisteredJob {
    pub run_id: u64,
    pub run_attempt: u32,
    pub keys: crate::runner_binding::RunnerPublicKeys,
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn parse<T: Serialize + for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T, ProfileError> {
    if bytes.is_empty() || bytes.len() > 32 * 1024 {
        return Err(ProfileError);
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| ProfileError)?;
    if serde_json::to_vec(&value).map_err(|_| ProfileError)? != bytes {
        return Err(ProfileError);
    }
    Ok(value)
}
fn valid_image(image: &str) -> bool {
    image
        .strip_prefix("docker.io/library/rust@sha256:")
        .is_some_and(|d| {
            d.len() == 64
                && d.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn cloudflare_origin(origin: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(origin) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.as_str() == origin
        && (host.ends_with(".trycloudflare.com") || host.ends_with(".workers.dev"))
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
}
impl CommandProfile {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        let spec: CommandProfileSpec = parse(bytes)?;
        if spec.version != 1
            || spec.execution_id == [0; 32]
            || spec.fixture_sha256 == [0; 32]
            || !valid_image(&spec.rust_image)
            || !(1..=120).contains(&spec.timeout_seconds)
            || spec.isolation != "UNPRIVILEGED_NETWORKLESS_DOCKER_FIXED_RUST_FIXTURE_V1"
        {
            return Err(ProfileError);
        }
        Ok(Self {
            spec,
            digest: hash(bytes),
        })
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn spec(&self) -> &CommandProfileSpec {
        &self.spec
    }
    pub fn container_name(&self) -> String {
        format!("chinwag-ci-{}", hex::encode(self.spec.execution_id))
    }
    pub fn execution_directory(&self) -> PathBuf {
        PathBuf::from("/tmp").join(self.container_name())
    }
    pub fn verify_fixture(&self, bytes: &[u8]) -> Result<VerifiedFixture, ProfileError> {
        if bytes.is_empty() || bytes.len() > 1024 * 1024 || hash(bytes) != self.spec.fixture_sha256
        {
            return Err(ProfileError);
        }
        Ok(VerifiedFixture {
            bytes: bytes.to_vec(),
        })
    }
    pub fn observed_command_evidence(&self) -> Result<CommandEvidence, ProfileError> {
        CommandEvidence::snapshot(&self.build_command()).map_err(|_| ProfileError)
    }
    // Only the trusted in-crate runner can obtain a mutable Command. Public
    // callers receive observations, not an escape hatch to alter the policy.
    pub(crate) fn build_command(&self) -> Command {
        let root = self.execution_directory();
        let fixture = root.join("fixture");
        let mut c = Command::new("/usr/bin/docker");
        c.env_clear()
            .envs(self.parent_environment())
            .current_dir("/");
        c.args(["run","--rm","--pull","never","--platform","linux/amd64","--entrypoint","/bin/sh","--name"]).arg(self.container_name())
            .arg("--cidfile").arg(root.join("container-id"))
            .args(["--label",&format!("io.chinwag.ci.execution={}",hex::encode(self.spec.execution_id)),"--network","none","--cap-drop","ALL","--security-opt","no-new-privileges","--user","65532:65532","--read-only","--pids-limit","128","--memory","512m","--cpus","2","--tmpfs","/tmp:rw,noexec,nosuid,size=64m","--tmpfs","/build:rw,exec,nosuid,size=128m","--mount"])
            .arg(format!("type=bind,source={},target=/src,readonly",fixture.display()))
            .args(["--workdir","/src","--env","HOME=/tmp","--env","LC_ALL=C"])
            .arg(&self.spec.rust_image)
            .args(["-c","rustc --edition=2024 --test /src/fixture.rs -o /build/tests && /build/tests --nocapture"]);
        c
    }
    pub(crate) fn parent_environment(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("LC_ALL".into(), "C".into()),
            (
                "DOCKER_CONFIG".into(),
                self.execution_directory()
                    .join("empty-docker-config")
                    .to_string_lossy()
                    .into_owned(),
            ),
        ])
    }
}
impl VerifiedFixture {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl DeliveryProfile {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        let spec: DeliveryProfileSpec = parse(bytes)?;
        let r = &spec.recipient;
        let a = &spec.archive;
        if spec.version != 1
            || spec.repository_id == 0
            || spec.initiating_instance.is_empty()
            || spec.initiating_instance.len() > 193
            || r.role != Destination::Recipient
            || a.role != Destination::Archive
            || r.store_id == [0; 32]
            || a.store_id == [0; 32]
            || r.store_id == a.store_id
            || r.store_binding == [0; 32]
            || a.store_binding == [0; 32]
            || r.store_binding == a.store_binding
            || r.release_request_signer != r.receipt_signer
            || a.release_request_signer != a.receipt_signer
            || spec.command_profile_sha256 == [0; 32]
            || spec.original_policy_sha256 == [0; 32]
            || spec.original_policy_epoch == 0
            || spec.expires_unix == 0
            || spec.customer_custody_boundary != "CUSTOMER_ACU_AND_ARCHIVE_SHARED_HOST_UID"
            || !cloudflare_origin(&spec.relay_origin)
            || !cloudflare_origin(&spec.admission_origin)
            || !cloudflare_origin(&spec.acu_origin)
        {
            return Err(ProfileError);
        }
        let keys = KeyPins {
            acu_gate_base: spec.acu_gate_base.clone(),
            recipient_psk: r.psk.clone(),
            archive_psk: a.psk.clone(),
            recipient_response_base: r.response_base.clone(),
            archive_response_base: a.response_base.clone(),
            acu_signer: spec.acu_signer,
            recipient_receipt_signer: r.receipt_signer,
            archive_receipt_signer: a.receipt_signer,
        };
        envelope::validate_key_pins(&keys, &[spec.admission_signer, r.transport, a.transport])
            .map_err(|_| ProfileError)?;
        Ok(Self {
            spec,
            digest: hash(bytes),
            keys,
        })
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn spec(&self) -> &DeliveryProfileSpec {
        &self.spec
    }
    pub fn key_pins(&self) -> &KeyPins {
        &self.keys
    }
    pub fn suite(&self) -> KemSuite {
        self.keys
            .suite()
            .expect("DeliveryProfile::parse validated uniform KemSuite")
    }
    /// Verifies that the recipient's `psk` and `response_base` `X25519-MLKEM768`
    /// (`0x647a`) encryption keys in this `DeliveryProfile` are explicitly bound
    /// by valid, non-revoked, purpose-separated Ed25519 enrollment descriptors
    /// signed by the initiating seat's `.chinwag/allowed_signers` signing key.
    pub fn verify_recipient_key_bindings(
        &self,
        psk_enrollment: &[u8],
        response_base_enrollment: &[u8],
        signers: &SeatSignerDirectory,
        revocations: &VerifiedRevocationState,
        now_unix: u64,
    ) -> Result<(VerifiedRecipientKey, VerifiedRecipientKey), ProfileError> {
        if self.suite() != KemSuite::X25519MlKem768 || now_unix >= self.spec.expires_unix {
            return Err(ProfileError);
        }
        let Some((expected_seat, instance_suffix)) = self.spec.initiating_instance.split_once('#')
        else {
            return Err(ProfileError);
        };
        if !valid_seat(expected_seat) || instance_suffix.is_empty() || instance_suffix.contains('#')
        {
            return Err(ProfileError);
        }
        let verified_psk =
            verify_signed_recipient_key(psk_enrollment, signers, revocations, now_unix)
                .map_err(|_| ProfileError)?;
        let verified_response =
            verify_signed_recipient_key(response_base_enrollment, signers, revocations, now_unix)
                .map_err(|_| ProfileError)?;
        if verified_psk.seat() != expected_seat
            || verified_response.seat() != expected_seat
            || verified_psk.purpose() != RecipientKeyPurpose::AcuRecipientPsk
            || verified_response.purpose() != RecipientKeyPurpose::AcuRecipientResponseBase
            || verified_psk.kid() == verified_response.kid()
            || verified_psk.public_key() != &self.keys.recipient_psk
            || verified_response.public_key() != &self.keys.recipient_response_base
        {
            return Err(ProfileError);
        }
        Ok((verified_psk, verified_response))
    }
    pub fn historical_recovery_scope(&self) -> ([u8; 32], &KeyPins, [u8; 32], u64) {
        (
            self.spec.admission_signer,
            &self.keys,
            self.spec.original_policy_sha256,
            self.spec.original_policy_epoch,
        )
    }
}
impl BoundProfiles {
    pub fn resolve(
        intent: &VerifiedIntent,
        command_bytes: &[u8],
        delivery_bytes: &[u8],
        now: u64,
    ) -> Result<Self, ProfileError> {
        let command = CommandProfile::parse(command_bytes)?;
        let delivery = DeliveryProfile::parse(delivery_bytes)?;
        let s = intent.spec();
        let d = delivery.spec();
        if s.command_sha256 != hex::encode(command.digest())
            || s.delivery_profile_sha256 != hex::encode(delivery.digest())
            || d.command_profile_sha256 != command.digest()
            || d.repository_id != s.repository_id
            || d.initiating_instance != intent.initiating_instance()
            || s.recipient_instance != intent.initiating_instance()
            || now < intent.issued_unix()
            || now >= s.expires_unix
            || d.expires_unix < s.expires_unix
        {
            return Err(ProfileError);
        }
        Ok(Self {
            command,
            delivery,
            intent: s.clone(),
            intent_digest: *intent.original_digest(),
            initiating_instance: intent.initiating_instance().into(),
        })
    }
    pub fn command(&self) -> &CommandProfile {
        &self.command
    }
    pub fn delivery(&self) -> &DeliveryProfile {
        &self.delivery
    }
    pub(crate) fn intended_source(&self) -> &str {
        &self.intent.source_commit
    }
    pub fn validate_registered_job(&self, registered: &RegisteredJob) -> Result<(), ProfileError> {
        if registered.run_id == 0 || registered.run_attempt == 0 {
            return Err(ProfileError);
        }
        let d = self.delivery.spec();
        let k = registered.keys;
        envelope::validate_key_pins(
            self.delivery.key_pins(),
            &[
                d.admission_signer,
                d.recipient.transport,
                d.archive.transport,
                k.signing_ed25519,
                k.agent_transport_ed25519,
                k.archive_transport_ed25519,
            ],
        )
        .map_err(|_| ProfileError)
    }
    pub fn validate_admission(
        &self,
        admission: &authorization::CurrentAdmission,
        registered: &RegisteredJob,
        now: u64,
    ) -> Result<(), ProfileError> {
        self.validate_registered_job(registered)?;
        let r = admission.record();
        if admission.issuer() != self.delivery.spec().admission_signer
            || r.spec != self.intent
            || r.intent_digest != self.intent_digest
            || r.initiating_instance != self.initiating_instance
            || r.run_id != registered.run_id
            || r.run_attempt != registered.run_attempt
            || r.signing_key != registered.keys.signing_ed25519
            || r.agent_transport_key != registered.keys.agent_transport_ed25519
            || r.archive_transport_key != registered.keys.archive_transport_ed25519
            || now < r.usable_from_unix
            || now >= r.expires_unix
        {
            return Err(ProfileError);
        }
        Ok(())
    }
    pub fn authenticate_current_artifact(
        &self,
        certificate: &[u8],
        envelope: envelope::SealedEnvelope,
        registered: &RegisteredJob,
        now: u64,
    ) -> Result<authorization::AdmissionBoundEnvelope, ProfileError> {
        self.validate_registered_job(registered)?;
        let d = self.delivery.spec();
        let admission =
            authorization::verify_historical_certificate(certificate, d.admission_signer)
                .map_err(|_| ProfileError)?
                .require_current(now)
                .map_err(|_| ProfileError)?;
        self.validate_admission(&admission, registered, now)?;
        admission
            .authenticate_envelope(
                envelope,
                self.delivery.key_pins(),
                d.original_policy_sha256,
                d.original_policy_epoch,
                now,
            )
            .map_err(|_| ProfileError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admission::{AdmissionRecord, CommittedAdmission},
        custody::{OwnerCustody, OwnerRole, PublicEnrollment},
        envelope::{AcuGateKey, DestinationKey, ResponseKey},
        intent::{self, IntentSpec, IntentVerification},
        runner_identity::RunnerIdentity,
    };
    use ed25519_dalek::Signer;
    use std::os::unix::fs::PermissionsExt;
    fn command() -> CommandProfileSpec {
        CommandProfileSpec {
            version: 1,
            execution_id: [1; 32],
            rust_image: format!("docker.io/library/rust@sha256:{}", "a".repeat(64)),
            fixture_sha256: hash(b"public fixture"),
            timeout_seconds: 60,
            isolation: "UNPRIVILEGED_NETWORKLESS_DOCKER_FIXED_RUST_FIXTURE_V1".into(),
        }
    }
    fn delivery(command: [u8; 32], issuer: [u8; 32]) -> DeliveryProfileSpec {
        let ed = |n| *iroh::SecretKey::from_bytes(&[n; 32]).public().as_bytes();
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
        DeliveryProfileSpec {
            version: 1,
            repository_id: 42,
            initiating_instance: "WORKHORSE#profile-fixture".into(),
            recipient,
            archive,
            acu_gate_base: AcuGateKey::generate().unwrap().public(),
            acu_signer: ed(10),
            admission_signer: issuer,
            relay_origin: "https://relay-fixture.trycloudflare.com/".into(),
            admission_origin: "https://admission-fixture.trycloudflare.com/".into(),
            acu_origin: "https://acu-fixture.trycloudflare.com/".into(),
            command_profile_sha256: command,
            original_policy_sha256: [11; 32],
            original_policy_epoch: 1,
            expires_unix: 1600,
            customer_custody_boundary: "CUSTOMER_ACU_AND_ARCHIVE_SHARED_HOST_UID".into(),
        }
    }
    fn verified_intent(command: [u8; 32], delivery: [u8; 32], nonce: u8) -> VerifiedIntent {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
        let key = hex::encode(signer.verifying_key().to_bytes());
        let spec = IntentSpec {
            schema: "chinwag.ci-dispatch-intent.v1".into(),
            repository: "example/ci-test".into(),
            repository_id: 42,
            source_commit: hex::encode([13; 20]),
            workflow_ref: "example/ci-test/.github/workflows/ci.yml@refs/heads/review".into(),
            workflow_commit: hex::encode([13; 20]),
            recipient_instance: "WORKHORSE#profile-fixture".into(),
            delivery_profile_sha256: hex::encode(delivery),
            command_sha256: hex::encode(command),
            nonce: hex::encode([nonce; 32]),
            expires_unix: 1500,
        };
        let body = serde_json::to_string(&spec).unwrap();
        let id = "bus-profile-test";
        let sender = "WORKHORSE#profile-fixture";
        let to = "ADMISSION#profile-fixture";
        let room = "#eng";
        let task = "CHWG-CI-TEST";
        let signed = format!(
            "chinwag-bus-sig-v2|{}",
            [id, "1000", sender, to, room, task, &body]
                .map(|s| format!("{}:{s}", s.len()))
                .join("|")
        );
        let digest = hex::encode(hash(
            format!("chinwag-bus-v1|1000|{room}|{sender}|{key}|{to}|{task}|{body}").as_bytes(),
        ));
        let original = serde_json::json!({"id":id,"ts_unix":1000,"sender":sender,"sender_endpoint_id":key,"to":to,"room":room,"task_id":task,"body":body,"digest_sha256":digest,"pubkey_ed25519":key,"signature_ed25519":hex::encode(signer.sign(signed.as_bytes()).to_bytes())});
        intent::verify_original(
            &serde_json::to_vec(&original).unwrap(),
            IntentVerification {
                initiator_instance: sender,
                initiator_public_key: signer.verifying_key().to_bytes(),
                admission_addressee: to,
                task_id: task,
                room,
                now_unix: 1001,
            },
        )
        .unwrap()
    }
    #[test]
    fn isolated_plan_has_exact_mount_environment_image_and_fixture_commitment() {
        let spec = command();
        let bytes = serde_json::to_vec(&spec).unwrap();
        let profile = CommandProfile::parse(&bytes).unwrap();
        assert_eq!(profile.digest(), hash(&bytes));
        assert_eq!(
            profile.verify_fixture(b"public fixture").unwrap().bytes(),
            b"public fixture"
        );
        assert!(profile.verify_fixture(b"changed fixture").is_err());
        let c = profile.build_command();
        let c = c.as_std();
        assert_eq!(c.get_program(), "/usr/bin/docker");
        assert_eq!(c.get_current_dir(), Some(std::path::Path::new("/")));
        let args: Vec<_> = c.get_args().map(|a| a.to_str().unwrap()).collect();
        for pair in [
            ["--network", "none"],
            ["--cap-drop", "ALL"],
            ["--user", "65532:65532"],
            ["--pull", "never"],
            ["--security-opt", "no-new-privileges"],
            ["--entrypoint", "/bin/sh"],
            // Docker prepends noexec to tmpfs mounts. Only the bounded build
            // scratch space may execute the binary that the admitted command
            // compiles; general temporary data remains non-executable.
            ["--tmpfs", "/build:rw,exec,nosuid,size=128m"],
            ["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"],
        ] {
            assert!(args.windows(2).any(|w| w == pair));
        }
        assert!(args.contains(&"--read-only"));
        assert_eq!(args.iter().filter(|a| **a == "--mount").count(), 1);
        let environment: Vec<_> = c
            .get_envs()
            .map(|(k, v)| (k.to_str().unwrap(), v.unwrap().to_str().unwrap()))
            .collect();
        assert_eq!(environment.len(), 3);
        assert!(
            environment
                .iter()
                .all(|(k, _)| ["PATH", "LC_ALL", "DOCKER_CONFIG"].contains(k))
        );
        let argv = profile
            .observed_command_evidence()
            .unwrap()
            .argv_sha256()
            .to_string();
        let mut changed = spec;
        changed.timeout_seconds = 61;
        let altered = CommandProfile::parse(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_ne!(profile.digest(), altered.digest());
        assert_eq!(
            argv,
            altered.observed_command_evidence().unwrap().argv_sha256()
        ); // Profile commits MORE than argv.
        changed.rust_image = "docker.io/library/rust:latest".into();
        assert!(CommandProfile::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    #[test]
    fn unsigned_changes_cross_role_keys_and_noncanonical_or_non_cf_routes_refuse() {
        let cb = serde_json::to_vec(&command()).unwrap();
        let cp = CommandProfile::parse(&cb).unwrap();
        let issuer = *iroh::SecretKey::from_bytes(&[15; 32]).public().as_bytes();
        let spec = delivery(cp.digest(), issuer);
        let db = serde_json::to_vec(&spec).unwrap();
        let intent = verified_intent(cp.digest(), hash(&db), 16);
        BoundProfiles::resolve(&intent, &cb, &db, 1001).unwrap();
        let mut changed = spec.clone();
        changed.archive.transport = changed.recipient.transport;
        assert!(DeliveryProfile::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        for origin in [
            "http://relay-fixture.trycloudflare.com/",
            "https://relay-fixture.trycloudflare.com/?query=x",
            "https://user@relay-fixture.trycloudflare.com/",
            "https://relay-fixture.trycloudflare.com.evil.example/",
            "https://127.0.0.1/",
        ] {
            let mut changed = spec.clone();
            changed.relay_origin = origin.into();
            assert!(DeliveryProfile::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut changed = spec.clone();
        changed.original_policy_epoch = 2;
        assert!(
            BoundProfiles::resolve(&intent, &cb, &serde_json::to_vec(&changed).unwrap(), 1001)
                .is_err()
        );
        let mut padded = db;
        padded.push(b' ');
        assert!(DeliveryProfile::parse(&padded).is_err());
    }
    #[test]
    fn final_artifact_must_match_native_original_exact_registered_run_and_all_job_keys() {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = OwnerCustody::create_new(
            &d.path().canonicalize().unwrap(),
            OwnerRole::Admission,
            [17; 32],
            None,
        )
        .unwrap();
        let PublicEnrollment::Admission { signer: issuer } = owner.public_enrollment().unwrap()
        else {
            panic!("issuer")
        };
        let cb = serde_json::to_vec(&command()).unwrap();
        let cp = CommandProfile::parse(&cb).unwrap();
        let spec = delivery(cp.digest(), issuer);
        let db = serde_json::to_vec(&spec).unwrap();
        let intent = verified_intent(cp.digest(), hash(&db), 18);
        let bound = BoundProfiles::resolve(&intent, &cb, &db, 1001).unwrap();
        let runner = RunnerIdentity::generate().unwrap();
        let keys = runner.public_keys();
        let admitted = CommittedAdmission::synthetic_fixture(AdmissionRecord {
            spec: intent.spec().clone(),
            initiating_instance: intent.initiating_instance().into(),
            intent_digest: *intent.original_digest(),
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
        let claims = current
            .expected_provenance(spec.original_policy_sha256, 1)
            .unwrap();
        let packet = runner
            .seal_failure(
                claims,
                bound.delivery().key_pins().clone(),
                b"full encrypted fixture failure",
            )
            .unwrap();
        let copy = || envelope::SealedEnvelope {
            manifest: packet.manifest.clone(),
            ciphertext: packet.ciphertext.clone(),
        };
        let registered = RegisteredJob {
            run_id: 100,
            run_attempt: 1,
            keys,
        };
        bound
            .authenticate_current_artifact(&certificate, copy(), &registered, 1002)
            .unwrap();
        let other_vault = tempfile::tempdir().unwrap();
        std::fs::set_permissions(other_vault.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let other_issuer = OwnerCustody::create_new(
            &other_vault.path().canonicalize().unwrap(),
            OwnerRole::Admission,
            [22; 32],
            None,
        )
        .unwrap();
        let PublicEnrollment::Admission { signer: other_pin } =
            other_issuer.public_enrollment().unwrap()
        else {
            panic!("other issuer")
        };
        let other_certificate = other_issuer.certify_admission(&admitted).unwrap();
        let other_current =
            authorization::verify_historical_certificate(&other_certificate, other_pin)
                .unwrap()
                .require_current(1001)
                .unwrap();
        assert!(
            bound
                .validate_admission(&other_current, &registered, 1002)
                .is_err()
        );
        let mut aliased = registered.keys;
        aliased.agent_transport_ed25519 = bound.delivery.spec().recipient.transport;
        assert!(
            bound
                .validate_registered_job(&RegisteredJob {
                    run_id: 100,
                    run_attempt: 1,
                    keys: aliased
                })
                .is_err()
        );
        let wrong = RegisteredJob {
            run_id: 101,
            run_attempt: 1,
            keys,
        };
        assert!(
            bound
                .authenticate_current_artifact(&certificate, copy(), &wrong, 1002)
                .is_err()
        );
        let wrong = RegisteredJob {
            run_id: 100,
            run_attempt: 1,
            keys: RunnerIdentity::generate().unwrap().public_keys(),
        };
        assert!(
            bound
                .authenticate_current_artifact(&certificate, copy(), &wrong, 1002)
                .is_err()
        );
        let other_intent = verified_intent(cp.digest(), hash(&db), 21);
        let other = BoundProfiles::resolve(&other_intent, &cb, &db, 1001).unwrap();
        assert!(
            other
                .authenticate_current_artifact(&certificate, copy(), &registered, 1002)
                .is_err()
        );
    }

    #[test]
    fn enterprise_acu_release_ledger_and_recipient_bindings_roundtrip_on_x25519_mlkem768() {
        use crate::{
            acu::{self, PolicySpec, ReleaseLedger},
            recipient_key::sign_public_key_enrollment,
            storage::CiphertextStore,
        };
        let mk_dir = || {
            let d = tempfile::tempdir().unwrap();
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            d
        };
        let dirs: Vec<_> = (0..7).map(|_| mk_dir()).collect();
        let store =
            |i: usize| CiphertextStore::open(&dirs[i].path().canonicalize().unwrap()).unwrap();

        let recipient_owner = OwnerCustody::create_new(
            &dirs[0].path().canonicalize().unwrap(),
            OwnerRole::Recipient,
            [31; 32],
            Some((store(4), [41; 32])),
        )
        .unwrap();
        let archive_owner = OwnerCustody::create_new(
            &dirs[1].path().canonicalize().unwrap(),
            OwnerRole::Archive,
            [32; 32],
            Some((store(5), [42; 32])),
        )
        .unwrap();
        let acu_owner = OwnerCustody::create_new(
            &dirs[2].path().canonicalize().unwrap(),
            OwnerRole::Acu,
            [33; 32],
            None,
        )
        .unwrap();
        let admission_owner = OwnerCustody::create_new(
            &dirs[3].path().canonicalize().unwrap(),
            OwnerRole::Admission,
            [34; 32],
            None,
        )
        .unwrap();

        let PublicEnrollment::Destination(r_dest) = recipient_owner.public_enrollment().unwrap()
        else {
            panic!("recipient")
        };
        let PublicEnrollment::Destination(a_dest) = archive_owner.public_enrollment().unwrap()
        else {
            panic!("archive")
        };
        let PublicEnrollment::Acu {
            gate_base,
            signer: acu_signer,
        } = acu_owner.public_enrollment().unwrap()
        else {
            panic!("acu")
        };
        let PublicEnrollment::Admission {
            signer: admission_signer,
        } = admission_owner.public_enrollment().unwrap()
        else {
            panic!("admission")
        };

        let seat_sk = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
        let signers = SeatSignerDirectory::from_pinned_seats(&[(
            "WORKHORSE",
            seat_sk.verifying_key().to_bytes(),
        )])
        .unwrap();
        let revocations = VerifiedRevocationState::new();
        let psk_binding = sign_public_key_enrollment(
            "WORKHORSE",
            "wh-profile-acu-psk-e1",
            1,
            RecipientKeyPurpose::AcuRecipientPsk,
            &r_dest.psk,
            900,
            2_000,
            &seat_sk,
        )
        .unwrap();
        let resp_binding = sign_public_key_enrollment(
            "WORKHORSE",
            "wh-profile-acu-resp-e1",
            1,
            RecipientKeyPurpose::AcuRecipientResponseBase,
            &r_dest.response_base,
            900,
            2_000,
            &seat_sk,
        )
        .unwrap();

        let cb = serde_json::to_vec(&command()).unwrap();
        let cp = CommandProfile::parse(&cb).unwrap();
        let pins = KeyPins {
            acu_gate_base: gate_base.clone(),
            recipient_psk: r_dest.psk.clone(),
            archive_psk: a_dest.psk.clone(),
            recipient_response_base: r_dest.response_base.clone(),
            archive_response_base: a_dest.response_base.clone(),
            acu_signer,
            recipient_receipt_signer: r_dest.receipt_signer,
            archive_receipt_signer: a_dest.receipt_signer,
        };
        let policy_spec = PolicySpec {
            version: 1,
            epoch: 1,
            issued_unix: 1_000,
            expires_unix: 1_600,
            active: true,
            allow_recipient: true,
            allow_archive: true,
            repository_id: 42,
            initiating_instance: "WORKHORSE#profile-fixture".into(),
            key_pins_sha256: acu::key_pins_digest(&pins).unwrap(),
            recipient_store_id: [41; 32],
            archive_store_id: [42; 32],
            allowed_historical_envelopes: Vec::new(),
        };
        let policy = acu::verify_current_policy(
            &acu_owner.sign_release_policy(&policy_spec).unwrap(),
            acu_signer,
            1_001,
        )
        .unwrap();

        let spec = DeliveryProfileSpec {
            version: 1,
            repository_id: 42,
            initiating_instance: "WORKHORSE#profile-fixture".into(),
            recipient: r_dest,
            archive: a_dest,
            acu_gate_base: gate_base,
            acu_signer,
            admission_signer,
            relay_origin: "https://relay-fixture.trycloudflare.com/".into(),
            admission_origin: "https://admission-fixture.trycloudflare.com/".into(),
            acu_origin: "https://acu-fixture.trycloudflare.com/".into(),
            command_profile_sha256: cp.digest(),
            original_policy_sha256: policy.digest(),
            original_policy_epoch: 1,
            expires_unix: 1_600,
            customer_custody_boundary: "CUSTOMER_ACU_AND_ARCHIVE_SHARED_HOST_UID".into(),
        };
        let db = serde_json::to_vec(&spec).unwrap();
        let intent = verified_intent(cp.digest(), hash(&db), 99);
        let bound = BoundProfiles::resolve(&intent, &cb, &db, 1_001).unwrap();
        bound
            .delivery()
            .verify_recipient_key_bindings(
                &psk_binding,
                &resp_binding,
                &signers,
                &revocations,
                1_001,
            )
            .unwrap();

        let runner = RunnerIdentity::generate().unwrap();
        let r_keys = runner.public_keys();
        let admitted = CommittedAdmission::synthetic_fixture(AdmissionRecord {
            spec: intent.spec().clone(),
            initiating_instance: intent.initiating_instance().into(),
            intent_digest: *intent.original_digest(),
            token_sha256: [51; 32],
            issuer_jti_sha256: [52; 32],
            audience: "fixture".into(),
            run_id: 267,
            run_attempt: 1,
            signing_key: r_keys.signing_ed25519,
            agent_transport_key: r_keys.agent_transport_ed25519,
            archive_transport_key: r_keys.archive_transport_ed25519,
            usable_from_unix: 1_000,
            expires_unix: 1_300,
        });
        let certificate = admission_owner.certify_admission(&admitted).unwrap();
        let current = authorization::verify_historical_certificate(&certificate, admission_signer)
            .unwrap()
            .require_current(1_001)
            .unwrap();
        let claims = current.expected_provenance(policy.digest(), 1).unwrap();
        let secret_payload = b"full X25519-MLKEM768 + ReleaseLedger 2-of-3 roundtrip";
        let sealed = runner
            .seal_failure(claims, bound.delivery().key_pins().clone(), secret_payload)
            .unwrap();
        let admitted_env = bound
            .authenticate_current_artifact(
                &certificate,
                sealed,
                &RegisteredJob {
                    run_id: 267,
                    run_attempt: 1,
                    keys: r_keys,
                },
                1_002,
            )
            .unwrap();
        let raw_req = recipient_owner
            .create_release_request(&admitted_env, &policy, 1_002, 1_200)
            .unwrap();
        let mut ledger = ReleaseLedger::open(
            &dirs[6].path().canonicalize().unwrap(),
            acu_signer,
            admission_signer,
        )
        .unwrap();
        let grant_bytes = ledger
            .release(&acu_owner, &admitted_env, &policy, &raw_req, 1_003)
            .unwrap();
        let verified_grant =
            acu::verify_grant(&grant_bytes, &raw_req, &admitted_env, &policy, 1_004).unwrap();
        let opened = recipient_owner
            .open_payload_from_grant(&admitted_env, &verified_grant, &policy, 1_004)
            .unwrap();
        assert_eq!(&*opened, secret_payload.as_slice());
    }
}
