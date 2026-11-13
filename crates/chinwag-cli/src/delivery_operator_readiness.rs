// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Signed fleet consumer enrollment and durable, at-most-once arrival invocation.
//!
//! A reservation is synced before any child can start. An interrupted reservation
//! remains held: recovery never guesses whether an external process ran.

use crate::agent_instance::{ActorAddress, parse_fleet_recipients};
use crate::bus_federation::BusMessage;
use chinwag_fleet::{
    DispatchRequest, ExecutionContext, FleetManifest, KeyBijectionValidator,
    ProcessExecutionDriver, WorkspaceLeaseReceipt, prepare_execution_sandbox,
    release_execution_sandbox, resolve_dispatch_plan,
};
use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const BINDING_SCHEMA: &str = "chinwag.fleet-consumer-binding.v1";
const MAX_BINDINGS_BYTES: u64 = 1_048_576;

#[derive(Debug)]
pub enum WakeError {
    Identity,
    Signature,
    Expired,
    Manifest(String),
    Policy(String),
    Persistence(String),
    Conflict,
}
impl std::fmt::Display for WakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fleet wake held: {self:?}")
    }
}
impl std::error::Error for WakeError {}
fn io(error: std::io::Error) -> WakeError {
    WakeError::Persistence(error.to_string())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode<const N: usize>(value: &str) -> Result<[u8; N], WakeError> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(WakeError::Signature);
    }
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| WakeError::Signature)?;
    }
    Ok(bytes)
}
fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// An explicit operator grant. Digests bind the current scheduler projection;
/// these values are covered by both enrollment signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetTaskGrant {
    pub task_key_hex: String,
    pub grant_id: String,
    pub action: String,
    pub resource: String,
    pub task_spec_digest: String,
    pub task_control_digest: String,
    pub max_tokens: u64,
    pub max_micro_usd: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerBindingClaim {
    pub schema: String,
    pub binding_id: String,
    pub recipient: String,
    pub operator: String,
    pub host: String,
    pub generation: u64,
    pub manifest_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub requested_skills: Vec<String>,
    #[serde(default)]
    pub rooms: Vec<String>,
    #[serde(default)]
    pub requested_write_roots: Vec<String>,
    #[serde(default)]
    pub execution_binding_id: String,
    #[serde(default)]
    pub task_grants: Vec<FleetTaskGrant>,
    #[serde(default)]
    pub resource_capacities: BTreeMap<String, u16>,
    #[serde(default)]
    pub token_limit: u64,
    #[serde(default)]
    pub micro_usd_limit: u64,
}
impl ConsumerBindingClaim {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WakeError> {
        let mut bytes = b"chinwag-fleet-consumer-binding-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| WakeError::Identity)?);
        Ok(bytes)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConsumerBinding {
    pub claim: ConsumerBindingClaim,
    pub consumer_signature: String,
    pub operator_signature: String,
}
impl SignedConsumerBinding {
    pub fn sign(
        claim: ConsumerBindingClaim,
        consumer: &SecretKey,
        operator: &SecretKey,
    ) -> Result<Self, WakeError> {
        let bytes = claim.signing_bytes()?;
        Ok(Self {
            claim,
            consumer_signature: hex(&consumer.sign(&bytes).to_bytes()),
            operator_signature: hex(&operator.sign(&bytes).to_bytes()),
        })
    }
}

/// Only verified signatures, manifest binding and current policy can mint this
/// host capability. Parsed JSON and `sig_verified` booleans cannot mint it.
#[derive(Clone)]
pub struct DeliveryOperatorReadiness {
    manifest: FleetManifest,
    binding: SignedConsumerBinding,
    cwd: PathBuf,
    claim_root: PathBuf,
    consumer_key: EndpointId,
    operator_key: EndpointId,
    seat: String,
}
impl DeliveryOperatorReadiness {
    pub fn qualify(
        manifest: FleetManifest,
        binding: SignedConsumerBinding,
        cwd: &Path,
        claim_root: &Path,
        now: u64,
    ) -> Result<Self, WakeError> {
        manifest
            .validate()
            .map_err(|e| WakeError::Manifest(e.to_string()))?;
        KeyBijectionValidator::validate(&manifest, true)
            .map_err(|e| WakeError::Manifest(e.to_string()))?;
        let claim = &binding.claim;
        let recipient =
            ActorAddress::parse_fleet(&claim.recipient).map_err(|_| WakeError::Identity)?;
        let operator =
            ActorAddress::parse_fleet(&claim.operator).map_err(|_| WakeError::Identity)?;
        recipient
            .clone()
            .require_instance()
            .map_err(|_| WakeError::Identity)?;
        operator
            .clone()
            .require_instance()
            .map_err(|_| WakeError::Identity)?;
        if claim.schema != BINDING_SCHEMA
            || claim.binding_id.is_empty()
            || claim.binding_id.len() > 256
            || claim.host.is_empty()
            || claim.generation == 0
            || claim.expires_at <= claim.issued_at
            || claim.expires_at - claim.issued_at > 300
            || recipient.instance().is_none()
            || operator.instance().is_none()
            || recipient.to_string() != claim.recipient
            || operator.to_string() != claim.operator
            || !manifest.policy.operator_signers.contains(&claim.operator)
            || !manifest
                .seat(operator.seat())
                .is_some_and(|seat| seat.lifecycle.is_active())
            || claim.manifest_digest
                != manifest
                    .digest()
                    .map_err(|e| WakeError::Manifest(e.to_string()))?
        {
            return Err(WakeError::Identity);
        }
        let find_key = |actor: &ActorAddress| -> Result<EndpointId, WakeError> {
            let key = manifest
                .pubkey_map
                .iter()
                .find(|(seat, _)| seat.as_str() == actor.seat())
                .map(|(_, key)| key)
                .ok_or(WakeError::Identity)?;
            EndpointId::from_bytes(&decode::<32>(key)?).map_err(|_| WakeError::Identity)
        };
        if manifest
            .seat(recipient.seat())
            .is_some_and(|seat| seat.write_mode == chinwag_fleet::WriteMode::Isolated)
            && claim.requested_write_roots.is_empty()
        {
            return Err(WakeError::Policy(
                "mutating consumer requires signed write roots".into(),
            ));
        }
        let consumer_key = find_key(&recipient)?;
        let operator_key = find_key(&operator)?;
        let bytes = claim.signing_bytes()?;
        consumer_key
            .verify(
                &bytes,
                &Signature::from_bytes(&decode(&binding.consumer_signature)?),
            )
            .map_err(|_| WakeError::Signature)?;
        operator_key
            .verify(
                &bytes,
                &Signature::from_bytes(&decode(&binding.operator_signature)?),
            )
            .map_err(|_| WakeError::Signature)?;
        let readiness = Self {
            manifest,
            binding,
            cwd: fs::canonicalize(cwd).map_err(io)?,
            claim_root: claim_root.to_owned(),
            consumer_key,
            operator_key,
            seat: recipient.seat().into(),
        };
        readiness.revalidate(now)?;
        Ok(readiness)
    }
    pub fn claim(&self) -> &ConsumerBindingClaim {
        &self.binding.claim
    }
    pub fn consumer_key(&self) -> EndpointId {
        self.consumer_key
    }
    pub fn operator_key(&self) -> EndpointId {
        self.operator_key
    }
    pub fn workspace_root(&self) -> &Path {
        &self.cwd
    }
    pub fn claim_root(&self) -> &Path {
        &self.claim_root
    }
    pub fn revalidate(&self, now: u64) -> Result<(), WakeError> {
        let claim = self.claim();
        if now < claim.issued_at || now >= claim.expires_at {
            return Err(WakeError::Expired);
        }
        if claim.rooms.is_empty() {
            resolve_dispatch_plan(&self.manifest, &self.request(None))
                .map_err(|e| WakeError::Policy(e.to_string()))?;
        } else {
            for room in &claim.rooms {
                resolve_dispatch_plan(&self.manifest, &self.request(Some(room)))
                    .map_err(|e| WakeError::Policy(e.to_string()))?;
            }
        }
        Ok(())
    }
    fn request(&self, room: Option<&str>) -> DispatchRequest {
        DispatchRequest {
            seat: self.seat.clone(),
            room: room.map(str::to_owned),
            cwd: self.cwd.clone(),
            actor: Some(self.claim().recipient.clone()),
            requested_skills: self.claim().requested_skills.clone(),
            requested_write_globs: self.claim().requested_write_roots.clone(),
            ..DispatchRequest::default()
        }
    }
    pub(crate) fn execute_admitted_task(
        &self,
        message: &crate::task_wire::VerifiedTaskMessage,
        lease: &WorkspaceLeaseReceipt,
        now: u64,
    ) -> Result<chinwag_fleet::ExecutionOutcome, WakeError> {
        self.verify_lease(lease, now)?;
        let transcript = message.authenticated().transcript();
        if !transcript
            .recipient_full_actor_addresses
            .contains(&self.claim().recipient)
        {
            return Err(WakeError::Identity);
        }
        if !self.claim().rooms.is_empty() && !self.claim().rooms.contains(&transcript.room) {
            return Err(WakeError::Policy(
                "room is outside signed consumer binding".into(),
            ));
        }
        let plan = resolve_dispatch_plan(&self.manifest, &self.request(Some(&transcript.room)))
            .map_err(|error| WakeError::Policy(error.to_string()))?;
        let plan = plan
            .with_sandbox(&self.claim_root, lease)
            .map_err(|error| WakeError::Policy(error.to_string()))?;
        let actor =
            ActorAddress::parse_fleet(&self.claim().recipient).map_err(|_| WakeError::Identity)?;
        let context = ExecutionContext {
            prompt: Some(transcript.body_utf8.clone()),
            env: BTreeMap::from([
                ("CHINWAG_ACTOR".into(), self.claim().recipient.clone()),
                (
                    "CHINWAG_INSTANCE_ID".into(),
                    actor.instance().ok_or(WakeError::Identity)?.into(),
                ),
                (
                    "CHINWAG_CALLER".into(),
                    transcript.sender_full_actor_address.clone(),
                ),
                (
                    "CHINWAG_PARENT_INSTANCE".into(),
                    transcript.sender_full_actor_address.clone(),
                ),
                (
                    "CHINWAG_WAKE_MESSAGE_ID".into(),
                    transcript.message_id.clone(),
                ),
                (
                    "CHINWAG_WAKE_MESSAGE_DIGEST_SHA256".into(),
                    message.authenticated().transcript_digest().to_string(),
                ),
                (
                    "CHINWAG_CONSUMER_BINDING".into(),
                    self.claim().binding_id.clone(),
                ),
            ]),
            ..ExecutionContext::default()
        };
        ProcessExecutionDriver
            .execute_with_started(&plan, &context, |_| {})
            .map_err(|error| WakeError::Policy(error.to_string()))
    }
    pub fn verify_lease(&self, receipt: &WorkspaceLeaseReceipt, now: u64) -> Result<(), WakeError> {
        self.revalidate(now)?;
        if receipt.seat_actor != self.claim().recipient
            || receipt.repository() != self.cwd
            || receipt.manifest_digest() != Some(self.claim().manifest_digest.as_str())
            || self
                .claim()
                .requested_write_roots
                .iter()
                .any(|root| !receipt.allowed_write_roots.contains(root))
        {
            return Err(WakeError::Identity);
        }
        chinwag_fleet::verify_execution_sandbox(&self.claim_root, receipt)
            .map_err(|e| WakeError::Policy(e.to_string()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeReceipt {
    pub schema: String,
    pub original_message_id: String,
    pub original_message_digest_sha256: String,
    pub recipient: String,
    pub consumer_binding: String,
    pub scheduling: String,
    pub processing_ack: bool,
    pub work_started: bool,
    pub pid: Option<u32>,
    pub terminal_exit_code: Option<i32>,
    pub terminal_success: Option<bool>,
    pub timed_out: bool,
    pub termination_signal: Option<i32>,
    pub output_limit_exceeded: bool,
    pub lease: Option<WorkspaceLeaseReceipt>,
    pub diagnostic: Option<String>,
}
#[derive(Clone, Debug)]
pub enum ArrivalOutcome {
    Unaddressed,
    Duplicate { journal: PathBuf },
    Completed(Box<WakeReceipt>),
}

pub struct MessageArrivalWakeCoordinator {
    journal_root: PathBuf,
    consumers: BTreeMap<String, DeliveryOperatorReadiness>,
}
fn private_directory(path: &Path) -> Result<(), WakeError> {
    if let Some(parent) = path.parent() {
        for ancestor in parent.ancestors() {
            if fs::symlink_metadata(ancestor)
                .map_err(io)?
                .file_type()
                .is_symlink()
            {
                return Err(WakeError::Persistence(
                    "symlink in wake journal path".into(),
                ));
            }
        }
    }
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io)?;
            if let Some(parent) = path.parent() {
                File::open(parent).and_then(|f| f.sync_all()).map_err(io)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io(error)),
    }
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(WakeError::Persistence(
            "wake journal directory is not private".into(),
        ));
    }
    Ok(())
}
fn persist_new(path: &Path, value: &impl Serialize) -> Result<(), WakeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(io)?;
    let bytes = serde_json::to_vec(value).map_err(|_| WakeError::Identity)?;
    file.write_all(&bytes).map_err(io)?;
    file.write_all(b"\n").map_err(io)?;
    file.sync_all().map_err(io)?;
    File::open(path.parent().ok_or(WakeError::Identity)?)
        .and_then(|f| f.sync_all())
        .map_err(io)
}
/// Keep one stable lock inode per arrival. Never replace or unlink the lock:
/// crash recovery and concurrent daemon replays must serialize on the same file.
fn lock_entry(entry: &Path) -> Result<File, WakeError> {
    let path = entry.join("arrival.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .map_err(io)?;
    file.lock().map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    let named = fs::symlink_metadata(&path).map_err(io)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || (metadata.dev(), metadata.ino()) != (named.dev(), named.ino())
    {
        return Err(WakeError::Conflict);
    }
    Ok(file)
}
fn persist_arrival(entry: &Path, value: &impl Serialize) -> Result<(), WakeError> {
    let temporary = entry.join(format!("arrival-{:032x}.tmp", rand::random::<u128>()));
    let result = (|| {
        persist_new(&temporary, value)?;
        fs::rename(&temporary, entry.join("arrival.json")).map_err(io)?;
        File::open(entry)
            .and_then(|file| file.sync_all())
            .map_err(io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
impl MessageArrivalWakeCoordinator {
    pub fn open(
        journal_root: &Path,
        consumers: Vec<DeliveryOperatorReadiness>,
    ) -> Result<Self, WakeError> {
        if consumers.is_empty() {
            return Err(WakeError::Identity);
        }
        let parent =
            fs::canonicalize(journal_root.parent().ok_or(WakeError::Identity)?).map_err(io)?;
        let journal_root = parent.join(journal_root.file_name().ok_or(WakeError::Identity)?);
        private_directory(&journal_root)?;
        let mut by_actor = BTreeMap::new();
        let mut seats = BTreeSet::new();
        let mut manifest_digest = None;
        for consumer in consumers {
            if !seats.insert(consumer.seat.clone()) {
                return Err(WakeError::Conflict);
            }
            if manifest_digest
                .as_ref()
                .is_some_and(|digest| digest != &consumer.claim().manifest_digest)
            {
                return Err(WakeError::Conflict);
            }
            manifest_digest = Some(consumer.claim().manifest_digest.clone());
            if by_actor
                .insert(consumer.claim().recipient.clone(), consumer)
                .is_some()
            {
                return Err(WakeError::Conflict);
            }
        }
        Ok(Self {
            journal_root: journal_root.to_owned(),
            consumers: by_actor,
        })
    }
    /// Fleet-less operation returns None and retains honest publication-only
    /// behavior. A configured but invalid binding is a visible startup error.
    pub fn from_workspace(root: &Path, now: u64) -> Result<Option<Self>, WakeError> {
        Self::from_workspace_with_manifest(root, None, now)
    }
    pub fn from_workspace_with_manifest(
        root: &Path,
        explicit: Option<&Path>,
        now: u64,
    ) -> Result<Option<Self>, WakeError> {
        let binding_path = std::env::var_os("CHINWAG_CONSUMER_BINDINGS")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join(".chinwag/consumer-bindings.json"));
        if !binding_path.exists() {
            return Ok(None);
        }
        let metadata = fs::symlink_metadata(&binding_path).map_err(io)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_BINDINGS_BYTES
        {
            return Err(WakeError::Identity);
        }
        let bindings: Vec<SignedConsumerBinding> =
            serde_json::from_slice(&fs::read(binding_path).map_err(io)?)
                .map_err(|_| WakeError::Identity)?;
        if bindings.is_empty() {
            return Ok(None);
        }
        let manifest_path = FleetManifest::discover_path(explicit, root);
        let manifest =
            FleetManifest::load(&manifest_path).map_err(|e| WakeError::Manifest(e.to_string()))?;
        let claim_root = root.join(".chinwag/fleet-claims");
        let consumers = bindings
            .into_iter()
            .map(|binding| {
                DeliveryOperatorReadiness::qualify(
                    manifest.clone(),
                    binding,
                    root,
                    &claim_root,
                    now,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bus_dir = root.join(".chinwag/bus");
        if !bus_dir.exists() {
            private_directory(&bus_dir)?;
        }
        Ok(Some(Self::open(&bus_dir.join("wakes"), consumers)?))
    }
    /// Signatures are verified again here; transport ACKs and cached booleans
    /// are insufficient. A registered, signed enrollment is the wake capability.
    pub fn enqueue(&self, message: &BusMessage, now: u64) -> Result<Vec<String>, WakeError> {
        let Some(to) = message.to.as_deref() else {
            return Ok(Vec::new());
        };
        let recipients = parse_fleet_recipients(to).map_err(|_| WakeError::Identity)?;
        let Some(readiness) = self.consumers.values().next() else {
            return Ok(Vec::new());
        };
        let roster = readiness
            .manifest
            .pubkey_map
            .iter()
            .map(|(seat, key)| (seat.as_str().to_owned(), key.clone()))
            .collect();
        crate::bus_wait_message::verify_with_roster(message, &roster)
            .map_err(|_| WakeError::Signature)?;
        let mut queued = Vec::new();
        for consumer in self.consumers.values() {
            let actor = ActorAddress::parse_fleet(&consumer.claim().recipient)
                .map_err(|_| WakeError::Identity)?;
            if !recipients.iter().any(|recipient| {
                recipient == &actor
                    || (recipient.instance().is_none() && recipient.seat() == actor.seat())
            }) {
                continue;
            }
            consumer.revalidate(now)?;
            if !consumer.claim().rooms.is_empty() && !consumer.claim().rooms.contains(&message.room)
            {
                return Err(WakeError::Policy(
                    "room is outside signed consumer binding".into(),
                ));
            }
            resolve_dispatch_plan(&consumer.manifest, &consumer.request(Some(&message.room)))
                .map_err(|e| WakeError::Policy(e.to_string()))?;
            let entry = self.entry(message, &consumer.claim().recipient)?;
            private_directory(&entry)?;
            let _lock = lock_entry(&entry)?;
            // An invocation marker is permanent. A directory or interrupted
            // arrival write alone is recoverable because no child could start.
            if entry.join("invocation.json").exists() {
                continue;
            }
            let arrival = entry.join("arrival.json");
            let existing = match fs::symlink_metadata(&arrival) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink()
                        || !metadata.is_file()
                        || metadata.len() > MAX_BINDINGS_BYTES
                    {
                        return Err(WakeError::Conflict);
                    }
                    let bytes = fs::read(&arrival).map_err(io)?;
                    serde_json::from_slice::<(String, BusMessage)>(&bytes).ok()
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(io(error)),
            };
            if let Some((recipient, stored)) = existing {
                if recipient != consumer.claim().recipient
                    || !crate::bus_federation::same_immutable_original(&stored, message)
                {
                    return Err(WakeError::Conflict);
                }
            } else {
                persist_arrival(&entry, &(consumer.claim().recipient.clone(), message))?;
            }
            queued.push(consumer.claim().recipient.clone());
        }
        Ok(queued)
    }
    fn entry(&self, message: &BusMessage, recipient: &str) -> Result<PathBuf, WakeError> {
        let key = serde_json::to_vec(&(&message.id, &message.digest_sha256, recipient))
            .map_err(|_| WakeError::Identity)?;
        Ok(self.journal_root.join(hash(&key)))
    }
    pub fn receive(
        &self,
        message: &BusMessage,
        now: u64,
    ) -> Result<Vec<ArrivalOutcome>, WakeError> {
        let queued = self.enqueue(message, now)?;
        if queued.is_empty() {
            let duplicate = self.consumers.keys().any(|recipient| {
                self.entry(message, recipient)
                    .is_ok_and(|entry| entry.exists())
            });
            return Ok(vec![if duplicate {
                ArrivalOutcome::Duplicate {
                    journal: self.journal_root.clone(),
                }
            } else {
                ArrivalOutcome::Unaddressed
            }]);
        }
        queued
            .iter()
            .map(|recipient| self.process_enqueued(message, recipient, now))
            .collect()
    }
    /// Recover arrivals whose invocation was never claimed. An invocation marker
    /// without a terminal receipt is deliberately held and never retried.
    pub fn resume_pending(&self, now: u64) -> Result<Vec<ArrivalOutcome>, WakeError> {
        let mut outcomes = Vec::new();
        for entry in fs::read_dir(&self.journal_root).map_err(io)? {
            let entry = entry.map_err(io)?.path();
            let metadata = fs::symlink_metadata(&entry).map_err(io)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(WakeError::Conflict);
            }
            if entry.join("invocation.json").exists() || !entry.join("arrival.json").exists() {
                continue;
            }
            let bytes = fs::read(entry.join("arrival.json")).map_err(io)?;
            let (recipient, message): (String, BusMessage) =
                serde_json::from_slice(&bytes).map_err(|_| WakeError::Conflict)?;
            outcomes.push(self.process_enqueued(&message, &recipient, now)?);
        }
        Ok(outcomes)
    }
    pub fn process_enqueued(
        &self,
        message: &BusMessage,
        recipient: &str,
        now: u64,
    ) -> Result<ArrivalOutcome, WakeError> {
        // Recovery re-verifies the signature and room policy before claiming
        // an invocation; a mutable local JSON row is never authority.
        let _ = self.enqueue(message, now)?;
        let consumer = self.consumers.get(recipient).ok_or(WakeError::Identity)?;
        let actor = ActorAddress::parse_fleet(&consumer.claim().recipient)
            .map_err(|_| WakeError::Identity)?;
        let targets = parse_fleet_recipients(message.to.as_deref().ok_or(WakeError::Identity)?)
            .map_err(|_| WakeError::Identity)?;
        if !targets.iter().any(|target| {
            target == &actor || (target.instance().is_none() && target.seat() == actor.seat())
        }) {
            return Err(WakeError::Identity);
        }

        consumer.revalidate(now)?;
        let entry = self.entry(message, recipient)?;
        let bytes = fs::read(entry.join("arrival.json")).map_err(io)?;
        let (stored_recipient, stored): (String, BusMessage) =
            serde_json::from_slice(&bytes).map_err(|_| WakeError::Conflict)?;
        if stored_recipient != recipient
            || !crate::bus_federation::same_immutable_original(&stored, message)
        {
            return Err(WakeError::Conflict);
        }
        if entry.join("invocation.json").exists() {
            return Ok(ArrivalOutcome::Duplicate { journal: entry });
        }
        // create_new atomically wins across daemon processes and replays.
        match persist_new(&entry.join("invocation.json"), &(recipient, now)) {
            Ok(()) => {}
            Err(error) if entry.join("invocation.json").exists() => {
                // A partial marker is an uncertain invocation, never permission
                // to run again. The process which wrote it owns the attempt.
                let _ = error;
                return Ok(ArrivalOutcome::Duplicate { journal: entry });
            }
            Err(error) => return Err(error),
        }
        let mut receipt = WakeReceipt {
            schema: "chinwag.wake-receipt.v1".into(),
            original_message_id: message.id.clone(),
            original_message_digest_sha256: message.digest_sha256.clone(),
            recipient: consumer.claim().recipient.clone(),
            consumer_binding: consumer.claim().binding_id.clone(),
            scheduling: "DURABLY_RESERVED".into(),
            processing_ack: true,
            work_started: false,
            pid: None,
            terminal_exit_code: None,
            terminal_success: None,
            timed_out: false,
            termination_signal: None,
            output_limit_exceeded: false,
            lease: None,
            diagnostic: None,
        };
        persist_new(&entry.join("scheduled.json"), &receipt)?;
        let mut execute = || -> Result<WakeReceipt, WakeError> {
            let plan =
                resolve_dispatch_plan(&consumer.manifest, &consumer.request(Some(&message.room)))
                    .map_err(|e| WakeError::Policy(e.to_string()))?;
            let lease = prepare_execution_sandbox(
                &consumer.manifest,
                &plan,
                &consumer.claim_root,
                &consumer.claim().recipient,
            )
            .map_err(|e| WakeError::Policy(e.to_string()))?;
            let plan = match plan.with_sandbox(&consumer.claim_root, &lease) {
                Ok(plan) => plan,
                Err(error) => {
                    release_execution_sandbox(&consumer.claim_root, &lease, true).map_err(
                        |cleanup| {
                            WakeError::Policy(format!("{error}; quarantine failed: {cleanup}"))
                        },
                    )?;
                    return Err(WakeError::Policy(error.to_string()));
                }
            };
            receipt.lease = Some(lease.clone());
            let actor = ActorAddress::parse_fleet(&consumer.claim().recipient)
                .map_err(|_| WakeError::Identity)?;
            let mut context = ExecutionContext {
                prompt: Some(message.body.clone()),
                ..ExecutionContext::default()
            };
            context.env = BTreeMap::from([
                ("CHINWAG_ACTOR".into(), consumer.claim().recipient.clone()),
                (
                    "CHINWAG_INSTANCE_ID".into(),
                    actor.instance().ok_or(WakeError::Identity)?.into(),
                ),
                ("CHINWAG_CALLER".into(), message.sender.clone()),
                ("CHINWAG_PARENT_INSTANCE".into(), message.sender.clone()),
                (
                    "CHINWAG_ALLOWED_SKILLS".into(),
                    plan.allowed_skills.join(","),
                ),
                ("CHINWAG_WAKE_MESSAGE_ID".into(), message.id.clone()),
                (
                    "CHINWAG_WAKE_MESSAGE_DIGEST_SHA256".into(),
                    message.digest_sha256.clone(),
                ),
                (
                    "CHINWAG_WAKE_RECIPIENT".into(),
                    consumer.claim().recipient.clone(),
                ),
                ("CHINWAG_WAKE_ROOM".into(), message.room.clone()),
                (
                    "CHINWAG_CONSUMER_BINDING".into(),
                    consumer.claim().binding_id.clone(),
                ),
            ]);
            let mut started_persistence = Ok(());
            let outcome = ProcessExecutionDriver.execute_with_started(&plan, &context, |pid| {
                receipt.work_started = true;
                receipt.pid = Some(pid);
                receipt.scheduling = "INVOKED".into();
                started_persistence = persist_new(&entry.join("started.json"), &receipt);
            });
            if let Err(error) = started_persistence {
                let _ = release_execution_sandbox(&consumer.claim_root, &lease, true);
                return Err(error);
            }
            match outcome {
                Ok(outcome) => {
                    receipt.terminal_exit_code = outcome.exit_code;
                    receipt.terminal_success = Some(outcome.success);
                    receipt.timed_out = outcome.timed_out;
                    receipt.termination_signal = outcome.termination_signal;
                    receipt.output_limit_exceeded = outcome.output_limit_exceeded;
                    receipt.scheduling = "TERMINAL".into();
                    release_execution_sandbox(&consumer.claim_root, &lease, !outcome.success)
                        .map_err(|e| WakeError::Policy(e.to_string()))?;
                    Ok(receipt.clone())
                }
                Err(error) => {
                    let _ = release_execution_sandbox(&consumer.claim_root, &lease, true);
                    Err(WakeError::Policy(error.to_string()))
                }
            }
        };
        match execute() {
            Ok(completed) => receipt = completed,
            Err(error) => {
                receipt.scheduling = if receipt.work_started {
                    "INVOCATION_UNKNOWN"
                } else {
                    "REJECTED_BEFORE_INVOCATION"
                }
                .into();
                receipt.diagnostic = Some(error.to_string());
            }
        }
        persist_new(&entry.join("wake-receipt.json"), &receipt)?;
        let mut report = serde_json::to_value(&receipt).map_err(|_| WakeError::Identity)?;
        report["schema"] = "chinwag.delivery-report.v1".into();
        persist_new(&entry.join("delivery-report.json"), &report)?;
        Ok(ArrivalOutcome::Completed(Box::new(receipt)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use chinwag_fleet::{
        CredentialIsolation, DriverSpec, IsolationSpec, SeatId, SeatLifecycle, WriteMode,
    };
    use tempfile::TempDir;

    pub(crate) struct Fixture {
        _temp: TempDir,
        pub(crate) root: PathBuf,
        pub(crate) manifest: FleetManifest,
        pub(crate) binding: SignedConsumerBinding,
        pub(crate) operator: SecretKey,
        pub(crate) consumer: SecretKey,
    }
    impl Fixture {
        pub(crate) fn new() -> Self {
            let temp = TempDir::new().unwrap();
            let root = temp.path().canonicalize().unwrap();
            assert!(
                std::process::Command::new("git")
                    .args(["init", "--quiet"])
                    .current_dir(&root)
                    .status()
                    .unwrap()
                    .success()
            );
            fs::write(root.join("handler.sh"),
                "#!/bin/sh\n/bin/cat >/dev/null\nprintf '%s|%s|%s|%s|%s\\n' \"$CHINWAG_ACTOR\" \"$CHINWAG_INSTANCE_ID\" \"$CHINWAG_WAKE_MESSAGE_ID\" \"$CHINWAG_WAKE_MESSAGE_DIGEST_SHA256\" \"$CHINWAG_CONSUMER_BINDING\" > evidence.txt\n").unwrap();
            let mut manifest = FleetManifest::starter_profile("solo").unwrap();
            let seat = &mut manifest.seats[0];
            seat.id = SeatId::new("RUNNER").unwrap();
            seat.lifecycle = SeatLifecycle::ActiveStanding;
            seat.driver = DriverSpec::CliSubprocess {
                executable: "/bin/sh".into(),
                argv_template: vec![root.join("handler.sh").to_string_lossy().into_owned()],
                auth_isolation: CredentialIsolation::NoneLocal,
                env_allowlist: vec![],
                env_overrides: BTreeMap::new(),
                framing: "stdin".into(),
                timeout_secs: 10,
            };
            seat.write_mode = WriteMode::Isolated;
            seat.isolation = IsolationSpec::ArtifactSubdirOnly {
                root: root.join("artifacts"),
            };
            seat.allowed_write_roots = vec!["artifacts/**".into()];
            let mut operator_seat = seat.clone();
            operator_seat.id = SeatId::new("OPERATOR").unwrap();
            manifest.seats.push(operator_seat);
            let consumer = SecretKey::from_bytes(&[11; 32]);
            let operator = SecretKey::from_bytes(&[12; 32]);
            for (seat, key) in [("RUNNER", &consumer), ("OPERATOR", &operator)] {
                manifest
                    .pubkey_map
                    .insert(SeatId::new(seat).unwrap(), key.public().to_string());
                manifest
                    .allowed_signers
                    .insert(SeatId::new(seat).unwrap(), key.public().to_string());
            }
            manifest.policy.operator_signers = vec!["OPERATOR#admin".into()];
            let claim = ConsumerBindingClaim {
                schema: BINDING_SCHEMA.into(),
                binding_id: "consumer-binding".into(),
                recipient: "RUNNER#session".into(),
                operator: "OPERATOR#admin".into(),
                host: "fixture-host".into(),
                generation: 1,
                manifest_digest: manifest.digest().unwrap(),
                issued_at: 100,
                expires_at: 200,
                requested_skills: vec![],
                rooms: vec![],
                requested_write_roots: vec!["artifacts/**".into()],
                execution_binding_id: "execution-binding".into(),
                task_grants: vec![],
                resource_capacities: BTreeMap::new(),
                token_limit: 0,
                micro_usd_limit: 0,
            };
            let binding = SignedConsumerBinding::sign(claim, &consumer, &operator).unwrap();
            Self {
                _temp: temp,
                root,
                manifest,
                binding,
                operator,
                consumer,
            }
        }
        fn dotted() -> Self {
            let mut fixture = Self::new();
            fixture.manifest.seats[0].id = SeatId::new("runner.pool").unwrap();
            fixture.manifest.seats[1].id = SeatId::new("operator.control").unwrap();
            fixture.manifest.pubkey_map.clear();
            fixture.manifest.allowed_signers.clear();
            for (seat, key) in [
                ("runner.pool", &fixture.consumer),
                ("operator.control", &fixture.operator),
            ] {
                fixture
                    .manifest
                    .pubkey_map
                    .insert(SeatId::new(seat).unwrap(), key.public().to_string());
                fixture
                    .manifest
                    .allowed_signers
                    .insert(SeatId::new(seat).unwrap(), key.public().to_string());
            }
            fixture.manifest.policy.operator_signers = vec!["operator.control#AdminCase".into()];
            fixture.binding.claim.recipient = "runner.pool#SessionCase".into();
            fixture.binding.claim.operator = "operator.control#AdminCase".into();
            fixture.binding.claim.manifest_digest = fixture.manifest.digest().unwrap();
            fixture.binding = SignedConsumerBinding::sign(
                fixture.binding.claim.clone(),
                &fixture.consumer,
                &fixture.operator,
            )
            .unwrap();
            fixture
        }
        fn readiness(&self) -> DeliveryOperatorReadiness {
            DeliveryOperatorReadiness::qualify(
                self.manifest.clone(),
                self.binding.clone(),
                &self.root,
                &self.root.join("claims"),
                110,
            )
            .unwrap()
        }
        fn coordinator(&self) -> MessageArrivalWakeCoordinator {
            MessageArrivalWakeCoordinator::open(
                &self.root.join("wake-journal"),
                vec![self.readiness()],
            )
            .unwrap()
        }
        pub(crate) fn install_daemon_config(&mut self) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.binding.claim.issued_at = now;
            self.binding.claim.expires_at = now + 120;
            self.binding = SignedConsumerBinding::sign(
                self.binding.claim.clone(),
                &self.consumer,
                &self.operator,
            )
            .unwrap();
            let chinwag = self.root.join(".chinwag");
            fs::create_dir(&chinwag).unwrap();
            fs::write(chinwag.join("fleet.toml"), self.manifest.to_toml().unwrap()).unwrap();
            fs::write(
                chinwag.join("consumer-bindings.json"),
                serde_json::to_vec(&vec![self.binding.clone()]).unwrap(),
            )
            .unwrap();
            let public = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(
                *self.operator.public().as_bytes(),
            ));
            fs::write(
                chinwag.join("allowed_signers"),
                format!(
                    "operator@example.test namespaces=\"git\" {} chinwag {}\n",
                    public.to_openssh().unwrap(),
                    ActorAddress::parse_fleet(&self.binding.claim.operator)
                        .unwrap()
                        .seat()
                ),
            )
            .unwrap();
        }
        pub(crate) fn message(&self) -> BusMessage {
            let mut message = BusMessage {
                id: "arrival-one".into(),
                seq: 1,
                ts_unix: 110,
                ts_iso: "110".into(),
                room: "#jobs".into(),
                sender: self.binding.claim.operator.clone(),
                sender_cast: "".into(),
                sender_endpoint_id: self.operator.public().to_string(),
                to: Some(format!(
                    "@{}",
                    ActorAddress::parse_fleet(&self.binding.claim.recipient)
                        .unwrap()
                        .seat()
                )),
                task_id: None,
                body: "perform fixture work".into(),
                digest_sha256: String::new(),
                pubkey_ed25519: Some(self.operator.public().to_string()),
                signature_ed25519: None,
                // Deliberately false: only the real signature establishes trust.
                sig_verified: false,
            };
            message.digest_sha256 = crate::bus_wait_message::message_digest(&message);
            message.signature_ed25519 = Some(hex(&self
                .operator
                .sign(crate::bus_wait_message::signing_payload(&message).as_bytes())
                .to_bytes()));
            message
        }
    }
    #[test]
    fn tampered_recovery_recipient_cannot_redirect_a_signed_arrival() {
        for target in ["@other.pool", "RUNNER#different-session"] {
            let fixture = Fixture::new();
            let mut message = fixture.message();
            message.to = Some(target.into());
            message.digest_sha256 = crate::bus_wait_message::message_digest(&message);
            message.signature_ed25519 = Some(hex(&fixture
                .operator
                .sign(crate::bus_wait_message::signing_payload(&message).as_bytes())
                .to_bytes()));
            let coordinator = fixture.coordinator();
            // A corrupt local row and its path claim the registered consumer,
            // while the authentic sender's signed target names someone else.
            let entry = coordinator.entry(&message, "RUNNER#session").unwrap();
            private_directory(&entry).unwrap();
            persist_arrival(&entry, &("RUNNER#session", &message)).unwrap();
            drop(coordinator);
            assert!(matches!(
                fixture.coordinator().resume_pending(111),
                Err(WakeError::Identity)
            ));
            assert!(!entry.join("invocation.json").exists());
            assert!(!fixture.root.join("artifacts").exists());
        }
    }

    #[test]
    fn preinvocation_empty_and_partial_arrivals_recover_on_replay_once() {
        for interrupted in [None, Some(b"{partial".as_slice())] {
            let fixture = Fixture::new();
            let message = fixture.message();
            let coordinator = fixture.coordinator();
            let entry = coordinator.entry(&message, "RUNNER#session").unwrap();
            private_directory(&entry).unwrap();
            if let Some(bytes) = interrupted {
                fs::write(entry.join("arrival.json"), bytes).unwrap();
            }
            drop(coordinator);
            let restarted = fixture.coordinator();
            let result = restarted.receive(&message, 111).unwrap();
            assert!(
                matches!(&result[0], ArrivalOutcome::Completed(receipt) if receipt.work_started && receipt.terminal_success == Some(true))
            );
            assert!(matches!(
                &restarted.receive(&message, 112).unwrap()[0],
                ArrivalOutcome::Duplicate { .. }
            ));
            assert_eq!(
                fs::read_dir(fixture.root.join("artifacts"))
                    .unwrap()
                    .count(),
                1
            );
        }
    }

    #[test]
    fn concurrent_pending_replays_acquire_one_invocation() {
        let fixture = Fixture::new();
        let message = fixture.message();
        let coordinator = fixture.coordinator();
        coordinator.enqueue(&message, 110).unwrap();
        let outcomes = std::thread::scope(|scope| {
            let first = scope.spawn(|| coordinator.receive(&message, 111).unwrap());
            let second = scope.spawn(|| coordinator.receive(&message, 111).unwrap());
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(outcomes.iter().flatten().filter(|result| matches!(result, ArrivalOutcome::Completed(receipt) if receipt.work_started)).count(), 1);
        assert_eq!(
            fs::read_dir(fixture.root.join("artifacts"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn empty_consumer_file_remains_unconfigured() {
        let fixture = Fixture::new();
        let chinwag = fixture.root.join(".chinwag");
        fs::create_dir(&chinwag).unwrap();
        fs::write(chinwag.join("consumer-bindings.json"), "[]").unwrap();
        assert!(
            MessageArrivalWakeCoordinator::from_workspace_with_manifest(
                &fixture.root,
                Some(&fixture.root.join("missing-manifest.toml")),
                110
            )
            .unwrap()
            .is_none()
        );
        assert!(
            MessageArrivalWakeCoordinator::open(&fixture.root.join("empty-journal"), Vec::new())
                .is_err()
        );
    }

    #[test]
    fn exact_lowercase_dotted_fleet_addresses_invoke_real_process() {
        let fixture = Fixture::dotted();
        struct Provider(crate::bus_delivery::ConsumerBinding);
        impl crate::bus_delivery::ConsumerEvidenceProvider for Provider {
            fn verified_now(&self) -> Result<u64, crate::bus_delivery::DeliveryError> {
                Ok(110)
            }
            fn current_binding(
                &self,
                _: &str,
            ) -> Result<crate::bus_delivery::ConsumerBinding, crate::bus_delivery::DeliveryError>
            {
                Ok(self.0.clone())
            }
        }
        let binding =
            crate::bus_delivery::ConsumerBinding::from_qualified_fleet(&fixture.readiness(), 110)
                .unwrap();
        let snapshot =
            crate::bus_delivery::consumer_cadence(&Provider(binding), "runner.pool#SessionCase");
        assert_eq!(
            snapshot.state,
            crate::bus_delivery::ConsumerLifecycle::CadenceStale
        );
        assert_eq!(snapshot.conversation.as_deref(), Some("SessionCase"));
        let message = fixture.message();
        let result = fixture.coordinator().receive(&message, 110).unwrap();
        let ArrivalOutcome::Completed(receipt) = &result[0] else {
            panic!("expected real dotted-seat invocation");
        };
        assert_eq!(receipt.recipient, "runner.pool#SessionCase");
        assert_eq!(
            receipt.terminal_success,
            Some(true),
            "{:?}",
            receipt.diagnostic
        );
        let evidence = fs::read_to_string(
            receipt
                .lease
                .as_ref()
                .unwrap()
                .isolated_cwd
                .join("evidence.txt"),
        )
        .unwrap();
        assert!(evidence.starts_with("runner.pool#SessionCase|SessionCase|"));
        let mut wrong_case = message.clone();
        wrong_case.to = Some("@Runner.pool".into());
        wrong_case.digest_sha256 = crate::bus_wait_message::message_digest(&wrong_case);
        wrong_case.signature_ed25519 = Some(hex(&fixture
            .operator
            .sign(crate::bus_wait_message::signing_payload(&wrong_case).as_bytes())
            .to_bytes()));
        assert!(matches!(
            fixture.coordinator().receive(&wrong_case, 111).unwrap()[0],
            ArrivalOutcome::Unaddressed
        ));
    }

    #[test]
    fn qualified_daemon_signed_arrival_wakes_once_across_replay_and_restart() {
        use crate::bus_run::{
            daemon_json_path, publish_over_iroh_quic, read_all_messages, read_daemon_state,
            run_daemon_loop,
        };
        use std::time::{Duration, Instant};
        let mut fixture = Fixture::dotted();
        fixture.install_daemon_config();
        let message = fixture.message();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for restart in [false, true] {
            rt.block_on(async {
                let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
                let mut output = Vec::new();
                let daemon = run_daemon_loop(
                    fixture.root.clone(),
                    0,
                    None,
                    true,
                    &mut output,
                    async move {
                        let _ = stop_rx.await;
                    },
                );
                let probe = async {
                    let deadline = Instant::now() + Duration::from_secs(10);
                    let state = loop {
                        if let Some(state) = read_daemon_state(&fixture.root)
                            && state.delivery_router == "QUALIFIED_FLEET_MESSAGE_ARRIVAL_WAKE"
                        {
                            break state;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "qualified daemon startup timed out"
                        );
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    };
                    for _ in 0..2 {
                        let ack =
                            publish_over_iroh_quic(&state, fixture.operator.clone(), &message)
                                .await
                                .unwrap();
                        assert!(ack.ok && ack.sig_verified);
                    }
                    loop {
                        let journal = fixture.root.join(".chinwag/bus/wakes");
                        let completed = fs::read_dir(&journal)
                            .ok()
                            .into_iter()
                            .flatten()
                            .flatten()
                            .any(|entry| entry.path().join("wake-receipt.json").exists());
                        if completed {
                            break;
                        }
                        assert!(Instant::now() < deadline, "real wake receipt timed out");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    assert_eq!(
                        fs::read_dir(fixture.root.join("artifacts"))
                            .unwrap()
                            .count(),
                        1
                    );
                    assert_eq!(read_all_messages(&fixture.root).len(), 1);
                    let _ = stop_tx.send(());
                };
                let (code, ()) = tokio::join!(daemon, probe);
                assert_eq!(
                    code,
                    0,
                    "restart={restart}, {}",
                    String::from_utf8_lossy(&output)
                );
            });
            // Drop stale diagnostic state so the next probe waits for the new endpoint.
            fs::remove_file(daemon_json_path(&fixture.root)).unwrap();
        }
    }

    #[test]
    fn signed_arrival_invokes_real_child_and_restarts_never_duplicate() {
        let fixture = Fixture::new();
        let message = fixture.message();
        let coordinator = fixture.coordinator();
        let outcomes = coordinator.receive(&message, 110).unwrap();
        let ArrivalOutcome::Completed(receipt) = &outcomes[0] else {
            panic!("expected real invocation");
        };
        assert!(receipt.work_started, "{:?}", receipt.diagnostic);
        assert!(receipt.processing_ack);
        assert_eq!(receipt.terminal_success, Some(true));
        assert_eq!(receipt.terminal_exit_code, Some(0));
        assert_eq!(receipt.original_message_id, message.id);
        assert_eq!(
            receipt.original_message_digest_sha256,
            message.digest_sha256
        );
        let evidence = receipt
            .lease
            .as_ref()
            .unwrap()
            .isolated_cwd
            .join("evidence.txt");
        let expected = format!(
            "RUNNER#session|session|arrival-one|{}|consumer-binding\n",
            message.digest_sha256
        );
        assert_eq!(fs::read_to_string(&evidence).unwrap(), expected);
        let entry = coordinator.entry(&message, "RUNNER#session").unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(entry.join("delivery-report.json")).unwrap()).unwrap();
        assert_eq!(report["schema"], "chinwag.delivery-report.v1");
        assert_eq!(report["work_started"], true);
        assert!(entry.join("started.json").exists());
        drop(coordinator);
        let restarted = fixture.coordinator();
        assert!(matches!(
            restarted.receive(&message, 111).unwrap()[0],
            ArrivalOutcome::Duplicate { .. }
        ));
        assert!(restarted.resume_pending(111).unwrap().is_empty());
        assert_eq!(fs::read_to_string(evidence).unwrap(), expected);
        assert_eq!(
            fs::read_dir(fixture.root.join("artifacts"))
                .unwrap()
                .count(),
            1
        );
    }
    #[test]
    fn restart_recovers_queued_arrival_but_quarantines_uncertain_invocation() {
        let fixture = Fixture::new();
        let message = fixture.message();
        let coordinator = fixture.coordinator();
        assert_eq!(
            coordinator.enqueue(&message, 110).unwrap(),
            vec!["RUNNER#session"]
        );
        drop(coordinator);
        let coordinator = fixture.coordinator();
        let recovered = coordinator.resume_pending(111).unwrap();
        assert!(
            matches!(&recovered[0], ArrivalOutcome::Completed(receipt) if receipt.work_started)
        );
        let mut next = message.clone();
        next.id = "interrupted-arrival".into();
        next.signature_ed25519 = Some(hex(&fixture
            .operator
            .sign(crate::bus_wait_message::signing_payload(&next).as_bytes())
            .to_bytes()));
        coordinator.enqueue(&next, 111).unwrap();
        let entry = coordinator.entry(&next, "RUNNER#session").unwrap();
        persist_new(
            &entry.join("invocation.json"),
            &"crash after invocation claim",
        )
        .unwrap();
        drop(coordinator);
        assert!(
            fixture
                .coordinator()
                .resume_pending(112)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            fs::read_dir(fixture.root.join("artifacts"))
                .unwrap()
                .count(),
            1
        );
    }
    #[test]
    fn forged_signature_expiry_manifest_change_and_operator_escalation_are_held() {
        let fixture = Fixture::new();
        let mut forged = fixture.binding.clone();
        forged.claim.host = "tampered-host".into();
        assert!(matches!(
            DeliveryOperatorReadiness::qualify(
                fixture.manifest.clone(),
                forged,
                &fixture.root,
                &fixture.root.join("claims"),
                110
            ),
            Err(WakeError::Signature)
        ));
        assert!(matches!(
            DeliveryOperatorReadiness::qualify(
                fixture.manifest.clone(),
                fixture.binding.clone(),
                &fixture.root,
                &fixture.root.join("claims"),
                200
            ),
            Err(WakeError::Expired)
        ));
        let mut manifest = fixture.manifest.clone();
        manifest.seats[0].model.model_id = "changed-binding".into();
        assert!(
            DeliveryOperatorReadiness::qualify(
                manifest,
                fixture.binding.clone(),
                &fixture.root,
                &fixture.root.join("claims"),
                110
            )
            .is_err()
        );
        let mut claim = fixture.binding.claim.clone();
        claim.operator = "RUNNER#session".into();
        let self_signed =
            SignedConsumerBinding::sign(claim, &fixture.consumer, &fixture.consumer).unwrap();
        assert!(matches!(
            DeliveryOperatorReadiness::qualify(
                fixture.manifest.clone(),
                self_signed,
                &fixture.root,
                &fixture.root.join("claims"),
                110
            ),
            Err(WakeError::Identity)
        ));
        let mut message = fixture.message();
        message.body = "tampered".into();
        message.sig_verified = true;
        assert!(fixture.coordinator().receive(&message, 110).is_err());
        assert!(!fixture.root.join("artifacts").exists());
    }
    #[test]
    fn policy_and_expired_binding_fail_before_arrival_or_child() {
        let mut fixture = Fixture::new();
        fixture.manifest.seats[0].lifecycle = SeatLifecycle::Paused;
        fixture.binding.claim.manifest_digest = fixture.manifest.digest().unwrap();
        fixture.binding = SignedConsumerBinding::sign(
            fixture.binding.claim.clone(),
            &fixture.consumer,
            &fixture.operator,
        )
        .unwrap();
        assert!(
            DeliveryOperatorReadiness::qualify(
                fixture.manifest.clone(),
                fixture.binding.clone(),
                &fixture.root,
                &fixture.root.join("claims"),
                110
            )
            .is_err()
        );
        assert!(!fixture.root.join("artifacts").exists());
        let fixture = Fixture::new();
        assert!(
            fixture
                .coordinator()
                .receive(&fixture.message(), 201)
                .is_err()
        );
        assert_eq!(
            fs::read_dir(fixture.root.join("wake-journal"))
                .unwrap()
                .count(),
            0
        );
    }
}
