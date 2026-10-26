//! Operator-owned claim attempt slot.
//!
//! Trust comes from the binding passed to [`AttemptJournal::open`], not from
//! the directory contents. `Armed` does not prove a packet was never sent.
//! `Unknown` means the outcome is unknown. `Verified` is a bound reply, not a
//! write permit. Hashes detect a changed file; they are not a MAC.

#![forbid(unsafe_code)]

use std::cell::Cell;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use rand::TryRngCore;
use rand::rngs::OsRng;
use rustix::fs::{
    CWD, FileType, FlockOperation, Mode, OFlags, flock, fstat, fsync, openat, renameat,
};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};

use chinwag_claim::reply::{
    MAX_REPLY_BODY_BYTES, ParsedClaimReply, PreparedClaim, parse_claim_reply,
};
use chinwag_claim::{decode_hex_exact, encode_hex, sha256};

const LOCK_NAME: &str = "journal.lock";
const RECORD_NAME: &str = "attempt.json";
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const SCHEMA: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptError {
    Binding,
    Directory,
    Lock,
    Occupied,
    Inode,
    Corrupt,
    Stale,
    Phase,
    Overflow,
    Random,
    Poisoned,
    Io,
    Refusal,
    Verify,
}

impl std::fmt::Display for AttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AttemptError::Binding => "attempt binding rejected",
            AttemptError::Directory => "attempt directory rejected",
            AttemptError::Lock => "attempt journal lock unavailable",
            AttemptError::Occupied => "attempt slot occupied",
            AttemptError::Inode => "attempt inode rejected",
            AttemptError::Corrupt => "attempt record corrupt",
            AttemptError::Stale => "attempt handle is stale",
            AttemptError::Phase => "attempt phase rejected",
            AttemptError::Overflow => "attempt generation overflow",
            AttemptError::Random => "attempt id unavailable",
            AttemptError::Poisoned => "attempt journal poisoned",
            AttemptError::Io => "attempt journal io failed",
            AttemptError::Refusal => "attempt refusal rejected",
            AttemptError::Verify => "attempt reply rejected",
        })
    }
}

impl std::error::Error for AttemptError {}

/// Durable local phase. `Verified` is a bound reply only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptPhase {
    Armed,
    Unknown,
    Refused,
    Verified,
}

/// A validated local outcome. It contains no live-session or write authority.
///
/// ```compile_fail,E0599
/// fn no_current(outcome: chinwag_swarm::attempt_journal::StoredOutcome) {
///     outcome.check_current();
/// }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub enum StoredOutcome {
    Refused {
        status: u16,
        code: String,
        cf_ray: String,
    },
    Verified {
        receipt_json: String,
        receipt_json_sha256: [u8; 32],
        cf_ray: String,
    },
}

impl std::fmt::Debug for StoredOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused {
                status,
                code,
                cf_ray,
            } => f
                .debug_struct("Refused")
                .field("status", status)
                .field("code", code)
                .field("cf_ray", cf_ray)
                .finish(),
            Self::Verified {
                receipt_json_sha256,
                cf_ray,
                ..
            } => f
                .debug_struct("Verified")
                .field("receipt_json_sha256", &encode_hex(receipt_json_sha256))
                .field("cf_ray", cf_ray)
                .finish_non_exhaustive(),
        }
    }
}

/// Operator configuration. Fields stay private and are never taken from disk.
#[derive(Debug, PartialEq, Eq)]
pub struct AttemptBinding {
    origin: String,
    actor: [u8; 32],
    coordinator: [u8; 32],
}

impl AttemptBinding {
    pub fn new(origin: &str, actor: [u8; 32], coordinator: [u8; 32]) -> Result<Self, AttemptError> {
        let origin = clean_origin(origin)?;
        if actor == coordinator {
            return Err(AttemptError::Binding);
        }
        let actor_key = VerifyingKey::from_bytes(&actor).map_err(|_| AttemptError::Binding)?;
        let coordinator_key =
            VerifyingKey::from_bytes(&coordinator).map_err(|_| AttemptError::Binding)?;
        if actor_key.is_weak() || coordinator_key.is_weak() {
            return Err(AttemptError::Binding);
        }
        Ok(Self {
            origin,
            actor,
            coordinator,
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn actor(&self) -> &[u8; 32] {
        &self.actor
    }

    pub fn coordinator(&self) -> &[u8; 32] {
        &self.coordinator
    }

    fn duplicate(&self) -> Self {
        Self {
            origin: self.origin.clone(),
            actor: self.actor,
            coordinator: self.coordinator,
        }
    }
}

/// One non-replaceable original attempt. This value cannot be cloned.
pub struct ArmedAttempt {
    id: [u8; 16],
    generation: u64,
    fingerprint: [u8; 32],
    phase: AttemptPhase,
    prepared: PreparedClaim,
    binding: AttemptBinding,
}

impl std::fmt::Debug for ArmedAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArmedAttempt")
            .field("id", &encode_hex(&self.id))
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl ArmedAttempt {
    pub fn phase(&self) -> AttemptPhase {
        self.phase
    }

    pub fn prepared(&self) -> &PreparedClaim {
        &self.prepared
    }

    pub fn binding(&self) -> &AttemptBinding {
        &self.binding
    }

    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }
}

/// Stable lock plus one record inode. The directory fd stays pinned.
#[derive(Debug)]
pub struct AttemptJournal {
    dir: File,
    binding: AttemptBinding,
    poisoned: Cell<bool>,
    lock: File,
}

impl AttemptJournal {
    pub fn open(dir: &Path, binding: AttemptBinding) -> Result<Self, AttemptError> {
        let dir = open_directory(dir)?;
        let lock_fd = openat(
            &dir,
            LOCK_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(map_errno)?;
        let lock = File::from(lock_fd);
        inspect_file(&lock, true)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|err| {
            if err == Errno::WOULDBLOCK || err == Errno::AGAIN {
                AttemptError::Lock
            } else {
                AttemptError::Io
            }
        })?;
        Ok(Self {
            dir,
            binding,
            poisoned: Cell::new(false),
            lock,
        })
    }

    pub fn arm(&mut self, prepared: &PreparedClaim) -> Result<ArmedAttempt, AttemptError> {
        self.ensure_open()?;
        self.require_claim_actor(prepared)?;
        match self.open_record() {
            Ok(Some(_)) => return Err(AttemptError::Occupied),
            Ok(None) => {}
            Err(AttemptError::Inode) => return Err(AttemptError::Inode),
            Err(error) => return Err(error),
        }
        let id = random_bytes::<16>()?;
        let record = DiskRecord {
            schema: SCHEMA,
            attempt_id: encode_hex(&id),
            request_json: prepared.request_json().to_owned(),
            canonical_sha256: encode_hex(prepared.request_sha256()),
            wire_sha256: encode_hex(prepared.wire_sha256()),
            origin: self.binding.origin.clone(),
            actor: encode_hex(&self.binding.actor),
            coordinator: encode_hex(&self.binding.coordinator),
            generation: 1,
            state: DiskState::Armed,
            status: None,
            code: None,
            ray: None,
            reply_body: None,
        };
        let bytes = to_record_bytes(&record)?;
        let fingerprint = self.create_record(&bytes)?;
        Ok(ArmedAttempt {
            id,
            generation: 1,
            fingerprint,
            phase: AttemptPhase::Armed,
            prepared: PreparedClaim::from_request_json_exact(prepared.request_json().as_bytes())
                .map_err(|_| AttemptError::Corrupt)?,
            binding: self.binding.duplicate(),
        })
    }

    pub fn load(&self) -> Result<Option<ArmedAttempt>, AttemptError> {
        self.ensure_open()?;
        let Some(file) = self.open_record()? else {
            return Ok(None);
        };
        let bytes = read_capped(file)?;
        let validated = validate_record(&bytes, &self.binding)?;
        Ok(Some(validated.into_attempt(sha256(&bytes), &self.binding)))
    }

    /// Revalidate this exact handle and project only a stored outcome. This
    /// never signs, sends, changes a phase, or promotes a reported disposition.
    pub fn stored_outcome(
        &self,
        attempt: &ArmedAttempt,
    ) -> Result<Option<StoredOutcome>, AttemptError> {
        self.ensure_open()?;
        self.require_same_binding(attempt)?;
        let file = self.open_record()?.ok_or(AttemptError::Stale)?;
        let bytes = read_capped(file)?;
        if sha256(&bytes) != attempt.fingerprint {
            return Err(AttemptError::Stale);
        }
        let current = validate_record(&bytes, &self.binding)?;
        if current.id != attempt.id
            || current.generation != attempt.generation
            || current.phase != attempt.phase
        {
            return Err(AttemptError::Stale);
        }
        let record = &current.disk;
        match current.phase {
            AttemptPhase::Armed | AttemptPhase::Unknown => Ok(None),
            AttemptPhase::Refused => Ok(Some(StoredOutcome::Refused {
                status: record.status.ok_or(AttemptError::Corrupt)?,
                code: record.code.clone().ok_or(AttemptError::Corrupt)?,
                cf_ray: record.ray.clone().ok_or(AttemptError::Corrupt)?,
            })),
            AttemptPhase::Verified => {
                let actor = VerifyingKey::from_bytes(&self.binding.actor)
                    .map_err(|_| AttemptError::Corrupt)?;
                let coordinator = VerifyingKey::from_bytes(&self.binding.coordinator)
                    .map_err(|_| AttemptError::Corrupt)?;
                let body = record.reply_body.as_deref().ok_or(AttemptError::Corrupt)?;
                let parsed = parse_claim_reply(
                    body.as_bytes(),
                    current.prepared.signed(),
                    &actor,
                    &coordinator,
                )
                .map_err(|_| AttemptError::Corrupt)?;
                let (receipt_json, receipt_json_sha256) = match parsed {
                    ParsedClaimReply::Historical(reply) => (
                        reply.receipt_json().to_owned(),
                        *reply.receipt_json_sha256(),
                    ),
                    ParsedClaimReply::FreshlyStored(reply) => (
                        reply.receipt_json().to_owned(),
                        *reply.receipt_json_sha256(),
                    ),
                };
                Ok(Some(StoredOutcome::Verified {
                    receipt_json,
                    receipt_json_sha256,
                    cf_ray: record.ray.clone().ok_or(AttemptError::Corrupt)?,
                }))
            }
        }
    }

    pub fn note_unknown(&mut self, attempt: &mut ArmedAttempt) -> Result<(), AttemptError> {
        if attempt.phase != AttemptPhase::Armed && attempt.phase != AttemptPhase::Unknown {
            return Err(AttemptError::Phase);
        }
        self.transition(attempt, None)
    }

    pub fn note_refused(
        &mut self,
        attempt: &mut ArmedAttempt,
        status: u16,
        code: &str,
        ray: &str,
    ) -> Result<(), AttemptError> {
        if !valid_refusal(status, code) || !valid_ray(ray) {
            return Err(AttemptError::Refusal);
        }
        if attempt.phase != AttemptPhase::Unknown {
            return Err(AttemptError::Phase);
        }
        self.transition(
            attempt,
            Some(Outcome::Refused {
                status,
                code: code.to_owned(),
                ray: ray.to_owned(),
            }),
        )
    }

    pub fn note_verified(
        &mut self,
        attempt: &mut ArmedAttempt,
        reply_body: &[u8],
        ray: &str,
    ) -> Result<(), AttemptError> {
        if !valid_ray(ray) || reply_body.len() > MAX_REPLY_BODY_BYTES {
            return Err(AttemptError::Verify);
        }
        let reply_body = std::str::from_utf8(reply_body).map_err(|_| AttemptError::Verify)?;
        if attempt.phase != AttemptPhase::Unknown {
            return Err(AttemptError::Phase);
        }
        let actor =
            VerifyingKey::from_bytes(&self.binding.actor).map_err(|_| AttemptError::Binding)?;
        let coordinator = VerifyingKey::from_bytes(&self.binding.coordinator)
            .map_err(|_| AttemptError::Binding)?;
        parse_claim_reply(
            reply_body.as_bytes(),
            attempt.prepared.signed(),
            &actor,
            &coordinator,
        )
        .map_err(|_| AttemptError::Verify)?;
        self.transition(
            attempt,
            Some(Outcome::Verified {
                reply_body: reply_body.to_owned(),
                ray: ray.to_owned(),
            }),
        )
    }

    fn transition(
        &mut self,
        attempt: &mut ArmedAttempt,
        outcome: Option<Outcome>,
    ) -> Result<(), AttemptError> {
        self.ensure_open()?;
        self.require_same_binding(attempt)?;
        let Some(file) = self.open_record()? else {
            return Err(AttemptError::Stale);
        };
        let current_bytes = read_capped(file)?;
        if sha256(&current_bytes) != attempt.fingerprint {
            return Err(AttemptError::Stale);
        }
        let current = validate_record(&current_bytes, &self.binding)?;
        if current.generation != attempt.generation || current.id != attempt.id {
            return Err(AttemptError::Stale);
        }
        if current.phase != attempt.phase {
            return Err(AttemptError::Stale);
        }
        let generation = current
            .generation
            .checked_add(1)
            .ok_or(AttemptError::Overflow)?;
        let phase = match outcome {
            None => AttemptPhase::Unknown,
            Some(Outcome::Refused { .. }) | Some(Outcome::Verified { .. }) => {
                if current.phase != AttemptPhase::Unknown {
                    return Err(AttemptError::Phase);
                }
                match &outcome {
                    Some(Outcome::Refused { .. }) => AttemptPhase::Refused,
                    Some(Outcome::Verified { .. }) => AttemptPhase::Verified,
                    None => AttemptPhase::Unknown,
                }
            }
        };
        let mut next = current.disk;
        next.generation = generation;
        next.state = DiskState::from_phase(phase);
        next.status = None;
        next.code = None;
        next.ray = None;
        next.reply_body = None;
        match outcome {
            None => {}
            Some(Outcome::Refused { status, code, ray }) => {
                next.status = Some(status);
                next.code = Some(code);
                next.ray = Some(ray);
            }
            Some(Outcome::Verified { reply_body, ray }) => {
                next.reply_body = Some(reply_body);
                next.ray = Some(ray);
            }
        }
        let bytes = to_record_bytes(&next)?;
        let fingerprint = self.replace_record(&bytes)?;
        attempt.generation = generation;
        attempt.phase = phase;
        attempt.fingerprint = fingerprint;
        Ok(())
    }

    fn create_record(&mut self, bytes: &[u8]) -> Result<[u8; 32], AttemptError> {
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(AttemptError::Overflow);
        }
        let fd = match openat(
            &self.dir,
            RECORD_NAME,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => fd,
            Err(Errno::EXIST) => return Err(AttemptError::Occupied),
            Err(Errno::LOOP) => return Err(AttemptError::Inode),
            Err(_) => return Err(AttemptError::Io),
        };
        let mut file = File::from(fd);
        if inspect_file(&file, true).is_err()
            || file.write_all(bytes).is_err()
            || fsync(&file).is_err()
            || fsync(&self.dir).is_err()
        {
            self.poisoned.set(true);
            return Err(AttemptError::Poisoned);
        }
        Ok(sha256(bytes))
    }

    fn replace_record(&mut self, bytes: &[u8]) -> Result<[u8; 32], AttemptError> {
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(AttemptError::Overflow);
        }
        let name = format!("attempt-{}.tmp", encode_hex(&random_bytes::<8>()?));
        let fd = match openat(
            &self.dir,
            name.as_str(),
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => fd,
            Err(_) => {
                self.poisoned.set(true);
                return Err(AttemptError::Poisoned);
            }
        };
        let mut file = File::from(fd);
        if inspect_file(&file, true).is_err()
            || file.write_all(bytes).is_err()
            || fsync(&file).is_err()
            || renameat(&self.dir, name.as_str(), &self.dir, RECORD_NAME).is_err()
            || fsync(&self.dir).is_err()
        {
            self.poisoned.set(true);
            return Err(AttemptError::Poisoned);
        }
        Ok(sha256(bytes))
    }

    fn open_record(&self) -> Result<Option<File>, AttemptError> {
        match openat(
            &self.dir,
            RECORD_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let file = File::from(fd);
                inspect_file(&file, true)?;
                Ok(Some(file))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(Errno::LOOP) => Err(AttemptError::Inode),
            Err(_) => Err(AttemptError::Io),
        }
    }

    fn ensure_open(&self) -> Result<(), AttemptError> {
        if self.poisoned.get() {
            return Err(AttemptError::Poisoned);
        }
        inspect_directory(&self.dir)?;
        if self.check_lock_identity().is_err() {
            self.poisoned.set(true);
            return Err(AttemptError::Lock);
        }
        Ok(())
    }

    fn check_lock_identity(&self) -> Result<(), AttemptError> {
        inspect_file(&self.lock, true)?;
        let current = File::from(
            openat(
                &self.dir,
                LOCK_NAME,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| AttemptError::Lock)?,
        );
        inspect_file(&current, true)?;
        let held = fstat(&self.lock).map_err(|_| AttemptError::Lock)?;
        let named = fstat(&current).map_err(|_| AttemptError::Lock)?;
        if held.st_dev != named.st_dev || held.st_ino != named.st_ino {
            return Err(AttemptError::Lock);
        }
        Ok(())
    }

    fn require_claim_actor(&self, prepared: &PreparedClaim) -> Result<(), AttemptError> {
        if prepared.signed().request.actor != encode_hex(&self.binding.actor) {
            return Err(AttemptError::Binding);
        }
        let declared = decode_hex_exact::<32>(&prepared.signed().request.actor)
            .map_err(|_| AttemptError::Binding)?;
        if declared != self.binding.actor {
            return Err(AttemptError::Binding);
        }
        Ok(())
    }

    fn require_same_binding(&self, attempt: &ArmedAttempt) -> Result<(), AttemptError> {
        if attempt.binding.origin != self.binding.origin
            || attempt.binding.actor != self.binding.actor
            || attempt.binding.coordinator != self.binding.coordinator
        {
            return Err(AttemptError::Binding);
        }
        Ok(())
    }
}

enum Outcome {
    Refused {
        status: u16,
        code: String,
        ray: String,
    },
    Verified {
        reply_body: String,
        ray: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct DiskRecord {
    schema: u64,
    attempt_id: String,
    request_json: String,
    canonical_sha256: String,
    wire_sha256: String,
    origin: String,
    actor: String,
    coordinator: String,
    generation: u64,
    state: DiskState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ray: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply_body: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DiskState {
    Armed,
    Unknown,
    Refused,
    Verified,
}

impl DiskState {
    fn phase(self) -> AttemptPhase {
        match self {
            DiskState::Armed => AttemptPhase::Armed,
            DiskState::Unknown => AttemptPhase::Unknown,
            DiskState::Refused => AttemptPhase::Refused,
            DiskState::Verified => AttemptPhase::Verified,
        }
    }

    fn from_phase(phase: AttemptPhase) -> Self {
        match phase {
            AttemptPhase::Armed => DiskState::Armed,
            AttemptPhase::Unknown => DiskState::Unknown,
            AttemptPhase::Refused => DiskState::Refused,
            AttemptPhase::Verified => DiskState::Verified,
        }
    }
}

struct Validated {
    disk: DiskRecord,
    id: [u8; 16],
    generation: u64,
    phase: AttemptPhase,
    prepared: PreparedClaim,
}

impl Validated {
    fn into_attempt(self, fingerprint: [u8; 32], binding: &AttemptBinding) -> ArmedAttempt {
        ArmedAttempt {
            id: self.id,
            generation: self.generation,
            fingerprint,
            phase: self.phase,
            prepared: self.prepared,
            binding: binding.duplicate(),
        }
    }
}

fn validate_record(bytes: &[u8], binding: &AttemptBinding) -> Result<Validated, AttemptError> {
    let disk: DiskRecord = serde_json::from_slice(bytes).map_err(|_| AttemptError::Corrupt)?;
    if disk.schema != SCHEMA
        || disk.generation == 0
        || (disk.state == DiskState::Armed && disk.generation != 1)
        || (disk.state == DiskState::Unknown && disk.generation < 2)
        || (matches!(disk.state, DiskState::Refused | DiskState::Verified) && disk.generation < 3)
    {
        return Err(AttemptError::Corrupt);
    }
    if disk.origin != binding.origin {
        return Err(AttemptError::Corrupt);
    }
    let actor = decode_hex_exact::<32>(&disk.actor).map_err(|_| AttemptError::Corrupt)?;
    let coordinator =
        decode_hex_exact::<32>(&disk.coordinator).map_err(|_| AttemptError::Corrupt)?;
    if actor != binding.actor || coordinator != binding.coordinator {
        return Err(AttemptError::Corrupt);
    }
    let id = decode_hex_exact::<16>(&disk.attempt_id).map_err(|_| AttemptError::Corrupt)?;
    let canonical =
        decode_hex_exact::<32>(&disk.canonical_sha256).map_err(|_| AttemptError::Corrupt)?;
    let wire = decode_hex_exact::<32>(&disk.wire_sha256).map_err(|_| AttemptError::Corrupt)?;
    let prepared = PreparedClaim::from_request_json_exact(disk.request_json.as_bytes())
        .map_err(|_| AttemptError::Corrupt)?;
    if prepared.request_json() != disk.request_json
        || prepared.request_sha256() != &canonical
        || prepared.wire_sha256() != &wire
        || prepared.signed().request.actor != disk.actor
    {
        return Err(AttemptError::Corrupt);
    }
    match disk.state {
        DiskState::Armed | DiskState::Unknown => {
            if disk.status.is_some()
                || disk.code.is_some()
                || disk.ray.is_some()
                || disk.reply_body.is_some()
            {
                return Err(AttemptError::Corrupt);
            }
        }
        DiskState::Refused => {
            let status = disk.status.ok_or(AttemptError::Corrupt)?;
            let code = disk.code.as_deref().ok_or(AttemptError::Corrupt)?;
            let ray = disk.ray.as_deref().ok_or(AttemptError::Corrupt)?;
            if disk.reply_body.is_some() || !valid_refusal(status, code) || !valid_ray(ray) {
                return Err(AttemptError::Corrupt);
            }
        }
        DiskState::Verified => {
            if disk.status.is_some() || disk.code.is_some() {
                return Err(AttemptError::Corrupt);
            }
            let reply = disk.reply_body.as_deref().ok_or(AttemptError::Corrupt)?;
            let ray = disk.ray.as_deref().ok_or(AttemptError::Corrupt)?;
            if reply.len() > MAX_REPLY_BODY_BYTES || !valid_ray(ray) {
                return Err(AttemptError::Corrupt);
            }
            let actor_key =
                VerifyingKey::from_bytes(&binding.actor).map_err(|_| AttemptError::Corrupt)?;
            let coordinator_key = VerifyingKey::from_bytes(&binding.coordinator)
                .map_err(|_| AttemptError::Corrupt)?;
            parse_claim_reply(
                reply.as_bytes(),
                prepared.signed(),
                &actor_key,
                &coordinator_key,
            )
            .map_err(|_| AttemptError::Corrupt)?;
        }
    }
    Ok(Validated {
        phase: disk.state.phase(),
        generation: disk.generation,
        id,
        prepared,
        disk,
    })
}

fn to_record_bytes(record: &DiskRecord) -> Result<Vec<u8>, AttemptError> {
    let bytes = serde_json::to_vec(record).map_err(|_| AttemptError::Corrupt)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(AttemptError::Overflow);
    }
    Ok(bytes)
}

fn clean_origin(origin: &str) -> Result<String, AttemptError> {
    let url = reqwest::Url::parse(origin).map_err(|_| AttemptError::Binding)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(AttemptError::Binding);
    }
    Ok(url.to_string())
}

fn valid_ray(ray: &str) -> bool {
    !ray.is_empty()
        && ray.len() <= 128
        && ray
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_refusal(status: u16, code: &str) -> bool {
    matches!(
        (status, code),
        (400, "claim_malformed" | "claim_overflow")
            | (401, "claim_signature" | "claim_actor")
            | (403, "claim_policy")
            | (
                409,
                "claim_state_changed"
                    | "claim_session"
                    | "claim_time"
                    | "claim_conflict"
                    | "claim_retired"
                    | "claim_revision"
                    | "claim_nonce_conflict"
            )
    )
}

fn open_directory(path: &Path) -> Result<File, AttemptError> {
    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| AttemptError::Directory)?;
    let dir = File::from(fd);
    inspect_directory(&dir)?;
    Ok(dir)
}

fn inspect_directory(dir: &File) -> Result<(), AttemptError> {
    let stat = fstat(dir).map_err(|_| AttemptError::Directory)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(AttemptError::Directory);
    }
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err(AttemptError::Directory);
    }
    Ok(())
}

fn inspect_file(file: &File, expect_private: bool) -> Result<(), AttemptError> {
    let stat = fstat(file).map_err(|_| AttemptError::Io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
        return Err(AttemptError::Inode);
    }
    if stat.st_uid != geteuid().as_raw() {
        return Err(AttemptError::Inode);
    }
    if expect_private && stat.st_mode & 0o777 != 0o600 {
        return Err(AttemptError::Inode);
    }
    Ok(())
}

fn read_capped(mut file: File) -> Result<Vec<u8>, AttemptError> {
    let stat = fstat(&file).map_err(|_| AttemptError::Io)?;
    inspect_file(&file, true)?;
    if stat.st_size <= 0 || stat.st_size as u64 > MAX_RECORD_BYTES {
        return Err(AttemptError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    Read::by_ref(&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AttemptError::Io)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES || bytes.len() != stat.st_size as usize {
        return Err(AttemptError::Corrupt);
    }
    Ok(bytes)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], AttemptError> {
    let mut bytes = [0u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AttemptError::Random)?;
    Ok(bytes)
}

fn map_errno(err: Errno) -> AttemptError {
    if err == Errno::EXIST {
        AttemptError::Occupied
    } else if err == Errno::LOOP {
        AttemptError::Inode
    } else if err == Errno::WOULDBLOCK || err == Errno::AGAIN {
        AttemptError::Lock
    } else {
        AttemptError::Io
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chinwag_claim::reply::ParsedClaimReply;
    use chinwag_claim::{ClaimReceiptUnsigned, ClaimRequestUnsigned, Pr};
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::{PermissionsExt, symlink};

    const ORIGIN: &str = "https://bootstrap.chinwag.sh/";
    const SAMPLE: &str = "crates/chinwag-seed/src/main.rs";

    struct Keys {
        actor: SigningKey,
        coordinator: SigningKey,
    }

    fn keys() -> Keys {
        Keys {
            actor: SigningKey::from_bytes(&[0x11; 32]),
            coordinator: SigningKey::from_bytes(&[0x44; 32]),
        }
    }

    fn binding_for(keys: &Keys) -> AttemptBinding {
        AttemptBinding::new(
            ORIGIN,
            keys.actor.verifying_key().to_bytes(),
            keys.coordinator.verifying_key().to_bytes(),
        )
        .unwrap()
    }

    fn signed_claim(keys: &Keys, spaced: bool) -> PreparedClaim {
        let signed = ClaimRequestUnsigned {
            claim_id: encode_hex(&[0x88; 32]),
            actor: encode_hex(keys.actor.verifying_key().as_bytes()),
            session: encode_hex(&[0x02; 32]),
            nonce: encode_hex(&[0x03; 32]),
            pr: Pr::Pr01,
            files: vec![SAMPLE.to_owned()],
            expected_revision: 0,
            issued: 1_700_000_000,
            expiry: 1_700_000_060,
        }
        .sign(&keys.actor)
        .unwrap();
        if spaced {
            let wire = serde_json::to_string(&signed)
                .unwrap()
                .replacen('{', "{ ", 1);
            PreparedClaim::from_request_json_exact(wire.as_bytes()).unwrap()
        } else {
            PreparedClaim::from_signed(signed).unwrap()
        }
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn reply_body(keys: &Keys, prepared: &PreparedClaim, disposition: &str) -> String {
        let request = prepared.signed();
        let receipt = ClaimReceiptUnsigned {
            claim_id: request.request.claim_id.clone(),
            actor: request.request.actor.clone(),
            session: request.request.session.clone(),
            pr: request.request.pr,
            files: request.request.files.clone(),
            revision: chinwag_claim::receipt_revision_for(request.request.expected_revision)
                .unwrap(),
            issued: request.request.issued,
            expiry: request.request.expiry,
            request_sha256: request.request_sha256_hex().unwrap(),
            coordinator: encode_hex(keys.coordinator.verifying_key().as_bytes()),
        }
        .sign(&keys.coordinator)
        .unwrap();
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        format!(
            "{{\"disposition\":{},\"receipt_json\":{}}}",
            serde_json::to_string(disposition).unwrap(),
            serde_json::to_string(&receipt_json).unwrap()
        )
    }

    #[test]
    fn binding_rejects_unclean_origin_and_identical_or_invalid_keys() {
        let keys = keys();
        let actor = keys.actor.verifying_key().to_bytes();
        let coordinator = keys.coordinator.verifying_key().to_bytes();
        assert!(AttemptBinding::new("http://bootstrap.chinwag.sh/", actor, coordinator).is_err());
        assert!(
            AttemptBinding::new("https://user@bootstrap.chinwag.sh/", actor, coordinator).is_err()
        );
        assert!(
            AttemptBinding::new("https://bootstrap.chinwag.sh/room", actor, coordinator).is_err()
        );
        assert!(
            AttemptBinding::new("https://bootstrap.chinwag.sh/?q=1", actor, coordinator).is_err()
        );
        assert!(AttemptBinding::new(ORIGIN, actor, actor).is_err());
        assert!(AttemptBinding::new(ORIGIN, [0; 32], coordinator).is_err());
    }

    #[test]
    fn whitespace_unknown_survives_reopen_and_second_arm_is_refused() {
        let keys = keys();
        let binding = binding_for(&keys);
        let prepared = signed_claim(&keys, true);
        assert_ne!(prepared.wire_sha256(), prepared.request_sha256());
        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut attempt = journal.arm(&prepared).unwrap();
        let id = *attempt.id();
        let nonce = attempt.prepared().signed().request.nonce.clone();
        journal.note_unknown(&mut attempt).unwrap();
        assert_eq!(attempt.phase(), AttemptPhase::Unknown);
        assert!(journal.arm(&prepared).is_err());
        drop(journal);
        let journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let loaded = journal.load().unwrap().unwrap();
        assert_eq!(loaded.phase(), AttemptPhase::Unknown);
        assert_eq!(loaded.id(), &id);
        assert_eq!(loaded.prepared().request_json(), prepared.request_json());
        assert_eq!(loaded.prepared().wire_sha256(), prepared.wire_sha256());
        assert_eq!(
            loaded.prepared().request_sha256(),
            prepared.request_sha256()
        );
        assert_eq!(loaded.prepared().signed().request.nonce, nonce);
        assert_eq!(loaded.binding().origin(), binding.origin());
    }

    #[test]
    fn actor_mismatch_and_corrupt_byte_are_refused() {
        let keys = keys();
        let other = SigningKey::from_bytes(&[0x12; 32]);
        let prepared = signed_claim(&keys, false);
        let dir = private_dir();
        let mut wrong = AttemptJournal::open(
            dir.path(),
            AttemptBinding::new(
                ORIGIN,
                other.verifying_key().to_bytes(),
                keys.coordinator.verifying_key().to_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(wrong.arm(&prepared).unwrap_err(), AttemptError::Binding);
        drop(wrong);
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut attempt = journal.arm(&prepared).unwrap();
        let path = dir.path().join(RECORD_NAME);
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(journal.load().unwrap_err(), AttemptError::Corrupt);
        assert_eq!(
            journal.note_unknown(&mut attempt).unwrap_err(),
            AttemptError::Stale
        );
    }

    #[test]
    fn symlink_mode_hardlink_broad_directory_and_lock_are_rejected() {
        let keys = keys();
        let prepared = signed_claim(&keys, false);
        let dir = private_dir();
        symlink("elsewhere", dir.path().join(LOCK_NAME)).unwrap();
        assert_eq!(
            AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap_err(),
            AttemptError::Inode
        );
        std::fs::remove_file(dir.path().join(LOCK_NAME)).unwrap();

        std::fs::write(dir.path().join(RECORD_NAME), b"{}").unwrap();
        std::fs::set_permissions(
            dir.path().join(RECORD_NAME),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        assert_eq!(journal.arm(&prepared).unwrap_err(), AttemptError::Inode);
        assert_eq!(journal.load().unwrap_err(), AttemptError::Inode);
        drop(journal);
        std::fs::remove_file(dir.path().join(RECORD_NAME)).unwrap();
        std::fs::remove_file(dir.path().join(LOCK_NAME)).unwrap();

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap_err(),
            AttemptError::Directory
        );
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        journal.arm(&prepared).unwrap();
        std::fs::hard_link(dir.path().join(RECORD_NAME), dir.path().join("linked")).unwrap();
        assert_eq!(journal.load().unwrap_err(), AttemptError::Inode);
        drop(journal);

        let first = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        assert_eq!(
            AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap_err(),
            AttemptError::Lock
        );
        drop(first);
        assert!(AttemptJournal::open(dir.path(), binding_for(&keys)).is_ok());
    }

    #[test]
    fn stale_handle_and_terminal_from_armed_fail_closed() {
        let keys = keys();
        let prepared = signed_claim(&keys, false);
        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut first = journal.arm(&prepared).unwrap();
        let mut second = journal.load().unwrap().unwrap();
        assert_eq!(
            journal
                .note_refused(&mut first, 403, "claim_policy", "ray-1")
                .unwrap_err(),
            AttemptError::Phase
        );
        journal.note_unknown(&mut first).unwrap();
        assert_eq!(
            journal.note_unknown(&mut second).unwrap_err(),
            AttemptError::Stale
        );
        journal
            .note_refused(&mut first, 403, "claim_policy", "ray-1")
            .unwrap();
        assert_eq!(
            journal.note_unknown(&mut first).unwrap_err(),
            AttemptError::Phase
        );
        assert!(journal.arm(&prepared).is_err());
    }

    #[test]
    fn refusal_and_verified_recovery_keep_the_original_wire() {
        let keys = keys();
        let prepared = signed_claim(&keys, true);
        let nonce = prepared.signed().request.nonce.clone();
        let wire = prepared.wire_sha256().to_owned();
        let canonical = prepared.request_sha256().to_owned();
        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut attempt = journal.arm(&prepared).unwrap();
        assert_eq!(
            journal
                .note_refused(&mut attempt, 403, "claim_session", "ray-1")
                .unwrap_err(),
            AttemptError::Refusal
        );
        assert_eq!(
            journal
                .note_refused(&mut attempt, 500, "claim_policy", "ray-1")
                .unwrap_err(),
            AttemptError::Refusal
        );
        assert_eq!(
            journal
                .note_refused(&mut attempt, 403, "claim_policy", "")
                .unwrap_err(),
            AttemptError::Refusal
        );
        journal.note_unknown(&mut attempt).unwrap();
        journal
            .note_refused(&mut attempt, 403, "claim_policy", "Ab-12")
            .unwrap();
        assert_eq!(attempt.prepared().signed().request.nonce, nonce);
        assert_eq!(attempt.prepared().wire_sha256(), &wire);
        assert_eq!(attempt.prepared().request_sha256(), &canonical);
        drop(journal);
        let journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let loaded = journal.load().unwrap().unwrap();
        assert_eq!(loaded.phase(), AttemptPhase::Refused);
        assert_eq!(loaded.prepared().request_json(), prepared.request_json());
        drop(journal);

        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut attempt = journal.arm(&prepared).unwrap();
        let body = reply_body(&keys, &prepared, "outcome_resolution");
        journal.note_unknown(&mut attempt).unwrap();
        let mut forged = body.clone();
        forged.pop();
        forged.push('x');
        assert_eq!(
            journal
                .note_verified(&mut attempt, forged.as_bytes(), "ray-9")
                .unwrap_err(),
            AttemptError::Verify
        );
        assert_eq!(attempt.phase(), AttemptPhase::Unknown);
        journal
            .note_verified(&mut attempt, body.as_bytes(), "ray-9")
            .unwrap();
        assert_eq!(attempt.phase(), AttemptPhase::Verified);
        assert_eq!(attempt.prepared().request_json(), prepared.request_json());
        assert_eq!(attempt.prepared().wire_sha256(), &wire);
        assert_eq!(attempt.prepared().request_sha256(), &canonical);
        drop(journal);
        let journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let loaded = journal.load().unwrap().unwrap();
        assert_eq!(loaded.phase(), AttemptPhase::Verified);
        let actor = keys.actor.verifying_key();
        let coordinator = keys.coordinator.verifying_key();
        let raw = std::fs::read_to_string(dir.path().join(RECORD_NAME)).unwrap();
        let record: DiskRecord = serde_json::from_str(&raw).unwrap();
        assert_eq!(record.reply_body.as_deref(), Some(body.as_str()));
        assert!(matches!(
            parse_claim_reply(
                body.as_bytes(),
                loaded.prepared().signed(),
                &actor,
                &coordinator
            )
            .unwrap(),
            ParsedClaimReply::Historical(_)
        ));
        drop(journal);
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        assert!(journal.arm(&prepared).is_err());
    }
    #[test]
    fn root_reopen_requires_trusted_config_not_disk_pins_or_origin() {
        let keys = keys();
        let prepared = signed_claim(&keys, false);
        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        journal.arm(&prepared).unwrap();
        drop(journal);
        let other = SigningKey::from_bytes(&[0x55; 32])
            .verifying_key()
            .to_bytes();
        for binding in [
            AttemptBinding::new(
                "https://example.invalid/",
                keys.actor.verifying_key().to_bytes(),
                keys.coordinator.verifying_key().to_bytes(),
            )
            .unwrap(),
            AttemptBinding::new(ORIGIN, other, keys.coordinator.verifying_key().to_bytes())
                .unwrap(),
            AttemptBinding::new(ORIGIN, keys.actor.verifying_key().to_bytes(), other).unwrap(),
        ] {
            let journal = AttemptJournal::open(dir.path(), binding).unwrap();
            assert_eq!(journal.load().unwrap_err(), AttemptError::Corrupt);
        }
        let journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        assert_eq!(
            journal.load().unwrap().unwrap().prepared().request_json(),
            prepared.request_json()
        );
    }

    #[test]
    fn root_symlink_record_and_oversize_are_refused_without_reading_target() {
        let keys = keys();
        let dir = private_dir();
        let outside = private_dir();
        let target = outside.path().join("untouched");
        std::fs::write(&target, b"untouched").unwrap();
        let journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        symlink(&target, dir.path().join(RECORD_NAME)).unwrap();
        assert_eq!(journal.load().unwrap_err(), AttemptError::Inode);
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        std::fs::remove_file(dir.path().join(RECORD_NAME)).unwrap();
        std::fs::write(
            dir.path().join(RECORD_NAME),
            vec![b'x'; MAX_RECORD_BYTES as usize + 1],
        )
        .unwrap();
        std::fs::set_permissions(
            dir.path().join(RECORD_NAME),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(journal.load().unwrap_err(), AttemptError::Corrupt);
    }

    #[test]
    fn root_protection_withdrawal_and_failed_persistence_poison_handle() {
        let keys = keys();
        let prepared = signed_claim(&keys, false);
        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut attempt = journal.arm(&prepared).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(journal.load().unwrap_err(), AttemptError::Directory);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let outcome = journal.note_unknown(&mut attempt);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(outcome.unwrap_err(), AttemptError::Poisoned);
        assert_eq!(attempt.phase(), AttemptPhase::Armed);
        assert_eq!(journal.load().unwrap_err(), AttemptError::Poisoned);
        drop(journal);
        let journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let recovered = journal.load().unwrap().unwrap();
        assert_eq!(recovered.phase(), AttemptPhase::Armed);
        assert_eq!(recovered.prepared().request_json(), prepared.request_json());
    }

    #[test]
    fn root_forged_crypto_and_terminal_tamper_do_not_become_verified() {
        let keys = keys();
        let prepared = signed_claim(&keys, true);
        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut attempt = journal.arm(&prepared).unwrap();
        journal.note_unknown(&mut attempt).unwrap();
        let original = reply_body(&keys, &prepared, "outcome_resolution");
        let mut envelope: serde_json::Value = serde_json::from_str(&original).unwrap();
        let mut receipt: serde_json::Value =
            serde_json::from_str(envelope["receipt_json"].as_str().unwrap()).unwrap();
        let mut signature = receipt["signature"].as_str().unwrap().to_owned();
        let last = signature.pop().unwrap();
        signature.push(if last == 'a' { 'b' } else { 'a' });
        receipt["signature"] = signature.into();
        envelope["receipt_json"] = serde_json::to_string(&receipt).unwrap().into();
        let forged = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            journal
                .note_verified(&mut attempt, &forged, "ray-2")
                .unwrap_err(),
            AttemptError::Verify
        );
        assert_eq!(
            journal.load().unwrap().unwrap().phase(),
            AttemptPhase::Unknown
        );
        journal
            .note_verified(&mut attempt, original.as_bytes(), "ray-2")
            .unwrap();
        let path = dir.path().join(RECORD_NAME);
        let mut record: DiskRecord =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record.reply_body = Some(String::from_utf8(forged).unwrap());
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(journal.load().unwrap_err(), AttemptError::Corrupt);
        assert!(!format!("{attempt:?}").contains(&prepared.signed().request.nonce));
    }

    #[test]
    fn root_duplicate_record_and_impossible_generation_are_refused() {
        let keys = keys();
        let prepared = signed_claim(&keys, false);
        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        journal.arm(&prepared).unwrap();
        let path = dir.path().join(RECORD_NAME);
        let bytes = std::fs::read(&path).unwrap();
        let mut duplicate = String::from_utf8(bytes.clone()).unwrap();
        duplicate.insert_str(1, "\"schema\":1,");
        std::fs::write(&path, duplicate).unwrap();
        assert_eq!(journal.load().unwrap_err(), AttemptError::Corrupt);
        let mut record: DiskRecord = serde_json::from_slice(&bytes).unwrap();
        record.generation = 9;
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(journal.load().unwrap_err(), AttemptError::Corrupt);
    }
    #[test]
    fn root_renamed_lock_cannot_leave_two_valid_journals() {
        let keys = keys();
        let prepared = signed_claim(&keys, false);
        let dir = private_dir();
        let mut old = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut attempt = old.arm(&prepared).unwrap();
        std::fs::rename(dir.path().join(LOCK_NAME), dir.path().join("moved.lock")).unwrap();
        let replacement = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        assert_eq!(old.load().unwrap_err(), AttemptError::Lock);
        assert_eq!(old.load().unwrap_err(), AttemptError::Poisoned);
        assert_eq!(
            old.note_unknown(&mut attempt).unwrap_err(),
            AttemptError::Poisoned
        );
        assert_eq!(
            replacement
                .load()
                .unwrap()
                .unwrap()
                .prepared()
                .request_json(),
            prepared.request_json()
        );
    }
    #[test]
    fn stored_outcome_refusal_reopens_exact_and_does_not_write() {
        let keys = keys();
        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut attempt = journal.arm(&signed_claim(&keys, true)).unwrap();
        journal.note_unknown(&mut attempt).unwrap();
        journal
            .note_refused(&mut attempt, 409, "claim_session", "actual-ray-1")
            .unwrap();
        let before = std::fs::read(dir.path().join(RECORD_NAME)).unwrap();
        drop(journal);
        let journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let loaded = journal.load().unwrap().unwrap();
        assert_eq!(
            journal.stored_outcome(&loaded).unwrap(),
            Some(StoredOutcome::Refused {
                status: 409,
                code: "claim_session".into(),
                cf_ray: "actual-ray-1".into(),
            })
        );
        assert_eq!(std::fs::read(dir.path().join(RECORD_NAME)).unwrap(), before);
    }

    #[test]
    fn stored_outcome_verified_preserves_inner_bytes_and_drops_outer_fresh_label() {
        let keys = keys();
        let prepared = signed_claim(&keys, true);
        let mut outcomes = Vec::new();
        for disposition in ["outcome_resolution", "freshly_stored"] {
            let dir = private_dir();
            let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
            let mut attempt = journal.arm(&prepared).unwrap();
            journal.note_unknown(&mut attempt).unwrap();
            let body = reply_body(&keys, &prepared, disposition);
            let envelope: serde_json::Value = serde_json::from_str(&body).unwrap();
            let inner = envelope["receipt_json"].as_str().unwrap().to_owned();
            journal
                .note_verified(&mut attempt, body.as_bytes(), "stored-ray")
                .unwrap();
            let before = std::fs::read(dir.path().join(RECORD_NAME)).unwrap();
            drop(journal);
            let journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
            let loaded = journal.load().unwrap().unwrap();
            let outcome = journal.stored_outcome(&loaded).unwrap().unwrap();
            assert_eq!(
                outcome,
                StoredOutcome::Verified {
                    receipt_json: inner.clone(),
                    receipt_json_sha256: sha256(inner.as_bytes()),
                    cf_ray: "stored-ray".into(),
                }
            );
            assert!(!format!("{outcome:?}").contains(&loaded.prepared().signed().request.session));
            assert_eq!(std::fs::read(dir.path().join(RECORD_NAME)).unwrap(), before);
            outcomes.push(outcome);
        }
        assert_eq!(outcomes[0], outcomes[1]);
    }

    #[test]
    fn stored_outcome_unresolved_returns_none_without_changing_original() {
        let keys = keys();
        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut attempt = journal.arm(&signed_claim(&keys, true)).unwrap();
        for phase in [AttemptPhase::Armed, AttemptPhase::Unknown] {
            if phase == AttemptPhase::Unknown {
                journal.note_unknown(&mut attempt).unwrap();
            }
            let before = std::fs::read(dir.path().join(RECORD_NAME)).unwrap();
            let loaded = journal.load().unwrap().unwrap();
            assert_eq!(loaded.phase(), phase);
            assert_eq!(journal.stored_outcome(&loaded).unwrap(), None);
            assert_eq!(std::fs::read(dir.path().join(RECORD_NAME)).unwrap(), before);
            assert_eq!(
                loaded.prepared().request_json(),
                attempt.prepared().request_json()
            );
        }
    }

    #[test]
    fn stored_outcome_rejects_stale_handle_wrong_binding_and_renamed_lock() {
        let keys = keys();
        let dir = private_dir();
        let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        let mut attempt = journal.arm(&signed_claim(&keys, false)).unwrap();
        let stale = journal.load().unwrap().unwrap();
        journal.note_unknown(&mut attempt).unwrap();
        assert_eq!(
            journal.stored_outcome(&stale).unwrap_err(),
            AttemptError::Stale
        );
        let mut same_fingerprint = journal.load().unwrap().unwrap();
        same_fingerprint.generation += 1;
        assert_eq!(
            journal.stored_outcome(&same_fingerprint).unwrap_err(),
            AttemptError::Stale
        );
        same_fingerprint.generation -= 1;
        same_fingerprint.phase = AttemptPhase::Armed;
        assert_eq!(
            journal.stored_outcome(&same_fingerprint).unwrap_err(),
            AttemptError::Stale
        );
        same_fingerprint.phase = AttemptPhase::Unknown;
        same_fingerprint.id[0] ^= 1;
        assert_eq!(
            journal.stored_outcome(&same_fingerprint).unwrap_err(),
            AttemptError::Stale
        );
        drop(journal);
        let other = AttemptBinding::new(
            "https://example.invalid/",
            keys.actor.verifying_key().to_bytes(),
            keys.coordinator.verifying_key().to_bytes(),
        )
        .unwrap();
        let wrong = AttemptJournal::open(dir.path(), other).unwrap();
        assert_eq!(
            wrong.stored_outcome(&attempt).unwrap_err(),
            AttemptError::Binding
        );
        assert_eq!(wrong.load().unwrap_err(), AttemptError::Corrupt);
        drop(wrong);
        let journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        std::fs::rename(dir.path().join(LOCK_NAME), dir.path().join("moved.lock")).unwrap();
        let _replacement = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
        assert_eq!(
            journal.stored_outcome(&attempt).unwrap_err(),
            AttemptError::Lock
        );
        assert_eq!(
            journal.stored_outcome(&attempt).unwrap_err(),
            AttemptError::Poisoned
        );
    }

    #[test]
    fn stored_outcome_corrupt_terminal_never_projects_an_authenticated_outcome() {
        let keys = keys();
        for verified in [false, true] {
            let dir = private_dir();
            let prepared = signed_claim(&keys, false);
            let mut journal = AttemptJournal::open(dir.path(), binding_for(&keys)).unwrap();
            let mut attempt = journal.arm(&prepared).unwrap();
            journal.note_unknown(&mut attempt).unwrap();
            if verified {
                journal
                    .note_verified(
                        &mut attempt,
                        reply_body(&keys, &prepared, "freshly_stored").as_bytes(),
                        "ray-2",
                    )
                    .unwrap();
            } else {
                journal
                    .note_refused(&mut attempt, 403, "claim_policy", "ray-2")
                    .unwrap();
            }
            let path = dir.path().join(RECORD_NAME);
            let mut record: DiskRecord =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            if verified {
                let mut envelope: serde_json::Value =
                    serde_json::from_str(record.reply_body.as_ref().unwrap()).unwrap();
                let mut inner: serde_json::Value =
                    serde_json::from_str(envelope["receipt_json"].as_str().unwrap()).unwrap();
                inner["signature"] = encode_hex(&[0; 64]).into();
                envelope["receipt_json"] = serde_json::to_string(&inner).unwrap().into();
                record.reply_body = Some(serde_json::to_string(&envelope).unwrap());
            } else {
                record.code = Some("claim_session".into());
            }
            let bytes = serde_json::to_vec(&record).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert_eq!(
                journal.stored_outcome(&attempt).unwrap_err(),
                AttemptError::Stale
            );
            assert_eq!(journal.load().unwrap_err(), AttemptError::Corrupt);
            // Even a handle with a matching fingerprint cannot bypass full validation.
            attempt.fingerprint = sha256(&bytes);
            assert_eq!(
                journal.stored_outcome(&attempt).unwrap_err(),
                AttemptError::Corrupt
            );
        }
    }
}
