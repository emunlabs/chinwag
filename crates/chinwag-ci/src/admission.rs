// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Single owner, descriptor-anchored private admission ledger. One canonical
//! state replacement atomically consumes challenge + issuer/jti + intent/run.
//! Exact reconciliation returns the ORIGINAL record, never renewed authority or
//! permission to repeat effects. No raw JWT is persisted. No K2/repair grant.
//! Callers must authenticate fixed-origin JWKS and exact dispatch metadata.
//! Ordinary owner-trusted filesystem durability is not rollback-proof hardware.

use crate::{
    intent::{IntentSpec, VerifiedIntent},
    runner_binding::{self, RunnerPublicKeys, VerifiedRunnerBinding},
    storage::CiphertextStore,
};
use rustix::{
    fd::AsFd,
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat},
    io::Errno,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::Path,
};

const MAX_STATE: usize = 8 * 1024 * 1024;
const MAX_CHALLENGES: usize = 1024;
const STATE: &str = "admission-state-v1.json";
const LOCK: &str = "admission-state-v1.lock";
const INITIALIZED: &[u8] = b"CHINWAG-CI-ADMISSION-INITIALIZED-V1\n";
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    #[error("CI admission ledger is unavailable, changed or not private")]
    Store,
    #[error("CI admission ledger already has an owner")]
    Busy,
    #[error("CI admission conflicts with consumed challenge, token or intent/run scope")]
    Conflict,
    #[error("CI admission challenge or proof is outside its finite lifetime")]
    Lifetime,
    #[error("CI admission entropy is unavailable")]
    Entropy,
    #[error("CI admission ledger capacity is exhausted")]
    Capacity,
    #[error("CI admission state commit is uncertain; reconcile without new side effects")]
    CommitUnknown,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRecord {
    audience: String,
    issued_unix: u64,
    expires_unix: u64,
    admitted: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRecord {
    pub spec: IntentSpec,
    pub initiating_instance: String,
    pub intent_digest: [u8; 32],
    pub token_sha256: [u8; 32],
    pub issuer_jti_sha256: [u8; 32],
    pub audience: String,
    pub run_id: u64,
    pub run_attempt: u32,
    pub signing_key: [u8; 32],
    pub agent_transport_key: [u8; 32],
    pub archive_transport_key: [u8; 32],
    pub usable_from_unix: u64,
    pub expires_unix: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u16,
    purpose: u8,
    challenges: BTreeMap<String, ChallengeRecord>,
    token_admissions: BTreeMap<String, String>,
    scope_admissions: BTreeMap<String, String>,
    admissions: BTreeMap<String, AdmissionRecord>,
    releases: BTreeMap<String, ReleaseRecord>,
    acu_policy: Option<PolicyRecord>,
    release_enrollment: Option<ReleaseEnrollment>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRecord {
    request_sha256: [u8; 32],
    encrypted_signed_response: Option<Vec<u8>>,
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRecord {
    signer: [u8; 32],
    epoch: u64,
    sha256: [u8; 32],
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEnrollment {
    acu: [u8; 32],
    admission: [u8; 32],
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            purpose: 1,
            challenges: BTreeMap::new(),
            token_admissions: BTreeMap::new(),
            scope_admissions: BTreeMap::new(),
            admissions: BTreeMap::new(),
            releases: BTreeMap::new(),
            acu_policy: None,
            release_enrollment: None,
        }
    }
}
#[derive(Serialize)]
pub struct IssuedChallenge {
    pub nonce: [u8; 32],
    pub audience: String,
    pub expires_unix: u64,
}
pub struct CommittedAdmission {
    digest: [u8; 32],
    record: AdmissionRecord,
}
impl CommittedAdmission {
    #[cfg(test)]
    pub(crate) fn synthetic_fixture(record: AdmissionRecord) -> Self {
        let digest = digest(
            b"chinwag-ci-admission-record-v1\0",
            &[&canonical(&record).unwrap()],
        );
        Self { digest, record }
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn record(&self) -> &AdmissionRecord {
        &self.record
    }
    pub fn canonical_record(&self) -> Result<Vec<u8>, AdmissionError> {
        canonical(&self.record)
    }
}
pub enum AdmissionOutcome {
    NewlyCommitted(CommittedAdmission),
    ReconciledOriginal(CommittedAdmission),
}
pub struct AdmissionLedger {
    directory: CiphertextStore,
    lock: File,
    poisoned: bool,
    initializing: bool,
    purpose: u8,
}
/// Consumed before any ACU gate unwrap. No public constructor or serialization.
pub(crate) struct ReservedRelease {
    scope: String,
    request_sha256: [u8; 32],
}
pub(crate) enum ReleaseDisposition {
    Reserved(ReservedRelease),
    Ready(Vec<u8>),
}
impl Drop for AdmissionLedger {
    fn drop(&mut self) {
        let _ = fs::flock(&self.lock, FlockOperation::NonBlockingUnlock);
    }
}
fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, AdmissionError> {
    serde_json::to_vec(v).map_err(|_| AdmissionError::Store)
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn digest(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for f in fields {
        h.update((f.len() as u64).to_be_bytes());
        h.update(f);
    }
    h.finalize().into()
}
fn private(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_nlink == 1
        && stat.st_mode & 0o7777 == 0o600
}
fn check_file(fd: impl AsFd) -> Result<Stat, AdmissionError> {
    let s = fs::fstat(&fd).map_err(|_| AdmissionError::Store)?;
    if !private(&s) {
        return Err(AdmissionError::Store);
    }
    #[cfg(target_os = "macos")]
    crate::macos_acl::require_absent(fd.as_fd()).map_err(|_| AdmissionError::Store)?;
    Ok(s)
}
impl AdmissionLedger {
    pub fn open(path: &Path) -> Result<Self, AdmissionError> {
        Self::open_purpose(path, 1)
    }
    pub(crate) fn open_release(path: &Path) -> Result<Self, AdmissionError> {
        Self::open_purpose(path, 2)
    }
    fn open_purpose(path: &Path, purpose: u8) -> Result<Self, AdmissionError> {
        let directory = CiphertextStore::open(path).map_err(|_| AdmissionError::Store)?;
        let mode = Mode::RUSR | Mode::WUSR;
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let (fd, fresh) = match fs::openat(
            directory.directory(),
            LOCK,
            flags | OFlags::CREATE | OFlags::EXCL,
            mode,
        ) {
            Ok(fd) => {
                fs::fchmod(&fd, mode).map_err(|_| AdmissionError::Store)?;
                (fd, true)
            }
            Err(Errno::EXIST) => (
                fs::openat(directory.directory(), LOCK, flags, Mode::empty())
                    .map_err(|_| AdmissionError::Store)?,
                false,
            ),
            Err(_) => return Err(AdmissionError::Store),
        };
        let mut lock = File::from(fd);
        check_file(&lock)?;
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| AdmissionError::Busy)?;
        if !fresh {
            let mut marker = Vec::new();
            (&mut lock)
                .take(INITIALIZED.len() as u64 + 1)
                .read_to_end(&mut marker)
                .map_err(|_| AdmissionError::Store)?;
            if marker != INITIALIZED {
                return Err(AdmissionError::Store);
            }
        }
        let mut ledger = Self {
            directory,
            lock,
            poisoned: false,
            initializing: fresh,
            purpose,
        };
        ledger.check_lock()?;
        let (_, prior) = ledger.read()?;
        if fresh {
            // Only an explicitly fresh, exclusively locked namespace may
            // initialize. A missing state after initialization is an error,
            // never permission to forget consumed tokens or create defaults.
            if prior.is_some() {
                return Err(AdmissionError::Store);
            }
            ledger.commit(
                &State {
                    purpose,
                    ..State::default()
                },
                None,
            )?;
            ledger
                .lock
                .write_all(INITIALIZED)
                .map_err(|_| AdmissionError::CommitUnknown)?;
            ledger
                .lock
                .sync_all()
                .map_err(|_| AdmissionError::CommitUnknown)?;
            fs::fsync(ledger.directory.directory()).map_err(|_| AdmissionError::CommitUnknown)?;
            ledger.initializing = false;
            ledger.check_lock()?;
        }
        Ok(ledger)
    }
    fn check_name(&self, name: &str, observed: &Stat) -> Result<(), AdmissionError> {
        let named = fs::statat(self.directory.directory(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| AdmissionError::Store)?;
        if !private(&named)
            || named.st_dev != observed.st_dev
            || named.st_ino != observed.st_ino
            || named.st_size != observed.st_size
        {
            return Err(AdmissionError::Store);
        }
        Ok(())
    }
    fn check_lock(&self) -> Result<(), AdmissionError> {
        self.directory.check().map_err(|_| AdmissionError::Store)?;
        self.check_name(LOCK, &check_file(&self.lock)?)
    }
    fn read(&self) -> Result<(State, Option<[u8; 32]>), AdmissionError> {
        self.check_lock()?;
        let fd = match fs::openat(
            self.directory.directory(),
            STATE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) if self.initializing => {
                return Ok((
                    State {
                        purpose: self.purpose,
                        ..State::default()
                    },
                    None,
                ));
            }
            Err(_) => return Err(AdmissionError::Store),
        };
        let initial = check_file(&fd)?;
        if initial.st_size < 1 || initial.st_size as u64 > MAX_STATE as u64 {
            return Err(AdmissionError::Store);
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_STATE as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AdmissionError::Store)?;
        if bytes.len() > MAX_STATE || bytes.len() as i64 != initial.st_size {
            return Err(AdmissionError::Store);
        }
        file.sync_all().map_err(|_| AdmissionError::Store)?;
        let end = check_file(&file)?;
        if end.st_dev != initial.st_dev
            || end.st_ino != initial.st_ino
            || end.st_size != initial.st_size
        {
            return Err(AdmissionError::Store);
        }
        let state: State = serde_json::from_slice(&bytes).map_err(|_| AdmissionError::Store)?;
        if state.version != 1
            || state.purpose != self.purpose
            || state.challenges.len() > MAX_CHALLENGES
            || state.releases.len() > MAX_CHALLENGES
            || canonical(&state)? != bytes
        {
            return Err(AdmissionError::Store);
        }
        fs::fsync(self.directory.directory()).map_err(|_| AdmissionError::Store)?;
        self.check_name(STATE, &end)?;
        self.check_lock()?;
        Ok((state, Some(hash(&bytes))))
    }
    fn commit(&mut self, state: &State, prior: Option<[u8; 32]>) -> Result<(), AdmissionError> {
        if self.poisoned {
            return Err(AdmissionError::CommitUnknown);
        }
        let bytes = canonical(state)?;
        if bytes.len() > MAX_STATE {
            return Err(AdmissionError::Capacity);
        }
        if self.read()?.1 != prior {
            return Err(AdmissionError::Store);
        }
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| AdmissionError::Entropy)?;
        let name = format!("admission-pending-{}.json", hex::encode(nonce));
        self.poisoned = true;
        let write = || -> Result<(), AdmissionError> {
            let mode = Mode::RUSR | Mode::WUSR;
            let fd = fs::openat(
                self.directory.directory(),
                &name,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                mode,
            )
            .map_err(|_| AdmissionError::CommitUnknown)?;
            fs::fchmod(&fd, mode).map_err(|_| AdmissionError::CommitUnknown)?;
            check_file(&fd)?;
            let mut file = File::from(fd);
            file.write_all(&bytes)
                .map_err(|_| AdmissionError::CommitUnknown)?;
            file.sync_all().map_err(|_| AdmissionError::CommitUnknown)?;
            self.check_lock()?;
            self.check_name(&name, &check_file(&file)?)?;
            fs::renameat(
                self.directory.directory(),
                &name,
                self.directory.directory(),
                STATE,
            )
            .map_err(|_| AdmissionError::CommitUnknown)?;
            fs::fsync(self.directory.directory()).map_err(|_| AdmissionError::CommitUnknown)?;
            if self.read()?.1 != Some(hash(&bytes)) {
                return Err(AdmissionError::CommitUnknown);
            }
            Ok(())
        };
        match write() {
            Ok(()) => {
                self.poisoned = false;
                Ok(())
            }
            Err(_) => Err(AdmissionError::CommitUnknown),
        }
    }
    /// The HTTP admission service independently authorizes the initiating intent
    /// and exact dispatch first; challenge issuance itself grants no authority.
    pub fn issue(
        &mut self,
        intent: &VerifiedIntent,
        keys: RunnerPublicKeys,
        run: u64,
        attempt: u32,
        now: u64,
        expires: u64,
    ) -> Result<IssuedChallenge, AdmissionError> {
        if self.purpose != 1 {
            return Err(AdmissionError::Conflict);
        }
        if self.poisoned {
            return Err(AdmissionError::CommitUnknown);
        }
        if now < intent.issued_unix()
            || expires <= now
            || expires > intent.spec().expires_unix
            || expires.saturating_sub(now) > 300
        {
            return Err(AdmissionError::Lifetime);
        }
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| AdmissionError::Entropy)?;
        if nonce == [0; 32] {
            return Err(AdmissionError::Entropy);
        }
        let audience = runner_binding::audience_for(intent, keys, nonce, run, attempt)
            .map_err(|_| AdmissionError::Conflict)?;
        let (mut state, prior) = self.read()?;
        if state.challenges.len() >= MAX_CHALLENGES {
            return Err(AdmissionError::Capacity);
        }
        if state
            .challenges
            .insert(
                hex::encode(nonce),
                ChallengeRecord {
                    audience: audience.clone(),
                    issued_unix: now,
                    expires_unix: expires,
                    admitted: None,
                },
            )
            .is_some()
        {
            return Err(AdmissionError::Conflict);
        }
        self.commit(&state, prior)?;
        Ok(IssuedChallenge {
            nonce,
            audience,
            expires_unix: expires,
        })
    }
    pub fn consume(
        &mut self,
        binding: &VerifiedRunnerBinding,
        nonce: [u8; 32],
        now: u64,
    ) -> Result<AdmissionOutcome, AdmissionError> {
        if self.purpose != 1 {
            return Err(AdmissionError::Conflict);
        }
        if self.poisoned {
            return Err(AdmissionError::CommitUnknown);
        }
        let (mut state, prior) = self.read()?;
        let nonce_id = hex::encode(nonce);
        let challenge = state
            .challenges
            .get(&nonce_id)
            .ok_or(AdmissionError::Conflict)?;
        if challenge.audience != binding.audience() {
            return Err(AdmissionError::Conflict);
        }
        let token_id = digest(
            b"chinwag-ci-issuer-jti-v1\0",
            &[
                crate::oidc::GITHUB_ISSUER.as_bytes(),
                binding.token_id().as_bytes(),
            ],
        );
        let record = AdmissionRecord {
            spec: binding.intent_spec().clone(),
            initiating_instance: binding.initiating_instance().into(),
            intent_digest: *binding.intent_digest(),
            token_sha256: *binding.token_sha256(),
            issuer_jti_sha256: token_id,
            audience: binding.audience().into(),
            run_id: binding.run_id(),
            run_attempt: binding.run_attempt(),
            signing_key: *binding.signing_public_key(),
            agent_transport_key: *binding.claimed_agent_transport_key(),
            archive_transport_key: *binding.claimed_archive_transport_key(),
            usable_from_unix: binding.usable_from_unix().max(challenge.issued_unix),
            expires_unix: binding.expires_unix().min(challenge.expires_unix),
        };
        let record_digest = digest(b"chinwag-ci-admission-record-v1\0", &[&canonical(&record)?]);
        let record_id = hex::encode(record_digest);
        let scope_id = hex::encode(digest(
            b"chinwag-ci-single-intent-run-v1\0",
            &[
                binding.intent_digest(),
                &binding.run_id().to_be_bytes(),
                &binding.run_attempt().to_be_bytes(),
            ],
        ));
        let token_id = hex::encode(token_id);
        if let Some(existing) = &challenge.admitted {
            if existing != &record_id
                || state.token_admissions.get(&token_id) != Some(&record_id)
                || state.scope_admissions.get(&scope_id) != Some(&record_id)
                || state.admissions.get(&record_id) != Some(&record)
            {
                return Err(AdmissionError::Conflict);
            }
            return Ok(AdmissionOutcome::ReconciledOriginal(CommittedAdmission {
                digest: record_digest,
                record,
            }));
        }
        if now < record.usable_from_unix || now >= record.expires_unix {
            return Err(AdmissionError::Lifetime);
        }
        if state.token_admissions.contains_key(&token_id)
            || state.scope_admissions.contains_key(&scope_id)
        {
            return Err(AdmissionError::Conflict);
        }
        state
            .challenges
            .get_mut(&nonce_id)
            .ok_or(AdmissionError::Conflict)?
            .admitted = Some(record_id.clone());
        state.token_admissions.insert(token_id, record_id.clone());
        state.scope_admissions.insert(scope_id, record_id.clone());
        state.admissions.insert(record_id, record.clone());
        self.commit(&state, prior)?;
        Ok(AdmissionOutcome::NewlyCommitted(CommittedAdmission {
            digest: record_digest,
            record,
        }))
    }
    pub(crate) fn bind_release_enrollment(
        &mut self,
        acu: [u8; 32],
        admission: [u8; 32],
    ) -> Result<(), AdmissionError> {
        if self.purpose != 2 {
            return Err(AdmissionError::Conflict);
        }
        if self.poisoned {
            return Err(AdmissionError::CommitUnknown);
        }
        let (mut state, prior) = self.read()?;
        let enrollment = ReleaseEnrollment { acu, admission };
        if let Some(old) = &state.release_enrollment {
            return if old == &enrollment {
                Ok(())
            } else {
                Err(AdmissionError::Conflict)
            };
        }
        state.release_enrollment = Some(enrollment);
        self.commit(&state, prior)
    }
    pub(crate) fn observe_policy(
        &mut self,
        signer: [u8; 32],
        epoch: u64,
        sha256: [u8; 32],
    ) -> Result<(), AdmissionError> {
        if self.purpose != 2 {
            return Err(AdmissionError::Conflict);
        }
        if self.poisoned {
            return Err(AdmissionError::CommitUnknown);
        }
        let (mut state, prior) = self.read()?;
        let policy = PolicyRecord {
            signer,
            epoch,
            sha256,
        };
        if let Some(old) = &state.acu_policy {
            if old == &policy {
                return Ok(());
            }
            if old.signer != signer || epoch <= old.epoch {
                return Err(AdmissionError::Conflict);
            }
        }
        state.acu_policy = Some(policy);
        self.commit(&state, prior)
    }
    pub(crate) fn reserve_release(
        &mut self,
        scope: [u8; 32],
        request_sha256: [u8; 32],
    ) -> Result<ReleaseDisposition, AdmissionError> {
        if self.purpose != 2 {
            return Err(AdmissionError::Conflict);
        }
        if self.poisoned {
            return Err(AdmissionError::CommitUnknown);
        }
        let (mut state, prior) = self.read()?;
        let scope = hex::encode(scope);
        if let Some(old) = state.releases.get(&scope) {
            if old.request_sha256 != request_sha256 {
                return Err(AdmissionError::Conflict);
            }
            return match &old.encrypted_signed_response {
                Some(bytes) => Ok(ReleaseDisposition::Ready(bytes.clone())),
                None => Err(AdmissionError::CommitUnknown),
            };
        }
        if state.releases.len() >= MAX_CHALLENGES {
            return Err(AdmissionError::Capacity);
        }
        state.releases.insert(
            scope.clone(),
            ReleaseRecord {
                request_sha256,
                encrypted_signed_response: None,
            },
        );
        self.commit(&state, prior)?;
        Ok(ReleaseDisposition::Reserved(ReservedRelease {
            scope,
            request_sha256,
        }))
    }
    pub(crate) fn finish_release(
        &mut self,
        reserved: ReservedRelease,
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>, AdmissionError> {
        if self.purpose != 2 {
            return Err(AdmissionError::Conflict);
        }
        if self.poisoned {
            return Err(AdmissionError::CommitUnknown);
        }
        if bytes.is_empty() || bytes.len() > crate::authorization::MAX_AUTH_BYTES {
            return Err(AdmissionError::Capacity);
        }
        let (mut state, prior) = self.read()?;
        let entry = state
            .releases
            .get_mut(&reserved.scope)
            .ok_or(AdmissionError::Conflict)?;
        if entry.request_sha256 != reserved.request_sha256
            || entry.encrypted_signed_response.is_some()
        {
            return Err(AdmissionError::Conflict);
        }
        entry.encrypted_signed_response = Some(bytes.clone());
        self.commit(&state, prior)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn directory() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    #[test]
    fn final_ledger_owner_releases_lock_even_with_a_transient_inherited_fd() {
        let d = directory();
        let p = d.path().canonicalize().unwrap();
        let ledger = AdmissionLedger::open(&p).unwrap();
        let inherited = rustix::io::dup(&ledger.lock).unwrap();
        drop(ledger);
        AdmissionLedger::open(&p).unwrap();
        drop(inherited);
    }
    #[test]
    fn initialized_state_disappearance_and_mismatched_initialization_never_reset_replay_memory() {
        let d = directory();
        let p = d.path().canonicalize().unwrap();
        let ledger = AdmissionLedger::open(&p).unwrap();
        std::fs::rename(p.join(STATE), p.join("preserved-state.json")).unwrap();
        assert!(matches!(ledger.read(), Err(AdmissionError::Store)));
        drop(ledger);
        assert!(matches!(
            AdmissionLedger::open(&p),
            Err(AdmissionError::Store)
        ));
        // Restore only this controlled fixture's exact preimage, then test a
        // missing lock. No production repair/recovery API is implied.
        std::fs::rename(p.join("preserved-state.json"), p.join(STATE)).unwrap();
        std::fs::rename(p.join(LOCK), p.join("preserved-lock")).unwrap();
        assert!(matches!(
            AdmissionLedger::open(&p),
            Err(AdmissionError::Store)
        ));
        assert!(matches!(
            AdmissionLedger::open(&p),
            Err(AdmissionError::Store)
        ));
    }
    #[test]
    fn unsafe_lock_modes_and_malformed_state_are_refused_without_permission_repair() {
        let d = directory();
        let p = d.path().canonicalize().unwrap();
        drop(AdmissionLedger::open(&p).unwrap());
        std::fs::set_permissions(p.join(LOCK), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            AdmissionLedger::open(&p),
            Err(AdmissionError::Store)
        ));
        assert_eq!(
            std::fs::metadata(p.join(LOCK))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        std::fs::set_permissions(p.join(LOCK), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(p.join(STATE), b"{\"version\":1,\"version\":1}").unwrap();
        assert!(matches!(
            AdmissionLedger::open(&p),
            Err(AdmissionError::Store)
        ));
    }
}
