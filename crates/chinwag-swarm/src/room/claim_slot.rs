//! One permanent, operator-owned PR-01 claim slot. No automatic original replay.

use super::{ClaimSubmission, RoomClient, RoomSession, now_unix};
use crate::{
    DiscoveryScope,
    attempt_journal::{AttemptBinding, AttemptError, AttemptJournal, AttemptPhase, StoredOutcome},
    bind_sovereign_endpoint,
    identity::Identity,
    lan::LanInterfaces,
    relay_policy::RelayPolicy,
};
use chinwag_claim::{
    ClaimRequestUnsigned, Pr, SignedClaimRequest, encode_hex,
    reply::{FreshReply, PreparedClaim},
};
use ed25519_dalek::VerifyingKey;
use iroh::{Endpoint, EndpointId, address_lookup::memory::MemoryLookup};
use rand::{TryRngCore, rngs::OsRng};
use serde::Serialize;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::timeout;

#[path = "claim_slot/lease.rs"]
mod lease;
mod peer_transport;
pub use peer_transport::PeerError;

pub use lease::{LeaseError, WriteWitness};

const ORIGIN: &str = "https://bootstrap.chinwag.sh/";
const COORDINATOR: &str = "366eb665b85888a6b5f265d340b29d0623c6c92c96e6c0746c7b4554b5949919";
const A: &str = "63e44fbb5054e0730793b2be61daf203b912c7cc5777f86ebbfe5f73b096c3d0";
const B: &str = "df7676a8680f06f1cddb51a793be9a07a0d022638cb25ebe681dd42328867931";
pub const CLAIM_FILE: &str = "crates/chinwag-seed/src/main.rs";
const FILE: &str = CLAIM_FILE;

/// Supplied by the process operator, never by tool arguments.
pub struct ClaimOperatorConfig {
    pub key_path: PathBuf,
    pub journal_directory: PathBuf,
    pub lan_ipv4: Ipv4Addr,
    pub policy: Arc<RelayPolicy>,
}

/// Reports are observations, never a lease or file-write capability.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ClaimTaskReport {
    Refused {
        status: u16,
        code: String,
        cf_ray: String,
    },
    OriginalUnresolved,
    Reported {
        disposition: &'static str,
        cf_ray: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimTaskError {
    #[error("claim operator configuration rejected")]
    Configuration,
    #[error("claim identity unavailable or not pinned")]
    Identity,
    #[error(transparent)]
    Journal(#[from] AttemptError),
    #[error("claim session unavailable; no original was armed")]
    SessionUnavailable,
    #[error("claim request could not be prepared")]
    Prepare,
    #[error("claim submission failed; preserve the original slot")]
    Submission,
    #[error("claim service is shut down")]
    Closed,
}

/// `Send`, not `Sync`. A server must serialize calls with one async mutex.
/// The journal lock is held for the service lifetime, including across POSTs.
pub struct ClaimService {
    journal: AttemptJournal,
    identity: Identity,
    client: RoomClient,
    peer: EndpointId,
    lan: Ipv4Addr,
    /// Pinned coordinator key bytes. Receipt checks use this, not a caller argument.
    coordinator: [u8; 32],
    endpoint: Option<Endpoint>,
    room: Option<RoomSession>,
    room_start_attempted: bool,
    peer_plane: Option<crate::transport::DataPlane>,
    peer_recv_once: bool,
    peer_start_once: bool,
    /// In-memory only. Shutdown clears it. A stored report never rebuilds it.
    lease: Option<lease::ActiveLease>,
    closed: bool,
    /// Fixture stand-in for `attached_session_id` when no room socket exists.
    /// Production builds do not have this field.
    #[cfg(test)]
    test_observed: Option<String>,
}

fn genesis_opposite(own_public_hex: &str) -> Result<EndpointId, ClaimTaskError> {
    match own_public_hex {
        A => B,
        B => A,
        _ => return Err(ClaimTaskError::Identity),
    }
    .parse()
    .map_err(|_| ClaimTaskError::Configuration)
}

impl ClaimService {
    /// No sockets are opened here. Corrupt stored originals fail before any
    /// room startup, and valid occupied slots are read without a new room.
    pub fn open(config: ClaimOperatorConfig) -> Result<Self, ClaimTaskError> {
        let identity = Identity::from_ssh_signing_file(&config.key_path)
            .map_err(|_| ClaimTaskError::Identity)?;
        let actor = encode_hex(&identity.ssh_public_bytes());
        let peer = genesis_opposite(&actor)?;
        let coordinator: EndpointId = COORDINATOR
            .parse()
            .map_err(|_| ClaimTaskError::Configuration)?;
        let coordinator_bytes = *coordinator.as_bytes();
        let binding = AttemptBinding::new(ORIGIN, identity.ssh_public_bytes(), coordinator_bytes)?;
        let journal = AttemptJournal::open(&config.journal_directory, binding)?;
        if let Some(attempt) = journal.load()? {
            journal.stored_outcome(&attempt)?;
        }
        LanInterfaces::new(vec![config.lan_ipv4]).map_err(|_| ClaimTaskError::Configuration)?;
        let client = RoomClient::new(ORIGIN, coordinator, config.policy)
            .map_err(|_| ClaimTaskError::Configuration)?;
        Ok(Self {
            journal,
            identity,
            client,
            peer,
            lan: config.lan_ipv4,
            coordinator: coordinator_bytes,
            endpoint: None,
            room: None,
            room_start_attempted: false,
            peer_plane: None,
            peer_recv_once: false,
            peer_start_once: false,
            lease: None,
            closed: false,
            #[cfg(test)]
            test_observed: None,
        })
    }

    /// Immutable operator preflight only; this grants no session, lease, or
    /// access to the identity or endpoint. Closed services always refuse.
    pub fn matches_bundle_pins(&self, builder: [u8; 32], peer: EndpointId) -> bool {
        !self.closed && self.identity.ssh_public_bytes() == builder && self.peer == peer
    }

    fn stored_report(&self) -> Result<Option<ClaimTaskReport>, ClaimTaskError> {
        let Some(attempt) = self.journal.load()? else {
            return Ok(None);
        };
        match attempt.phase() {
            AttemptPhase::Armed | AttemptPhase::Unknown => {
                Ok(Some(ClaimTaskReport::OriginalUnresolved))
            }
            AttemptPhase::Refused | AttemptPhase::Verified => {
                let outcome = self
                    .journal
                    .stored_outcome(&attempt)?
                    .ok_or(AttemptError::Corrupt)?;
                Ok(Some(match outcome {
                    StoredOutcome::Refused {
                        status,
                        code,
                        cf_ray,
                    } => ClaimTaskReport::Refused {
                        status,
                        code,
                        cf_ray,
                    },
                    StoredOutcome::Verified { cf_ray, .. } => ClaimTaskReport::Reported {
                        disposition: "stored_authenticated_outcome",
                        cf_ray,
                    },
                }))
            }
        }
    }

    pub async fn claim_task(&mut self) -> Result<ClaimTaskReport, ClaimTaskError> {
        if self.closed {
            return Err(ClaimTaskError::Closed);
        }
        if let Some(report) = self.stored_report()? {
            return Ok(report);
        }
        let session = self.open_room().await?;
        self.submit_empty(Some(&session)).await
    }

    /// Borrow the current process lease for one path check. Does not clear it.
    pub fn authorize_local_write(&self, path: &Path) -> Result<WriteWitness<'_>, LeaseError> {
        let witness = WriteWitness::from_service(self);
        witness.validate(path)?;
        Ok(witness)
    }

    fn current_session(&self) -> Result<&str, LeaseError> {
        if let Some(room) = &self.room {
            return room.attached_session_id().map_err(|_| LeaseError::Session);
        }
        #[cfg(test)]
        if let Some(session) = self.test_observed.as_deref() {
            return Ok(session);
        }
        Err(LeaseError::Session)
    }

    async fn open_room(&mut self) -> Result<String, ClaimTaskError> {
        if self.room.is_none() {
            if self.room_start_attempted {
                return Err(ClaimTaskError::SessionUnavailable);
            }
            // Cancellation during startup cannot trigger a second startup in
            // this process. No signed claim exists until startup completes.
            self.room_start_attempted = true;
            let book = MemoryLookup::new();
            let endpoint = timeout(
                Duration::from_secs(3),
                bind_sovereign_endpoint(
                    &self.identity,
                    book.clone(),
                    self.peer,
                    LanInterfaces::new(vec![self.lan])
                        .map_err(|_| ClaimTaskError::Configuration)?,
                    DiscoveryScope::RoomOnly,
                    vec![b"chinwag-seed-claim/v1".to_vec()],
                    self.client.relay_policy(),
                ),
            )
            .await
            .map_err(|_| ClaimTaskError::SessionUnavailable)?
            .map_err(|_| ClaimTaskError::SessionUnavailable)?;
            // Retain ownership before the next await, also on cancellation.
            self.endpoint = Some(endpoint);
            let endpoint = self
                .endpoint
                .as_ref()
                .ok_or(ClaimTaskError::SessionUnavailable)?;
            self.client
                .relay_policy()
                .observe_relay_urls(endpoint.addr().relay_urls())
                .map_err(|_| ClaimTaskError::Configuration)?;
            let mut addresses = Vec::new();
            for _ in 0..100 {
                addresses = endpoint
                    .addr()
                    .ip_addrs()
                    .copied()
                    .filter(|a| a.ip() == IpAddr::V4(self.lan))
                    .collect();
                if !addresses.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if addresses.is_empty() {
                return Err(ClaimTaskError::SessionUnavailable);
            }
            let room = timeout(
                Duration::from_secs(20),
                self.client.open(&self.identity, self.peer, addresses, book),
            )
            .await
            .map_err(|_| ClaimTaskError::SessionUnavailable)?
            .map_err(|_| ClaimTaskError::SessionUnavailable)?;
            self.room = Some(room);
        }
        self.room
            .as_ref()
            .ok_or(ClaimTaskError::SessionUnavailable)?
            .attached_session_id()
            .map(str::to_owned)
            .map_err(|_| ClaimTaskError::SessionUnavailable)
    }

    // Only production open_room supplies this observed session. It is private:
    // neither another crate nor MCP input can manufacture this argument.
    async fn submit_empty(
        &mut self,
        observed_session: Option<&str>,
    ) -> Result<ClaimTaskReport, ClaimTaskError> {
        if self.closed {
            return Err(ClaimTaskError::Closed);
        }
        if let Some(report) = self.stored_report()? {
            return Ok(report);
        }
        let session = observed_session.ok_or(ClaimTaskError::SessionUnavailable)?;
        #[cfg(test)]
        {
            // The synthetic fixture has no RoomSession. Remember the private
            // argument so authorize can run without pretending a socket is live.
            self.test_observed = Some(session.to_owned());
        }
        let issued = now_unix().map_err(|_| ClaimTaskError::Prepare)?;
        let signed = self
            .identity
            .sign_claim(ClaimRequestUnsigned {
                claim_id: random_id()?,
                actor: encode_hex(&self.identity.ssh_public_bytes()),
                session: session.to_owned(),
                nonce: random_id()?,
                pr: Pr::Pr01,
                files: vec![FILE.into()],
                expected_revision: 0,
                issued,
                expiry: issued.checked_add(60).ok_or(ClaimTaskError::Prepare)?,
            })
            .map_err(|_| ClaimTaskError::Prepare)?;
        let prepared = PreparedClaim::from_signed(signed).map_err(|_| ClaimTaskError::Prepare)?;
        let mut original = self.journal.arm(&prepared)?;
        let started = Instant::now();
        let result = self
            .client
            .submit_original(&mut self.journal, &mut original)
            .await
            .map_err(|_| ClaimTaskError::Submission)?;
        match result {
            ClaimSubmission::Unknown { .. } => Ok(ClaimTaskReport::OriginalUnresolved),
            ClaimSubmission::Refused { .. } | ClaimSubmission::Historical { .. } => {
                self.stored_report()?.ok_or(ClaimTaskError::Submission)
            }
            ClaimSubmission::ReportedFresh { reply, .. } => {
                self.install_fresh(&reply, session, prepared.signed(), started);
                self.stored_report()?.ok_or(ClaimTaskError::Submission)
            }
        }
    }

    /// Mint only from this service's own fresh POST. A forged enum value has no
    /// path into this function. Failure leaves any persisted history in place.
    fn install_fresh(
        &mut self,
        reply: &FreshReply,
        observed_session: &str,
        prepared: &SignedClaimRequest,
        started: Instant,
    ) {
        if self.closed || self.lease.is_some() {
            return;
        }
        let Ok(coordinator_key) = VerifyingKey::from_bytes(&self.coordinator) else {
            return;
        };
        let actor_bytes = self.identity.ssh_public_bytes();
        let Ok(actor_key) = VerifyingKey::from_bytes(&actor_bytes) else {
            return;
        };
        let signed_receipt = reply.receipt();
        if signed_receipt
            .verify_binding(prepared, &actor_key, &coordinator_key)
            .is_err()
        {
            return;
        }
        let request = &prepared.request;
        let receipt = &signed_receipt.receipt;
        if request.expected_revision != 0 || receipt.revision != 1 {
            return;
        }
        if request.pr != Pr::Pr01 || receipt.pr != Pr::Pr01 {
            return;
        }
        if !sole_claim_file(&request.files) || !sole_claim_file(&receipt.files) {
            return;
        }
        if request.session != observed_session || receipt.session != observed_session {
            return;
        }
        let actor_hex = encode_hex(&actor_bytes);
        if request.actor != actor_hex || receipt.actor != actor_hex {
            return;
        }
        if request.issued != receipt.issued || request.expiry != receipt.expiry {
            return;
        }
        let Some(span) = receipt.expiry.checked_sub(receipt.issued) else {
            return;
        };
        if !(1..=60).contains(&span) {
            return;
        }
        let Some(deadline) = started.checked_add(Duration::from_secs(span)) else {
            return;
        };
        let Ok(wall) = now_unix() else {
            return;
        };
        if wall < receipt.issued || wall >= receipt.expiry || Instant::now() >= deadline {
            return;
        }
        if self.current_session().ok() != Some(observed_session) {
            return;
        }
        self.lease = Some(lease::ActiveLease::new(
            actor_bytes,
            observed_session.to_owned(),
            receipt.issued,
            receipt.expiry,
            deadline,
        ));
    }

    /// Normal shutdown only closes owned network resources. It never alters
    /// an original request, arms a replacement, or tries to resolve an unknown.
    pub async fn shutdown(&mut self) {
        self.closed = true;
        self.lease = None;
        #[cfg(test)]
        {
            self.test_observed = None;
        }
        if let Some(mut room) = self.room.take() {
            room.close().await;
        }
        let closed_by_plane = if let Some(plane) = self.peer_plane.take() {
            matches!(
                timeout(Duration::from_secs(2), plane.shutdown()).await,
                Ok(Ok(()))
            )
        } else {
            false
        };
        if !closed_by_plane {
            // Retain this handle through the await so cancellation leaves it
            // available to a later explicit shutdown. This is cleanup only.
            if let Some(endpoint) = self.endpoint.as_ref() {
                let _ = timeout(Duration::from_secs(2), endpoint.close()).await;
            }
        }
        self.endpoint = None;
    }
}

fn sole_claim_file(files: &[String]) -> bool {
    files.len() == 1 && files[0] == CLAIM_FILE
}

fn random_id() -> Result<String, ClaimTaskError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ClaimTaskError::Prepare)?;
    Ok(encode_hex(&bytes))
}

#[cfg(test)]
#[path = "claim_slot_tests.rs"]
mod tests;
