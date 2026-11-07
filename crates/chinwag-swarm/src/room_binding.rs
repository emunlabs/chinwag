//! Ordinary room transport membership. Stored-peer receipts do not confer a
//! mesh ticket, production K2 license, task admission or message processing.
#![forbid(unsafe_code)]

use crate::{
    identity::Identity,
    relay_policy::RelayPolicy,
    room_wire::{self, Advertisement, Receipt, ValidatedRoomMessage},
};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey, Signature,
    endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("ordinary daemon room binding unavailable")]
pub enum BindingError {
    Configuration,
    Endpoint,
    Unavailable,
    Receipt,
    Replay,
    Expired,
    Revoked,
    Time,
}

fn same_endpoint(left: EndpointId, right: EndpointId) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}
mod signer_seal {
    pub trait Sealed {}
}
/// Sealed signers accept only a message validated by the existing room codec.
/// The nonconstructible message type prevents a general raw signing API.
pub trait RoomSigner: signer_seal::Sealed {
    fn endpoint_id(&self) -> EndpointId;
    #[doc(hidden)]
    fn sign_validated_room_message(&self, message: &ValidatedRoomMessage<'_>) -> Signature;
}
impl signer_seal::Sealed for Identity {}
impl RoomSigner for Identity {
    fn endpoint_id(&self) -> EndpointId {
        Identity::endpoint_id(self)
    }
    fn sign_validated_room_message(&self, message: &ValidatedRoomMessage<'_>) -> Signature {
        self.secret_key().sign(message.bytes())
    }
}
/// An opaque already-owned daemon key joined to the actual bound endpoint.
/// This identity does not assert SSH provenance or room/coordinator approval.
pub struct DaemonRoomIdentity {
    key: SecretKey,
    endpoint: EndpointId,
}
impl DaemonRoomIdentity {
    pub fn for_endpoint(key: SecretKey, endpoint: &Endpoint) -> Result<Self, BindingError> {
        if !same_endpoint(key.public(), endpoint.id()) {
            return Err(BindingError::Endpoint);
        }
        Ok(Self {
            key,
            endpoint: endpoint.id(),
        })
    }
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint
    }
}
impl signer_seal::Sealed for DaemonRoomIdentity {}
impl RoomSigner for DaemonRoomIdentity {
    fn endpoint_id(&self) -> EndpointId {
        self.endpoint
    }
    fn sign_validated_room_message(&self, message: &ValidatedRoomMessage<'_>) -> Signature {
        self.key.sign(message.bytes())
    }
}

/// Selected configuration data only. Parsing pins or matching relay strings
/// never installs a peer. ROOT's selected-config loader owns its provenance.
#[derive(Clone)]
pub struct DaemonPairConfig {
    configuration_id: String,
    generation: u64,
    local: EndpointId,
    peer: EndpointId,
    coordinator: EndpointId,
    policy: Arc<RelayPolicy>,
}
impl DaemonPairConfig {
    pub fn try_new(
        configuration_id: String,
        generation: u64,
        local: EndpointId,
        peer: EndpointId,
        coordinator: EndpointId,
        policy: Arc<RelayPolicy>,
    ) -> Result<Self, BindingError> {
        if configuration_id.is_empty()
            || configuration_id.len() > 128
            || !configuration_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
            || generation == 0
            || generation > 9_007_199_254_740_991
            || same_endpoint(local, peer)
            || same_endpoint(local, coordinator)
            || same_endpoint(peer, coordinator)
            || policy.relay_mode().is_err()
        {
            return Err(BindingError::Configuration);
        }
        Ok(Self {
            configuration_id,
            generation,
            local,
            peer,
            coordinator,
            policy,
        })
    }
    pub fn configuration_id(&self) -> &str {
        &self.configuration_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn local_endpoint_id(&self) -> EndpointId {
        self.local
    }
    pub fn peer_endpoint_id(&self) -> EndpointId {
        self.peer
    }
    pub fn coordinator_endpoint_id(&self) -> EndpointId {
        self.coordinator
    }
    pub fn relay_policy(&self) -> &RelayPolicy {
        &self.policy
    }
}

trait Clock: Send + Sync {
    fn now(&self) -> Result<(u64, Instant), BindingError>;
}
struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Result<(u64, Instant), BindingError> {
        Ok((
            crate::room::now_unix().map_err(|_| BindingError::Time)?,
            Instant::now(),
        ))
    }
}
struct OwnJoin {
    advertisement: Advertisement,
    receipt: Receipt,
    session: String,
    origin: String,
    deadline: Instant,
    refresh_at: Instant,
}
/// A single renewal of the exact current own transport advertisement. Merely
/// preparing or retaining this ticket grants no additional time or authority.
pub(crate) struct OwnRenewal {
    previous: Arc<OwnJoin>,
}
impl OwnRenewal {
    pub(crate) fn advertisement(&self) -> &Advertisement {
        &self.previous.advertisement
    }
    pub(crate) fn next_revision(&self) -> Result<u64, BindingError> {
        self.previous
            .advertisement
            .revision
            .checked_add(1)
            .filter(|revision| *revision <= 9_007_199_254_740_991)
            .ok_or(BindingError::Replay)
    }
}
struct PeerJoin {
    advertisement: Advertisement,
    receipt: Receipt,
    address: EndpointAddr,
    deadline: Instant,
    generation: u64,
}
struct State {
    started: bool,
    closed: bool,
    generation: u64,
    own: Option<Arc<OwnJoin>>,
    peer: Option<Arc<PeerJoin>>,
    active_peer_session: Option<String>,
    seen_peer_sessions: BTreeMap<String, u64>,
}
struct Shared {
    config: DaemonPairConfig,
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
}
/// A cloneable pending/live gate. Construction starts deny-all. Only the
/// original verified RoomSession owner can install its private proof state.
#[derive(Clone)]
pub struct DaemonPeerGate {
    shared: Arc<Shared>,
}
impl DaemonPeerGate {
    pub fn pending(config: DaemonPairConfig) -> Self {
        Self::with_clock(config, Arc::new(SystemClock))
    }
    fn with_clock(config: DaemonPairConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                clock,
                state: Mutex::new(State {
                    started: false,
                    closed: false,
                    generation: 0,
                    own: None,
                    peer: None,
                    active_peer_session: None,
                    seen_peer_sessions: BTreeMap::new(),
                }),
            }),
        }
    }
    pub fn configuration(&self) -> &DaemonPairConfig {
        &self.shared.config
    }
    pub fn hooks(&self) -> DaemonPeerHooks {
        DaemonPeerHooks { gate: self.clone() }
    }
    pub fn current_peer(&self) -> Result<VerifiedDaemonPeer, BindingError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| BindingError::Revoked)?;
        let (now, instant) = self.shared.clock.now()?;
        check_live(&state, now, instant)?;
        let peer = state
            .peer
            .as_ref()
            .ok_or(BindingError::Unavailable)?
            .clone();
        Ok(VerifiedDaemonPeer {
            shared: Arc::downgrade(&self.shared),
            own: state.own.as_ref().ok_or(BindingError::Unavailable)?.clone(),
            peer,
        })
    }
    pub fn check_peer(&self, actual: EndpointId) -> Result<(), BindingError> {
        self.current_peer()?.revalidate_for(actual).map(|_| ())
    }
    /// Revocation only reduces access and is terminal for this gate/owner.
    /// A fresh selected configuration/session needs a fresh pending gate.
    pub fn revoke(&self) -> Result<(), BindingError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| BindingError::Revoked)?;
        state.closed = true;
        state.peer = None;
        state.own = None;
        Ok(())
    }
    pub(crate) fn begin_owner(
        &self,
        actual: EndpointId,
        coordinator: EndpointId,
        policy: &RelayPolicy,
        origin: &str,
    ) -> Result<DaemonRoomOwner, BindingError> {
        let config = &self.shared.config;
        if !same_endpoint(actual, config.local)
            || !same_endpoint(coordinator, config.coordinator)
            || policy != &*config.policy
            || origin.is_empty()
        {
            return Err(BindingError::Configuration);
        }
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| BindingError::Revoked)?;
        if state.started || state.closed {
            return Err(BindingError::Revoked);
        }
        state.started = true;
        Ok(DaemonRoomOwner {
            gate: self.clone(),
            origin: origin.into(),
        })
    }
}
fn check_time(
    expiry: u64,
    deadline: Instant,
    now: u64,
    instant: Instant,
) -> Result<(), BindingError> {
    if now == 0
        || expiry <= now
        || expiry > now.checked_add(120).ok_or(BindingError::Time)?
        || instant >= deadline
    {
        return Err(BindingError::Expired);
    }
    Ok(())
}
fn check_live(state: &State, now: u64, instant: Instant) -> Result<(), BindingError> {
    if state.closed {
        return Err(BindingError::Revoked);
    }
    let own = state.own.as_ref().ok_or(BindingError::Unavailable)?;
    check_time(own.advertisement.expiry_unix, own.deadline, now, instant)?;
    let peer = state.peer.as_ref().ok_or(BindingError::Unavailable)?;
    if peer.generation != state.generation {
        return Err(BindingError::Revoked);
    }
    check_time(peer.advertisement.expiry_unix, peer.deadline, now, instant)
}
fn deadline(expiry: u64, now: u64, instant: Instant) -> Result<Instant, BindingError> {
    let remaining = expiry
        .checked_sub(now)
        .filter(|seconds| *seconds > 0 && *seconds <= 120)
        .ok_or(BindingError::Expired)?;
    instant
        .checked_add(Duration::from_secs(remaining))
        .ok_or(BindingError::Time)
}

/// Immutable verified facts plus a live owner join. Clone is not renewal:
/// every later frame/dial must revalidate against the original live gate.
#[derive(Clone)]
pub struct VerifiedDaemonPeer {
    shared: Weak<Shared>,
    own: Arc<OwnJoin>,
    peer: Arc<PeerJoin>,
}
impl VerifiedDaemonPeer {
    pub fn peer_advertisement(&self) -> &Advertisement {
        &self.peer.advertisement
    }
    pub fn peer_storage_receipt(&self) -> &Receipt {
        &self.peer.receipt
    }
    pub fn revalidate_for(&self, actual: EndpointId) -> Result<EndpointAddr, BindingError> {
        self.with_current(Some(actual), |_, _, peer| peer.address.clone())
    }
    fn with_current<T>(
        &self,
        actual: Option<EndpointId>,
        read: impl FnOnce(&Shared, &OwnJoin, &PeerJoin) -> T,
    ) -> Result<T, BindingError> {
        let shared = self.shared.upgrade().ok_or(BindingError::Revoked)?;
        if actual.is_some_and(|actual| !same_endpoint(actual, shared.config.peer)) {
            return Err(BindingError::Endpoint);
        }
        let state = shared.state.lock().map_err(|_| BindingError::Revoked)?;
        let (now, instant) = shared.clock.now()?;
        check_live(&state, now, instant)?;
        if !state
            .peer
            .as_ref()
            .is_some_and(|peer| Arc::ptr_eq(peer, &self.peer))
        {
            return Err(BindingError::Revoked);
        }
        let own = state.own.as_ref().ok_or(BindingError::Unavailable)?;
        if !Arc::ptr_eq(own, &self.own) {
            return Err(BindingError::Revoked);
        }
        Ok(read(&shared, own, &self.peer))
    }
    pub fn local_session_id(&self) -> Result<String, BindingError> {
        self.with_current(None, |_, own, _| own.session.clone())
    }
    pub fn configuration_id(&self) -> Result<String, BindingError> {
        self.with_current(None, |shared, _, _| shared.config.configuration_id.clone())
    }
    pub fn configuration_generation(&self) -> Result<u64, BindingError> {
        self.with_current(None, |shared, _, _| shared.config.generation)
    }
    pub fn own_advertisement_and_receipt(&self) -> Result<(Advertisement, Receipt), BindingError> {
        self.with_current(None, |_, own, _| {
            (own.advertisement.clone(), own.receipt.clone())
        })
    }
    pub fn control_plane_origin(&self) -> Result<String, BindingError> {
        self.with_current(None, |_, own, _| own.origin.clone())
    }
}

/// Optional endpoint adapter. ROOT keeps its local ephemeral publisher path
/// separate; installing these hooks gates remote daemon identities only.
#[derive(Clone)]
pub struct DaemonPeerHooks {
    gate: DaemonPeerGate,
}
impl std::fmt::Debug for DaemonPeerHooks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DaemonPeerHooks")
    }
}
impl EndpointHooks for DaemonPeerHooks {
    async fn before_connect<'a>(
        &'a self,
        remote: &'a EndpointAddr,
        _alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if self.gate.check_peer(remote.id).is_ok() {
            BeforeConnectOutcome::Accept
        } else {
            BeforeConnectOutcome::Reject
        }
    }
    async fn after_handshake<'a>(&'a self, connection: &'a Connection) -> AfterHandshakeOutcome {
        if self.gate.check_peer(connection.remote_id()).is_ok() {
            AfterHandshakeOutcome::Accept
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: 0x403u32.into(),
                reason: b"ordinary_room_peer_unavailable".to_vec(),
            }
        }
    }
}

/// Original nonclone session owner; cancellation/drop revokes every issued
/// snapshot and hook. It cannot mint proof from a public RoomProof boolean.
pub(crate) struct DaemonRoomOwner {
    gate: DaemonPeerGate,
    origin: String,
}
impl DaemonRoomOwner {
    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }
    pub(crate) fn renewal_wait(&self) -> Result<Duration, BindingError> {
        let ticket = self.prepare_renewal()?;
        let (_, instant) = self.gate.shared.clock.now()?;
        Ok(ticket
            .previous
            .refresh_at
            .saturating_duration_since(instant))
    }
    pub(crate) fn prepare_renewal(&self) -> Result<OwnRenewal, BindingError> {
        let state = self
            .gate
            .shared
            .state
            .lock()
            .map_err(|_| BindingError::Revoked)?;
        let (now, instant) = self.gate.shared.clock.now()?;
        if state.closed {
            return Err(BindingError::Revoked);
        }
        let own = state.own.as_ref().ok_or(BindingError::Unavailable)?;
        check_time(own.advertisement.expiry_unix, own.deadline, now, instant)?;
        let ticket = OwnRenewal {
            previous: own.clone(),
        };
        ticket.next_revision()?;
        Ok(ticket)
    }
    pub(crate) fn commit_renewal(
        &mut self,
        ticket: OwnRenewal,
        advertisement: Advertisement,
        receipt: Receipt,
    ) -> Result<(), BindingError> {
        let config = &self.gate.shared.config;
        let (now, instant) = self.gate.shared.clock.now()?;
        room_wire::verify_daemon_advertisement(&advertisement, config.local, now, &config.policy)
            .map_err(|_| BindingError::Receipt)?;
        room_wire::verify_receipt(&receipt, config.coordinator, &advertisement)
            .map_err(|_| BindingError::Receipt)?;
        let old = ticket.advertisement();
        if advertisement.revision != ticket.next_revision()?
            || advertisement.actor_id != old.actor_id
            || advertisement.node_id != old.node_id
            || advertisement.session_id != old.session_id
            || advertisement.direct_addresses != old.direct_addresses
            || advertisement.expiry_unix <= old.expiry_unix
            || bool::from(
                advertisement
                    .challenge_nonce
                    .as_bytes()
                    .ct_eq(old.challenge_nonce.as_bytes()),
            )
        {
            return Err(BindingError::Replay);
        }
        let expires = deadline(advertisement.expiry_unix, now, instant)?;
        let refresh_at = instant
            .checked_add(expires.saturating_duration_since(instant) / 2)
            .ok_or(BindingError::Time)?;
        let mut state = self
            .gate
            .shared
            .state
            .lock()
            .map_err(|_| BindingError::Revoked)?;
        let (now, instant) = self.gate.shared.clock.now()?;
        if state.closed
            || !state
                .own
                .as_ref()
                .is_some_and(|own| Arc::ptr_eq(own, &ticket.previous))
        {
            return Err(BindingError::Revoked);
        }
        // The old authorization must still be live when its successor commits.
        // A valid new signature cannot resurrect a timed out or revoked owner.
        check_time(old.expiry_unix, ticket.previous.deadline, now, instant)?;
        check_time(advertisement.expiry_unix, expires, now, instant)?;
        state.own = Some(Arc::new(OwnJoin {
            advertisement,
            receipt,
            session: ticket.previous.session.clone(),
            origin: ticket.previous.origin.clone(),
            deadline: expires,
            refresh_at,
        }));
        Ok(())
    }
    pub(crate) fn remaining_validity(&self) -> Result<Duration, BindingError> {
        let state = self
            .gate
            .shared
            .state
            .lock()
            .map_err(|_| BindingError::Revoked)?;
        let (now, instant) = self.gate.shared.clock.now()?;
        if state.closed {
            return Err(BindingError::Revoked);
        }
        let own = state.own.as_ref().ok_or(BindingError::Unavailable)?;
        check_time(own.advertisement.expiry_unix, own.deadline, now, instant)?;
        Ok(Duration::from_secs(own.advertisement.expiry_unix - now)
            .min(own.deadline.saturating_duration_since(instant)))
    }
    pub(crate) fn gate(&self) -> &DaemonPeerGate {
        &self.gate
    }
    pub(crate) fn bind_own(
        &mut self,
        advertisement: Advertisement,
        receipt: Receipt,
        session: &str,
    ) -> Result<(), BindingError> {
        let config = &self.gate.shared.config;
        let (now, instant) = self.gate.shared.clock.now()?;
        room_wire::verify_daemon_advertisement(&advertisement, config.local, now, &config.policy)
            .map_err(|_| BindingError::Receipt)?;
        room_wire::verify_receipt(&receipt, config.coordinator, &advertisement)
            .map_err(|_| BindingError::Receipt)?;
        if advertisement.session_id != session {
            return Err(BindingError::Receipt);
        }
        let expires = deadline(advertisement.expiry_unix, now, instant)?;
        let refresh_at = instant
            .checked_add(expires.saturating_duration_since(instant) / 2)
            .ok_or(BindingError::Time)?;
        let mut state = self
            .gate
            .shared
            .state
            .lock()
            .map_err(|_| BindingError::Revoked)?;
        if state.closed || state.own.is_some() {
            return Err(BindingError::Revoked);
        }
        let (now, instant) = self.gate.shared.clock.now()?;
        check_time(advertisement.expiry_unix, expires, now, instant)?;
        state.own = Some(Arc::new(OwnJoin {
            advertisement,
            receipt,
            session: session.into(),
            origin: self.origin.clone(),
            deadline: expires,
            refresh_at,
        }));
        Ok(())
    }
    pub(crate) fn clear_peer(&mut self) -> Result<(), BindingError> {
        let mut state = self
            .gate
            .shared
            .state
            .lock()
            .map_err(|_| BindingError::Revoked)?;
        state.peer = None;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(BindingError::Revoked)?;
        Ok(())
    }
    pub(crate) fn bind_peer(
        &mut self,
        advertisement: &Advertisement,
        receipt: &Receipt,
    ) -> Result<(), BindingError> {
        let config = &self.gate.shared.config;
        let (now, instant) = self.gate.shared.clock.now()?;
        let addresses =
            room_wire::verify_daemon_advertisement(advertisement, config.peer, now, &config.policy)
                .map_err(|_| BindingError::Receipt)?;
        room_wire::verify_receipt(receipt, config.coordinator, advertisement)
            .map_err(|_| BindingError::Receipt)?;
        let address = config
            .policy
            .attach_verified_peer(
                addresses
                    .into_iter()
                    .fold(EndpointAddr::new(config.peer), |address, ip| {
                        address.with_ip_addr(ip)
                    }),
                config.peer,
            )
            .map_err(|_| BindingError::Configuration)?;
        let expires = deadline(advertisement.expiry_unix, now, instant)?;
        let mut state = self
            .gate
            .shared
            .state
            .lock()
            .map_err(|_| BindingError::Revoked)?;
        if state.closed {
            return Err(BindingError::Revoked);
        }
        let (now, instant) = self.gate.shared.clock.now()?;
        check_time(advertisement.expiry_unix, expires, now, instant)?;
        let own = state.own.as_ref().ok_or(BindingError::Unavailable)?;
        check_time(own.advertisement.expiry_unix, own.deadline, now, instant)?;
        if let Some(previous) = state.seen_peer_sessions.get(&advertisement.session_id) {
            if state.active_peer_session.as_deref() != Some(advertisement.session_id.as_str())
                || advertisement.revision <= *previous
            {
                return Err(BindingError::Replay);
            }
        } else if state.seen_peer_sessions.len() >= 8 {
            return Err(BindingError::Replay);
        }
        state.active_peer_session = Some(advertisement.session_id.clone());
        state
            .seen_peer_sessions
            .insert(advertisement.session_id.clone(), advertisement.revision);
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(BindingError::Revoked)?;
        state.peer = Some(Arc::new(PeerJoin {
            advertisement: advertisement.clone(),
            receipt: receipt.clone(),
            address,
            deadline: expires,
            generation: state.generation,
        }));
        Ok(())
    }
}
impl Drop for DaemonRoomOwner {
    fn drop(&mut self) {
        let _ = self.gate.revoke();
    }
}

#[cfg(test)]
#[path = "room/binding_tests.rs"]
mod binding_tests;
