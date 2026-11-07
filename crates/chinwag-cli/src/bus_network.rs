//! Native daemon route selection. Configuration and path observations are not
//! processing, task-start, mesh-license or production K2 authority.
#![forbid(unsafe_code)]

use chinwag_swarm::{
    relay_policy::RelayPolicy,
    room::RoomClient,
    room_binding::{DaemonPairConfig, DaemonPeerGate},
};
use iroh::{
    EndpointAddr, EndpointId, TransportAddr,
    endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks},
};
use serde::Serialize;
use std::sync::Arc;
use subtle::ConstantTimeEq;

fn same_endpoint(left: EndpointId, right: EndpointId) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

#[derive(Clone)]
pub struct NetworkSelection {
    origin: String,
    coordinator: EndpointId,
    peer: EndpointId,
    policy: Arc<RelayPolicy>,
    relay_only: bool,
    configuration: String,
    generation: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkUnavailable;
impl std::fmt::Display for NetworkUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native bus network unavailable or refused")
    }
}
impl std::error::Error for NetworkUnavailable {}
impl NetworkSelection {
    /// These are explicit local selections, not approved pins manufactured by
    /// matching strings. Only genuine current room records can open the gate.
    #[allow(clippy::too_many_arguments)] // Explicit selected origin, identity and generation fields.
    pub fn try_new(
        origin: String,
        coordinator: &str,
        peer: &str,
        relay_origin: &str,
        expected_relay_origin: &str,
        configuration: String,
        generation: u64,
        relay_only: bool,
    ) -> Result<Self, NetworkUnavailable> {
        let coordinator = coordinator.parse().map_err(|_| NetworkUnavailable)?;
        let peer = peer.parse().map_err(|_| NetworkUnavailable)?;
        let policy = Arc::new(
            RelayPolicy::from_local_manifest(Some(relay_origin), Some(expected_relay_origin))
                .map_err(|_| NetworkUnavailable)?,
        );
        RoomClient::new(&origin, coordinator, policy.clone()).map_err(|_| NetworkUnavailable)?;
        if origin.len() > 2048
            || configuration.is_empty()
            || configuration.len() > 128
            || !configuration
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
            || generation == 0
            || generation > 9_007_199_254_740_991
            || same_endpoint(coordinator, peer)
        {
            return Err(NetworkUnavailable);
        }
        Ok(Self {
            origin,
            coordinator,
            peer,
            policy,
            relay_only,
            configuration,
            generation,
        })
    }
    pub fn relay_only(&self) -> bool {
        self.relay_only
    }
    pub fn peer(&self) -> EndpointId {
        self.peer
    }
    pub fn policy(&self) -> &RelayPolicy {
        &self.policy
    }
    pub fn client(&self) -> Result<RoomClient, NetworkUnavailable> {
        RoomClient::new(&self.origin, self.coordinator, self.policy.clone())
            .map_err(|_| NetworkUnavailable)
    }
    pub fn pending_gate(
        &self,
        actual_local: EndpointId,
    ) -> Result<DaemonPeerGate, NetworkUnavailable> {
        let config = DaemonPairConfig::try_new(
            self.configuration.clone(),
            self.generation,
            actual_local,
            self.peer,
            self.coordinator,
            self.policy.clone(),
        )
        .map_err(|_| NetworkUnavailable)?;
        Ok(DaemonPeerGate::pending(config))
    }
    pub fn current_address(
        &self,
        gate: &DaemonPeerGate,
    ) -> Result<EndpointAddr, NetworkUnavailable> {
        let peer = gate.current_peer().map_err(|_| NetworkUnavailable)?;
        let mut address = peer
            .revalidate_for(self.peer)
            .map_err(|_| NetworkUnavailable)?;
        if self.relay_only {
            address
                .addrs
                .retain(|address| matches!(address, TransportAddr::Relay(_)));
        }
        if address.addrs.is_empty() {
            return Err(NetworkUnavailable);
        }
        Ok(address)
    }
    pub fn remote_path(
        &self,
        connection: &Connection,
        gate: &DaemonPeerGate,
    ) -> Result<PathObservation, NetworkUnavailable> {
        gate.check_peer(connection.remote_id())
            .map_err(|_| NetworkUnavailable)?;
        if !same_endpoint(connection.remote_id(), self.peer)
            || connection.alpn() != b"chinwag/bus/1"
        {
            return Err(NetworkUnavailable);
        }
        let observation = selected_path(connection)?;
        match &observation.address {
            TransportAddr::Relay(url) if Some(url) == self.policy.relay_url() => {}
            TransportAddr::Ip(_) if !self.relay_only => {}
            _ => return Err(NetworkUnavailable),
        }
        Ok(observation)
    }
}

/// Derived from the actual connection's selected path, never cached discovery.
#[derive(Debug, Clone, Serialize)]
pub struct PathObservation {
    pub peer_endpoint_id: String,
    pub selected_transport: &'static str,
    pub remote_address: String,
    #[serde(skip)]
    address: TransportAddr,
}
fn selected_path(connection: &Connection) -> Result<PathObservation, NetworkUnavailable> {
    let paths = connection.paths();
    let mut selected = paths.iter().filter(|path| path.is_selected());
    let path = selected.next().ok_or(NetworkUnavailable)?;
    if selected.next().is_some() {
        return Err(NetworkUnavailable);
    }
    let address = path.remote_addr().clone();
    let selected_transport = match &address {
        TransportAddr::Relay(_) => "relay",
        TransportAddr::Ip(_) => "direct",
        _ => return Err(NetworkUnavailable),
    };
    Ok(PathObservation {
        peer_endpoint_id: connection.remote_id().to_string(),
        selected_transport,
        remote_address: address.to_string(),
        address,
    })
}

/// Local publishers have their existing ephemeral transport identity and still
/// require the existing seat signature. They enter only over actual loopback.
/// This exception cannot authorize a remote Federation frame.
pub fn local_publisher_path(connection: &Connection) -> bool {
    selected_path(connection).is_ok_and(|path| {
        matches!(path.address,
        TransportAddr::Ip(socket) if socket.ip().is_loopback())
    })
}

#[derive(Clone)]
pub struct NativeBusHooks {
    selection: NetworkSelection,
    gate: DaemonPeerGate,
}
impl NativeBusHooks {
    pub fn new(selection: NetworkSelection, gate: DaemonPeerGate) -> Self {
        Self { selection, gate }
    }
}
impl std::fmt::Debug for NativeBusHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeBusHooks")
    }
}
impl EndpointHooks for NativeBusHooks {
    async fn before_connect<'a>(
        &'a self,
        remote: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        let route_allowed = remote.addrs.iter().all(|address| match address {
            TransportAddr::Relay(url) => Some(url) == self.selection.policy.relay_url(),
            TransportAddr::Ip(_) => !self.selection.relay_only,
            _ => false,
        });
        if alpn == b"chinwag/bus/1"
            && same_endpoint(remote.id, self.selection.peer)
            && !remote.addrs.is_empty()
            && route_allowed
            && self.gate.check_peer(remote.id).is_ok()
        {
            BeforeConnectOutcome::Accept
        } else {
            BeforeConnectOutcome::Reject
        }
    }
    async fn after_handshake<'a>(&'a self, connection: &'a Connection) -> AfterHandshakeOutcome {
        if connection.alpn() == b"chinwag/bus/1"
            && (local_publisher_path(connection)
                || self.selection.remote_path(connection, &self.gate).is_ok())
        {
            AfterHandshakeOutcome::Accept
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: 0x403u32.into(),
                reason: b"native_bus_peer_unavailable".to_vec(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn public_id() -> String {
        iroh::SecretKey::generate().public().to_string()
    }
    #[test]
    fn selected_data_cannot_mint_peer_admission_or_accept_public_relay_fallback() {
        let coordinator = public_id();
        let peer = public_id();
        let local = public_id();
        let selection = NetworkSelection::try_new(
            "https://coordinator.invalid".into(),
            &coordinator,
            &peer,
            "https://owned-relay.invalid",
            "https://owned-relay.invalid",
            "fixture-selection".into(),
            1,
            true,
        )
        .unwrap();
        let gate = selection.pending_gate(local.parse().unwrap()).unwrap();
        assert!(gate.current_peer().is_err());
        assert!(selection.current_address(&gate).is_err());
        assert!(selection.pending_gate(peer.parse().unwrap()).is_err());
        for (origin, expected) in [
            ("https://relay.iroh.network", "https://relay.iroh.network"),
            ("https://owned-relay.invalid", "https://other.invalid"),
            ("wss://owned-relay.invalid", "wss://owned-relay.invalid"),
        ] {
            assert!(
                NetworkSelection::try_new(
                    "https://coordinator.invalid".into(),
                    &coordinator,
                    &peer,
                    origin,
                    expected,
                    "fixture-selection".into(),
                    1,
                    true
                )
                .is_err()
            );
        }
    }
}
