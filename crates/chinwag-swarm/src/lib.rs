//! Sovereign Stage-0 identity and endpoint configuration.
//!
//! iroh 1.4 renamed `clear_discovery` to `clear_address_lookup` and moved
//! mDNS/Mainline into separate crates. No n0 preset is used here.

pub mod attempt_journal;
pub mod identity;
pub mod lan;
pub mod relay_policy;
pub mod review;
pub mod room;
pub mod room_wire;
pub mod transport;

use identity::Identity;
use iroh::{
    Endpoint,
    address_lookup::{AddrFilter, memory::MemoryLookup},
    endpoint::presets,
};
use iroh_mainline_address_lookup::DhtAddressLookup;
use lan::{LanDiscovery, LanInterfaces};
use relay_policy::{PolicyError, RelayPolicy};

/// Only Mainline DHT bootstrap nodes. No HTTP Pkarr or n0 bootstrap service.
pub const MAINLINE_BOOTSTRAP: [&str; 3] = [
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "dht.libtorrent.org:25401",
];

/// Isolated LAN checks must not start a public DHT. This is a diagnostic scope,
/// not proof that the full three-layer discovery gate has passed.
#[derive(Clone, Copy, Debug)]
pub enum DiscoveryScope {
    LanAndRoom,
    RoomOnly,
    WithMainline,
}

/// The caller supplies a peer book containing verified room records.
/// Discovery supplies addresses, never permission to act as a peer. DHT
/// records contain addressing metadata only, never application content.
pub async fn bind_sovereign_endpoint(
    identity: &Identity,
    room_peer_book: MemoryLookup,
    other_peer: iroh::EndpointId,
    lan_interfaces: LanInterfaces,
    scope: DiscoveryScope,
    alpns: Vec<Vec<u8>>,
    policy: &RelayPolicy,
) -> Result<Endpoint, EndpointStartError> {
    let builder = sovereign_builder(
        identity,
        room_peer_book,
        other_peer,
        lan_interfaces,
        scope,
        alpns,
        policy,
    )
    .map_err(EndpointStartError::Policy)?;
    builder
        .bind()
        .await
        .map_err(BindError)
        .map_err(EndpointStartError::Bind)
}

fn sovereign_builder(
    identity: &Identity,
    room_peer_book: MemoryLookup,
    other_peer: iroh::EndpointId,
    lan_interfaces: LanInterfaces,
    scope: DiscoveryScope,
    alpns: Vec<Vec<u8>>,
    policy: &RelayPolicy,
) -> Result<iroh::endpoint::Builder, PolicyError> {
    let mut builder = base_builder(identity, alpns, policy)?
        .hooks(transport::PinnedEndpoint(other_peer))
        .address_lookup(room_peer_book);
    if !matches!(scope, DiscoveryScope::RoomOnly) {
        builder = builder.address_lookup(LanDiscovery {
            interfaces: lan_interfaces,
            peer: other_peer,
        });
    }
    if matches!(scope, DiscoveryScope::WithMainline) {
        let mut mainline = n0_mainline::Dht::builder();
        mainline.bootstrap(&MAINLINE_BOOTSTRAP);
        builder = builder.address_lookup(
            DhtAddressLookup::builder()
                .dht_builder(mainline)
                .addr_filter(AddrFilter::ip_only()),
        );
    }
    Ok(builder)
}

fn base_builder(
    identity: &Identity,
    alpns: Vec<Vec<u8>>,
    policy: &RelayPolicy,
) -> Result<iroh::endpoint::Builder, PolicyError> {
    let mode = policy.relay_mode()?;
    Ok(Endpoint::builder(presets::Minimal)
        .secret_key(identity.secret_key())
        .clear_address_lookup()
        .relay_mode(mode)
        .alpns(alpns))
}

#[derive(Debug, thiserror::Error)]
#[error("could not bind the sovereign endpoint")]
pub struct BindError(#[source] iroh::endpoint::BindError);

#[derive(Debug, thiserror::Error)]
pub enum EndpointStartError {
    #[error("the relay policy refused endpoint start")]
    Policy(#[source] PolicyError),
    #[error(transparent)]
    Bind(#[from] BindError),
}

pub async fn bind_sovereign_swarm(
    identity: &Identity,
    room_peer_book: MemoryLookup,
    other_peer: iroh::EndpointId,
    lan_interfaces: LanInterfaces,
    scope: DiscoveryScope,
    policy: &RelayPolicy,
) -> Result<transport::DataPlane, SwarmError> {
    if other_peer == identity.endpoint_id() {
        return Err(transport::TransportError::Peer.into());
    }
    let endpoint = bind_sovereign_endpoint(
        identity,
        room_peer_book,
        other_peer,
        lan_interfaces,
        scope,
        vec![iroh_gossip::ALPN.to_vec(), iroh_blobs::ALPN.to_vec()],
        policy,
    )
    .await?;
    Ok(transport::DataPlane::start(endpoint, other_peer)?)
}

#[derive(Debug, thiserror::Error)]
pub enum SwarmError {
    #[error(transparent)]
    Start(#[from] EndpointStartError),
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn disabled() -> RelayPolicy {
        RelayPolicy::from_local_manifest(None, None).unwrap()
    }

    #[tokio::test]
    async fn room_only_has_one_memory_lookup_no_lan_dht_or_relay() {
        let identity = Identity::test_identity([0x11; 32]);
        let peer = Identity::test_identity([0x22; 32]).endpoint_id();
        let endpoint = sovereign_builder(
            &identity,
            MemoryLookup::new(),
            peer,
            LanInterfaces::new(vec!["192.0.2.1".parse().unwrap()]).unwrap(),
            DiscoveryScope::RoomOnly,
            vec![b"chinwag-room-test/v1".to_vec()],
            &disabled(),
        )
        .unwrap()
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
        assert_eq!(endpoint.address_lookup().unwrap().len(), 1);
        let sockets = endpoint.bound_sockets();
        assert!(!sockets.is_empty());
        assert!(sockets.iter().all(|addr| addr.ip().is_loopback()));
        assert!(endpoint.addr().relay_urls().next().is_none());
        tokio::time::timeout(Duration::from_secs(3), endpoint.close())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn bound_endpoint_uses_the_git_ssh_public_key_without_any_lookup_or_relay() {
        let identity = Identity::test_identity([0x11; 32]);
        // This fixture tests the identity/disabled-relay base. It deliberately
        // does not start mDNS or a public DHT and is not three-layer acceptance.
        let endpoint = base_builder(
            &identity,
            vec![b"chinwag-identity-test/v1".to_vec()],
            &disabled(),
        )
        .unwrap()
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
        assert_eq!(endpoint.id().as_bytes(), &identity.ssh_public_bytes());
        assert_eq!(endpoint.address_lookup().unwrap().len(), 0);
        let sockets = endpoint.bound_sockets();
        assert!(!sockets.is_empty());
        assert!(sockets.iter().all(|addr| addr.ip().is_loopback()));
        assert!(endpoint.addr().relay_urls().next().is_none());
        tokio::time::timeout(Duration::from_secs(3), endpoint.close())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn room_only_uses_cloned_book_populated_after_gossip_spawn() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let first = Identity::test_identity([0x31; 32]);
            let second = Identity::test_identity([0x32; 32]);
            let first_book = MemoryLookup::new();
            let second_book = MemoryLookup::new();
            let interfaces = || LanInterfaces::new(vec!["192.0.2.1".parse().unwrap()]).unwrap();
            let policy = disabled();
            let make = |identity: &Identity, book: MemoryLookup, peer| {
                sovereign_builder(
                    identity,
                    book,
                    peer,
                    interfaces(),
                    DiscoveryScope::RoomOnly,
                    vec![],
                    &policy,
                )
                .unwrap()
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
                .unwrap()
            };
            let a = make(&first, first_book.clone(), second.endpoint_id())
                .bind()
                .await
                .unwrap();
            let b = make(&second, second_book.clone(), first.endpoint_id())
                .bind()
                .await
                .unwrap();
            let one = transport::DataPlane::start(a, second.endpoint_id()).unwrap();
            let two = transport::DataPlane::start(b, first.endpoint_id()).unwrap();
            // Match RoomSession's late set, after both endpoints and gossip actors exist.
            assert!(first_book.get_endpoint_info(second.endpoint_id()).is_none());
            assert!(second_book.get_endpoint_info(first.endpoint_id()).is_none());
            first_book.set_endpoint_info(two.endpoint_addr());
            second_book.set_endpoint_info(one.endpoint_addr());
            let topic = iroh_gossip::TopicId::from([0x63; 32]);
            let (_, mut rx_one) = one.join_topic(topic).await.unwrap().split();
            let (_, mut rx_two) = two.join_topic(topic).await.unwrap().split();
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::try_join!(rx_one.joined(), rx_two.joined()).unwrap();
            })
            .await
            .unwrap();
            let expected = b"late verified room book".to_vec();
            let tag = one.publish_blob(expected.clone()).await.unwrap();
            let received = two
                .fetch_blob(tag.hash(), expected.len() as u64)
                .await
                .unwrap();
            assert_eq!(received, expected);
            drop(tag);
            one.shutdown().await.unwrap();
            two.shutdown().await.unwrap();
        })
        .await
        .expect("late room-book loopback must complete within 15 seconds");
    }
}
