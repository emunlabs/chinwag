use std::time::Duration;

use bao_tree::io::BaoContentItem;
use futures_util::StreamExt;
use iroh::{
    Endpoint, EndpointId,
    endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_blobs::{
    BlobsProtocol, Hash,
    get::request::{GetBlobItem, get_blob},
    store::mem::MemStore,
};
use iroh_gossip::{Gossip, TopicId, api::GossipTopic};

pub const MAX_BLOB_BYTES: usize = 32 * 1024 * 1024;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

/// Enforce the two-actor boundary for library-initiated outgoing dials too.
/// A gossip membership hint cannot add another transport identity.
#[derive(Debug)]
pub(crate) struct PinnedEndpoint(pub EndpointId);

impl EndpointHooks for PinnedEndpoint {
    async fn before_connect<'a>(
        &'a self,
        remote: &'a iroh::EndpointAddr,
        _alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if remote.id == self.0 {
            BeforeConnectOutcome::Accept
        } else {
            BeforeConnectOutcome::Reject
        }
    }

    async fn after_handshake<'a>(&'a self, connection: &'a Connection) -> AfterHandshakeOutcome {
        if connection.remote_id() == self.0 {
            tracing::info!(
                quic_peer = %connection.remote_id(),
                quic_alpn = %String::from_utf8_lossy(connection.alpn()),
                "pinned_QUIC_handshake"
            );
            AfterHandshakeOutcome::Accept
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: 0x401u32.into(),
                reason: b"peer_not_pinned".to_vec(),
            }
        }
    }
}

struct TransferConnection(Connection);

impl Drop for TransferConnection {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"transfer_finished");
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("the peer must be the other pinned identity")]
    Peer,
    #[error("blob size exceeds the bounded transfer scope")]
    Size,
    #[error("peer transport failed")]
    Network,
    #[error("blob transfer did not match its declared hash and size")]
    Integrity,
}

/// Only the other configured Stage-0 identity reaches a protocol handler.
/// Address discovery and knowledge of an ALPN grant no membership.
#[derive(Debug)]
struct PinnedHandler<H> {
    peer: EndpointId,
    inner: H,
}

impl<H: ProtocolHandler> ProtocolHandler for PinnedHandler<H> {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        if connection.remote_id() != self.peer {
            connection.close(0x401u32.into(), b"peer_not_pinned");
            return Err(AcceptError::from_err(TransportError::Peer));
        }
        self.inner.accept(connection).await
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

/// Bounded cached IP metadata only. No identity, freshness, or transport authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedIps {
    addrs: Vec<std::net::SocketAddr>,
    truncated: bool,
}

impl BoundedIps {
    pub fn from_ips(ips: impl IntoIterator<Item = std::net::SocketAddr>) -> Self {
        let mut ips = ips.into_iter();
        let mut addrs = Vec::with_capacity(4);
        while addrs.len() < 4 {
            match ips.next() {
                Some(addr) => addrs.push(addr),
                None => {
                    return Self {
                        addrs,
                        truncated: false,
                    };
                }
            }
        }
        Self {
            addrs,
            truncated: ips.next().is_some(),
        }
    }

    pub fn addrs(&self) -> &[std::net::SocketAddr] {
        &self.addrs
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Native QUIC protocols. These transport primitives do not confer a task
/// lease, verify a source review, or authorize sealing a commit.
pub struct DataPlane {
    endpoint: Endpoint,
    peer: EndpointId,
    router: Router,
    gossip: Gossip,
    blobs: MemStore,
}

impl DataPlane {
    /// The fixed other transport identity, not a discovery or write grant.
    pub fn pinned_peer_id(&self) -> EndpointId {
        self.peer
    }

    pub fn endpoint_addr(&self) -> iroh::EndpointAddr {
        self.endpoint.addr()
    }

    /// Snapshot of cached transport-address metadata for the configured peer.
    /// This does not dial, resolve a new identity, or prove a QUIC handshake.
    pub async fn pinned_peer_path_info(&self) -> Option<iroh::endpoint::RemoteInfo> {
        self.endpoint.remote_info(self.peer).await
    }

    pub(crate) fn start(endpoint: Endpoint, peer: EndpointId) -> Result<Self, TransportError> {
        if peer == endpoint.id() {
            return Err(TransportError::Peer);
        }
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let blobs = MemStore::new();
        let router = Router::builder(endpoint.clone())
            .accept(
                iroh_gossip::ALPN,
                PinnedHandler {
                    peer,
                    inner: gossip.clone(),
                },
            )
            .accept(
                iroh_blobs::ALPN,
                PinnedHandler {
                    peer,
                    inner: BlobsProtocol::new(&blobs, None),
                },
            )
            .spawn();
        Ok(Self {
            endpoint,
            peer,
            router,
            gossip,
            blobs,
        })
    }

    /// The topic carries application envelopes. Claim signatures and conflict
    /// resolution are enforced by the caller before a write is permitted.
    pub async fn join_topic(&self, topic: TopicId) -> Result<GossipTopic, TransportError> {
        self.gossip
            .subscribe(topic, vec![self.peer])
            .await
            .map_err(|_| TransportError::Network)
    }

    /// Retain the returned temporary tag until the peer finishes receiving.
    pub async fn publish_blob(
        &self,
        bytes: Vec<u8>,
    ) -> Result<iroh_blobs::api::TempTag, TransportError> {
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(TransportError::Size);
        }
        self.blobs
            .add_bytes(bytes)
            .temp_tag()
            .await
            .map_err(|_| TransportError::Network)
    }

    /// Fetch only from the pinned peer. The caller obtains hash and size from
    /// an authenticated offer; neither value is accepted from a blob header.
    pub async fn fetch_blob(
        &self,
        hash: Hash,
        declared_size: u64,
    ) -> Result<Vec<u8>, TransportError> {
        if declared_size > MAX_BLOB_BYTES as u64 {
            return Err(TransportError::Size);
        }
        let connection = tokio::time::timeout(
            TRANSFER_TIMEOUT,
            self.endpoint.connect(self.peer, iroh_blobs::ALPN),
        )
        .await
        .map_err(|_| TransportError::Network)?
        .map_err(|_| TransportError::Network)?;
        let connection = TransferConnection(connection);
        let result = tokio::time::timeout(TRANSFER_TIMEOUT, async {
            let mut progress = get_blob(connection.0.clone(), hash);
            let mut bytes = Vec::new();
            let mut done = false;
            while let Some(item) = progress.next().await {
                match item {
                    GetBlobItem::Item(BaoContentItem::Leaf(leaf)) => {
                        if leaf.offset != bytes.len() as u64
                            || leaf.data.len() as u64
                                > declared_size.saturating_sub(bytes.len() as u64)
                        {
                            return Err(TransportError::Integrity);
                        }
                        bytes.extend_from_slice(&leaf.data);
                    }
                    GetBlobItem::Item(BaoContentItem::Parent(_)) => {}
                    GetBlobItem::Done(_) => {
                        done = true;
                        break;
                    }
                    GetBlobItem::Error(_) => return Err(TransportError::Integrity),
                }
            }
            if !done || bytes.len() as u64 != declared_size || Hash::new(&bytes) != hash {
                return Err(TransportError::Integrity);
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| TransportError::Network)
        .and_then(|result| result);
        // The guard closes this transfer's connection on success, error,
        // timeout, and caller cancellation.
        result
    }

    pub async fn shutdown(self) -> Result<(), TransportError> {
        let result = self
            .router
            .shutdown()
            .await
            .map_err(|_| TransportError::Network);
        self.endpoint.close().await;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{base_builder, identity::Identity};
    use iroh::{EndpointAddr, address_lookup::memory::MemoryLookup};
    use iroh_gossip::api::Event;

    async fn endpoint(seed: u8, peer_seed: Option<u8>) -> Endpoint {
        let mut builder = base_builder(
            &Identity::test_identity([seed; 32]),
            vec![],
            &crate::relay_policy::RelayPolicy::Disabled,
        )
        .unwrap();
        if let Some(peer) = peer_seed {
            builder = builder.hooks(PinnedEndpoint(
                Identity::test_identity([peer; 32]).endpoint_id(),
            ));
        }
        builder
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    fn remember(endpoint: &Endpoint, peer: EndpointAddr) {
        let book = MemoryLookup::new();
        book.add_endpoint_info(peer);
        endpoint.address_lookup().unwrap().add(book);
    }

    #[tokio::test]
    async fn pinned_peers_gossip_and_transfer_verified_bounded_blobs() {
        // Isolated QUIC fixture: explicit addresses, no mDNS, DHT, relay or
        // hosted room. It tests data-plane behavior, not three-layer discovery.
        let a = endpoint(0x11, Some(0x22)).await;
        let b = endpoint(0x22, Some(0x11)).await;
        remember(&a, b.addr());
        remember(&b, a.addr());
        let a_id = a.id();
        let b_id = b.id();
        let one = DataPlane::start(a, b_id).unwrap();
        let two = DataPlane::start(b, a_id).unwrap();
        let topic = TopicId::from([0x55; 32]);
        let (sender, mut first) = one.join_topic(topic).await.unwrap().split();
        let (other_sender, mut second) = two.join_topic(topic).await.unwrap().split();
        tokio::time::timeout(Duration::from_secs(5), first.joined())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), second.joined())
            .await
            .unwrap()
            .unwrap();
        // Synthetic envelope bytes only, not the seed codec or a live room.
        // Keep the real tag across the pinned receive and actual blob fetch.
        assert_eq!(one.pinned_peer_id(), b_id);
        assert_eq!(two.pinned_peer_id(), a_id);
        let bytes = (0..131_072).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let tag = one.publish_blob(bytes.clone()).await.unwrap();
        assert_eq!(
            one.blobs
                .tags()
                .list_temp_tags()
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await
                .len(),
            1
        );
        sender
            .broadcast(b"bundle-offer-transport-fixture".to_vec().into())
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(Ok(Event::Received(message))) = second.next().await {
                    assert_eq!(message.delivered_from, a_id);
                    break message.content;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(&received[..], b"bundle-offer-transport-fixture");
        assert_eq!(
            one.blobs
                .tags()
                .list_temp_tags()
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await
                .len(),
            1
        );
        let received = two
            .fetch_blob(tag.hash(), bytes.len() as u64)
            .await
            .unwrap();
        assert_eq!(received, bytes);
        let paths = one.pinned_peer_path_info().await.unwrap();
        assert_eq!(paths.id(), b_id);
        assert!(paths.addrs().next().is_some());
        assert!(matches!(
            two.fetch_blob(tag.hash(), bytes.len() as u64 - 1).await,
            Err(TransportError::Integrity)
        ));
        assert!(matches!(
            two.fetch_blob(tag.hash(), MAX_BLOB_BYTES as u64 + 1).await,
            Err(TransportError::Size)
        ));
        other_sender
            .broadcast(b"byte-receipt-transport-fixture".to_vec().into())
            .await
            .unwrap();
        let ack = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(Ok(Event::Received(message))) = first.next().await {
                    assert_eq!(message.delivered_from, b_id);
                    break message.content;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(&ack[..], b"byte-receipt-transport-fixture");
        assert_eq!(
            one.blobs
                .tags()
                .list_temp_tags()
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await
                .len(),
            1
        );
        drop(tag);
        assert!(
            one.blobs
                .tags()
                .list_temp_tags()
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await
                .is_empty()
        );
        println!(
            "loopback_tag_receipt pinned_received=true real_fetch=true tag_held=1 tag_after=0 no_codec_or_live_room=true"
        );
        let stranger = endpoint(0x33, None).await;
        assert!(matches!(
            one.endpoint
                .connect(stranger.addr(), iroh_blobs::ALPN)
                .await,
            Err(iroh::endpoint::ConnectError::Connect {
                source: iroh::endpoint::ConnectWithOptsError::LocallyRejected { .. },
                ..
            })
        ));
        if let Ok(connection) = stranger
            .connect(one.endpoint.addr(), iroh_blobs::ALPN)
            .await
        {
            let error = tokio::time::timeout(Duration::from_secs(3), connection.closed())
                .await
                .unwrap();
            assert!(error.to_string().contains("peer_not_pinned"));
        }
        stranger.close().await;
        let own_one = one.endpoint.clone();
        let own_two = two.endpoint.clone();
        one.shutdown().await.unwrap();
        two.shutdown().await.unwrap();
        assert!(own_one.is_closed() && own_two.is_closed());
        println!(
            "driver_cleanup normal_loopback_shutdown_closed_both=true router_error_branch_not_forced=true"
        );
    }
}
