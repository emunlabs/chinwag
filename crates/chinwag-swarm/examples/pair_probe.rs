//! A synthetic cross-machine probe; no model, Git operation, or private data.
use std::{error::Error, io, path::Path, time::Duration};

use chinwag_swarm::{DiscoveryScope, bind_sovereign_swarm, identity::Identity, lan::LanInterfaces};
use futures_util::StreamExt;
use iroh::{EndpointAddr, EndpointId, address_lookup::memory::MemoryLookup};
use iroh_blobs::Hash;
use iroh_gossip::{TopicId, api::Event};

const SIZE: usize = 131_072;

fn fixture() -> Vec<u8> {
    (0..SIZE).map(|i| (i % 251) as u8).collect()
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let args = std::env::args().collect::<Vec<_>>();
    if !(args.len() == 5 || args.len() == 6) || !matches!(args[3].as_str(), "send" | "receive") {
        return Err(
            invalid("usage: pair_probe KEY_PATH PEER_PUBLIC_HEX send|receive RUN_ID [DIAGNOSTIC_PEER_SOCKET_ADDR]").into(),
        );
    }
    let identity = Identity::from_ssh_signing_file(Path::new(&args[1]))?;
    let peer: EndpointId = args[2].parse()?;
    if args[4].len() > 64
        || !args[4]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(invalid("invalid probe run id").into());
    }
    let peer_book = MemoryLookup::new();
    if let Some(socket) = args.get(5) {
        // An explicit diagnostic address isolates QUIC from discovery. It is
        // not evidence of a verified Durable Object advertisement.
        peer_book.add_endpoint_info(
            EndpointAddr::new(peer).with_ip_addr(socket.parse::<std::net::SocketAddr>()?),
        );
        println!("diagnostic_static_peer=true hosted_room_proof=false");
    }
    let lan = std::env::var("CHINWAG_LAN_IPV4")?
        .split(',')
        .map(str::parse)
        .collect::<Result<Vec<std::net::Ipv4Addr>, _>>()?;
    // This example isolates LAN discovery and QUIC. Public DHT and the hosted
    // room have separate acceptance gates and are not started by this probe.
    let plane = bind_sovereign_swarm(
        &identity,
        peer_book,
        peer,
        LanInterfaces::new(lan)?,
        DiscoveryScope::LanAndRoom,
        &chinwag_swarm::relay_policy::RelayPolicy::Disabled,
    )
    .await?;
    println!("public_dht_enabled=false hosted_room_proof=false");
    println!(
        "bound_public_identity={} pinned_peer={} relay_count={} initial_ip_count={}",
        identity.endpoint_id(),
        peer,
        plane.endpoint_addr().relay_urls().count(),
        plane.endpoint_addr().ip_addrs().count()
    );
    println!(
        "diagnostic_local_addresses={:?}",
        plane.endpoint_addr().ip_addrs().collect::<Vec<_>>()
    );
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        let topic = TopicId::from(*Hash::new(args[4].as_bytes()).as_bytes());
        let (sender, mut receiver) = plane.join_topic(topic).await?.split();
        receiver.joined().await?;
        println!("pinned_peer_joined=true");
        let expected = fixture();
        let hash = Hash::new(&expected);
        let offer = format!("chinwag-probe/v1:{}:{}:{hash}", args[4], expected.len());
        let ack = format!("chinwag-probe-ack/v1:{}:{hash}", args[4]);
        if args[3] == "send" {
            let _tag = plane.publish_blob(expected).await?;
            sender.broadcast(offer.into_bytes().into()).await?;
            while let Some(event) = receiver.next().await {
                if let Event::Received(message) = event? {
                    if message.content.as_ref() != ack.as_bytes() {
                        return Err(invalid("unexpected probe acknowledgement").into());
                    }
                    println!("peer_verified_blob=true bytes={SIZE} blake3={hash}");
                    return Ok::<(), Box<dyn Error>>(());
                }
            }
        } else {
            while let Some(event) = receiver.next().await {
                if let Event::Received(message) = event? {
                    if message.content.as_ref() != offer.as_bytes() {
                        return Err(invalid("unexpected probe offer").into());
                    }
                    let bytes = plane.fetch_blob(hash, SIZE as u64).await?;
                    if bytes != expected {
                        return Err(invalid("probe payload mismatch").into());
                    }
                    sender.broadcast(ack.into_bytes().into()).await?;
                    // Give the protocol actor time to flush the acknowledgement
                    // before explicitly closing its endpoint.
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    println!("received_verified_blob=true bytes={SIZE} blake3={hash}");
                    return Ok(());
                }
            }
        }
        Err(invalid("probe stream ended before completion").into())
    })
    .await;
    plane.shutdown().await?;
    result??;
    Ok(())
}
