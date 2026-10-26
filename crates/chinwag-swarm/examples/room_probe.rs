//! One bounded, two-actor Cloudflare room + direct QUIC diagnostic.
use chinwag_swarm::{
    DiscoveryScope, bind_sovereign_swarm,
    identity::Identity,
    lan::LanInterfaces,
    room::{RoomClient, RoomSession},
};
use futures_util::StreamExt;
use iroh::{EndpointId, address_lookup::memory::MemoryLookup};
use iroh_blobs::Hash;
use iroh_gossip::{TopicId, api::Event};
use std::{error::Error, io, net::Ipv4Addr, path::Path, time::Duration};

const SIZE: usize = 131_072;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn fixture() -> Vec<u8> {
    (0..SIZE).map(|i| (i % 251) as u8).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("chinwag_swarm=info"))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 7 || !matches!(args[5].as_str(), "send" | "receive") {
        return Err(invalid(
            "usage: room_probe KEY_PATH PEER_HEX COORDINATOR_HEX HTTPS_BASE send|receive RUN_ID",
        )
        .into());
    }
    if args[6].is_empty()
        || args[6].len() > 64
        || !args[6]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(invalid("invalid run id").into());
    }
    let identity = Identity::from_ssh_signing_file(Path::new(&args[1]))?;
    let peer: EndpointId = args[2].parse()?;
    let coordinator: EndpointId = args[3].parse()?;
    let local: Ipv4Addr = std::env::var("CHINWAG_LAN_IPV4")?.parse()?;
    let book = MemoryLookup::new();
    let client = RoomClient::new(
        &args[4],
        coordinator,
        std::sync::Arc::new(chinwag_swarm::relay_policy::RelayPolicy::Disabled),
    )?;
    let plane = tokio::time::timeout(
        Duration::from_secs(3),
        bind_sovereign_swarm(
            &identity,
            book.clone(),
            peer,
            LanInterfaces::new(vec![local])?,
            DiscoveryScope::RoomOnly,
            client.relay_policy(),
        ),
    )
    .await??;
    let mut session: Option<RoomSession> = None;
    let result=tokio::time::timeout(Duration::from_secs(23),async {
        if plane.endpoint_addr().relay_urls().next().is_some() { return Err(invalid("unexpected relay").into()); }
        let mut addresses=Vec::new();
        for _ in 0..100 {
            addresses=plane.endpoint_addr().ip_addrs().copied().filter(|a|a.ip()==std::net::IpAddr::V4(local)).collect();
            if !addresses.is_empty() { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if addresses.is_empty() { return Err(invalid("endpoint did not publish its selected local address").into()); }
        session=Some(client.open(&identity,peer,addresses,book.clone()).await?);
        let room=session.as_mut().ok_or_else(||invalid("missing owned room session"))?;
        room.receive_peer().await?;
        room.require_fresh_peer()?;
        println!("{}",serde_json::to_string(&serde_json::json!({"kind":"room_ready","room_only":true,"public_dht_enabled":false,"lan_discovery_enabled":false,"relay_count":0,"actor":identity.endpoint_id().to_string(),"peer":peer.to_string(),"proof":room.proof()?}))?);
        let topic=TopicId::from(*Hash::new(args[6].as_bytes()).as_bytes());
        let (sender,mut receiver)=plane.join_topic(topic).await?.split();
        receiver.joined().await?;
        println!("pinned_peer_joined=true");
        let expected=fixture();let hash=Hash::new(&expected);
        let offer=format!("chinwag-room-probe/v1:{}:{}:{hash}",args[6],SIZE);
        let ack=format!("chinwag-room-probe-ack/v1:{}:{hash}",args[6]);
        if args[5]=="send" {
            let _tag=plane.publish_blob(expected).await?;
            sender.broadcast(offer.into_bytes().into()).await?;
            while let Some(event)=receiver.next().await {
                if let Event::Received(message)=event? {
                    if message.content.as_ref()!=ack.as_bytes() {return Err(invalid("unexpected acknowledgement").into());}
                    room.require_fresh_peer()?;
                    println!("peer_verified_blob=true bytes={SIZE} blake3={hash}");
                    return Ok::<(),Box<dyn Error>>(());
                }
            }
        } else {
            while let Some(event)=receiver.next().await {
                if let Event::Received(message)=event? {
                    if message.content.as_ref()!=offer.as_bytes() {return Err(invalid("unexpected offer").into());}
                    let bytes=plane.fetch_blob(hash,SIZE as u64).await?;
                    if bytes!=expected {return Err(invalid("blob fixture mismatch").into());}
                    room.require_fresh_peer()?;
                    sender.broadcast(ack.into_bytes().into()).await?;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    println!("received_verified_blob=true bytes={SIZE} blake3={hash}");
                    return Ok(());
                }
            }
        }
        Err(invalid("gossip stream ended before completion").into())
    }).await;
    if let Some(mut room) = session {
        room.close().await;
    }
    tokio::time::timeout(Duration::from_secs(2), plane.shutdown()).await??;
    result??;
    Ok(())
}
