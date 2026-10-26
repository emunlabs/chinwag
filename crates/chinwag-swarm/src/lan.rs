//! LAN discovery stays on explicitly selected local interfaces, even when a VPN
//! owns the default multicast route. Discovered addresses do not authorize peers.
use std::{
    collections::BTreeMap,
    fmt, io,
    net::{IpAddr, Ipv4Addr},
};

use futures_util::{StreamExt, stream::BoxStream};
use iroh::{
    Endpoint, EndpointId,
    address_lookup::{
        AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData, EndpointInfo,
        Error, Item,
    },
};
use swarm_discovery::{Discoverer, DropGuard, IpClass};
use tokio::sync::watch;

const NAME: &str = "chinwag-lan";

/// Local IPv4 interface addresses, never the remote peer's address.
#[derive(Clone, Debug)]
pub struct LanInterfaces(Vec<Ipv4Addr>);

impl LanInterfaces {
    pub fn new(mut addresses: Vec<Ipv4Addr>) -> Result<Self, io::Error> {
        if addresses.is_empty()
            || addresses.len() > 8
            || addresses.iter().any(|ip| {
                ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_loopback()
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid LAN interfaces",
            ));
        }
        addresses.sort_unstable();
        addresses.dedup();
        Ok(Self(addresses))
    }
}

#[derive(Debug)]
pub(crate) struct LanDiscovery {
    pub interfaces: LanInterfaces,
    pub peer: EndpointId,
}

impl AddressLookupBuilder for LanDiscovery {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        let (updates, receiver) = watch::channel(None);
        // DNS labels are limited to 63 bytes; the 64-character hex display
        // form of EndpointId does not fit. z-base-32 is 52 DNS-safe bytes.
        let expected = self.peer.to_z32();
        let peer_id = self.peer;
        let discoverer =
            Discoverer::new_interactive("chinwag-genesis-v1".into(), endpoint.id().to_z32())
                .with_ip_class(IpClass::V4Only)
                .with_multicast_interfaces_v4(self.interfaces.0.clone())
                .with_callback(move |id, peer| {
                    tracing::debug!(
                        event = "lan_record",
                        matches_pinned = id == expected,
                        label_bytes = id.len()
                    );
                    if id != expected {
                        return;
                    }
                    let addresses = peer
                        .addrs()
                        .iter()
                        .filter_map(|(ip, port)| {
                            let std::net::IpAddr::V4(ip) = ip else {
                                return None;
                            };
                            (!ip.is_unspecified()
                                && !ip.is_multicast()
                                && !ip.is_broadcast()
                                && !ip.is_loopback()
                                && *port != 0)
                                .then_some(iroh::TransportAddr::Ip((*ip, *port).into()))
                        })
                        .take(8)
                        .collect::<Vec<_>>();
                    let info = (!peer.is_expiry() && !addresses.is_empty()).then(|| {
                        EndpointInfo::from_parts(peer_id, EndpointData::from_iter(addresses))
                    });
                    tracing::debug!(
                        event = "peer_update",
                        address_count = info
                            .as_ref()
                            .map_or(0, |value| value.data.ip_addrs().count()),
                        expired = peer.is_expiry()
                    );
                    updates.send_replace(info);
                })
                .spawn(&tokio::runtime::Handle::current())
                .map_err(|err| AddressLookupBuilderError::from_err(NAME, err))?;
        Ok(LanLookup {
            discoverer,
            receiver,
            peer: self.peer,
            interfaces: self.interfaces,
        })
    }
}

struct LanLookup {
    discoverer: DropGuard,
    receiver: watch::Receiver<Option<EndpointInfo>>,
    peer: EndpointId,
    interfaces: LanInterfaces,
}

impl fmt::Debug for LanLookup {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("LanLookup")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl AddressLookup for LanLookup {
    fn publish(&self, data: &EndpointData) {
        let ports = selected_ports(&self.interfaces, data);
        tracing::debug!(event = "publish", port_count = ports.len());
        // EndpointData is the authoritative current set. An empty intersection
        // withdraws a vanished LAN interface instead of advertising stale IPs.
        self.discoverer.remove_all();
        for (port, addresses) in ports {
            self.discoverer.add(port, addresses);
        }
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<'static, Result<Item, Error>>> {
        resolve_peer(self.peer, self.receiver.clone(), endpoint_id)
    }
}

fn selected_ports(interfaces: &LanInterfaces, data: &EndpointData) -> BTreeMap<u16, Vec<IpAddr>> {
    let mut ports: BTreeMap<u16, Vec<IpAddr>> = BTreeMap::new();
    for address in data.ip_addrs() {
        if let IpAddr::V4(ip) = address.ip()
            && interfaces.0.contains(&ip)
        {
            ports.entry(address.port()).or_default().push(ip.into());
        }
    }
    ports
}

fn resolve_peer(
    pinned: EndpointId,
    receiver: watch::Receiver<Option<EndpointInfo>>,
    requested: EndpointId,
) -> Option<BoxStream<'static, Result<Item, Error>>> {
    if requested != pinned {
        return None;
    }
    Some(
        futures_util::stream::unfold(
            (receiver, true),
            move |(mut receiver, initial)| async move {
                let has_current = receiver.borrow().is_some();
                if (!initial || !has_current) && receiver.changed().await.is_err() {
                    return None;
                }
                let info = receiver
                    .borrow_and_update()
                    .clone()
                    .unwrap_or_else(|| EndpointInfo::from_parts(pinned, EndpointData::default()));
                tracing::debug!(
                    event = "resolved",
                    address_count = info.data.ip_addrs().count()
                );
                Some((Ok(Item::new(info, NAME, None)), (receiver, false)))
            },
        )
        .boxed(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn pending_lookup_waits_for_the_pinned_peer_and_refuses_other_ids() {
        let peer = iroh::SecretKey::from_bytes(&[0x22; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[0x33; 32]).public();
        let (updates, receiver) = watch::channel(None);
        assert!(resolve_peer(peer, receiver.clone(), other).is_none());
        let mut stream = resolve_peer(peer, receiver, peer).unwrap();
        let info = EndpointInfo::from_parts(
            peer,
            EndpointData::from_iter([iroh::TransportAddr::Ip(
                "192.168.1.161:45001".parse().unwrap(),
            )]),
        );
        let expected = info.clone();
        let received = async { stream.next().await.unwrap().unwrap() };
        let publish = async {
            tokio::task::yield_now().await;
            updates.send_replace(Some(info));
        };
        let (item, ()) = tokio::join!(received, publish);
        assert_eq!(item.endpoint_info(), &expected);
        assert_eq!(item.provenance(), NAME);
        // A replacement and expiry arrive on the same stream; it must not end
        // after its first answer or keep the previous address snapshot.
        updates.send_replace(None);
        let expired = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(expired.endpoint_id(), peer);
        assert_eq!(expired.endpoint_info().data.ip_addrs().count(), 0);
        let replacement = EndpointInfo::from_parts(
            peer,
            EndpointData::from_iter([iroh::TransportAddr::Ip(
                "192.168.1.161:45002".parse().unwrap(),
            )]),
        );
        updates.send_replace(Some(replacement.clone()));
        let received = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(received.endpoint_info(), &replacement);
        drop(updates);
        assert!(stream.next().await.is_none());
    }

    #[test]
    fn announcements_group_selected_interfaces_and_withdraw_missing_addresses() {
        let interfaces = LanInterfaces::new(vec![
            "192.168.1.150".parse().unwrap(),
            "192.168.2.150".parse().unwrap(),
        ])
        .unwrap();
        let data = EndpointData::from_iter(
            [
                "192.168.1.150:45001",
                "192.168.2.150:45001",
                "100.108.108.25:45001",
            ]
            .map(|s| iroh::TransportAddr::Ip(s.parse().unwrap())),
        );
        let selected = selected_ports(&interfaces, &data);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[&45001].len(), 2);
        assert!(selected_ports(&interfaces, &EndpointData::default()).is_empty());
    }

    #[test]
    fn selected_interfaces_must_be_usable_and_bounded() {
        for addresses in [
            vec![],
            vec![Ipv4Addr::UNSPECIFIED],
            vec![Ipv4Addr::BROADCAST],
            vec![Ipv4Addr::LOCALHOST],
            vec![Ipv4Addr::new(224, 0, 0, 251)],
            vec![Ipv4Addr::new(192, 168, 1, 150); 9],
        ] {
            assert!(LanInterfaces::new(addresses).is_err());
        }
        assert!(LanInterfaces::new(vec![Ipv4Addr::new(192, 168, 1, 150)]).is_ok());
    }
}
