use crate::{sender::MdnsMsg, Peer, TxtData};
use acto::{ActoCell, ActoRef, ActoRuntime};
use hickory_proto::{
    op::Message,
    rr::{DNSClass, Name, RData, RecordType},
};
use std::{collections::BTreeMap, net::IpAddr, str::FromStr, sync::Arc, time::Instant};
use thiserror::Error;
use tokio::net::UdpSocket;

/// Errors that can occur when receiving on the socket.
#[derive(Debug, Error)]
#[error("Could not receive from the socket")]
pub struct ReceiverError {
    #[from]
    source: std::io::Error,
}

pub async fn receiver(
    _ctx: ActoCell<(), impl ActoRuntime>,
    service_name: Name,
    socket: Arc<UdpSocket>,
    target: ActoRef<MdnsMsg>,
) -> Result<(), ReceiverError> {
    let mut buf = [0; 1472];
    loop {
        let (len, addr) = socket
            .recv_from(&mut buf)
            .await
            .map_err(ReceiverError::from)?;
        let msg = &buf[..len];
        tracing::trace!("received {} bytes from {}", len, addr);
        if let Some(msg) = handle_msg(msg, &service_name, addr.ip()) {
            let peers = match &msg {
                MdnsMsg::Response(peers) => Some(peers.len()),
                _ => None,
            };
            let accepted = target.send(msg);
            tracing::debug!(target: "chinwag_mdns_diag", event="receiver_forward", peers=?peers, accepted);
        }
    }
}

fn handle_msg(buf: &[u8], service_name: &Name, addr: IpAddr) -> Option<MdnsMsg> {
    let packet = match Message::from_vec(buf) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!("error parsing mDNS packet: {}", e);
            return None;
        }
    };
    for question in &packet.queries {
        if question.query_class() != DNSClass::IN {
            tracing::trace!(
                "received mDNS query with wrong class {}",
                question.query_class()
            );
            continue;
        }
        if question.query_type() != RecordType::PTR {
            tracing::trace!(
                "received mDNS query with wrong type {}",
                question.query_type()
            );
            continue;
        }
        if question.name() != service_name {
            tracing::trace!("received mDNS query for wrong service {}", question.name());
            continue;
        }
        tracing::debug!("received mDNS query for {}", question.name());
        return Some(match addr {
            IpAddr::V4(_) => MdnsMsg::QueryV4,
            IpAddr::V6(_) => MdnsMsg::QueryV6,
        });
    }

    let local = Name::from_str("local.").unwrap();

    let mut peer_ports: BTreeMap<Name, Vec<(u16, String)>> = BTreeMap::new();
    let mut peer_txt: BTreeMap<String, TxtData> = BTreeMap::new();
    for response in &packet.answers {
        if response.dns_class != DNSClass::IN {
            tracing::trace!(
                "received mDNS response with wrong class {:?}",
                response.dns_class
            );
            continue;
        }
        let name = &response.name;
        if name.base_name() != *service_name {
            tracing::trace!("received mDNS response with wrong service {}", name);
            continue;
        }
        tracing::debug!("received mDNS response for {}", name);
        let Some(peer_id_bytes) = name.iter().next() else {
            continue;
        };
        let Ok(peer_id) = std::str::from_utf8(peer_id_bytes) else {
            tracing::debug!(
                "received mDNS response with invalid peer ID {:?}",
                peer_id_bytes
            );
            continue;
        };
        match &response.data {
            RData::SRV(srv) => {
                peer_ports
                    .entry(srv.target.clone())
                    .or_default()
                    .push((srv.port, peer_id.to_string()));
            }
            RData::TXT(txt) => {
                for s in txt.txt_data.iter() {
                    let Ok(s) = std::str::from_utf8(s) else {
                        continue;
                    };
                    if s.is_empty() {
                        continue;
                    }
                    let (key, value) = match s.split_once('=') {
                        Some((key, value)) => (key, Some(value)),
                        None => (s, None),
                    };
                    let map = peer_txt.entry(peer_id.to_string()).or_default();
                    if !map.contains_key(key) {
                        map.insert(key.to_string(), value.map(ToString::to_string));
                    }
                }
            }
            _ => {
                tracing::trace!("received mDNS response with wrong data {:?}", response.data);
            }
        }
    }

    let mut peer_addrs: BTreeMap<String, Vec<(IpAddr, u16)>> = BTreeMap::new();
    for additional in &packet.additionals {
        if additional.dns_class != DNSClass::IN {
            tracing::trace!(
                "received mDNS additional with wrong class {:?}",
                additional.dns_class
            );
            continue;
        }
        let name = &additional.name;
        if name.base_name() != local {
            tracing::trace!("received mDNS additional for wrong service {}", name);
            continue;
        }
        tracing::trace!("received mDNS additional for {}", name);
        let ip: IpAddr = match &additional.data {
            RData::A(a) => a.0.into(),
            RData::AAAA(a) => a.0.into(),
            _ => {
                tracing::debug!(
                    "received mDNS additional with wrong data {:?}",
                    additional.data
                );
                continue;
            }
        };
        for (port, peer_id) in peer_ports.get(name).map(|x| &**x).unwrap_or(&[]) {
            peer_addrs
                .entry(peer_id.clone())
                .or_default()
                .push((ip, *port));
        }
    }
    let mut ret = BTreeMap::new();
    for (peer_id, mut addrs) in peer_addrs {
        addrs.sort_unstable();
        addrs.dedup();
        let txt = peer_txt.remove(&peer_id).unwrap_or_default();
        let last_seen = Instant::now();
        let peer = Peer {
            addrs,
            last_seen,
            txt,
        };
        ret.insert(peer_id, peer);
    }
    (!ret.is_empty()).then_some(MdnsMsg::Response(ret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{MessageType, OpCode, Query},
        rr::{rdata, Record},
    };

    #[test]
    fn unrelated_mdns_traffic_does_not_fill_the_actor_mailbox() {
        let service = Name::from_str("_chinwag-genesis-v1._udp.local.").unwrap();
        let mut packet = Message::new(0, MessageType::Query, OpCode::Query);
        let mut question = Query::new();
        question.set_name(Name::from_str("_unrelated._tcp.local.").unwrap());
        question.set_query_type(RecordType::PTR);
        question.set_query_class(DNSClass::IN);
        packet.add_query(question);
        assert!(handle_msg(
            &packet.to_vec().unwrap(),
            &service,
            "192.168.1.2".parse().unwrap()
        )
        .is_none());
        assert!(handle_msg(&[0xff], &service, "192.168.1.2".parse().unwrap()).is_none());
    }

    #[test]
    fn matching_queries_still_trigger_each_address_family() {
        let service = Name::from_str("_chinwag-genesis-v1._udp.local.").unwrap();
        let mut packet = Message::new(0, MessageType::Query, OpCode::Query);
        let mut question = Query::new();
        question.set_name(service.clone());
        question.set_query_type(RecordType::PTR);
        question.set_query_class(DNSClass::IN);
        packet.add_query(question);
        let bytes = packet.to_vec().unwrap();
        assert!(matches!(
            handle_msg(&bytes, &service, "192.168.1.2".parse().unwrap()),
            Some(MdnsMsg::QueryV4)
        ));
        assert!(matches!(
            handle_msg(&bytes, &service, "fe80::1".parse().unwrap()),
            Some(MdnsMsg::QueryV6)
        ));
    }

    #[test]
    fn matching_peer_announcement_preserves_address_and_port() {
        let service = Name::from_str("_chinwag-genesis-v1._udp.local.").unwrap();
        let label = "5758pkdebhdxduq5kgu38xw4y6opyeudt13f7xuedzkngkrgxrao";
        let instance = Name::from_str(label)
            .unwrap()
            .append_domain(&service)
            .unwrap();
        let target = Name::from_str(&format!("{label}-45001.local.")).unwrap();
        let mut packet = Message::new(0, MessageType::Response, OpCode::Query);
        packet.add_answer(Record::from_rdata(
            instance,
            120,
            RData::SRV(rdata::SRV::new(0, 0, 45001, target.clone())),
        ));
        packet.add_additional(Record::from_rdata(
            target,
            120,
            RData::A(rdata::A::from(
                "192.168.1.2".parse::<std::net::Ipv4Addr>().unwrap(),
            )),
        ));
        let Some(MdnsMsg::Response(peers)) = handle_msg(
            &packet.to_vec().unwrap(),
            &service,
            "192.168.1.2".parse().unwrap(),
        ) else {
            panic!("matching peer was lost");
        };
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[label].addrs(),
            &[("192.168.1.2".parse::<IpAddr>().unwrap(), 45001)]
        );
    }
}
