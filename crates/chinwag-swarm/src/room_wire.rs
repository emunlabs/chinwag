//! Strict genesis room records: auth, advertisement, and storage receipt.
//! No sockets. A receipt attests that a record was stored, not that QUIC worked.

use std::net::{IpAddr, SocketAddr};

use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::Identity;

const ROOM: &str = "genesis";
const AUTH_DOMAIN: &str = "chinwag-do-auth/v1";
const AD_DOMAIN: &str = "chinwag-room-peer/v1";
const RECEIPT_DOMAIN: &str = "chinwag-peer-stored/v1";
/// Inclusive ceiling for signed integers. JSON numbers above this are not exact.
const MAX_SAFE: u64 = 9_007_199_254_740_991;
const MAX_TTL: u64 = 120;
const MAX_ADDRESSES: usize = 8;
const MAX_ADDRESS_BYTES: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed room record")]
    Malformed,
    #[error("room actor pin refused")]
    Pin,
    #[error("room record expired")]
    Expired,
    #[error("room signature refused")]
    Signature,
    #[error("room receipt refused")]
    Receipt,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub room: String,
    pub actor_id: String,
    pub operation: String,
    pub session_id: String,
    pub nonce: String,
    pub expiry_unix: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advertisement {
    pub v: u8,
    pub room: String,
    pub actor_id: String,
    pub session_id: String,
    pub challenge_nonce: String,
    pub revision: u64,
    pub expiry_unix: u64,
    pub node_id: String,
    pub direct_addresses: Vec<String>,
    pub signature: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub v: u8,
    pub domain: String,
    pub actor_id: String,
    pub session_id: String,
    pub challenge_nonce: String,
    pub revision: u64,
    pub expiry_unix: u64,
    pub advertisement_sha256: String,
    pub coordinator_public_key: String,
    pub signature: String,
}

pub fn validate_challenge(
    ch: &Challenge,
    actor: EndpointId,
    operation: &str,
    session: Option<&str>,
    now: u64,
) -> Result<(), Error> {
    if !matches!(operation, "attach" | "advertise") || ch.operation != operation {
        return Err(Error::Malformed);
    }
    challenge_shape(ch, actor)?;
    if operation == "advertise" {
        match session {
            Some(bound) if bound == ch.session_id => {}
            _ => return Err(Error::Pin),
        }
    } else if let Some(bound) = session
        && bound != ch.session_id
    {
        return Err(Error::Pin);
    }
    check_fresh(ch.expiry_unix, now)
}

/// Format and pin only. The caller has already applied the freshness window.
pub fn auth_headers(
    identity: &Identity,
    ch: &Challenge,
) -> Result<Vec<(&'static str, String)>, Error> {
    challenge_shape(ch, identity.endpoint_id())?;
    let message = auth_preimage(ch);
    let signature = encode_hex(&identity.secret_key().sign(message.as_bytes()).to_bytes());
    Ok(vec![
        ("chinwag-room", ROOM.to_string()),
        ("chinwag-actor", ch.actor_id.clone()),
        ("chinwag-operation", ch.operation.clone()),
        ("chinwag-session", ch.session_id.clone()),
        ("chinwag-nonce", ch.nonce.clone()),
        ("chinwag-expiry", ch.expiry_unix.to_string()),
        ("chinwag-signature", signature),
    ])
}

pub fn sign_advertisement(
    identity: &Identity,
    ch: &Challenge,
    revision: u64,
    addresses: Vec<SocketAddr>,
    now: u64,
) -> Result<Advertisement, Error> {
    validate_challenge(
        ch,
        identity.endpoint_id(),
        "advertise",
        Some(ch.session_id.as_str()),
        now,
    )?;
    if revision == 0 || revision > MAX_SAFE {
        return Err(Error::Malformed);
    }
    if addresses.is_empty() || addresses.len() > MAX_ADDRESSES {
        return Err(Error::Malformed);
    }
    let actor = actor_hex(identity.endpoint_id());
    let mut direct_addresses = Vec::with_capacity(addresses.len());
    for addr in addresses {
        direct_addresses.push(canonical_text(addr)?);
    }
    let mut wire = Advertisement {
        v: 1,
        room: ROOM.to_string(),
        actor_id: actor.clone(),
        session_id: ch.session_id.clone(),
        challenge_nonce: ch.nonce.clone(),
        revision,
        expiry_unix: ch.expiry_unix,
        node_id: actor,
        direct_addresses,
        signature: String::new(),
    };
    let (message, _) = advertisement_preimage(&wire)?;
    wire.signature = encode_hex(&identity.secret_key().sign(message.as_bytes()).to_bytes());
    Ok(wire)
}

pub fn verify_advertisement(
    wire: &Advertisement,
    expected: EndpointId,
    now: u64,
) -> Result<Vec<SocketAddr>, Error> {
    if !is_id(&wire.actor_id) || !is_id(&wire.node_id) {
        return Err(Error::Malformed);
    }
    if wire.actor_id != actor_hex(expected) || wire.node_id != wire.actor_id {
        return Err(Error::Pin);
    }
    let (message, addresses) = advertisement_preimage(wire)?;
    verify_hex(expected, message.as_bytes(), &wire.signature)?;
    check_fresh(wire.expiry_unix, now)?;
    Ok(addresses)
}

/// Binds the receipt to this wire and the independent coordinator pin.
/// Historical receipts stay verifiable: this function does not read the clock.
pub fn verify_receipt(
    receipt: &Receipt,
    expected_coordinator: EndpointId,
    wire: &Advertisement,
) -> Result<(), Error> {
    let pinned = actor_hex(expected_coordinator);
    if receipt.coordinator_public_key != pinned {
        return Err(Error::Pin);
    }
    let hash = wire_hash(wire)?;
    if receipt.v != 1
        || receipt.domain != RECEIPT_DOMAIN
        || receipt.actor_id != wire.actor_id
        || receipt.session_id != wire.session_id
        || receipt.challenge_nonce != wire.challenge_nonce
        || receipt.revision != wire.revision
        || receipt.expiry_unix != wire.expiry_unix
        || receipt.advertisement_sha256 != hash
    {
        return Err(Error::Receipt);
    }
    let message = receipt_preimage(receipt)?;
    verify_hex(expected_coordinator, message.as_bytes(), &receipt.signature)
}

fn challenge_shape(ch: &Challenge, actor: EndpointId) -> Result<(), Error> {
    if ch.room != ROOM || !matches!(ch.operation.as_str(), "attach" | "advertise") {
        return Err(Error::Malformed);
    }
    if !is_id(&ch.actor_id) || !is_id(&ch.session_id) || !is_id(&ch.nonce) {
        return Err(Error::Malformed);
    }
    if ch.expiry_unix == 0 || ch.expiry_unix > MAX_SAFE {
        return Err(Error::Malformed);
    }
    if ch.actor_id != actor_hex(actor) {
        return Err(Error::Pin);
    }
    Ok(())
}

fn check_fresh(expiry: u64, now: u64) -> Result<(), Error> {
    if now == 0 || now > MAX_SAFE || expiry == 0 || expiry > MAX_SAFE {
        return Err(Error::Malformed);
    }
    if expiry <= now || expiry > now + MAX_TTL {
        return Err(Error::Expired);
    }
    Ok(())
}

fn auth_preimage(ch: &Challenge) -> String {
    let mut out = String::new();
    push_line(&mut out, AUTH_DOMAIN);
    push_line(&mut out, &format!("room={ROOM}"));
    push_line(&mut out, &format!("actor={}", ch.actor_id));
    push_line(&mut out, &format!("operation={}", ch.operation));
    push_line(&mut out, &format!("session={}", ch.session_id));
    push_line(&mut out, &format!("nonce={}", ch.nonce));
    push_line(&mut out, &format!("expiry={}", ch.expiry_unix));
    out
}

fn advertisement_preimage(wire: &Advertisement) -> Result<(String, Vec<SocketAddr>), Error> {
    if wire.v != 1 || wire.room != ROOM || wire.node_id != wire.actor_id {
        return Err(Error::Malformed);
    }
    if !is_id(&wire.actor_id)
        || !is_id(&wire.session_id)
        || !is_id(&wire.challenge_nonce)
        || !is_id(&wire.node_id)
    {
        return Err(Error::Malformed);
    }
    if wire.revision == 0
        || wire.revision > MAX_SAFE
        || wire.expiry_unix == 0
        || wire.expiry_unix > MAX_SAFE
    {
        return Err(Error::Malformed);
    }
    let addresses = canonical_addresses(&wire.direct_addresses)?;
    let mut out = String::new();
    push_line(&mut out, AD_DOMAIN);
    push_line(&mut out, &format!("v={}", wire.v));
    push_line(&mut out, &format!("room={}", wire.room));
    push_line(&mut out, &format!("actor_id={}", wire.actor_id));
    push_line(&mut out, &format!("session_id={}", wire.session_id));
    push_line(
        &mut out,
        &format!("challenge_nonce={}", wire.challenge_nonce),
    );
    push_line(&mut out, &format!("revision={}", wire.revision));
    push_line(&mut out, &format!("expiry_unix={}", wire.expiry_unix));
    push_line(&mut out, &format!("node_id={}", wire.node_id));
    push_line(&mut out, &format!("address_count={}", addresses.len()));
    for (index, address) in wire.direct_addresses.iter().enumerate() {
        push_line(&mut out, &format!("address.{index}={address}"));
    }
    Ok((out, addresses))
}

fn receipt_preimage(receipt: &Receipt) -> Result<String, Error> {
    if receipt.v != 1 || receipt.domain != RECEIPT_DOMAIN {
        return Err(Error::Receipt);
    }
    if receipt.revision == 0
        || receipt.revision > MAX_SAFE
        || receipt.expiry_unix == 0
        || receipt.expiry_unix > MAX_SAFE
    {
        return Err(Error::Receipt);
    }
    for id in [
        &receipt.actor_id,
        &receipt.session_id,
        &receipt.challenge_nonce,
        &receipt.advertisement_sha256,
        &receipt.coordinator_public_key,
    ] {
        if !is_id(id) {
            return Err(Error::Receipt);
        }
    }
    let mut out = String::new();
    push_line(&mut out, RECEIPT_DOMAIN);
    push_line(&mut out, &format!("room={ROOM}"));
    push_line(&mut out, &format!("actor_id={}", receipt.actor_id));
    push_line(&mut out, &format!("session_id={}", receipt.session_id));
    push_line(
        &mut out,
        &format!("challenge_nonce={}", receipt.challenge_nonce),
    );
    push_line(&mut out, &format!("revision={}", receipt.revision));
    push_line(&mut out, &format!("expiry_unix={}", receipt.expiry_unix));
    push_line(
        &mut out,
        &format!("advertisement_sha256={}", receipt.advertisement_sha256),
    );
    push_line(
        &mut out,
        &format!("coordinator_public_key={}", receipt.coordinator_public_key),
    );
    Ok(out)
}

fn wire_hash(wire: &Advertisement) -> Result<String, Error> {
    if wire.v != 1
        || wire.room != ROOM
        || wire.node_id != wire.actor_id
        || wire.revision == 0
        || wire.revision > MAX_SAFE
        || wire.expiry_unix > MAX_SAFE
    {
        return Err(Error::Receipt);
    }
    if !is_id(&wire.actor_id) || !is_id(&wire.session_id) || !is_id(&wire.challenge_nonce) {
        return Err(Error::Receipt);
    }
    let bytes = serde_json::to_vec(wire).map_err(|_| Error::Receipt)?;
    Ok(encode_hex(&Sha256::digest(bytes)))
}

fn canonical_addresses(values: &[String]) -> Result<Vec<SocketAddr>, Error> {
    if values.is_empty() || values.len() > MAX_ADDRESSES {
        return Err(Error::Malformed);
    }
    values.iter().map(|value| canonical_socket(value)).collect()
}

fn canonical_text(addr: SocketAddr) -> Result<String, Error> {
    if let SocketAddr::V6(v6) = addr
        && v6.scope_id() != 0
    {
        return Err(Error::Malformed);
    }
    let text = addr.to_string();
    if canonical_socket(&text)? != addr {
        return Err(Error::Malformed);
    }
    Ok(text)
}

fn canonical_socket(value: &str) -> Result<SocketAddr, Error> {
    if value.is_empty()
        || value.len() > MAX_ADDRESS_BYTES
        || value.bytes().any(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'/' | b'\\' | b'%' | b'?' | b'#')
        })
    {
        return Err(Error::Malformed);
    }
    let addr: SocketAddr = value.parse().map_err(|_| Error::Malformed)?;
    if addr.port() == 0 || addr.to_string() != value {
        return Err(Error::Malformed);
    }
    if let SocketAddr::V6(v6) = addr
        && v6.scope_id() != 0
    {
        return Err(Error::Malformed);
    }
    reject_ip(addr.ip())?;
    Ok(addr)
}

fn reject_ip(ip: IpAddr) -> Result<(), Error> {
    match ip {
        IpAddr::V4(ip) => {
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(Error::Malformed);
            }
        }
        IpAddr::V6(ip) => {
            if ip.to_ipv4_mapped().is_some() || ip.is_unspecified() || ip.is_multicast() {
                return Err(Error::Malformed);
            }
        }
    }
    Ok(())
}

fn verify_hex(key: EndpointId, message: &[u8], hex: &str) -> Result<(), Error> {
    let bytes = decode_hex::<64>(hex).ok_or(Error::Malformed)?;
    key.verify(message, &Signature::from_bytes(&bytes))
        .map_err(|_| Error::Signature)
}

fn actor_hex(actor: EndpointId) -> String {
    encode_hex(actor.as_bytes())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let bytes = value.as_bytes();
    for index in 0..N {
        out[index] = (hex_val(bytes[index * 2])? << 4) | hex_val(bytes[index * 2 + 1])?;
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn is_id(value: &str) -> bool {
    decode_hex::<32>(value).is_some()
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    const NOW: u64 = 1_700_000_000;

    fn hex_id(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn identity(seed: u8) -> Identity {
        Identity::test_identity([seed; 32])
    }

    fn challenge_for(actor: &str, operation: &str, expiry: u64) -> Challenge {
        Challenge {
            room: ROOM.into(),
            actor_id: actor.into(),
            operation: operation.into(),
            session_id: hex_id(0x11),
            nonce: hex_id(0x22),
            expiry_unix: expiry,
        }
    }

    fn sample() -> (Identity, Challenge, Vec<SocketAddr>) {
        let id = identity(0x31);
        let ch = challenge_for(&actor_hex(id.endpoint_id()), "advertise", NOW + 60);
        let addrs = vec![
            "192.0.2.10:9".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ];
        (id, ch, addrs)
    }

    #[test]
    fn auth_preimage_and_signature_bytes() {
        let id = identity(0x31);
        let actor = actor_hex(id.endpoint_id());
        let ch = challenge_for(&actor, "attach", NOW + 60);
        let expected = format!(
            "chinwag-do-auth/v1\nroom=genesis\nactor={actor}\noperation=attach\nsession={}\nnonce={}\nexpiry={}\n",
            ch.session_id, ch.nonce, ch.expiry_unix
        );
        assert_eq!(auth_preimage(&ch), expected);
        let headers = auth_headers(&id, &ch).unwrap();
        assert_eq!(
            headers.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            [
                "chinwag-room",
                "chinwag-actor",
                "chinwag-operation",
                "chinwag-session",
                "chinwag-nonce",
                "chinwag-expiry",
                "chinwag-signature",
            ]
        );
        assert_eq!(headers[0].1, "genesis");
        assert_eq!(headers[1].1, actor);
        assert_eq!(headers[2].1, "attach");
        assert_eq!(headers[5].1, (NOW + 60).to_string());
        assert_eq!(
            headers[6].1,
            encode_hex(&id.secret_key().sign(expected.as_bytes()).to_bytes())
        );
        let mut stale = ch.clone();
        stale.expiry_unix = NOW - 1;
        assert!(auth_headers(&id, &stale).is_ok());
        assert!(matches!(
            validate_challenge(&stale, id.endpoint_id(), "attach", None, NOW),
            Err(Error::Expired)
        ));
    }

    #[test]
    fn advertisement_preimage_signature_and_pin() {
        let (id, ch, addrs) = sample();
        let wire = sign_advertisement(&id, &ch, 1, addrs.clone(), NOW).unwrap();
        let expected = format!(
            "chinwag-room-peer/v1\nv=1\nroom=genesis\nactor_id={actor}\nsession_id={session}\nchallenge_nonce={nonce}\nrevision=1\nexpiry_unix={expiry}\nnode_id={actor}\naddress_count=2\naddress.0=192.0.2.10:9\naddress.1=[2001:db8::1]:443\n",
            actor = wire.actor_id,
            session = wire.session_id,
            nonce = wire.challenge_nonce,
            expiry = wire.expiry_unix,
        );
        let (message, parsed) = advertisement_preimage(&wire).unwrap();
        assert_eq!(message, expected);
        assert_eq!(parsed, addrs);
        assert_eq!(
            wire.signature,
            encode_hex(&id.secret_key().sign(expected.as_bytes()).to_bytes())
        );
        assert!(
            serde_json::to_vec(&wire)
                .unwrap()
                .starts_with(br#"{"v":1,"room":"genesis","actor_id":""#)
        );
        assert_eq!(
            verify_advertisement(&wire, id.endpoint_id(), NOW).unwrap(),
            addrs
        );
        assert!(sign_advertisement(&id, &ch, 9_007_199_254_740_991, addrs.clone(), NOW).is_ok());
        assert!(matches!(
            sign_advertisement(&id, &ch, 0, addrs.clone(), NOW),
            Err(Error::Malformed)
        ));
        assert!(matches!(
            sign_advertisement(&id, &ch, 9_007_199_254_740_992, addrs, NOW),
            Err(Error::Malformed)
        ));
        let mut far = ch.clone();
        far.expiry_unix = NOW + 121;
        assert!(matches!(
            validate_challenge(
                &far,
                id.endpoint_id(),
                "advertise",
                Some(&far.session_id),
                NOW
            ),
            Err(Error::Expired)
        ));
        let mut edge = ch.clone();
        edge.expiry_unix = NOW + 120;
        assert!(
            validate_challenge(
                &edge,
                id.endpoint_id(),
                "advertise",
                Some(&edge.session_id),
                NOW
            )
            .is_ok()
        );
    }

    #[test]
    fn wrong_pin_tamper_expiry_address_and_unknown_fields() {
        let (id, ch, addrs) = sample();
        let wire = sign_advertisement(&id, &ch, 1, addrs, NOW).unwrap();
        let other = identity(0x32);
        assert!(matches!(
            verify_advertisement(&wire, other.endpoint_id(), NOW),
            Err(Error::Pin)
        ));
        let mut tampered = wire.clone();
        let last = tampered.signature.pop().unwrap();
        tampered.signature.push(if last == '0' { '1' } else { '0' });
        assert!(matches!(
            verify_advertisement(&tampered, id.endpoint_id(), NOW),
            Err(Error::Signature)
        ));
        assert!(matches!(
            verify_advertisement(&wire, id.endpoint_id(), wire.expiry_unix),
            Err(Error::Expired)
        ));
        let bad_addrs = [
            "0.0.0.0:9",
            "224.0.0.1:9",
            "255.255.255.255:9",
            "192.0.2.10:0",
            "192.0.2.10:9 ",
            "[::]:9",
            "[ff02::1]:9",
            "[::ffff:192.0.2.10]:9",
            "192.0.2.10:09",
            "http://192.0.2.10:9",
            "[2001:db8::1%eth0]:9",
        ];
        for bad in bad_addrs {
            let mut forged = wire.clone();
            forged.direct_addresses = vec![bad.into()];
            assert!(
                verify_advertisement(&forged, id.endpoint_id(), NOW).is_err(),
                "{bad}"
            );
        }
        let mapped: SocketAddr = "[::ffff:192.0.2.10]:9".parse().unwrap();
        let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9, 0, 1));
        let unspecified: SocketAddr = "0.0.0.0:9".parse().unwrap();
        for addr in [mapped, scoped, unspecified] {
            assert!(matches!(
                sign_advertisement(&id, &ch, 1, vec![addr], NOW),
                Err(Error::Malformed)
            ));
        }
        assert!(matches!(
            validate_challenge(&ch, id.endpoint_id(), "advertise", None, NOW),
            Err(Error::Pin)
        ));
        assert!(matches!(
            validate_challenge(&ch, id.endpoint_id(), "advertise", Some(&hex_id(0x33)), NOW),
            Err(Error::Pin)
        ));
        let mut challenge_json = serde_json::to_value(&ch).unwrap();
        challenge_json["unexpected"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Challenge>(challenge_json).is_err());
        assert!(
            serde_json::from_value::<Challenge>(serde_json::json!({"room":"genesis","extra":1}))
                .is_err()
        );
        let mut ad_json = serde_json::to_value(&wire).unwrap();
        ad_json["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Advertisement>(ad_json).is_err());
    }

    #[test]
    fn receipt_accepts_pinned_coordinator_and_refuses_other_pin_or_wire() {
        let (id, ch, addrs) = sample();
        let wire = sign_advertisement(&id, &ch, 7, addrs, NOW).unwrap();
        let coordinator = identity(0x44);
        let hash = encode_hex(&Sha256::digest(serde_json::to_vec(&wire).unwrap()));
        let mut receipt = Receipt {
            v: 1,
            domain: RECEIPT_DOMAIN.into(),
            actor_id: wire.actor_id.clone(),
            session_id: wire.session_id.clone(),
            challenge_nonce: wire.challenge_nonce.clone(),
            revision: wire.revision,
            expiry_unix: wire.expiry_unix,
            advertisement_sha256: hash,
            coordinator_public_key: actor_hex(coordinator.endpoint_id()),
            signature: String::new(),
        };
        let expected = format!(
            "chinwag-peer-stored/v1\nroom=genesis\nactor_id={}\nsession_id={}\nchallenge_nonce={}\nrevision={}\nexpiry_unix={}\nadvertisement_sha256={}\ncoordinator_public_key={}\n",
            receipt.actor_id,
            receipt.session_id,
            receipt.challenge_nonce,
            receipt.revision,
            receipt.expiry_unix,
            receipt.advertisement_sha256,
            receipt.coordinator_public_key,
        );
        assert_eq!(receipt_preimage(&receipt).unwrap(), expected);
        receipt.signature = encode_hex(
            &coordinator
                .secret_key()
                .sign(expected.as_bytes())
                .to_bytes(),
        );
        assert!(verify_receipt(&receipt, coordinator.endpoint_id(), &wire).is_ok());
        assert!(matches!(
            verify_receipt(&receipt, identity(0x55).endpoint_id(), &wire),
            Err(Error::Pin)
        ));
        let mut other_wire = wire.clone();
        other_wire.revision += 1;
        assert!(matches!(
            verify_receipt(&receipt, coordinator.endpoint_id(), &other_wire),
            Err(Error::Receipt)
        ));
        let mut forged = receipt.clone();
        forged.advertisement_sha256 = hex_id(0x99);
        assert!(matches!(
            verify_receipt(&forged, coordinator.endpoint_id(), &wire),
            Err(Error::Receipt)
        ));
        let mut bad_sig = receipt.clone();
        let last = bad_sig.signature.pop().unwrap();
        bad_sig.signature.push(if last == '0' { '1' } else { '0' });
        assert!(matches!(
            verify_receipt(&bad_sig, coordinator.endpoint_id(), &wire),
            Err(Error::Signature)
        ));
        let mut extra = serde_json::to_value(&receipt).unwrap();
        extra["signer"] = serde_json::json!(receipt.coordinator_public_key.clone());
        assert!(serde_json::from_value::<Receipt>(extra).is_err());
    }
}
