//! Wire format verified against iroh-relay 1.4.1's common/handshake/relay modules.
//! No relay payload is decrypted, persisted, interpreted or logged.
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

pub type EndpointId = [u8; 32];
pub const PROTOCOL: &str = "iroh-relay-v2";
pub const MAX_PACKET_SIZE: usize = 64 * 1024;
pub const MAX_MESSAGE_SIZE: usize = MAX_PACKET_SIZE + 8;
pub const MAX_AUTH_SIZE: usize = 128;
pub const ALLOWED_ENDPOINTS: [EndpointId; 2] = [
    [
        0xe0, 0x08, 0x80, 0xa1, 0xa3, 0x66, 0x27, 0x1a, 0x10, 0x06, 0xa5, 0x5d, 0xca, 0x47, 0xa8,
        0xa4, 0xcd, 0xc7, 0xf7, 0xa6, 0x05, 0x41, 0x49, 0x5f, 0x38, 0x13, 0xb1, 0x4e, 0x9f, 0x33,
        0x13, 0x2d,
    ],
    [
        0xd1, 0x3d, 0xe9, 0xe8, 0x97, 0xc2, 0x46, 0x1d, 0xe7, 0xaa, 0x5a, 0x7d, 0x7c, 0xee, 0xd9,
        0xaf, 0x73, 0xb0, 0x81, 0x76, 0x19, 0x0d, 0xb9, 0x92, 0x1b, 0x2f, 0xbc, 0x82, 0x71, 0x2a,
        0xa4, 0xfe,
    ],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Malformed,
    Oversized,
    Unauthorized,
    Expired,
    Budget,
    State,
}

/// QUIC varints are accepted at every legal encoded width, as in iroh's decoder.
pub fn tagged(bytes: &[u8]) -> Result<(u64, &[u8]), Failure> {
    let first = *bytes.first().ok_or(Failure::Malformed)?;
    let len = 1_usize << (first >> 6);
    if bytes.len() < len {
        return Err(Failure::Malformed);
    }
    let mut tag = u64::from(first & 0x3f);
    for byte in &bytes[1..len] {
        tag = (tag << 8) | u64::from(*byte);
    }
    Ok((tag, &bytes[len..]))
}

pub fn challenge_frame(challenge: &[u8; 16]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(17);
    frame.push(0);
    frame.extend_from_slice(challenge);
    frame
}

pub fn challenge_message(challenge: &[u8; 16]) -> [u8; 32] {
    blake3::derive_key("iroh-relay handshake v1 challenge signature", challenge)
}

#[derive(Deserialize)]
struct ClientAuth {
    public_key: EndpointId,
    #[serde(with = "serde_bytes")]
    signature: [u8; 64],
}

/// This fixed-size postcard structure cannot allocate from attacker-controlled lengths.
pub fn verify_auth(
    bytes: &[u8],
    challenge: &[u8; 16],
    allowed: &[EndpointId; 2],
) -> Result<EndpointId, Failure> {
    if bytes.len() > MAX_AUTH_SIZE {
        return Err(Failure::Oversized);
    }
    let (tag, body) = tagged(bytes)?;
    if tag != 1 {
        return Err(Failure::Malformed);
    }
    let (auth, rest) =
        postcard::take_from_bytes::<ClientAuth>(body).map_err(|_| Failure::Malformed)?;
    if !rest.is_empty() {
        return Err(Failure::Malformed);
    }
    if !allowed.contains(&auth.public_key) {
        return Err(Failure::Unauthorized);
    }
    let key = VerifyingKey::from_bytes(&auth.public_key).map_err(|_| Failure::Unauthorized)?;
    key.verify_strict(
        &challenge_message(challenge),
        &Signature::from_bytes(&auth.signature),
    )
    .map_err(|_| Failure::Unauthorized)?;
    Ok(auth.public_key)
}

pub const AUTH_CONFIRMED: &[u8] = &[2];
// postcard string "unauthorized" with the ServerDeniesAuth tag.
pub const AUTH_DENIED: &[u8] = b"\x03\x0cunauthorized";

#[derive(Debug, PartialEq, Eq)]
pub enum ClientFrame<'a> {
    Datagram {
        destination: EndpointId,
        batch: bool,
        body: &'a [u8],
    },
    Ping([u8; 8]),
    Pong([u8; 8]),
}

pub fn client_frame<'a>(
    bytes: &'a [u8],
    source: &EndpointId,
    allowed: &[EndpointId; 2],
) -> Result<ClientFrame<'a>, Failure> {
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(Failure::Oversized);
    }
    let (tag, body) = tagged(bytes)?;
    if body.len() > MAX_PACKET_SIZE {
        return Err(Failure::Oversized);
    }
    match tag {
        4 | 5 => {
            let metadata_len = if tag == 5 { 35 } else { 33 };
            if body.len() < metadata_len || body[32] > 3 {
                return Err(Failure::Malformed);
            }
            if tag == 5 && u16::from_be_bytes([body[33], body[34]]) == 0 {
                return Err(Failure::Malformed);
            }
            let destination = body[..32].try_into().map_err(|_| Failure::Malformed)?;
            if !allowed.contains(source)
                || !allowed.contains(&destination)
                || source == &destination
            {
                return Err(Failure::Unauthorized);
            }
            Ok(ClientFrame::Datagram {
                destination,
                batch: tag == 5,
                body: &body[32..],
            })
        }
        9 | 10 => {
            let data = body.try_into().map_err(|_| Failure::Malformed)?;
            Ok(if tag == 9 {
                ClientFrame::Ping(data)
            } else {
                ClientFrame::Pong(data)
            })
        }
        _ => Err(Failure::Malformed),
    }
}

pub fn relay_frame(source: &EndpointId, batch: bool, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(33 + body.len());
    frame.push(if batch { 7 } else { 6 });
    frame.extend_from_slice(source);
    frame.extend_from_slice(body);
    frame
}

pub fn control_frame(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + payload.len());
    frame.push(tag);
    frame.extend_from_slice(payload);
    frame
}

pub fn accepts_protocol(header: &str) -> bool {
    header.len() <= 256 && header.split(',').any(|token| token.trim() == PROTOCOL)
}
