//! Socket-free dispatch v1. JSON is an envelope; signatures cover the explicitly
//! length-delimited transcript, never JSON object ordering or whitespace.
use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::Identity;

pub const ALPN: &[u8] = b"chinwag/agent-dispatch/1";
pub const REQUEST_DOMAIN: &[u8] = b"chinwag-agent-dispatch-request/v1\0";
pub const RESPONSE_DOMAIN: &[u8] = b"chinwag-agent-dispatch-response/v1\0";
pub const MAX_REQUEST_BYTES: usize = 128 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_BODY_BYTES: usize = 60_000;
pub const MAX_REPLY_BYTES: usize = 120_000;
pub const MAX_TTL: u64 = 120;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
const MAX_NONCES: usize = 4096;

/// Deliberately one public failure for all untrusted input. No supplied values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("dispatch_refused")]
pub struct Refused;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub agent: String,
    pub sender: String,
    pub body: String,
    #[serde(rename = "itemKey")]
    pub item_key: String,
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
    #[serde(default, rename = "customAgent")]
    pub custom_agent: Option<CustomAgent>,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub sender: Option<String>,
    pub role: Option<String>,
    pub body: Option<String>,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomAgent {
    pub role: Option<String>,
    pub dept: Option<String>,
    pub engine: Option<String>,
    pub system_prompt: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u8,
    pub requester: String,
    pub studio: String,
    pub nonce: String,
    pub issued_unix: u64,
    pub expiry_unix: u64,
    pub payload: Payload,
    pub signature: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    None,
    DispatchFailed,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub v: u8,
    pub studio: String,
    pub request_sha256: String,
    pub expiry_unix: u64,
    pub ok: bool,
    pub exit_code: u8,
    /// Exact JSON output (including its newline), encoded as a JSON string.
    pub reply: String,
    pub error_code: ErrorCode,
    pub signature: String,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Result<[u8; N], Refused> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Refused);
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| Refused)?;
    }
    Ok(out)
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn verify(peer: EndpointId, bytes: &[u8], signature: &str) -> Result<(), Refused> {
    VerifyingKey::from_bytes(peer.as_bytes())
        .map_err(|_| Refused)?
        .verify_strict(bytes, &Signature::from_bytes(&unhex(signature)?))
        .map_err(|_| Refused)
}

fn optional_field(out: &mut Vec<u8>, value: &Option<String>) {
    field(out, &[u8::from(value.is_some())]);
    if let Some(value) = value {
        field(out, value.as_bytes());
    }
}

impl Payload {
    pub fn validate(&self) -> Result<(), Refused> {
        for (s, max) in [
            (&self.agent, 128),
            (&self.sender, 256),
            (&self.item_key, 256),
            (&self.body, MAX_BODY_BYTES),
        ] {
            if s.trim().is_empty() || s.len() > max || s.contains('\0') {
                return Err(Refused);
            }
        }
        if self.history.len() > 10 {
            return Err(Refused);
        }
        let mut total = 0usize;
        for entry in &self.history {
            for text in [&entry.sender, &entry.role, &entry.body]
                .into_iter()
                .flatten()
            {
                if text.contains('\0') {
                    return Err(Refused);
                }
                total = total.checked_add(text.len()).ok_or(Refused)?;
            }
        }
        if total > 30_000 {
            return Err(Refused);
        }
        if let Some(custom) = &self.custom_agent {
            for text in [
                &custom.role,
                &custom.dept,
                &custom.engine,
                &custom.system_prompt,
            ]
            .into_iter()
            .flatten()
            {
                if text.len() > 4000 || text.contains('\0') {
                    return Err(Refused);
                }
            }
        }
        Ok(())
    }
}

impl Request {
    pub fn sign(
        identity: &Identity,
        studio: EndpointId,
        payload: Payload,
        nonce: [u8; 32],
        now: u64,
    ) -> Result<Self, Refused> {
        let mut wire = Self {
            v: 1,
            requester: hex(identity.endpoint_id().as_bytes()),
            studio: hex(studio.as_bytes()),
            nonce: hex(&nonce),
            issued_unix: now,
            expiry_unix: now.checked_add(MAX_TTL).ok_or(Refused)?,
            payload,
            signature: String::new(),
        };
        wire.signature = hex(&identity
            .secret_key()
            .sign(&wire.canonical_bytes()?)
            .to_bytes());
        wire.to_bytes()?;
        Ok(wire)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refused> {
        self.payload.validate()?;
        if self.v != 1
            || self.issued_unix == 0
            || self.expiry_unix > MAX_SAFE
            || self.expiry_unix <= self.issued_unix
            || self.expiry_unix - self.issued_unix > MAX_TTL
        {
            return Err(Refused);
        }
        let mut out = REQUEST_DOMAIN.to_vec();
        for bytes in [
            unhex::<32>(&self.requester)?,
            unhex::<32>(&self.studio)?,
            unhex::<32>(&self.nonce)?,
        ] {
            field(&mut out, &bytes);
        }
        field(&mut out, &self.issued_unix.to_be_bytes());
        field(&mut out, &self.expiry_unix.to_be_bytes());
        for s in [
            &self.payload.agent,
            &self.payload.sender,
            &self.payload.body,
            &self.payload.item_key,
        ] {
            field(&mut out, s.as_bytes());
        }
        field(&mut out, &(self.payload.history.len() as u64).to_be_bytes());
        for entry in &self.payload.history {
            for value in [&entry.sender, &entry.role, &entry.body] {
                optional_field(&mut out, value);
            }
        }
        field(&mut out, &[u8::from(self.payload.custom_agent.is_some())]);
        if let Some(custom) = &self.payload.custom_agent {
            for value in [
                &custom.role,
                &custom.dept,
                &custom.engine,
                &custom.system_prompt,
            ] {
                optional_field(&mut out, value);
            }
        }
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Refused> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Refused);
        }
        let wire: Self = serde_json::from_slice(bytes).map_err(|_| Refused)?;
        wire.canonical_bytes()?;
        unhex::<64>(&wire.signature)?;
        Ok(wire)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Refused> {
        self.canonical_bytes()?;
        encode(self, MAX_REQUEST_BYTES)
    }

    pub fn hash(&self) -> Result<String, Refused> {
        let mut bytes = self.canonical_bytes()?;
        field(&mut bytes, &unhex::<64>(&self.signature)?);
        Ok(hex(&Sha256::digest(bytes)))
    }

    /// Cryptographic checks alone do not establish pin or room membership.
    pub fn verify(&self, peer: EndpointId, studio: EndpointId, now: u64) -> Result<(), Refused> {
        if self.requester != hex(peer.as_bytes())
            || self.studio != hex(studio.as_bytes())
            || self.issued_unix > now
            || self.expiry_unix <= now
        {
            return Err(Refused);
        }
        verify(peer, &self.canonical_bytes()?, &self.signature)
    }
}

fn encode(value: &impl Serialize, cap: usize) -> Result<Vec<u8>, Refused> {
    let bytes = serde_json::to_vec(value).map_err(|_| Refused)?;
    if bytes.len() > cap {
        return Err(Refused);
    }
    Ok(bytes)
}

impl Response {
    pub fn sign(
        identity: &Identity,
        request: &Request,
        exit_code: u8,
        reply: String,
        now: u64,
    ) -> Result<Self, Refused> {
        if request.studio != hex(identity.endpoint_id().as_bytes()) {
            return Err(Refused);
        }
        let mut wire = Self {
            v: 1,
            studio: hex(identity.endpoint_id().as_bytes()),
            request_sha256: request.hash()?,
            expiry_unix: now.checked_add(MAX_TTL).ok_or(Refused)?,
            ok: exit_code == 0,
            exit_code,
            reply,
            error_code: if exit_code == 0 {
                ErrorCode::None
            } else {
                ErrorCode::DispatchFailed
            },
            signature: String::new(),
        };
        wire.signature = hex(&identity
            .secret_key()
            .sign(&wire.canonical_bytes()?)
            .to_bytes());
        wire.to_bytes()?;
        Ok(wire)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refused> {
        if self.v != 1
            || self.expiry_unix == 0
            || self.expiry_unix > MAX_SAFE
            || self.reply.len() > MAX_REPLY_BYTES
            || self.ok != (self.exit_code == 0)
            || (self.error_code == ErrorCode::None) != self.ok
        {
            return Err(Refused);
        }
        if self.ok
            && !serde_json::from_str::<serde_json::Value>(&self.reply).is_ok_and(|v| v.is_object())
        {
            return Err(Refused);
        }
        if !self.ok && !self.reply.is_empty() {
            return Err(Refused);
        }
        let mut out = RESPONSE_DOMAIN.to_vec();
        field(&mut out, &unhex::<32>(&self.studio)?);
        field(&mut out, &unhex::<32>(&self.request_sha256)?);
        field(&mut out, &self.expiry_unix.to_be_bytes());
        field(&mut out, &[u8::from(self.ok), self.exit_code]);
        field(&mut out, self.reply.as_bytes());
        field(&mut out, if self.ok { b"none" } else { b"dispatch_failed" });
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Refused> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(Refused);
        }
        let wire: Self = serde_json::from_slice(bytes).map_err(|_| Refused)?;
        wire.canonical_bytes()?;
        unhex::<64>(&wire.signature)?;
        Ok(wire)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Refused> {
        self.canonical_bytes()?;
        encode(self, MAX_RESPONSE_BYTES)
    }
    pub fn verify(&self, studio: EndpointId, request: &Request, now: u64) -> Result<(), Refused> {
        if self.studio != hex(studio.as_bytes())
            || request.studio != self.studio
            || self.request_sha256 != request.hash()?
            || self.expiry_unix <= now
            || self.expiry_unix.saturating_sub(now) > MAX_TTL
        {
            return Err(Refused);
        }
        verify(studio, &self.canonical_bytes()?, &self.signature)
    }
}

/// The listener starts with an empty cache and rejects issuance at/before its
/// startup wall clock. A restarted process cannot admit an earlier request.
/// Clock rollback fails closed; capacity exhaustion never evicts live nonces.
pub struct ReplayGuard {
    started: u64,
    last_now: u64,
    seen: BTreeMap<(String, String), u64>,
}
impl ReplayGuard {
    pub fn new(started: u64) -> Self {
        Self {
            started,
            last_now: started,
            seen: BTreeMap::new(),
        }
    }
    pub fn accept(
        &mut self,
        wire: &Request,
        peer: EndpointId,
        studio: EndpointId,
        now: u64,
    ) -> Result<(), Refused> {
        wire.verify(peer, studio, now)?;
        if now < self.last_now || wire.issued_unix <= self.started {
            return Err(Refused);
        }
        self.last_now = now;
        self.seen.retain(|_, expiry| *expiry > now);
        let key = (wire.requester.clone(), wire.nonce.clone());
        if self.seen.contains_key(&key) || self.seen.len() >= MAX_NONCES {
            return Err(Refused);
        }
        self.seen.insert(key, wire.expiry_unix);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn payload() -> Payload {
        Payload {
            agent: "RUST".into(),
            sender: "Brian".into(),
            body: "quote\"\nbody".into(),
            item_key: "IROH-DISPATCH-1".into(),
            history: vec![],
            custom_agent: None,
        }
    }
    fn identities() -> (Identity, Identity) {
        (
            Identity::test_identity([1; 32]),
            Identity::test_identity([2; 32]),
        )
    }
    #[test]
    fn rfc8032_empty_message_verification_vector() {
        // Public RFC 8032 section 7.1 vector, not a deployed identity.
        let public: EndpointId = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .parse()
            .unwrap();
        let signature = concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        verify(public, b"", signature).unwrap();
        assert!(verify(public, REQUEST_DOMAIN, signature).is_err());
    }

    #[test]
    fn optional_context_is_authenticated_and_strictly_bounded() {
        let (peer, studio) = identities();
        let mut payload = payload();
        payload.history.push(HistoryEntry {
            sender: Some("Brian".into()),
            role: Some("user".into()),
            body: Some("previous message".into()),
        });
        payload.custom_agent = Some(CustomAgent {
            role: Some("engineer".into()),
            dept: None,
            engine: Some("codex".into()),
            system_prompt: Some("inert test context".into()),
        });
        let request = Request::sign(&peer, studio.endpoint_id(), payload, [3; 32], 1001).unwrap();
        request
            .verify(peer.endpoint_id(), studio.endpoint_id(), 1001)
            .unwrap();
        let mut changed = request.clone();
        changed.payload.history[0].body = Some("changed".into());
        assert!(
            changed
                .verify(peer.endpoint_id(), studio.endpoint_id(), 1001)
                .is_err()
        );
        let mut changed = request.clone();
        changed.payload.custom_agent.as_mut().unwrap().engine = Some("changed".into());
        assert!(
            changed
                .verify(peer.endpoint_id(), studio.endpoint_id(), 1001)
                .is_err()
        );
        let mut value = serde_json::to_value(&request).unwrap();
        value["payload"]["customAgent"]["extra"] = true.into();
        assert!(Request::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut big = request.payload.clone();
        big.history = vec![HistoryEntry::default(); 11];
        assert!(big.validate().is_err());
        let mut big = request.payload;
        big.custom_agent.as_mut().unwrap().system_prompt = Some("x".repeat(4001));
        assert!(big.validate().is_err());
    }

    #[test]
    fn response_rejects_forgery_unknown_fields_bad_shape_and_oversize() {
        let (peer, studio) = identities();
        let request = Request::sign(&peer, studio.endpoint_id(), payload(), [3; 32], 1001).unwrap();
        let response =
            Response::sign(&studio, &request, 0, "{\"ok\":true}\n".into(), 1002).unwrap();
        for name in ["studio", "request_sha256", "signature"] {
            let mut value = serde_json::to_value(&response).unwrap();
            value[name] = if name == "signature" {
                "0".repeat(128)
            } else {
                "0".repeat(64)
            }
            .into();
            let changed: Response = serde_json::from_value(value).unwrap();
            assert!(
                changed
                    .verify(studio.endpoint_id(), &request, 1003)
                    .is_err()
            );
        }
        let mut value = serde_json::to_value(&response).unwrap();
        value["diagnostic"] = "forbidden".into();
        assert!(Response::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(Response::from_bytes(&vec![b' '; MAX_RESPONSE_BYTES + 1]).is_err());
        assert!(Response::sign(&studio, &request, 0, "[]".into(), 1002).is_err());
        assert!(Response::sign(&studio, &request, 1, "diagnostic".into(), 1002).is_err());
        let failure = Response::sign(&studio, &request, 1, String::new(), 1002).unwrap();
        failure
            .verify(studio.endpoint_id(), &request, 1003)
            .unwrap();
    }

    #[test]
    fn request_response_round_trip_and_replay_restart() {
        let (peer, studio) = identities();
        let req = Request::sign(&peer, studio.endpoint_id(), payload(), [3; 32], 1001).unwrap();
        let req = Request::from_bytes(&req.to_bytes().unwrap()).unwrap();
        let mut guard = ReplayGuard::new(1000);
        guard
            .accept(&req, peer.endpoint_id(), studio.endpoint_id(), 1001)
            .unwrap();
        assert!(
            guard
                .accept(&req, peer.endpoint_id(), studio.endpoint_id(), 1001)
                .is_err()
        );
        assert!(
            ReplayGuard::new(1001)
                .accept(&req, peer.endpoint_id(), studio.endpoint_id(), 1002)
                .is_err()
        );
        let reply = Response::sign(
            &studio,
            &req,
            0,
            "{\"ok\":true,\"reply\":\"hello\"}\n".into(),
            1010,
        )
        .unwrap();
        let reply = Response::from_bytes(&reply.to_bytes().unwrap()).unwrap();
        reply.verify(studio.endpoint_id(), &req, 1011).unwrap();
        assert!(reply.verify(peer.endpoint_id(), &req, 1011).is_err());
        assert!(reply.verify(studio.endpoint_id(), &req, 1130).is_err());
        let other = Request::sign(&peer, studio.endpoint_id(), payload(), [4; 32], 1001).unwrap();
        assert!(reply.verify(studio.endpoint_id(), &other, 1011).is_err());
        let mut changed = reply.clone();
        changed.reply.push(' ');
        assert!(changed.verify(studio.endpoint_id(), &req, 1011).is_err());
    }
    #[test]
    fn tamper_wrong_key_expiry_size_and_unknown_fields() {
        let (peer, studio) = identities();
        let req = Request::sign(&peer, studio.endpoint_id(), payload(), [3; 32], 1001).unwrap();
        for name in ["agent", "sender", "body", "itemKey"] {
            let mut value = serde_json::to_value(&req).unwrap();
            value["payload"][name] = "changed".into();
            let changed: Request = serde_json::from_value(value).unwrap();
            assert!(
                changed
                    .verify(peer.endpoint_id(), studio.endpoint_id(), 1001)
                    .is_err()
            );
        }
        assert!(
            req.verify(studio.endpoint_id(), studio.endpoint_id(), 1001)
                .is_err()
        );
        assert!(
            req.verify(peer.endpoint_id(), peer.endpoint_id(), 1001)
                .is_err()
        );
        assert!(
            req.verify(peer.endpoint_id(), studio.endpoint_id(), 1121)
                .is_err()
        );
        assert!(
            req.verify(peer.endpoint_id(), studio.endpoint_id(), 1000)
                .is_err()
        );
        let mut value = serde_json::to_value(&req).unwrap();
        value["extra"] = true.into();
        assert!(Request::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        value.as_object_mut().unwrap().remove("extra");
        value["payload"]["extra"] = true.into();
        assert!(Request::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut big = payload();
        big.body = "x".repeat(MAX_BODY_BYTES + 1);
        assert!(Request::sign(&peer, studio.endpoint_id(), big, [3; 32], 1001).is_err());
        assert!(Request::from_bytes(&vec![b' '; MAX_REQUEST_BYTES + 1]).is_err());
        assert!(Response::sign(&studio, &req, 0, "x".repeat(MAX_REPLY_BYTES + 1), 1001).is_err());
    }
    #[test]
    fn canonical_transcript_is_length_delimited_and_domain_separated() {
        let (peer, studio) = identities();
        let req = Request::sign(&peer, studio.endpoint_id(), payload(), [3; 32], 1001).unwrap();
        let bytes = req.canonical_bytes().unwrap();
        assert!(bytes.starts_with(REQUEST_DOMAIN));
        let mut expected = REQUEST_DOMAIN.to_vec();
        for b in [
            peer.endpoint_id().as_bytes().as_slice(),
            studio.endpoint_id().as_bytes().as_slice(),
            &[3; 32],
            &1001u64.to_be_bytes(),
            &1121u64.to_be_bytes(),
            b"RUST",
            b"Brian",
            b"quote\"\nbody",
            b"IROH-DISPATCH-1",
        ] {
            expected.extend_from_slice(&(b.len() as u64).to_be_bytes());
            expected.extend_from_slice(b);
        }
        expected.extend_from_slice(&8u64.to_be_bytes());
        expected.extend_from_slice(&0u64.to_be_bytes());
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.push(0);
        assert_eq!(bytes, expected);
        assert_ne!(REQUEST_DOMAIN, RESPONSE_DOMAIN);
        let mut invalid = req.clone();
        invalid.nonce = "A".repeat(64);
        assert!(invalid.canonical_bytes().is_err());
        let raw = req.to_bytes().unwrap();
        let duplicate = String::from_utf8(raw)
            .unwrap()
            .replacen("{", "{\"v\":1,", 1);
        assert!(Request::from_bytes(duplicate.as_bytes()).is_err());
    }
}
