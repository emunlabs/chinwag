//! Verified, bounded wake classification. No scheduling or task authority.
#![forbid(unsafe_code)]

use crate::{agent_instance::ActorAddress, bus_federation::BusMessage};
use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;

// Compile the accepted public roster into the verifier; never load it from a
// candidate checkout at invocation time. WORKHORSE's separately enrolled public
// key is retained explicitly; no private signing material is embedded.
const COMPILED_ROSTER: &str = include_str!("../../../.chinwag/allowed_signers");
pub const WORKHORSE_PUBLIC_KEY: &str =
    "3a8eaffca3221988625e53f701b0bdf40bf5e5a973a624ad58c0ffa5dd7e466c";

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub fn decode<const N: usize>(text: &str) -> Result<[u8; N], &'static str> {
    if text.len() != N * 2 || !text.is_ascii() {
        return Err("INVALID_HEX");
    }
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| "INVALID_HEX")?;
    }
    Ok(result)
}

pub fn canonical_roster() -> BTreeMap<String, String> {
    let mut roster = BTreeMap::new();
    for (seat, bytes) in chinwag_swarm::identity::parse_allowed_signers(COMPILED_ROSTER) {
        if let Some(seat) = seat {
            roster.insert(seat.to_ascii_uppercase(), hex(&bytes));
        }
    }
    roster.insert("WORKHORSE".into(), WORKHORSE_PUBLIC_KEY.into());
    roster
}

pub fn signing_payload(message: &BusMessage) -> String {
    let timestamp = message.ts_unix.to_string();
    let fields = [
        message.id.as_str(),
        timestamp.as_str(),
        message.sender.as_str(),
        message.to.as_deref().unwrap_or(""),
        message.room.as_str(),
        message.task_id.as_deref().unwrap_or(""),
        message.body.as_str(),
    ];
    format!(
        "chinwag-bus-sig-v2|{}",
        fields
            .iter()
            .map(|field| format!("{}:{field}", field.len()))
            .collect::<Vec<_>>()
            .join("|")
    )
}

pub fn message_digest(message: &BusMessage) -> String {
    hash(
        [
            "chinwag-bus-v1",
            &message.ts_unix.to_string(),
            &message.room,
            &message.sender,
            &message.sender_endpoint_id,
            message.to.as_deref().unwrap_or(""),
            message.task_id.as_deref().unwrap_or(""),
            &message.body,
        ]
        .join("|")
        .as_bytes(),
    )
}

/// Original detached signature, digest, actor and immutable endpoint witness.
/// `sig_verified` is deliberately ignored; it is an untrusted cache field.
pub fn verify_original(message: &BusMessage) -> Result<(), &'static str> {
    verify_with_roster(message, &canonical_roster())
}

fn verify_with_roster(
    message: &BusMessage,
    roster: &BTreeMap<String, String>,
) -> Result<(), &'static str> {
    ActorAddress::parse(&message.sender)
        .and_then(ActorAddress::require_instance)
        .map_err(|_| "INVALID_SENDER")?;
    if message.id.len() > 160
        || message.sender.len() > 256
        || message.room.len() > 128
        || message
            .task_id
            .as_ref()
            .is_some_and(|task| task.len() > 256)
        || message.to.as_ref().is_some_and(|actor| actor.len() > 256)
        || message.body.len() > 65_536
    {
        return Err("MESSAGE_BOUND_EXCEEDED");
    }
    let seat = message
        .sender
        .split('#')
        .next()
        .unwrap_or("")
        .to_uppercase();
    let expected = roster.get(&seat).ok_or("UNPINNED_SENDER")?;
    if message.pubkey_ed25519.as_deref() != Some(expected)
        || message.sender_endpoint_id != *expected
        || !bool::from(
            message_digest(message)
                .as_bytes()
                .ct_eq(message.digest_sha256.as_bytes()),
        )
    {
        return Err("ORIGINAL_WITNESS_MISMATCH");
    }
    let public: EndpointId = expected.parse().map_err(|_| "INVALID_PIN")?;
    let signature = Signature::from_bytes(&decode::<64>(
        message
            .signature_ed25519
            .as_deref()
            .ok_or("MISSING_SIGNATURE")?,
    )?);
    public
        .verify(signing_payload(message).as_bytes(), &signature)
        .map_err(|_| "INVALID_SIGNATURE")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ChatMessage,
    TaskDispatch,
    CiWakeCard,
    Receipt,
    TaskStatus,
    SelfEcho,
    PresenceHeartbeat,
}
impl EventKind {
    pub fn wakes(self) -> bool {
        matches!(
            self,
            Self::ChatMessage | Self::TaskDispatch | Self::CiWakeCard
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplyPolicy {
    ReplyRequired,
    TaskLifecycle,
    NoReply,
}

/// All keys and values are strings in this closed schema. Sorting these ASCII
/// keys and serde's JSON string encoding yields the JCS representation without
/// admitting floating-point or arbitrary nested JSON canonicalization.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub event_kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    pub reply_policy: ReplyPolicy,
    pub schema: String,
    pub text: String,
}

pub fn classify_body(body: &str, allow_legacy: bool) -> Result<SignedBody, &'static str> {
    if body.len() > 65_536 {
        return Err("MESSAGE_BOUND_EXCEEDED");
    }
    if body
        .trim_start_matches([' ', '\t', '\r', '\n'])
        .starts_with('{')
    {
        // Derived struct deserialization rejects repeated fields, nested values,
        // unknown keys and trailing input rather than silently normalizing them.
        let parsed: SignedBody =
            serde_json::from_str(body).map_err(|_| "MALFORMED_OR_UNSUPPORTED_STRUCTURED_BODY")?;
        if parsed.schema != "chinwag.bus.body.v1"
            || serde_json::to_string(&parsed).map_err(|_| "BODY_ENCODING")? != body
        {
            return Err("MALFORMED_OR_UNSUPPORTED_STRUCTURED_BODY");
        }
        Ok(parsed)
    } else if allow_legacy {
        Ok(SignedBody {
            correlation_id: None,
            event_kind: EventKind::ChatMessage,
            in_reply_to: None,
            reply_policy: ReplyPolicy::ReplyRequired,
            schema: "chinwag.bus.body.v1".into(),
            text: body.into(),
        })
    } else {
        Err("LEGACY_PLAINTEXT_DISABLED")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn canonical_receipt_is_non_waking_and_malformed_json_never_downgrades() {
        let receipt = r#"{"correlation_id":"x","event_kind":"receipt","in_reply_to":"x","reply_policy":"NoReply","schema":"chinwag.bus.body.v1","text":"..."}"#;
        assert!(!classify_body(receipt, true).unwrap().event_kind.wakes());
        for rejected in [
            "{broken",
            r#"{"schema":"unknown"}"#,
            r#"{"event_kind":"receipt","event_kind":"chat_message","reply_policy":"NoReply","schema":"chinwag.bus.body.v1","text":"x"}"#,
            r#"{"event_kind":"receipt","reply_policy":"NoReply","schema":"chinwag.bus.body.v1","text":{"deep":{}}}"#,
        ] {
            assert!(classify_body(rejected, true).is_err(), "{rejected}");
        }
        assert!(classify_body("legacy", false).is_err());
    }

    fn signed_fixture() -> (BusMessage, BTreeMap<String, String>) {
        let secret = SecretKey::generate();
        let public = secret.public().to_string();
        let mut message = BusMessage {
            id: "fixture-é".into(),
            seq: 1,
            ts_unix: 1,
            ts_iso: "fixture".into(),
            room: "#eng".into(),
            sender: "WORKHORSE#fixture".into(),
            sender_cast: "■".into(),
            sender_endpoint_id: public.clone(),
            to: Some("GEMINI-PM#fixture".into()),
            task_id: Some("TEST".into()),
            body: "évidence".into(),
            digest_sha256: String::new(),
            pubkey_ed25519: Some(public.clone()),
            signature_ed25519: None,
            sig_verified: true,
        };
        message.digest_sha256 = message_digest(&message);
        message.signature_ed25519 = Some(hex(&secret
            .sign(signing_payload(&message).as_bytes())
            .to_bytes()));
        (message, BTreeMap::from([("WORKHORSE".into(), public)]))
    }

    #[test]
    fn verifies_exact_native_bytes_and_rejects_digest_endpoint_and_signature_forgery() {
        let (message, pins) = signed_fixture();
        assert!(signing_payload(&message).contains("10:fixture-é"));
        assert!(verify_with_roster(&message, &pins).is_ok());
        for field in ["body", "digest", "endpoint", "signature"] {
            let mut changed = message.clone();
            match field {
                "body" => changed.body.push('x'),
                "digest" => changed.digest_sha256 = "0".repeat(64),
                "endpoint" => changed.sender_endpoint_id = "0".repeat(64),
                _ => changed.signature_ed25519 = Some("0".repeat(128)),
            }
            assert!(verify_with_roster(&changed, &pins).is_err(), "{field}");
        }
        assert!(verify_original(&message).is_err()); // Test key is not production authority.
    }

    #[test]
    #[ignore = "owner supplies preserved signed original through CHINWAG_INTEROP_FIXTURE"]
    fn preserved_original_verifies_without_resigning() {
        let path = std::env::var("CHINWAG_INTEROP_FIXTURE").expect("fixture path");
        let bytes = std::fs::read_to_string(path).unwrap();
        let message = bytes
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|value| {
                serde_json::from_value::<BusMessage>(value.get("message").unwrap_or(&value).clone())
                    .ok()
            })
            .find(|message| message.id == "bus-1794264873-2b8773b6")
            .expect("preserved original");
        assert_eq!(
            message.digest_sha256,
            "2b8773b67437fe6174d54b112915bab0cac059846b1c41d034cc5c5904e469c7"
        );
        verify_original(&message).unwrap();
    }
}
