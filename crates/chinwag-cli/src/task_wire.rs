#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Bounded task frames and K1 authentication for the frozen Phase 0 profile.
//!
//! No payload profile is enabled by default. Callers supply ratified kind/profile
//! pairs and current authority pins. This module neither dispatches work nor
//! replaces grant, source enrollment, host-time evidence, or durable transactions.

use crate::agent_instance::ActorAddress;
use crate::task_ref::{
    CanonicalDecoder, MAX_ID_UTF8_BYTES, MAX_LIST_ITEMS, MAX_SCALAR_BYTES, Sha256Digest,
    TaskContractError, TaskRefV1, encode_bytes_field, encode_opt, encode_sorted_distinct_set,
    encode_str_field, encode_u64, validate_id,
};
use iroh::{EndpointId, SecretKey, Signature};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

pub const TASK_BUS_V2_ALPN: &[u8] = b"chinwag/bus/2";
pub const LEGACY_BUS_V1_ALPN: &[u8] = b"chinwag/bus/1";
pub const BUS_SIG_V3_DOMAIN: &[u8] = b"chinwag-bus-sig-v3\0";
pub const MAX_TASK_WIRE_FRAME_BYTES: usize = 131_072;
pub const NONCE_LEN_BYTES: usize = 32;
const BINARY_FRAME_DOMAIN: &[u8] = b"chinwag-task-frame-v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskWireError {
    EmptyFrame,
    FrameTooLarge,
    DuplicateJsonKey,
    InvalidJson,
    InvalidHex,
    UnsupportedFrame,
    UnknownMessageKind,
    UnratifiedPayloadProfile,
    PayloadDigestMismatch,
    InvalidCanonicalPayload,
    InvalidActorAddress,
    InvalidCorrelation,
    InvalidRecipientSet,
    InvalidValidityWindow,
    ProtocolDowngradeForbidden,
    SignerNotEnrolled,
    SignatureInvalid,
    TranscriptDigestMismatch,
    AudienceMismatch,
    AuthorityBindingMismatch,
    ActionNotAllowed,
    ClockRollback,
    TimeUnavailable,
    NotYetValid,
    Expired,
    ReplayConflict,
    ReplayOutcomePending,
    ReplayReservationMissing,
    ReadPermissionRequired,
    Contract(TaskContractError),
}

impl From<TaskContractError> for TaskWireError {
    fn from(error: TaskContractError) -> Self {
        Self::Contract(error)
    }
}

impl fmt::Display for TaskWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "task wire held: {self:?}")
    }
}

impl std::error::Error for TaskWireError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskMessageKind {
    TaskProposal,
    Assignment,
    CandidateResult,
    TaskReceipt,
}

impl TaskMessageKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskProposal => "TaskProposal",
            Self::Assignment => "Assignment",
            Self::CandidateResult => "CandidateResult",
            Self::TaskReceipt => "TaskReceipt",
        }
    }
}

impl FromStr for TaskMessageKind {
    type Err = TaskWireError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "TaskProposal" => Ok(Self::TaskProposal),
            "Assignment" => Ok(Self::Assignment),
            "CandidateResult" => Ok(Self::CandidateResult),
            "TaskReceipt" => Ok(Self::TaskReceipt),
            _ => Err(TaskWireError::UnknownMessageKind),
        }
    }
}

/// Ratification is per message kind. A name ratified for a receipt cannot enable
/// assignments. The caller supplies the approved canonical payload validator.
#[derive(Clone, Copy, Debug)]
pub struct RatifiedPayloadProfile<'a> {
    pub kind: TaskMessageKind,
    pub name: &'a str,
    /// Check the profile's canonical bytes without performing effects.
    pub validate_canonical_payload: fn(&[u8]) -> bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskActionableBodyV1 {
    pub payload_profile: String,
    pub canonical_payload: Vec<u8>,
    pub payload_digest_sha256: Sha256Digest,
    /// Non-authoritative presentation, never an executable instruction.
    pub display_text: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonActionableBody {
    payload_profile: Option<String>,
    canonical_payload_hex: String,
    payload_digest_sha256: String,
    display_text: Option<String>,
}

impl TaskActionableBodyV1 {
    pub fn parse(
        body_utf8: &str,
        kind: TaskMessageKind,
        profiles: &[RatifiedPayloadProfile<'_>],
    ) -> Result<Self, TaskWireError> {
        strict_json_object(body_utf8.as_bytes())?;
        let body: JsonActionableBody =
            serde_json::from_str(body_utf8).map_err(|_| TaskWireError::InvalidJson)?;
        let profile = body
            .payload_profile
            .ok_or(TaskWireError::UnratifiedPayloadProfile)?;
        let entry = profiles
            .iter()
            .find(|entry| entry.kind == kind && entry.name == profile)
            .ok_or(TaskWireError::UnratifiedPayloadProfile)?;
        wire_id(&profile, "payload_profile")?;
        let payload = decode_lower_hex(&body.canonical_payload_hex, MAX_SCALAR_BYTES)?;
        let digest = digest_from_hex(&body.payload_digest_sha256)?;
        if Sha256Digest::of(&payload) != digest {
            return Err(TaskWireError::PayloadDigestMismatch);
        }
        if !(entry.validate_canonical_payload)(&payload) {
            return Err(TaskWireError::InvalidCanonicalPayload);
        }
        Ok(Self {
            payload_profile: profile,
            canonical_payload: payload,
            payload_digest_sha256: digest,
            display_text: body.display_text,
        })
    }
}

/// The complete signed content. JSON formatting of `body_utf8` is preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskTranscriptV3 {
    pub message_id: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; NONCE_LEN_BYTES],
    pub sender_full_actor_address: String,
    pub parent_full_actor_address: Option<String>,
    pub recipient_full_actor_addresses: Vec<String>,
    pub room: String,
    pub message_kind: TaskMessageKind,
    pub receiver_authority_id: String,
    pub task_ref: TaskRefV1,
    pub assignment_id: Option<String>,
    pub operation_id: Option<String>,
    pub request_id: Option<String>,
    pub in_reply_to_message_id: Option<String>,
    pub config_digest: Sha256Digest,
    pub task_control_digest: Sha256Digest,
    pub body_utf8: String,
}

impl TaskTranscriptV3 {
    /// Prepare a new message once, before its first send. Retrying must retain
    /// this record, including message ID, nonce and original operation identity.
    pub fn random_message_id_and_nonce() -> (String, [u8; NONCE_LEN_BYTES]) {
        (lower_hex(&rand::random::<[u8; 32]>()), rand::random())
    }

    pub fn validate(&self, profiles: &[RatifiedPayloadProfile<'_>]) -> Result<(), TaskWireError> {
        wire_id(&self.message_id, "message_id")?;
        canonical_actor(&self.sender_full_actor_address)?;
        if let Some(parent) = &self.parent_full_actor_address {
            canonical_actor(parent)?;
        }
        validate_recipients(&self.recipient_full_actor_addresses)?;
        wire_id(&self.room, "room")?;
        wire_id(&self.receiver_authority_id, "receiver_authority_id")?;
        self.task_ref.validate()?;
        for (id, name) in [
            (&self.assignment_id, "assignment_id"),
            (&self.operation_id, "operation_id"),
            (&self.request_id, "request_id"),
            (&self.in_reply_to_message_id, "in_reply_to_message_id"),
        ] {
            if let Some(id) = id {
                wire_id(id, name)?;
            }
        }
        if self.operation_id.is_none()
            || (matches!(
                self.message_kind,
                TaskMessageKind::Assignment | TaskMessageKind::CandidateResult
            ) && self.assignment_id.is_none())
        {
            return Err(TaskWireError::InvalidCorrelation);
        }
        if self.expires_at_unix < self.issued_at_unix {
            return Err(TaskWireError::InvalidValidityWindow);
        }
        TaskActionableBodyV1::parse(&self.body_utf8, self.message_kind, profiles)?;
        Ok(())
    }

    /// No lineage can be inferred from an absent optional parent.
    pub fn require_declared_parent(&self) -> Result<&str, TaskWireError> {
        let parent = self
            .parent_full_actor_address
            .as_deref()
            .ok_or(TaskWireError::InvalidActorAddress)?;
        canonical_actor(parent)?;
        Ok(parent)
    }

    pub fn encode_transcript(
        &self,
        profiles: &[RatifiedPayloadProfile<'_>],
    ) -> Result<Vec<u8>, TaskWireError> {
        self.validate(profiles)?;
        let mut out = BUS_SIG_V3_DOMAIN.to_vec();
        out.extend(encode_str_field(&self.message_id));
        out.extend(encode_u64(self.issued_at_unix));
        out.extend(encode_u64(self.expires_at_unix));
        out.extend(encode_bytes_field(&self.nonce));
        out.extend(encode_str_field(&self.sender_full_actor_address));
        out.extend(encode_opt(
            self.parent_full_actor_address.as_deref(),
            encode_str_field,
        ));
        out.extend(encode_sorted_distinct_set(
            self.recipient_full_actor_addresses
                .iter()
                .map(|address| encode_str_field(address))
                .collect(),
        )?);
        out.extend(encode_str_field(&self.room));
        out.extend(encode_str_field(self.message_kind.as_str()));
        out.extend(encode_str_field(&self.receiver_authority_id));
        out.extend(encode_bytes_field(&self.task_ref.encode()?));
        for id in [
            &self.assignment_id,
            &self.operation_id,
            &self.request_id,
            &self.in_reply_to_message_id,
        ] {
            out.extend(encode_opt(id.as_deref(), encode_str_field));
        }
        out.extend(encode_bytes_field(&self.config_digest.encode_typed()));
        out.extend(encode_bytes_field(&self.task_control_digest.encode_typed()));
        out.extend(encode_str_field(&self.body_utf8));
        check_frame_size(&out)?;
        Ok(out)
    }

    pub fn decode_transcript(
        raw: &[u8],
        profiles: &[RatifiedPayloadProfile<'_>],
    ) -> Result<Self, TaskWireError> {
        check_frame_size(raw)?;
        let mut decoder = CanonicalDecoder::new(raw);
        if decoder.take(BUS_SIG_V3_DOMAIN.len())? != BUS_SIG_V3_DOMAIN {
            return Err(TaskWireError::UnsupportedFrame);
        }
        let message_id = decoder.string(MAX_ID_UTF8_BYTES)?;
        let issued_at_unix = decoder.u64()?;
        let expires_at_unix = decoder.u64()?;
        let nonce = decoder
            .bytes(NONCE_LEN_BYTES)?
            .try_into()
            .map_err(|_| TaskWireError::InvalidCorrelation)?;
        let sender_full_actor_address = decoder.string(MAX_ID_UTF8_BYTES)?;
        let parent_full_actor_address = decoder.optional(|d| d.string(MAX_ID_UTF8_BYTES))?;
        let recipient_full_actor_addresses =
            decoder.sorted_distinct_set(|d| d.string(MAX_ID_UTF8_BYTES))?;
        let room = decoder.string(MAX_ID_UTF8_BYTES)?;
        let message_kind = decoder.string(MAX_ID_UTF8_BYTES)?.parse()?;
        let receiver_authority_id = decoder.string(MAX_ID_UTF8_BYTES)?;
        let task_ref = TaskRefV1::decode(decoder.bytes(MAX_SCALAR_BYTES)?)?;
        let assignment_id = decoder.optional(|d| d.string(MAX_ID_UTF8_BYTES))?;
        let operation_id = decoder.optional(|d| d.string(MAX_ID_UTF8_BYTES))?;
        let request_id = decoder.optional(|d| d.string(MAX_ID_UTF8_BYTES))?;
        let in_reply_to_message_id = decoder.optional(|d| d.string(MAX_ID_UTF8_BYTES))?;
        let config_digest = decode_wrapped_digest(&mut decoder)?;
        let task_control_digest = decode_wrapped_digest(&mut decoder)?;
        let body_utf8 = decoder.string(MAX_TASK_WIRE_FRAME_BYTES)?;
        decoder.finish()?;
        let value = Self {
            message_id,
            issued_at_unix,
            expires_at_unix,
            nonce,
            sender_full_actor_address,
            parent_full_actor_address,
            recipient_full_actor_addresses,
            room,
            message_kind,
            receiver_authority_id,
            task_ref,
            assignment_id,
            operation_id,
            request_id,
            in_reply_to_message_id,
            config_digest,
            task_control_digest,
            body_utf8,
        };
        value.validate(profiles)?;
        Ok(value)
    }
}

fn decode_wrapped_digest(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<Sha256Digest, TaskWireError> {
    let mut inner = CanonicalDecoder::new(decoder.bytes(MAX_SCALAR_BYTES)?);
    let digest = inner.sha256_digest()?;
    inner.finish()?;
    Ok(digest)
}

/// Both serialization formats carry the same v3 transcript. Neither accepts a
/// transported `sig_verified` flag or a local sequence number as authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishTaskV1 {
    pub transcript: TaskTranscriptV3,
    pub signer_pubkey: EndpointId,
    pub signature_ed25519: [u8; 64],
    pub transcript_digest: Sha256Digest,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JsonTaskFrame {
    frame: String,
    transcript_hex: String,
    signer_pubkey_hex: String,
    signature_ed25519: String,
    transcript_digest_sha256: String,
}

impl PublishTaskV1 {
    pub fn sign(
        transcript: TaskTranscriptV3,
        secret: &SecretKey,
        profiles: &[RatifiedPayloadProfile<'_>],
    ) -> Result<Self, TaskWireError> {
        let bytes = transcript.encode_transcript(profiles)?;
        Ok(Self {
            transcript,
            signer_pubkey: secret.public(),
            signature_ed25519: secret.sign(&bytes).to_bytes(),
            transcript_digest: Sha256Digest::of(&bytes),
        })
    }

    pub fn encode_json(
        &self,
        profiles: &[RatifiedPayloadProfile<'_>],
    ) -> Result<Vec<u8>, TaskWireError> {
        let transcript = self.transcript.encode_transcript(profiles)?;
        // These values contain only ASCII hex and a fixed literal frame name,
        // so serialization adds no escaping. Bound the complete output before
        // allocating its hexadecimal transcript or serialization buffer.
        const JSON_OVERHEAD: usize = concat!(
            "{\"frame\":\"PublishTaskV1\",\"transcript_hex\":\"\",",
            "\"signer_pubkey_hex\":\"\",\"signature_ed25519\":\"\",",
            "\"transcript_digest_sha256\":\"\"}"
        )
        .len()
            + 64
            + 128
            + 64;
        if transcript.len() > (MAX_TASK_WIRE_FRAME_BYTES - JSON_OVERHEAD) / 2 {
            return Err(TaskWireError::FrameTooLarge);
        }
        let frame = JsonTaskFrame {
            frame: "PublishTaskV1".to_owned(),
            transcript_hex: lower_hex(&transcript),
            signer_pubkey_hex: lower_hex(self.signer_pubkey.as_bytes()),
            signature_ed25519: lower_hex(&self.signature_ed25519),
            transcript_digest_sha256: self.transcript_digest.to_string(),
        };
        let raw = serde_json::to_vec(&frame).map_err(|_| TaskWireError::InvalidJson)?;
        check_frame_size(&raw)?;
        Ok(raw)
    }

    pub fn decode_json(
        raw_frame: &[u8],
        alpn: &[u8],
        profiles: &[RatifiedPayloadProfile<'_>],
    ) -> Result<Self, TaskWireError> {
        check_frame_size(raw_frame)?;
        require_task_protocol(alpn)?;
        strict_json_object(raw_frame)?;
        let frame: JsonTaskFrame =
            serde_json::from_slice(raw_frame).map_err(|_| TaskWireError::InvalidJson)?;
        if frame.frame != "PublishTaskV1" {
            return Err(TaskWireError::UnsupportedFrame);
        }
        let transcript = decode_lower_hex(&frame.transcript_hex, MAX_TASK_WIRE_FRAME_BYTES)?;
        let pubkey = fixed_hex::<32>(&frame.signer_pubkey_hex)?;
        Ok(Self {
            transcript: TaskTranscriptV3::decode_transcript(&transcript, profiles)?,
            signer_pubkey: EndpointId::from_bytes(&pubkey)
                .map_err(|_| TaskWireError::SignatureInvalid)?,
            signature_ed25519: fixed_hex(&frame.signature_ed25519)?,
            transcript_digest: digest_from_hex(&frame.transcript_digest_sha256)?,
        })
    }

    pub fn encode_binary(
        &self,
        profiles: &[RatifiedPayloadProfile<'_>],
    ) -> Result<Vec<u8>, TaskWireError> {
        let transcript = self.transcript.encode_transcript(profiles)?;
        let length = BINARY_FRAME_DOMAIN.len() + 8 + transcript.len() + 32 + 64 + 32;
        if length > MAX_TASK_WIRE_FRAME_BYTES {
            return Err(TaskWireError::FrameTooLarge);
        }
        let mut raw = Vec::with_capacity(length);
        raw.extend_from_slice(BINARY_FRAME_DOMAIN);
        raw.extend(encode_bytes_field(&transcript));
        raw.extend_from_slice(self.signer_pubkey.as_bytes());
        raw.extend_from_slice(&self.signature_ed25519);
        raw.extend_from_slice(&self.transcript_digest.0);
        Ok(raw)
    }

    pub fn decode_binary(
        raw_frame: &[u8],
        alpn: &[u8],
        profiles: &[RatifiedPayloadProfile<'_>],
    ) -> Result<Self, TaskWireError> {
        check_frame_size(raw_frame)?;
        require_task_protocol(alpn)?;
        let mut decoder = CanonicalDecoder::new(raw_frame);
        if decoder.take(BINARY_FRAME_DOMAIN.len())? != BINARY_FRAME_DOMAIN {
            return Err(TaskWireError::UnsupportedFrame);
        }
        let transcript = TaskTranscriptV3::decode_transcript(
            decoder.bytes(MAX_TASK_WIRE_FRAME_BYTES)?,
            profiles,
        )?;
        let key = decoder
            .take(32)?
            .try_into()
            .map_err(|_| TaskWireError::SignatureInvalid)?;
        let signer_pubkey =
            EndpointId::from_bytes(key).map_err(|_| TaskWireError::SignatureInvalid)?;
        let signature_ed25519 = decoder
            .take(64)?
            .try_into()
            .map_err(|_| TaskWireError::SignatureInvalid)?;
        let transcript_digest = Sha256Digest(
            decoder
                .take(32)?
                .try_into()
                .map_err(|_| TaskWireError::TranscriptDigestMismatch)?,
        );
        decoder.finish()?;
        Ok(Self {
            transcript,
            signer_pubkey,
            signature_ed25519,
            transcript_digest,
        })
    }

    /// Authenticate only. This permits permission-checked historical replay
    /// lookup after expiry, but cannot create a replay reservation or new effect.
    pub fn authenticate(
        &self,
        alpn: &[u8],
        roster: &[SignerEnrollment],
        profiles: &[RatifiedPayloadProfile<'_>],
    ) -> Result<AuthenticatedTaskMessage, TaskWireError> {
        require_task_protocol(alpn)?;
        let bytes = self.transcript.encode_transcript(profiles)?;
        let digest = Sha256Digest::of(&bytes);
        if digest != self.transcript_digest {
            return Err(TaskWireError::TranscriptDigestMismatch);
        }
        self.signer_pubkey
            .verify(&bytes, &Signature::from_bytes(&self.signature_ed25519))
            .map_err(|_| TaskWireError::SignatureInvalid)?;
        let sender = canonical_actor(&self.transcript.sender_full_actor_address)?;
        let mut matches = roster.iter().filter(|entry| {
            entry.active
                && entry.signer_pubkey == self.signer_pubkey
                && entry.workspace_id == self.transcript.task_ref.workspace_id
                && entry.repo_id == self.transcript.task_ref.repo_id
                && entry.seat == sender.seat()
                && entry.config_digest == self.transcript.config_digest
        });
        let signer = matches.next().ok_or(TaskWireError::SignerNotEnrolled)?;
        if matches.next().is_some() {
            return Err(TaskWireError::SignerNotEnrolled);
        }
        wire_id(&signer.authenticated_signer_principal, "signer_principal")?;
        Ok(AuthenticatedTaskMessage {
            transcript: self.transcript.clone(),
            transcript_digest: digest,
            signer_principal: signer.authenticated_signer_principal.clone(),
            signer_public_key: self.signer_pubkey,
            key_epoch: signer.key_epoch,
            allowed_actions: signer.allowed_actions.clone(),
        })
    }

    pub fn verify(
        &self,
        alpn: &[u8],
        roster: &[SignerEnrollment],
        context: &TaskVerificationContext<'_>,
    ) -> Result<VerifiedTaskMessage, TaskWireError> {
        let authenticated = self.authenticate(alpn, roster, context.ratified_profiles)?;
        let transcript = &authenticated.transcript;
        canonical_actor(context.recipient_full_actor_address)?;
        if transcript.receiver_authority_id != context.receiver_authority_id
            || !transcript
                .recipient_full_actor_addresses
                .iter()
                .any(|address| address == context.recipient_full_actor_address)
        {
            return Err(TaskWireError::AudienceMismatch);
        }
        if &transcript.task_ref != context.current_task_ref
            || transcript.config_digest != context.config_digest
            || transcript.task_control_digest != context.task_control_digest
            || authenticated.key_epoch != context.required_key_epoch
        {
            return Err(TaskWireError::AuthorityBindingMismatch);
        }
        if !authenticated
            .allowed_actions
            .contains(&transcript.message_kind)
            || !context
                .current_granted_actions
                .contains(&transcript.message_kind)
        {
            return Err(TaskWireError::ActionNotAllowed);
        }
        let now = match context.host_clock {
            HostClockState::Verified { now_unix } => now_unix,
            HostClockState::ClockRollback => return Err(TaskWireError::ClockRollback),
            HostClockState::TimeUnavailable => return Err(TaskWireError::TimeUnavailable),
        };
        if now < transcript.issued_at_unix {
            return Err(TaskWireError::NotYetValid);
        }
        if now > transcript.expires_at_unix {
            return Err(TaskWireError::Expired);
        }
        Ok(VerifiedTaskMessage { authenticated })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerEnrollment {
    pub workspace_id: String,
    pub repo_id: String,
    pub seat: String,
    pub authenticated_signer_principal: String,
    pub signer_pubkey: EndpointId,
    pub key_epoch: u64,
    pub config_digest: Sha256Digest,
    pub allowed_actions: Vec<TaskMessageKind>,
    pub active: bool,
}

/// `Verified` means the caller validated evidence under the approved host-time
/// profile. This enum does not obtain or approve clock evidence itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostClockState {
    Verified { now_unix: u64 },
    ClockRollback,
    TimeUnavailable,
}

pub struct TaskVerificationContext<'a> {
    pub receiver_authority_id: &'a str,
    pub recipient_full_actor_address: &'a str,
    pub current_task_ref: &'a TaskRefV1,
    pub config_digest: Sha256Digest,
    pub task_control_digest: Sha256Digest,
    pub required_key_epoch: u64,
    pub current_granted_actions: &'a [TaskMessageKind],
    pub ratified_profiles: &'a [RatifiedPayloadProfile<'a>],
    pub host_clock: HostClockState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedTaskMessage {
    transcript: TaskTranscriptV3,
    transcript_digest: Sha256Digest,
    signer_principal: String,
    signer_public_key: EndpointId,
    key_epoch: u64,
    allowed_actions: Vec<TaskMessageKind>,
}

impl AuthenticatedTaskMessage {
    pub fn transcript(&self) -> &TaskTranscriptV3 {
        &self.transcript
    }

    pub fn signer_principal(&self) -> &str {
        &self.signer_principal
    }

    pub fn transcript_digest(&self) -> Sha256Digest {
        self.transcript_digest
    }

    /// The enrolled K1 that actually verified this exact transcript.
    pub fn signer_public_key(&self) -> EndpointId {
        self.signer_public_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTaskMessage {
    authenticated: AuthenticatedTaskMessage,
}

impl VerifiedTaskMessage {
    pub fn authenticated(&self) -> &AuthenticatedTaskMessage {
        &self.authenticated
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayDisposition {
    FirstSeen,
    DuplicateRecordedOutcome { outcome: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayEntry {
    transcript_digest: Sha256Digest,
    assignment_id: Option<String>,
    operation_id: Option<String>,
    outcome: Option<String>,
}

/// In-memory transaction model only. The authoritative adapter must durably
/// reserve before effects, atomically record outcomes, and retain tombstones
/// through the full recovery horizon. Dropping this value proves no retirement.
#[derive(Default)]
pub struct ReplayLedger {
    entries: BTreeMap<(String, String, String), ReplayEntry>,
}

impl ReplayLedger {
    pub fn reserve(
        &mut self,
        message: &VerifiedTaskMessage,
    ) -> Result<ReplayDisposition, TaskWireError> {
        let authenticated = message.authenticated();
        if let Some(disposition) = self.lookup(authenticated)? {
            return Ok(disposition);
        }
        self.entries.insert(
            replay_key(authenticated),
            ReplayEntry {
                transcript_digest: authenticated.transcript_digest,
                assignment_id: authenticated.transcript.assignment_id.clone(),
                operation_id: authenticated.transcript.operation_id.clone(),
                outcome: None,
            },
        );
        Ok(ReplayDisposition::FirstSeen)
    }

    pub fn record_outcome(
        &mut self,
        message: &VerifiedTaskMessage,
        outcome: &str,
    ) -> Result<(), TaskWireError> {
        check_frame_size(outcome.as_bytes())?;
        let authenticated = message.authenticated();
        let entry = self
            .entries
            .get_mut(&replay_key(authenticated))
            .ok_or(TaskWireError::ReplayReservationMissing)?;
        check_replay_entry(entry, authenticated)?;
        if entry
            .outcome
            .as_deref()
            .is_some_and(|recorded| recorded != outcome)
        {
            return Err(TaskWireError::ReplayConflict);
        }
        entry.outcome = Some(outcome.to_owned());
        Ok(())
    }

    pub fn lookup_recorded_outcome(
        &self,
        authenticated: &AuthenticatedTaskMessage,
        existing_read_permission: bool,
    ) -> Result<Option<ReplayDisposition>, TaskWireError> {
        if !existing_read_permission {
            return Err(TaskWireError::ReadPermissionRequired);
        }
        self.lookup(authenticated)
    }

    fn lookup(
        &self,
        message: &AuthenticatedTaskMessage,
    ) -> Result<Option<ReplayDisposition>, TaskWireError> {
        let Some(entry) = self.entries.get(&replay_key(message)) else {
            return Ok(None);
        };
        check_replay_entry(entry, message)?;
        match &entry.outcome {
            Some(outcome) => Ok(Some(ReplayDisposition::DuplicateRecordedOutcome {
                outcome: outcome.clone(),
            })),
            None => Err(TaskWireError::ReplayOutcomePending),
        }
    }
}

fn replay_key(message: &AuthenticatedTaskMessage) -> (String, String, String) {
    (
        message.transcript.task_ref.workspace_id.clone(),
        message.signer_principal.clone(),
        message.transcript.message_id.clone(),
    )
}

fn check_replay_entry(
    entry: &ReplayEntry,
    message: &AuthenticatedTaskMessage,
) -> Result<(), TaskWireError> {
    if entry.transcript_digest != message.transcript_digest
        || entry.assignment_id != message.transcript.assignment_id
        || entry.operation_id != message.transcript.operation_id
    {
        return Err(TaskWireError::ReplayConflict);
    }
    Ok(())
}

pub fn require_task_protocol(negotiated_alpn: &[u8]) -> Result<(), TaskWireError> {
    if negotiated_alpn != TASK_BUS_V2_ALPN {
        return Err(TaskWireError::ProtocolDowngradeForbidden);
    }
    Ok(())
}

/// Called before parsing, copying, UTF-8 conversion or constructing a decoder.
pub fn check_frame_size(raw_frame: &[u8]) -> Result<(), TaskWireError> {
    if raw_frame.is_empty() {
        Err(TaskWireError::EmptyFrame)
    } else if raw_frame.len() > MAX_TASK_WIRE_FRAME_BYTES {
        Err(TaskWireError::FrameTooLarge)
    } else {
        Ok(())
    }
}

fn wire_id(value: &str, field: &'static str) -> Result<(), TaskWireError> {
    validate_id(value, field)?;
    if value.chars().any(char::is_control) {
        return Err(TaskContractError::InvalidField(field).into());
    }
    Ok(())
}

fn canonical_actor(raw: &str) -> Result<ActorAddress, TaskWireError> {
    wire_id(raw, "actor_address")?;
    let address = ActorAddress::parse(raw)
        .and_then(ActorAddress::require_instance)
        .map_err(|_| TaskWireError::InvalidActorAddress)?;
    if address.to_string() != raw {
        return Err(TaskWireError::InvalidActorAddress);
    }
    Ok(address)
}

fn validate_recipients(recipients: &[String]) -> Result<(), TaskWireError> {
    if recipients.is_empty() || recipients.len() > MAX_LIST_ITEMS {
        return Err(TaskWireError::InvalidRecipientSet);
    }
    let mut previous = None;
    for recipient in recipients {
        canonical_actor(recipient)?;
        let encoded = encode_str_field(recipient);
        if previous
            .as_ref()
            .is_some_and(|previous| previous >= &encoded)
        {
            return Err(TaskWireError::InvalidRecipientSet);
        }
        previous = Some(encoded);
    }
    Ok(())
}

fn lower_hex(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(raw.len() * 2);
    for byte in raw {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 15)]));
    }
    value
}

fn decode_lower_hex(raw: &str, maximum: usize) -> Result<Vec<u8>, TaskWireError> {
    if !raw.len().is_multiple_of(2)
        || raw.len() / 2 > maximum
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(TaskWireError::InvalidHex);
    }
    let nibble = |byte: u8| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    Ok(raw
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect())
}

fn fixed_hex<const N: usize>(raw: &str) -> Result<[u8; N], TaskWireError> {
    decode_lower_hex(raw, N)?
        .try_into()
        .map_err(|_| TaskWireError::InvalidHex)
}

fn digest_from_hex(raw: &str) -> Result<Sha256Digest, TaskWireError> {
    Ok(Sha256Digest(fixed_hex(raw)?))
}

// Streaming preflight checks decoded keys at every nesting level, including
// escaped-equivalent spellings. Memory and token lengths are bounded by the
// checked frame; each container additionally permits at most MAX_LIST_ITEMS.
// serde_json's recursion limit remains enabled. No unbounded Value tree exists.
fn strict_json_object(raw: &[u8]) -> Result<(), TaskWireError> {
    check_frame_size(raw)?;
    if raw.iter().copied().find(|byte| !byte.is_ascii_whitespace()) != Some(b'{') {
        return Err(TaskWireError::InvalidJson);
    }
    let mut failure = None;
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    let result = JsonCheck(&mut failure).deserialize(&mut decoder);
    if result.is_err() {
        return Err(failure.unwrap_or(TaskWireError::InvalidJson));
    }
    decoder.end().map_err(|_| TaskWireError::InvalidJson)
}

struct JsonCheck<'a>(&'a mut Option<TaskWireError>);

impl<'de> DeserializeSeed<'de> for JsonCheck<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonCheck<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        let mut count = 0;
        while sequence
            .next_element_seed(JsonCheck(&mut *self.0))?
            .is_some()
        {
            count += 1;
            if count > MAX_LIST_ITEMS {
                return Err(serde::de::Error::custom("JSON list limit exceeded"));
            }
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                *self.0 = Some(TaskWireError::DuplicateJsonKey);
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            if keys.len() > MAX_LIST_ITEMS {
                return Err(serde::de::Error::custom("JSON object limit exceeded"));
            }
            map.next_value_seed(JsonCheck(&mut *self.0))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_ref::GitOid;

    const PROFILES: &[RatifiedPayloadProfile<'static>] = &[
        RatifiedPayloadProfile {
            kind: TaskMessageKind::TaskProposal,
            name: "p0-wire-fixture-v1",
            validate_canonical_payload: valid_fixture_payload,
        },
        RatifiedPayloadProfile {
            kind: TaskMessageKind::Assignment,
            name: "p0-wire-fixture-v1",
            validate_canonical_payload: valid_fixture_payload,
        },
        RatifiedPayloadProfile {
            kind: TaskMessageKind::CandidateResult,
            name: "p0-wire-fixture-v1",
            validate_canonical_payload: valid_fixture_payload,
        },
        RatifiedPayloadProfile {
            kind: TaskMessageKind::TaskReceipt,
            name: "p0-wire-fixture-v1",
            validate_canonical_payload: valid_fixture_payload,
        },
    ];
    const TASK_REF_HEX: &str = "6368696e7761672d7461736b7265662d763100000000000000001470302d666978747572652d776f726b7370616365000000000000000f70302d666978747572652d7265706f00000000000000203030303030303030303030303030303030303030303030303030303030303031000000000000000100000000000000085441534b532e6d64000000000000000c50302d464958545552452d310000000000000006736861323536000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000086769742d736861310000000000000014c4f8395af729fd7aecf5365f6a4b261a824d83ce";

    fn fixture() -> TaskTranscriptV3 {
        TaskTranscriptV3 {
            message_id: "message-1".to_owned(),
            issued_at_unix: 100,
            expires_at_unix: 200,
            nonce: [7; NONCE_LEN_BYTES],
            sender_full_actor_address: "RUST#sender".to_owned(),
            parent_full_actor_address: Some("DELIVERY#parent".to_owned()),
            recipient_full_actor_addresses: vec!["WORKHORSE#receiver".to_owned()],
            room: "#eng".to_owned(),
            message_kind: TaskMessageKind::Assignment,
            receiver_authority_id: "authority-1".to_owned(),
            task_ref: TaskRefV1 {
                workspace_id: "p0-fixture-workspace".to_owned(),
                repo_id: "p0-fixture-repo".to_owned(),
                task_source_id: "00000000000000000000000000000001".to_owned(),
                source_generation: 1,
                canonical_task_path: "TASKS.md".to_owned(),
                task_id: "P0-FIXTURE-1".to_owned(),
                task_spec_digest: Sha256Digest([0; 32]),
                task_status_rev: 0,
                file_cas_rev: 0,
                baseline_commit: GitOid::from_hex("c4f8395af729fd7aecf5365f6a4b261a824d83ce")
                    .unwrap(),
            },
            assignment_id: Some("assignment-1".to_owned()),
            operation_id: Some("operation-1".to_owned()),
            request_id: None,
            in_reply_to_message_id: None,
            config_digest: Sha256Digest([1; 32]),
            task_control_digest: Sha256Digest([2; 32]),
            body_utf8: concat!(
                "{\"payload_profile\":\"p0-wire-fixture-v1\",",
                "\"canonical_payload_hex\":\"616263\",\"payload_digest_sha256\":\"",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}"
            )
            .to_owned(),
        }
    }

    fn valid_fixture_payload(bytes: &[u8]) -> bool {
        !bytes.is_empty() && !bytes.contains(&0)
    }

    fn secret() -> SecretKey {
        static KEY: std::sync::OnceLock<SecretKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| SecretKey::from_bytes(&rand::random::<[u8; 32]>()))
            .clone()
    }

    fn alternate_secret() -> SecretKey {
        static KEY: std::sync::OnceLock<SecretKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            loop {
                let candidate = SecretKey::from_bytes(&rand::random::<[u8; 32]>());
                if candidate.public() != secret().public() {
                    return candidate;
                }
            }
        })
        .clone()
    }

    fn signed(transcript: TaskTranscriptV3) -> PublishTaskV1 {
        PublishTaskV1::sign(transcript, &secret(), PROFILES).unwrap()
    }

    fn roster() -> Vec<SignerEnrollment> {
        vec![SignerEnrollment {
            workspace_id: "p0-fixture-workspace".to_owned(),
            repo_id: "p0-fixture-repo".to_owned(),
            seat: "RUST".to_owned(),
            authenticated_signer_principal: "rust-principal".to_owned(),
            signer_pubkey: secret().public(),
            key_epoch: 3,
            config_digest: Sha256Digest([1; 32]),
            allowed_actions: vec![TaskMessageKind::Assignment],
            active: true,
        }]
    }

    fn context(task_ref: &TaskRefV1) -> TaskVerificationContext<'_> {
        TaskVerificationContext {
            receiver_authority_id: "authority-1",
            recipient_full_actor_address: "WORKHORSE#receiver",
            current_task_ref: task_ref,
            config_digest: Sha256Digest([1; 32]),
            task_control_digest: Sha256Digest([2; 32]),
            required_key_epoch: 3,
            current_granted_actions: &[TaskMessageKind::Assignment],
            ratified_profiles: PROFILES,
            host_clock: HostClockState::Verified { now_unix: 150 },
        }
    }

    fn verified(transcript: TaskTranscriptV3) -> VerifiedTaskMessage {
        let frame = signed(transcript);
        frame
            .verify(TASK_BUS_V2_ALPN, &roster(), &context(&fixture().task_ref))
            .unwrap()
    }

    #[test]
    fn p0_wire_literal_task_ref_vector_is_wrapped_in_v3() {
        let transcript = fixture();
        let task_ref = transcript.task_ref.encode().unwrap();
        assert_eq!(task_ref.len(), 268);
        assert_eq!(lower_hex(&task_ref), TASK_REF_HEX);
        assert_eq!(
            Sha256Digest::of(&task_ref).to_string(),
            "ac2421645d450eebef30a65a069427ecf86a32952faa647fa29babe9cdcef997"
        );
        let encoded = transcript.encode_transcript(PROFILES).unwrap();
        let wrapped = encode_bytes_field(&task_ref);
        assert_eq!(
            encoded
                .windows(wrapped.len())
                .filter(|bytes| *bytes == wrapped.as_slice())
                .count(),
            1
        );
        // Independently encoded from the frozen primitive definitions and literal
        // TaskRef vector, rather than generated by this Rust encoder.
        assert_eq!(encoded.len(), 833);
        assert_eq!(
            Sha256Digest::of(&encoded).to_string(),
            "0dab2a9cae6d5afebbcbcd928ae5a15a49924d66d16add937a38d029d2e92c75"
        );
    }

    #[test]
    fn p0_wire_transcript_round_trip_and_trailing_bytes() {
        let transcript = fixture();
        let encoded = transcript.encode_transcript(PROFILES).unwrap();
        assert_eq!(
            TaskTranscriptV3::decode_transcript(&encoded, PROFILES).unwrap(),
            transcript
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            TaskTranscriptV3::decode_transcript(&trailing, PROFILES),
            Err(TaskWireError::Contract(TaskContractError::TrailingBytes))
        );
        let encoded = transcript.encode_transcript(PROFILES).unwrap();
        let nonce_offset = BUS_SIG_V3_DOMAIN.len() + 8 + transcript.message_id.len() + 16;
        let mut wrong_nonce = encoded.clone();
        wrong_nonce[nonce_offset..nonce_offset + 8].copy_from_slice(&31_u64.to_be_bytes());
        assert!(TaskTranscriptV3::decode_transcript(&wrong_nonce, PROFILES).is_err());
        let parent_offset =
            nonce_offset + 8 + NONCE_LEN_BYTES + 8 + transcript.sender_full_actor_address.len();
        let mut bad_option = encoded;
        bad_option[parent_offset] = 2;
        assert_eq!(
            TaskTranscriptV3::decode_transcript(&bad_option, PROFILES),
            Err(TaskWireError::Contract(TaskContractError::InvalidOptionTag))
        );
        let mut wrapped = encode_bytes_field(&Sha256Digest([1; 32]).encode_typed());
        wrapped.push(0);
        wrapped[..8].copy_from_slice(&55_u64.to_be_bytes());
        assert_eq!(
            decode_wrapped_digest(&mut CanonicalDecoder::new(&wrapped)),
            Err(TaskWireError::Contract(TaskContractError::TrailingBytes))
        );
    }

    #[test]
    fn p0_wire_json_and_binary_frames_round_trip() {
        let frame = signed(fixture());
        let json = frame.encode_json(PROFILES).unwrap();
        assert_eq!(
            PublishTaskV1::decode_json(&json, TASK_BUS_V2_ALPN, PROFILES).unwrap(),
            frame
        );
        let mut binary = frame.encode_binary(PROFILES).unwrap();
        assert_eq!(
            PublishTaskV1::decode_binary(&binary, TASK_BUS_V2_ALPN, PROFILES).unwrap(),
            frame
        );
        binary.push(0);
        assert_eq!(
            PublishTaskV1::decode_binary(&binary, TASK_BUS_V2_ALPN, PROFILES),
            Err(TaskWireError::Contract(TaskContractError::TrailingBytes))
        );
    }

    #[test]
    fn p0_wire_frame_ceiling_is_inclusive_and_precedes_parsing() {
        let mut raw = signed(fixture()).encode_json(PROFILES).unwrap();
        raw.resize(MAX_TASK_WIRE_FRAME_BYTES, b' ');
        assert!(PublishTaskV1::decode_json(&raw, TASK_BUS_V2_ALPN, PROFILES).is_ok());
        raw.push(b' ');
        assert_eq!(
            PublishTaskV1::decode_json(&raw, LEGACY_BUS_V1_ALPN, PROFILES),
            Err(TaskWireError::FrameTooLarge)
        );
        assert_eq!(
            PublishTaskV1::decode_binary(&raw, TASK_BUS_V2_ALPN, PROFILES),
            Err(TaskWireError::FrameTooLarge)
        );
        assert_eq!(
            PublishTaskV1::decode_json(&[], TASK_BUS_V2_ALPN, PROFILES),
            Err(TaskWireError::EmptyFrame)
        );
    }

    #[test]
    fn p0_wire_transcript_encoder_rejects_oversized_canonical_bytes() {
        let mut transcript = fixture();
        let mut body: serde_json::Value = serde_json::from_str(&transcript.body_utf8).unwrap();
        body["display_text"] = serde_json::json!("");
        transcript.body_utf8 = body.to_string();
        let overhead = transcript.encode_transcript(PROFILES).unwrap().len();
        let padding = MAX_TASK_WIRE_FRAME_BYTES - overhead;
        body["display_text"] = serde_json::json!("x".repeat(padding));
        transcript.body_utf8 = body.to_string();
        assert_eq!(
            transcript.encode_transcript(PROFILES).unwrap().len(),
            MAX_TASK_WIRE_FRAME_BYTES
        );
        body["display_text"] = serde_json::json!("x".repeat(padding + 1));
        transcript.body_utf8 = body.to_string();
        assert!(transcript.validate(PROFILES).is_ok());
        assert_eq!(
            transcript.encode_transcript(PROFILES),
            Err(TaskWireError::FrameTooLarge)
        );
    }

    #[test]
    fn p0_wire_duplicate_keys_fail_before_frame_or_body_deserialization() {
        for raw in [
            br#"{"kind":"TaskProposal","kind":"Assignment"}"#.as_slice(),
            br#"{"kind":"TaskProposal","\u006bind":"Assignment"}"#.as_slice(),
            br#"{"nested":{"x":1,"x":2}}"#.as_slice(),
        ] {
            assert_eq!(
                PublishTaskV1::decode_json(raw, TASK_BUS_V2_ALPN, PROFILES),
                Err(TaskWireError::DuplicateJsonKey)
            );
            let body = std::str::from_utf8(raw).unwrap();
            assert_eq!(
                TaskActionableBodyV1::parse(body, TaskMessageKind::Assignment, PROFILES),
                Err(TaskWireError::DuplicateJsonKey)
            );
        }
    }

    #[test]
    fn p0_wire_unknown_fields_bad_types_utf8_and_trailing_json_fail() {
        let mut body = fixture().body_utf8;
        body.insert_str(1, "\"action\":\"dispatch\",");
        assert_eq!(
            TaskActionableBodyV1::parse(&body, TaskMessageKind::Assignment, PROFILES),
            Err(TaskWireError::InvalidJson)
        );
        for raw in [
            b"[]".as_slice(),
            b"{} {}".as_slice(),
            b"{\"x\":\"\xff\"}".as_slice(),
        ] {
            assert_eq!(strict_json_object(raw), Err(TaskWireError::InvalidJson));
        }
        let json = signed(fixture()).encode_json(PROFILES).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        value["sig_verified"] = serde_json::Value::Bool(true);
        assert_eq!(
            PublishTaskV1::decode_json(
                &serde_json::to_vec(&value).unwrap(),
                TASK_BUS_V2_ALPN,
                PROFILES,
            ),
            Err(TaskWireError::InvalidJson)
        );
        let mut value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        value["transcript_hex"] = serde_json::json!([]);
        assert_eq!(
            PublishTaskV1::decode_json(
                &serde_json::to_vec(&value).unwrap(),
                TASK_BUS_V2_ALPN,
                PROFILES,
            ),
            Err(TaskWireError::InvalidJson)
        );
        let mut body: serde_json::Value = serde_json::from_str(&fixture().body_utf8).unwrap();
        body["canonical_payload_hex"] = serde_json::json!(["616263"]);
        assert_eq!(
            TaskActionableBodyV1::parse(&body.to_string(), TaskMessageKind::Assignment, PROFILES),
            Err(TaskWireError::InvalidJson)
        );
    }

    #[test]
    fn p0_wire_lowercase_payload_hex_and_digest_are_mandatory() {
        let body = fixture().body_utf8;
        for invalid in ["6A6263", "61626", "gg6263"] {
            let bad = body.replace("616263", invalid);
            assert_eq!(
                TaskActionableBodyV1::parse(&bad, TaskMessageKind::Assignment, PROFILES),
                Err(TaskWireError::InvalidHex)
            );
        }
        let bad = body.replace("ba7816bf", "BA7816BF");
        assert_eq!(
            TaskActionableBodyV1::parse(&bad, TaskMessageKind::Assignment, PROFILES),
            Err(TaskWireError::InvalidHex)
        );
        let bad = body.replace("616263", "616264");
        assert_eq!(
            TaskActionableBodyV1::parse(&bad, TaskMessageKind::Assignment, PROFILES),
            Err(TaskWireError::PayloadDigestMismatch)
        );
        assert!(decode_lower_hex(&"00".repeat(MAX_SCALAR_BYTES), MAX_SCALAR_BYTES).is_ok());
        assert_eq!(
            decode_lower_hex(&"00".repeat(MAX_SCALAR_BYTES + 1), MAX_SCALAR_BYTES),
            Err(TaskWireError::InvalidHex)
        );
    }

    #[test]
    fn p0_wire_profiles_require_explicit_kind_specific_ratification() {
        let body = fixture().body_utf8;
        assert_eq!(
            TaskActionableBodyV1::parse(&body, TaskMessageKind::Assignment, &[]),
            Err(TaskWireError::UnratifiedPayloadProfile)
        );
        assert_eq!(
            TaskActionableBodyV1::parse(&body, TaskMessageKind::Assignment, &PROFILES[..1]),
            Err(TaskWireError::UnratifiedPayloadProfile)
        );
        let missing = body.replace("\"payload_profile\":\"p0-wire-fixture-v1\",", "");
        assert_eq!(
            TaskActionableBodyV1::parse(&missing, TaskMessageKind::Assignment, PROFILES),
            Err(TaskWireError::UnratifiedPayloadProfile)
        );
    }

    #[test]
    fn p0_wire_malformed_canonical_payload_with_matching_digest_rejected() {
        let mut transcript = fixture();
        transcript.body_utf8 = concat!(
            "{\"payload_profile\":\"p0-wire-fixture-v1\",\"canonical_payload_hex\":\"00\",",
            "\"payload_digest_sha256\":\"",
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d\"}"
        )
        .to_owned();
        assert_eq!(
            TaskActionableBodyV1::parse(&transcript.body_utf8, transcript.message_kind, PROFILES),
            Err(TaskWireError::InvalidCanonicalPayload),
        );
        assert_eq!(
            PublishTaskV1::sign(transcript.clone(), &secret(), PROFILES),
            Err(TaskWireError::InvalidCanonicalPayload),
        );

        // Sign under a permissive test profile so verification exercises the
        // receiving caller's validator on an otherwise authentic frame.
        let permissive_profiles = [RatifiedPayloadProfile {
            kind: TaskMessageKind::Assignment,
            name: "p0-wire-fixture-v1",
            validate_canonical_payload: |_| true,
        }];
        let frame = PublishTaskV1::sign(transcript, &secret(), &permissive_profiles).unwrap();
        let mut permissive_context = context(&frame.transcript.task_ref);
        permissive_context.ratified_profiles = &permissive_profiles;
        assert!(
            frame
                .verify(TASK_BUS_V2_ALPN, &roster(), &permissive_context)
                .is_ok()
        );
        assert_eq!(
            frame.verify(
                TASK_BUS_V2_ALPN,
                &roster(),
                &context(&frame.transcript.task_ref)
            ),
            Err(TaskWireError::InvalidCanonicalPayload),
        );
    }

    #[test]
    fn p0_wire_k1_signature_authenticates_enrolled_principal() {
        let frame = signed(fixture());
        let verified = frame
            .verify(
                TASK_BUS_V2_ALPN,
                &roster(),
                &context(&frame.transcript.task_ref),
            )
            .unwrap();
        assert_eq!(
            verified.authenticated().signer_principal(),
            "rust-principal"
        );
        assert_eq!(verified.authenticated().signer_public_key(), frame.signer_pubkey);
        // Recompute the transported digest on every substitution: only the
        // original K1 signature must remain unable to authenticate these bytes.
        for field in 0..18 {
            let mut substituted = frame.clone();
            let transcript = &mut substituted.transcript;
            match field {
                0 => transcript.message_id.push('x'),
                1 => transcript.issued_at_unix += 1,
                2 => transcript.expires_at_unix += 1,
                3 => transcript.nonce[0] ^= 1,
                4 => transcript.sender_full_actor_address.push('x'),
                5 => transcript.parent_full_actor_address = None,
                6 => transcript.recipient_full_actor_addresses[0].push('x'),
                7 => transcript.room.push('x'),
                8 => transcript.message_kind = TaskMessageKind::CandidateResult,
                9 => transcript.receiver_authority_id.push('x'),
                10 => transcript.task_ref.source_generation += 1,
                11 => transcript.assignment_id = Some("other-assignment".to_owned()),
                12 => transcript.operation_id = Some("other-operation".to_owned()),
                13 => transcript.request_id = Some("request-1".to_owned()),
                14 => transcript.in_reply_to_message_id = Some("reply-1".to_owned()),
                15 => transcript.config_digest.0[0] ^= 1,
                16 => transcript.task_control_digest.0[0] ^= 1,
                _ => transcript.body_utf8.insert(1, ' '),
            }
            substituted.transcript_digest =
                Sha256Digest::of(&transcript.encode_transcript(PROFILES).unwrap());
            assert_eq!(
                substituted.authenticate(TASK_BUS_V2_ALPN, &roster(), PROFILES),
                Err(TaskWireError::SignatureInvalid),
                "field {field}"
            );
        }
        let mut forged = frame;
        forged.signature_ed25519[0] ^= 1;
        assert_eq!(
            forged.authenticate(TASK_BUS_V2_ALPN, &roster(), PROFILES),
            Err(TaskWireError::SignatureInvalid)
        );
    }

    #[test]
    fn p0_wire_body_reformatting_invalidates_signature() {
        let mut frame = signed(fixture());
        frame.transcript.body_utf8.insert(1, ' ');
        let bytes = frame.transcript.encode_transcript(PROFILES).unwrap();
        frame.transcript_digest = Sha256Digest::of(&bytes);
        assert_eq!(
            frame.authenticate(TASK_BUS_V2_ALPN, &roster(), PROFILES),
            Err(TaskWireError::SignatureInvalid)
        );
    }

    #[test]
    fn p0_wire_transported_digest_is_recomputed() {
        let mut frame = signed(fixture());
        frame.transcript_digest = Sha256Digest([0; 32]);
        assert_eq!(
            frame.authenticate(TASK_BUS_V2_ALPN, &roster(), PROFILES),
            Err(TaskWireError::TranscriptDigestMismatch)
        );
    }

    #[test]
    fn p0_wire_recipient_order_is_encoded_order_without_duplicates() {
        let mut transcript = fixture();
        // B("Z#x") sorts before B("AA#x") because its byte length is shorter.
        transcript.recipient_full_actor_addresses = vec!["Z#x".to_owned(), "AA#x".to_owned()];
        assert!(transcript.validate(PROFILES).is_ok());
        let mut encoded = transcript.encode_transcript(PROFILES).unwrap();
        let ordered =
            encode_sorted_distinct_set(vec![encode_str_field("Z#x"), encode_str_field("AA#x")])
                .unwrap();
        let offset = encoded
            .windows(ordered.len())
            .position(|bytes| bytes == ordered.as_slice())
            .unwrap();
        let mut reversed = encode_u64(2).to_vec();
        reversed.extend(encode_str_field("AA#x"));
        reversed.extend(encode_str_field("Z#x"));
        encoded[offset..offset + reversed.len()].copy_from_slice(&reversed);
        assert_eq!(
            TaskTranscriptV3::decode_transcript(&encoded, PROFILES),
            Err(TaskWireError::Contract(TaskContractError::InvalidSetOrder))
        );
        transcript.recipient_full_actor_addresses.reverse();
        assert_eq!(
            transcript.validate(PROFILES),
            Err(TaskWireError::InvalidRecipientSet)
        );
        transcript.recipient_full_actor_addresses = vec!["Z#x".to_owned(); 2];
        assert_eq!(
            transcript.validate(PROFILES),
            Err(TaskWireError::InvalidRecipientSet)
        );
        transcript.recipient_full_actor_addresses.clear();
        assert_eq!(
            transcript.validate(PROFILES),
            Err(TaskWireError::InvalidRecipientSet)
        );
    }

    #[test]
    fn p0_wire_addresses_require_exact_canonical_instance_bytes() {
        for invalid in ["RUST", "@RUST#sender", " RUST#sender", "rust#sender", "ALL"] {
            let mut transcript = fixture();
            transcript.sender_full_actor_address = invalid.to_owned();
            assert!(transcript.validate(PROFILES).is_err(), "{invalid}");
        }
        assert!(canonical_actor("Brian").is_ok());
        assert!(canonical_actor("RUST#opaque.Case-1").is_ok());
    }

    #[test]
    fn p0_wire_parent_lineage_must_be_present_and_canonical_to_be_asserted() {
        let mut transcript = fixture();
        assert_eq!(
            transcript.require_declared_parent().unwrap(),
            "DELIVERY#parent"
        );
        transcript.parent_full_actor_address = None;
        assert!(transcript.validate(PROFILES).is_ok());
        assert_eq!(
            transcript.require_declared_parent(),
            Err(TaskWireError::InvalidActorAddress)
        );
        transcript.parent_full_actor_address = Some("DELIVERY".to_owned());
        assert_eq!(
            transcript.validate(PROFILES),
            Err(TaskWireError::InvalidActorAddress)
        );
    }

    #[test]
    fn p0_wire_each_kind_requires_its_original_correlation_ids() {
        for kind in [
            TaskMessageKind::TaskProposal,
            TaskMessageKind::Assignment,
            TaskMessageKind::CandidateResult,
            TaskMessageKind::TaskReceipt,
        ] {
            let mut transcript = fixture();
            transcript.message_kind = kind;
            transcript.operation_id = None;
            assert_eq!(
                transcript.validate(PROFILES),
                Err(TaskWireError::InvalidCorrelation)
            );
            transcript.operation_id = Some("operation-1".to_owned());
            transcript.assignment_id = None;
            assert_eq!(
                transcript.validate(PROFILES).is_err(),
                matches!(
                    kind,
                    TaskMessageKind::Assignment | TaskMessageKind::CandidateResult
                )
            );
        }
        for invalid in ["", " spaced", "tab\tinside", "line\nfeed"] {
            let mut transcript = fixture();
            transcript.request_id = Some(invalid.to_owned());
            assert!(transcript.validate(PROFILES).is_err());
        }
    }

    #[test]
    fn p0_wire_unknown_kinds_domains_and_length_overflow_fail_closed() {
        assert_eq!(
            "assignment".parse::<TaskMessageKind>(),
            Err(TaskWireError::UnknownMessageKind)
        );
        let mut raw = fixture().encode_transcript(PROFILES).unwrap();
        raw[0] ^= 1;
        assert_eq!(
            TaskTranscriptV3::decode_transcript(&raw, PROFILES),
            Err(TaskWireError::UnsupportedFrame)
        );
        let mut raw = BUS_SIG_V3_DOMAIN.to_vec();
        raw.extend(u64::MAX.to_be_bytes());
        assert!(matches!(
            TaskTranscriptV3::decode_transcript(&raw, PROFILES),
            Err(TaskWireError::Contract(TaskContractError::LimitExceeded(_)))
        ));
        let nested = format!("{{\"x\":{}0{}}}", "[".repeat(128), "]".repeat(128));
        assert_eq!(
            strict_json_object(nested.as_bytes()),
            Err(TaskWireError::InvalidJson)
        );
    }

    #[test]
    fn p0_wire_unenrolled_wrong_seat_repo_config_or_inactive_signer_holds() {
        let frame = signed(fixture());
        for field in 0..6 {
            let mut entries = roster();
            match field {
                0 => entries[0].seat = "DELIVERY".to_owned(),
                1 => entries[0].repo_id = "other-repo".to_owned(),
                2 => entries[0].workspace_id = "other-workspace".to_owned(),
                3 => entries[0].active = false,
                4 => entries[0].signer_pubkey = alternate_secret().public(),
                _ => entries[0].config_digest = Sha256Digest([9; 32]),
            }
            assert_eq!(
                frame.authenticate(TASK_BUS_V2_ALPN, &entries, PROFILES),
                Err(TaskWireError::SignerNotEnrolled)
            );
        }
        let mut entries = roster();
        entries.push(entries[0].clone());
        assert_eq!(
            frame.authenticate(TASK_BUS_V2_ALPN, &entries, PROFILES),
            Err(TaskWireError::SignerNotEnrolled)
        );
    }

    #[test]
    fn p0_wire_audience_and_current_authority_pins_are_exact() {
        let frame = signed(fixture());
        let mut expected_ref = frame.transcript.task_ref.clone();
        expected_ref.source_generation += 1;
        assert_eq!(
            frame.verify(TASK_BUS_V2_ALPN, &roster(), &context(&expected_ref)),
            Err(TaskWireError::AuthorityBindingMismatch)
        );
        let mut checks = context(&frame.transcript.task_ref);
        checks.recipient_full_actor_address = "WORKHORSE#other";
        assert_eq!(
            frame.verify(TASK_BUS_V2_ALPN, &roster(), &checks),
            Err(TaskWireError::AudienceMismatch)
        );
        checks = context(&frame.transcript.task_ref);
        checks.receiver_authority_id = "authority-2";
        assert_eq!(
            frame.verify(TASK_BUS_V2_ALPN, &roster(), &checks),
            Err(TaskWireError::AudienceMismatch)
        );
        checks = context(&frame.transcript.task_ref);
        checks.task_control_digest = Sha256Digest([9; 32]);
        assert_eq!(
            frame.verify(TASK_BUS_V2_ALPN, &roster(), &checks),
            Err(TaskWireError::AuthorityBindingMismatch)
        );
        checks = context(&frame.transcript.task_ref);
        checks.config_digest = Sha256Digest([9; 32]);
        assert_eq!(
            frame.verify(TASK_BUS_V2_ALPN, &roster(), &checks),
            Err(TaskWireError::AuthorityBindingMismatch)
        );
        checks = context(&frame.transcript.task_ref);
        checks.required_key_epoch += 1;
        assert_eq!(
            frame.verify(TASK_BUS_V2_ALPN, &roster(), &checks),
            Err(TaskWireError::AuthorityBindingMismatch)
        );
    }

    #[test]
    fn p0_wire_enrollment_actions_and_current_grants_are_both_required() {
        let frame = signed(fixture());
        let mut entries = roster();
        entries[0].allowed_actions.clear();
        assert_eq!(
            frame.verify(
                TASK_BUS_V2_ALPN,
                &entries,
                &context(&frame.transcript.task_ref)
            ),
            Err(TaskWireError::ActionNotAllowed)
        );
        let mut checks = context(&frame.transcript.task_ref);
        checks.current_granted_actions = &[];
        assert_eq!(
            frame.verify(TASK_BUS_V2_ALPN, &roster(), &checks),
            Err(TaskWireError::ActionNotAllowed)
        );
    }

    #[test]
    fn p0_wire_clock_holds_and_validity_boundaries_do_not_extend_deadlines() {
        let frame = signed(fixture());
        let mut checks = context(&frame.transcript.task_ref);
        for (clock, expected) in [
            (HostClockState::ClockRollback, TaskWireError::ClockRollback),
            (
                HostClockState::TimeUnavailable,
                TaskWireError::TimeUnavailable,
            ),
            (
                HostClockState::Verified { now_unix: 99 },
                TaskWireError::NotYetValid,
            ),
            (
                HostClockState::Verified { now_unix: 201 },
                TaskWireError::Expired,
            ),
        ] {
            checks.host_clock = clock;
            assert_eq!(
                frame.verify(TASK_BUS_V2_ALPN, &roster(), &checks),
                Err(expected)
            );
        }
        for now_unix in [100, 200] {
            checks.host_clock = HostClockState::Verified { now_unix };
            assert!(frame.verify(TASK_BUS_V2_ALPN, &roster(), &checks).is_ok());
        }
        let mut bad = fixture();
        bad.expires_at_unix = 99;
        assert_eq!(
            bad.validate(PROFILES),
            Err(TaskWireError::InvalidValidityWindow)
        );
    }

    #[test]
    fn p0_wire_protocol_failure_never_converts_to_v2_retry() {
        let frame = signed(fixture());
        let json = frame.encode_json(PROFILES).unwrap();
        let binary = frame.encode_binary(PROFILES).unwrap();
        for alpn in [
            LEGACY_BUS_V1_ALPN,
            b"".as_slice(),
            b"chinwag/bus/3".as_slice(),
        ] {
            assert_eq!(
                require_task_protocol(alpn),
                Err(TaskWireError::ProtocolDowngradeForbidden)
            );
            assert_eq!(
                PublishTaskV1::decode_json(&json, alpn, PROFILES),
                Err(TaskWireError::ProtocolDowngradeForbidden)
            );
            assert_eq!(
                PublishTaskV1::decode_binary(&binary, alpn, PROFILES),
                Err(TaskWireError::ProtocolDowngradeForbidden)
            );
            assert_eq!(
                frame.authenticate(alpn, &roster(), PROFILES),
                Err(TaskWireError::ProtocolDowngradeForbidden)
            );
        }
    }

    #[test]
    fn p0_wire_replay_returns_recorded_outcome_and_holds_uncertain_reservation() {
        let message = verified(fixture());
        let mut ledger = ReplayLedger::default();
        assert_eq!(
            ledger.reserve(&message).unwrap(),
            ReplayDisposition::FirstSeen
        );
        assert_eq!(
            ledger.reserve(&message),
            Err(TaskWireError::ReplayOutcomePending)
        );
        ledger
            .record_outcome(&message, "recorded-original-outcome")
            .unwrap();
        assert_eq!(
            ledger.reserve(&message).unwrap(),
            ReplayDisposition::DuplicateRecordedOutcome {
                outcome: "recorded-original-outcome".to_owned(),
            }
        );
        assert_eq!(
            ledger.record_outcome(&message, "different-outcome"),
            Err(TaskWireError::ReplayConflict)
        );
    }

    #[test]
    fn p0_wire_replay_conflicts_on_changed_bytes_or_original_operation() {
        let message = verified(fixture());
        let mut ledger = ReplayLedger::default();
        ledger.reserve(&message).unwrap();
        ledger.record_outcome(&message, "original").unwrap();
        for change in 0..2 {
            let mut transcript = fixture();
            if change == 0 {
                transcript.body_utf8.insert(1, ' ');
            } else {
                transcript.operation_id = Some("other-operation".to_owned());
            }
            assert_eq!(
                ledger.reserve(&verified(transcript)),
                Err(TaskWireError::ReplayConflict)
            );
        }
        let frame = signed(fixture());
        let mut checks = context(&frame.transcript.task_ref);
        checks.host_clock = HostClockState::Verified { now_unix: 201 };
        assert_eq!(
            frame.verify(TASK_BUS_V2_ALPN, &roster(), &checks),
            Err(TaskWireError::Expired)
        );
        let authenticated = frame
            .authenticate(TASK_BUS_V2_ALPN, &roster(), PROFILES)
            .unwrap();
        assert!(matches!(
            ledger
                .lookup_recorded_outcome(&authenticated, true)
                .unwrap(),
            Some(ReplayDisposition::DuplicateRecordedOutcome { .. })
        ));
        assert_eq!(
            ledger.lookup_recorded_outcome(&authenticated, false),
            Err(TaskWireError::ReadPermissionRequired)
        );
    }
}
