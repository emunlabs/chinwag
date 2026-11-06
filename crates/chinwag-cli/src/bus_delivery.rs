//! Evidence for publication and existing-consumer processing is kept separate.
//!
//! A legacy bus ACK authenticates a publication response. It supplies neither
//! durable-storage proof nor a supported existing-conversation host receipt.

use crate::agent_instance::parse_recipients;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_RECORD_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryError {
    Invalid, Correlation, Signature, Conflict, Persistence, Bounds,
    Unsupported, NoBinding, Revoked, Expired, ClockUnavailable, ClockRollback,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryExpectation {
    pub id: String,
    pub message_id: String,
    pub message_digest: String,
    pub sender: String,
    pub recipient: String,
    pub room: String,
    pub task: Option<String>,
    pub operation: Option<String>,
    pub created_at: u64,
    pub deadline: u64,
}

fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn bounded(s: &str) -> bool { !s.is_empty() && s.len() <= 256 }
fn full_actor(s: &str) -> bool {
    crate::agent_instance::ActorAddress::parse(s)
        .is_ok_and(|a| a.instance().is_some() && a.to_string() == s)
}
fn hash_string(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl DeliveryExpectation {
    fn validate(&self) -> Result<(), DeliveryError> {
        if !bounded(&self.id) || !bounded(&self.message_id) || !hash_string(&self.message_digest)
            || !full_actor(&self.sender) || !full_actor(&self.recipient) || !bounded(&self.room)
            || self.task.as_ref().is_some_and(|s| !bounded(s))
            || self.operation.as_ref().is_some_and(|s| !bounded(s))
            || self.deadline <= self.created_at || self.deadline - self.created_at > 300
        { return Err(DeliveryError::Invalid); }
        Ok(())
    }
    pub fn commitment(&self) -> Result<String, DeliveryError> {
        self.validate()?;
        let mut bytes = b"chinwag-consumer-expectation-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| DeliveryError::Invalid)?);
        Ok(digest(&bytes))
    }
}

/// Implementations are trusted host/storage adapters, not data supplied by a
/// bus sender. No supported production host profile is exposed by this unit.
pub trait ConsumerEvidenceProvider {
    fn verified_now(&self) -> Result<u64, DeliveryError>;
    fn current_binding(&self, recipient: &str) -> Result<ConsumerBinding, DeliveryError>;
}

/// Positive binding construction is confined to controlled fixtures until a
/// real existing-conversation adapter and its provenance are separately admitted.
#[derive(Clone)]
pub struct ConsumerBinding {
    recipient: String,
    binding_id: String,
    generation: u64,
    delegation: String,
    host: String,
    conversation: String,
    issued_at: u64,
    expires_at: u64,
    principal: Option<iroh::EndpointId>,
    revoked: bool,
    supported: bool,
    timer_armed: bool,
    turn: Option<ConsumerTurnEvidence>,
}

#[derive(Clone)]
struct ConsumerTurnEvidence {
    reference: String,
    binding_generation: u64,
    observed_at: u64,
    inbox_read_at: u64,
    inbox_cursor: String,
    evidence_digest: String,
    message_id: String,
    message_digest: String,
    scheduler_digest: Option<String>,
}

impl ConsumerBinding {
    pub fn unsupported(recipient: &str) -> Self {
        Self { recipient: recipient.to_owned(), binding_id: String::new(), generation: 0,
            delegation: String::new(), host: String::new(), conversation: String::new(),
            issued_at: 0, expires_at: 0, principal: None, revoked: false,
            supported: false, timer_armed: false, turn: None }
    }
    fn validate(&self, recipient: &str, now: u64) -> Result<(), DeliveryError> {
        if !self.supported { return Err(DeliveryError::Unsupported); }
        if self.recipient != recipient || !full_actor(recipient) || self.generation == 0
            || !bounded(&self.binding_id) || !bounded(&self.delegation) || !bounded(&self.host)
            || crate::agent_instance::ActorAddress::parse(recipient).ok()
                .and_then(|a| a.instance().map(str::to_owned)).as_deref() != Some(self.conversation.as_str())
            || self.principal.is_none() || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 300 || now < self.issued_at
        { return Err(DeliveryError::Correlation); }
        if self.revoked { return Err(DeliveryError::Revoked); }
        if now > self.expires_at { return Err(DeliveryError::Expired); }
        Ok(())
    }
    fn fresh_turn(&self, now: u64) -> Option<&ConsumerTurnEvidence> {
        self.turn.as_ref().filter(|t| t.binding_generation == self.generation
            && bounded(&t.reference) && bounded(&t.inbox_cursor) && hash_string(&t.evidence_digest)
            && self.issued_at <= t.observed_at && t.observed_at <= t.inbox_read_at
            && t.inbox_read_at <= now && now - t.observed_at <= 120)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsumerLifecycle { Active, CadenceStale, Stopped, Expired, Unsupported, Held, Unknown }

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConsumerCadenceSnapshot {
    pub full_actor: String,
    pub conversation: Option<String>,
    pub host: Option<String>,
    pub binding_id: Option<String>,
    pub binding_generation: Option<u64>,
    pub standing_delegation: Option<String>,
    pub lease_issued_at: Option<u64>,
    pub lease_expires_at: Option<u64>,
    pub profile: &'static str,
    pub cadence_seconds: u64,
    pub max_gap_seconds: u64,
    pub host_timer_id: Option<String>,
    pub timer_armed_at: Option<u64>,
    pub state: ConsumerLifecycle,
    pub reason: &'static str,
    pub observed_at: Option<u64>,
    pub configured_timer_armed: bool,
    pub last_actual_turn_at: Option<u64>,
    pub last_turn_ref: Option<String>,
    pub last_inbox_read_at: Option<u64>,
    pub last_inbox_cursor: Option<String>,
    pub evidence_digest: Option<String>,
    pub original_message_id: Option<String>,
    pub original_message_digest: Option<String>,
}
impl ConsumerCadenceSnapshot {
    /// A task owns neither the standing binding nor its retirement authority.
    pub fn after_task_closed(&self) -> Self { self.clone() }
}

pub fn consumer_cadence(provider: &impl ConsumerEvidenceProvider, recipient: &str) -> ConsumerCadenceSnapshot {
    let mut snapshot = ConsumerCadenceSnapshot {
        full_actor: recipient.to_owned(), conversation: None, host: None,
        binding_id: None, binding_generation: None, standing_delegation: None,
        lease_issued_at: None, lease_expires_at: None,
        profile: "CONSUMER01_CONTROLLED_TIME_AND_HOST_FIXTURE_V1",
        cadence_seconds: 60, max_gap_seconds: 120, host_timer_id: None, timer_armed_at: None,
        state: ConsumerLifecycle::Unknown, configured_timer_armed: false, last_actual_turn_at: None,
        reason: "NO_CONSUMER_BINDING", observed_at: None, last_turn_ref: None,
        last_inbox_read_at: None, last_inbox_cursor: None, evidence_digest: None,
        original_message_id: None, original_message_digest: None,
    };
    let binding = match provider.current_binding(recipient) {
        Ok(b) => b,
        Err(_) => return snapshot,
    };
    if !binding.supported {
        snapshot.state = ConsumerLifecycle::Unsupported;
        snapshot.reason = "UNSUPPORTED_EXISTING_CONVERSATION_CONTROL";
        return snapshot;
    }
    snapshot.conversation = Some(binding.conversation.clone());
    snapshot.host = Some(binding.host.clone());
    snapshot.binding_id = Some(binding.binding_id.clone());
    snapshot.binding_generation = Some(binding.generation);
    snapshot.standing_delegation = Some(binding.delegation.clone());
    snapshot.lease_issued_at = Some(binding.issued_at);
    snapshot.lease_expires_at = Some(binding.expires_at);
    snapshot.configured_timer_armed = binding.timer_armed;
    if let Some(turn) = &binding.turn {
        snapshot.last_actual_turn_at = Some(turn.observed_at);
        snapshot.last_turn_ref = Some(turn.reference.clone());
        snapshot.last_inbox_read_at = Some(turn.inbox_read_at);
        snapshot.last_inbox_cursor = Some(turn.inbox_cursor.clone());
        snapshot.evidence_digest = Some(turn.evidence_digest.clone());
        snapshot.original_message_id = Some(turn.message_id.clone());
        snapshot.original_message_digest = Some(turn.message_digest.clone());
    }
    let checked = provider.verified_now().and_then(|now| {
        snapshot.observed_at = Some(now);
        binding.validate(recipient, now).map(|()| now)
    });
    snapshot.state = match checked {
        Ok(now) => match binding.fresh_turn(now) {
            Some(turn) => { snapshot.last_actual_turn_at = Some(turn.observed_at); ConsumerLifecycle::Active }
            None => ConsumerLifecycle::CadenceStale,
        },
        Err(DeliveryError::Unsupported) => ConsumerLifecycle::Unsupported,
        Err(DeliveryError::Revoked) => ConsumerLifecycle::Stopped,
        Err(DeliveryError::Expired) => ConsumerLifecycle::Expired,
        Err(DeliveryError::ClockUnavailable) => ConsumerLifecycle::Unknown,
        Err(_) => ConsumerLifecycle::Held,
    };
    snapshot.reason = match snapshot.state {
        ConsumerLifecycle::Active => "CURRENT_BINDING_AND_ACTUAL_QUALIFIED_INBOX_TURN",
        ConsumerLifecycle::CadenceStale => "NO_FRESH_ACTUAL_QUALIFIED_INBOX_TURN",
        ConsumerLifecycle::Stopped => "CURRENT_BINDING_REVOKED",
        ConsumerLifecycle::Expired => "CURRENT_BINDING_LEASE_EXPIRED",
        ConsumerLifecycle::Unsupported => "UNSUPPORTED_EXISTING_CONVERSATION_CONTROL",
        ConsumerLifecycle::Unknown => "VERIFIED_TIME_UNAVAILABLE",
        ConsumerLifecycle::Held => "BINDING_OR_TIME_VALIDATION_FAILED",
    };
    snapshot
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessingKind { ProcessingStarted, ProcessingRejected }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingReceipt {
    pub schema: String,
    pub original_message_id: String,
    pub original_message_digest_sha256: String,
    pub original_sender_full_actor: String,
    pub recipient_full_actor: String,
    pub original_task_id: Option<String>,
    pub original_operation_id: Option<String>,
    pub delivery_expectation_id: String,
    pub delivery_expectation_digest: String,
    pub original_delivery_deadline: u64,
    pub consumer_binding_id: String,
    pub consumer_binding_generation: u64,
    pub consumer_turn_ref: Option<String>,
    pub host_scheduling_receipt_digest: Option<String>,
    pub observed_at: u64,
    pub kind: ProcessingKind,
    pub reason: Option<String>,
}

/// A view of the existing signed seven-field bus envelope. It is not a new
/// network envelope or a replacement for allowed-signers/current-role policy.
pub struct ProcessingEnvelope {
    pub id: String,
    pub timestamp: u64,
    pub sender: String,
    pub recipient: String,
    pub room: String,
    pub task: Option<String>,
    pub body: String,
    pub signature: [u8; 64],
}
impl ProcessingEnvelope {
    pub fn signing_payload(&self) -> String {
        let ts = self.timestamp.to_string();
        let fields = [self.id.as_str(), &ts, &self.sender, &self.recipient,
            &self.room, self.task.as_deref().unwrap_or(""), &self.body];
        format!("chinwag-bus-sig-v2|{}", fields.iter()
            .map(|s| format!("{}:{s}", s.len())).collect::<Vec<_>>().join("|"))
    }
}

/// Storage must perform an atomic original-preimage compare, durable commit
/// and recovery readback. No production storage adapter is installed here.
pub trait ConsumerOutcomeStore {
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, DeliveryError>;
    fn commit(&mut self, key: &str, previous: Option<&[u8]>, next: &[u8]) -> Result<(), DeliveryError>;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOutcome { id: String, fingerprint: String, kind: ProcessingKind, observed_at: u64 }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeRecord { schema: String, expectation: DeliveryExpectation, outcome: Option<StoredOutcome> }

/// The immutable original expectation is registered before a processing ACK.
/// A receipt cannot manufacture a deadline or restore a missing registration.
pub struct RegisteredExpectation { original: DeliveryExpectation, key: String }

#[derive(Debug, PartialEq, Eq)]
pub struct JoinedProcessing {
    pub kind: ProcessingKind,
    pub observed_at: u64,
    pub historical_replay: bool,
    pub work_started: &'static str,
}

fn load_record(store: &impl ConsumerOutcomeStore, key: &str) -> Result<(Vec<u8>, OutcomeRecord), DeliveryError> {
    let bytes = store.load(key)?.ok_or(DeliveryError::Persistence)?;
    if bytes.len() > MAX_RECORD_BYTES { return Err(DeliveryError::Bounds); }
    let record: OutcomeRecord = serde_json::from_slice(&bytes).map_err(|_| DeliveryError::Persistence)?;
    if record.schema != "chinwag.consumer-outcome.v1" || record.expectation.commitment()? != key {
        return Err(DeliveryError::Correlation);
    }
    Ok((bytes, record))
}

impl RegisteredExpectation {
    pub fn register(original: DeliveryExpectation, provider: &impl ConsumerEvidenceProvider,
        store: &mut impl ConsumerOutcomeStore) -> Result<Self, DeliveryError> {
        let key = original.commitment()?;
        if provider.verified_now()? != original.created_at { return Err(DeliveryError::Correlation); }
        let record = OutcomeRecord { schema: "chinwag.consumer-outcome.v1".into(), expectation: original.clone(), outcome: None };
        let bytes = serde_json::to_vec(&record).map_err(|_| DeliveryError::Invalid)?;
        store.commit(&key, None, &bytes)?;
        if store.load(&key)?.as_deref() != Some(bytes.as_slice()) { return Err(DeliveryError::Persistence); }
        Ok(Self { original, key })
    }
    pub fn reopen(key: &str, store: &impl ConsumerOutcomeStore) -> Result<Self, DeliveryError> {
        let (_, record) = load_record(store, key)?;
        Ok(Self { original: record.expectation, key: key.to_owned() })
    }
    pub fn key(&self) -> &str { &self.key }
    pub fn join(&self, envelope: &ProcessingEnvelope, provider: &impl ConsumerEvidenceProvider,
        store: &mut impl ConsumerOutcomeStore) -> Result<JoinedProcessing, DeliveryError> {
        if !bounded(&envelope.id) || envelope.body.len() > 16_384
            || !bounded(&envelope.sender) || !bounded(&envelope.recipient) || !bounded(&envelope.room)
            || envelope.task.as_ref().is_some_and(|s| !bounded(s))
        { return Err(DeliveryError::Bounds); }
        let binding = provider.current_binding(&self.original.recipient)?;
        if !binding.supported { return Err(DeliveryError::Unsupported); }
        let (prior, mut record) = load_record(store, &self.key)?;
        if record.expectation != self.original { return Err(DeliveryError::Correlation); }
        let payload = envelope.signing_payload();
        let mut fingerprint_bytes = payload.as_bytes().to_vec();
        fingerprint_bytes.extend(envelope.signature);
        let fingerprint = digest(&fingerprint_bytes);
        if let Some(outcome) = &record.outcome {
            return if outcome.id == envelope.id && outcome.fingerprint == fingerprint {
                Ok(JoinedProcessing { kind: outcome.kind.clone(), observed_at: outcome.observed_at,
                    historical_replay: true, work_started: "UNKNOWN" })
            } else { Err(DeliveryError::Conflict) };
        }
        let now = provider.verified_now()?;
        binding.validate(&self.original.recipient, now)?;
        if now > self.original.deadline { return Err(DeliveryError::Expired); }
        let principal = binding.principal.as_ref().ok_or(DeliveryError::Signature)?;
        principal.verify(payload.as_bytes(), &iroh::Signature::from_bytes(&envelope.signature))
            .map_err(|_| DeliveryError::Signature)?;
        let receipt: ProcessingReceipt = serde_json::from_str(&envelope.body).map_err(|_| DeliveryError::Invalid)?;
        let turn = binding.fresh_turn(now).ok_or(DeliveryError::Correlation)?;
        if receipt.schema != "chinwag.consumer-processing-receipt.v1"
            || receipt.original_message_id != self.original.message_id
            || receipt.original_message_digest_sha256 != self.original.message_digest
            || receipt.original_sender_full_actor != self.original.sender
            || receipt.recipient_full_actor != self.original.recipient
            || receipt.original_task_id != self.original.task
            || receipt.original_operation_id != self.original.operation
            || receipt.delivery_expectation_id != self.original.id
            || receipt.delivery_expectation_digest != self.key
            || receipt.original_delivery_deadline != self.original.deadline
            || receipt.consumer_binding_id != binding.binding_id
            || receipt.consumer_binding_generation != binding.generation
            || receipt.consumer_turn_ref.as_deref() != Some(turn.reference.as_str())
            || turn.message_id != self.original.message_id || turn.message_digest != self.original.message_digest
            || receipt.host_scheduling_receipt_digest.as_ref().is_some_and(|d| Some(d) != turn.scheduler_digest.as_ref())
            || receipt.observed_at < self.original.created_at || receipt.observed_at > now
            || receipt.observed_at < turn.inbox_read_at
            || receipt.observed_at > self.original.deadline || envelope.timestamp != receipt.observed_at
            || envelope.sender != self.original.recipient || envelope.recipient != self.original.sender
            || envelope.task != self.original.task || envelope.room != self.original.room
            || receipt.reason.as_ref().is_some_and(|s| s.len() > 256)
        { return Err(DeliveryError::Correlation); }
        record.outcome = Some(StoredOutcome { id: envelope.id.clone(), fingerprint,
            kind: receipt.kind.clone(), observed_at: receipt.observed_at });
        let bytes = serde_json::to_vec(&record).map_err(|_| DeliveryError::Invalid)?;
        if bytes.len() > MAX_RECORD_BYTES { return Err(DeliveryError::Bounds); }
        store.commit(&self.key, Some(&prior), &bytes)?;
        if store.load(&self.key)?.as_deref() != Some(bytes.as_slice()) { return Err(DeliveryError::Persistence); }
        Ok(JoinedProcessing { kind: receipt.kind, observed_at: receipt.observed_at,
            historical_replay: false, work_started: "UNKNOWN" })
    }
}

pub struct PublicationAck<'a> {
    pub message_id: &'a str,
    pub ok: bool,
    pub signature_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct RecipientFacts {
    pub recipient: String,
    pub consumer_binding: &'static str,
    pub scheduling: &'static str,
    pub processing_ack: &'static str,
    pub work_started: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct PublicationReport {
    pub schema: &'static str,
    pub completion_scope: &'static str,
    pub original_message_id: String,
    pub original_message_digest_sha256: String,
    pub publication_acknowledged: bool,
    pub persistence: &'static str,
    pub recipients: Vec<RecipientFacts>,
}

/// Report only facts supplied by the legacy publication API. Receiver counts
/// deliberately do not enter this interface. A future supported host adapter
/// must supply separate, authenticated evidence before processing can advance.
pub fn legacy_publication_report(
    message_id: &str,
    digest: &str,
    recipients: Option<&str>,
    ack: PublicationAck<'_>,
) -> PublicationReport {
    let recipients = recipients
        .and_then(|raw| parse_recipients(raw).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|recipient| RecipientFacts {
            recipient: recipient.to_string(),
            consumer_binding: "UNKNOWN",
            scheduling: "UNSUPPORTED",
            processing_ack: "UNKNOWN",
            work_started: "UNKNOWN",
            reason: "UNSUPPORTED_EXISTING_CONVERSATION_CONTROL",
        })
        .collect();
    PublicationReport {
        schema: "chinwag.delivery-report.v1",
        completion_scope: "PUBLISH_ONLY",
        original_message_id: message_id.to_owned(),
        original_message_digest_sha256: digest.to_owned(),
        publication_acknowledged: !message_id.is_empty()
            && ack.ok
            && ack.signature_verified
            && ack.message_id == message_id,
        persistence: "UNKNOWN",
        recipients,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct Host {
        now: Result<u64, DeliveryError>,
        binding: ConsumerBinding,
        key: iroh::SecretKey,
    }
    impl ConsumerEvidenceProvider for Host {
        fn verified_now(&self) -> Result<u64, DeliveryError> { self.now }
        fn current_binding(&self, _: &str) -> Result<ConsumerBinding, DeliveryError> { Ok(self.binding.clone()) }
    }
    struct Journal {
        root: tempfile::TempDir,
        writes: usize,
        fail_before: bool,
        fail_after: bool,
        corrupt_readback: bool,
    }
    impl ConsumerOutcomeStore for Journal {
        fn load(&self, key: &str) -> Result<Option<Vec<u8>>, DeliveryError> {
            if !hash_string(key) { return Err(DeliveryError::Invalid); }
            match std::fs::read(self.root.path().join(key)) {
                Ok(mut bytes) => {
                    if self.corrupt_readback && self.writes >= 2 { bytes.push(b' '); }
                    Ok(Some(bytes))
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(DeliveryError::Persistence),
            }
        }
        fn commit(&mut self, key: &str, previous: Option<&[u8]>, next: &[u8]) -> Result<(), DeliveryError> {
            if self.fail_before { return Err(DeliveryError::Persistence); }
            if self.load(key)?.as_deref() != previous { return Err(DeliveryError::Conflict); }
            let tmp = self.root.path().join("next");
            let mut file = std::fs::File::create(&tmp).map_err(|_| DeliveryError::Persistence)?;
            file.write_all(next).and_then(|()| file.sync_all()).map_err(|_| DeliveryError::Persistence)?;
            std::fs::rename(&tmp, self.root.path().join(key)).map_err(|_| DeliveryError::Persistence)?;
            std::fs::File::open(self.root.path()).and_then(|f| f.sync_all()).map_err(|_| DeliveryError::Persistence)?;
            self.writes += 1;
            if self.fail_after { return Err(DeliveryError::Persistence); }
            Ok(())
        }
    }
    fn fixture() -> (Host, Journal, RegisteredExpectation) {
        let key = iroh::SecretKey::from_bytes(&[7; 32]);
        let original = DeliveryExpectation { id: "expect-1".into(), message_id: "original".into(),
            message_digest: "ab".repeat(32), sender: "WORKHORSE#owner".into(), recipient: "QA#target".into(),
            room: "#eng".into(), task: Some("consumer01".into()), operation: Some("original-op".into()),
            created_at: 100, deadline: 250 };
        let mut host = Host { now: Ok(100), binding: ConsumerBinding {
            recipient: original.recipient.clone(), binding_id: "binding-1".into(), generation: 4,
            delegation: "standing-consumer-grant".into(), host: "controlled-host".into(), conversation: "target".into(),
            issued_at: 100, expires_at: 400, principal: Some(key.public()), revoked: false,
            supported: true, timer_armed: true, turn: Some(ConsumerTurnEvidence {
                reference: "turn-1".into(), binding_generation: 4, observed_at: 110, inbox_read_at: 115,
                inbox_cursor: "qualified-read-1".into(), evidence_digest: "cd".repeat(32),
                message_id: original.message_id.clone(), message_digest: original.message_digest.clone(), scheduler_digest: None,
            }),
        }, key };
        let mut store = Journal { root: tempfile::tempdir().unwrap(), writes: 0, fail_before: false, fail_after: false, corrupt_readback: false };
        let registered = RegisteredExpectation::register(original, &host, &mut store).unwrap();
        host.now = Ok(120);
        (host, store, registered)
    }
    fn receipt(host: &Host, original: &RegisteredExpectation) -> ProcessingReceipt {
        let e = &original.original;
        ProcessingReceipt { schema: "chinwag.consumer-processing-receipt.v1".into(),
            original_message_id: e.message_id.clone(), original_message_digest_sha256: e.message_digest.clone(),
            original_sender_full_actor: e.sender.clone(), recipient_full_actor: e.recipient.clone(),
            original_task_id: e.task.clone(), original_operation_id: e.operation.clone(),
            delivery_expectation_id: e.id.clone(), delivery_expectation_digest: original.key.clone(),
            original_delivery_deadline: e.deadline, consumer_binding_id: host.binding.binding_id.clone(),
            consumer_binding_generation: host.binding.generation,
            consumer_turn_ref: host.binding.turn.as_ref().map(|t| t.reference.clone()),
            host_scheduling_receipt_digest: None, observed_at: 116, kind: ProcessingKind::ProcessingStarted, reason: None }
    }
    fn sign(host: &Host, receipt: &ProcessingReceipt) -> ProcessingEnvelope {
        let mut e = ProcessingEnvelope { id: "receipt-1".into(), timestamp: receipt.observed_at,
            sender: receipt.recipient_full_actor.clone(), recipient: receipt.original_sender_full_actor.clone(),
            room: "#eng".into(), task: receipt.original_task_id.clone(),
            body: serde_json::to_string(receipt).unwrap(), signature: [0; 64] };
        e.signature = host.key.sign(e.signing_payload().as_bytes()).to_bytes();
        e
    }

    #[test]
    fn consumer01_t01_ghost_receiver_is_not_processing_or_durable_storage() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(4);
        assert_eq!(tx.send("original").unwrap(), 1);
        let report = legacy_publication_report(
            "original", "digest", Some("GEMINI-PM#one,DELIVERY#two"),
            PublicationAck { message_id: "original", ok: true, signature_verified: true },
        );
        assert!(report.publication_acknowledged);
        assert_eq!(report.completion_scope, "PUBLISH_ONLY");
        assert_eq!(report.persistence, "UNKNOWN");
        assert_eq!(report.recipients.len(), 2);
        for target in report.recipients {
            assert_eq!(target.scheduling, "UNSUPPORTED");
            assert_eq!(target.processing_ack, "UNKNOWN");
            assert_eq!(target.work_started, "UNKNOWN");
        }
        assert_eq!(rx.try_recv().unwrap(), "original");
    }

    #[test]
    fn consumer01_uncorrelated_ack_is_not_publication_evidence() {
        let report = legacy_publication_report(
            "original", "digest", Some("WORKHORSE#CaseSensitive"),
            PublicationAck { message_id: "other", ok: true, signature_verified: true },
        );
        assert!(!report.publication_acknowledged);
        assert_eq!(report.recipients[0].recipient, "WORKHORSE#CaseSensitive");
        assert_eq!(report.recipients[0].consumer_binding, "UNKNOWN");
    }

    #[test]
    fn consumer01_t02_missing_binding_capability_is_unsupported() {
        let (mut h, mut s, e) = fixture(); let ack = sign(&h, &receipt(&h, &e));
        h.binding.supported = false;
        assert_eq!(e.join(&ack, &h, &mut s), Err(DeliveryError::Unsupported));
        assert_eq!(consumer_cadence(&h, "QA#target").state, ConsumerLifecycle::Unsupported);
    }
    #[test]
    fn consumer01_t03_current_revocation_prevents_upgrade() {
        let (mut h, mut s, e) = fixture(); let ack = sign(&h, &receipt(&h, &e));
        h.binding.revoked = true;
        assert_eq!(e.join(&ack, &h, &mut s), Err(DeliveryError::Revoked)); assert_eq!(s.writes, 1);
    }
    #[test]
    fn consumer01_t04_wrong_actor_and_principal_are_rejected() {
        let (h, mut s, e) = fixture(); let mut ack = sign(&h, &receipt(&h, &e));
        ack.sender = "QA#other".into();
        assert_eq!(e.join(&ack, &h, &mut s), Err(DeliveryError::Signature));
        let other = iroh::SecretKey::from_bytes(&[8; 32]);
        let mut ack = sign(&h, &receipt(&h, &e)); ack.signature = other.sign(ack.signing_payload().as_bytes()).to_bytes();
        assert_eq!(e.join(&ack, &h, &mut s), Err(DeliveryError::Signature));
    }
    #[test]
    fn consumer01_t05_every_original_commitment_is_checked() {
        for field in 0..11 {
            let (h, mut s, e) = fixture(); let mut r = receipt(&h, &e);
            match field {
                0 => r.original_message_id.push('x'), 1 => r.original_message_digest_sha256 = "ef".repeat(32),
                2 => r.original_sender_full_actor.push('x'), 3 => r.recipient_full_actor.push('x'),
                4 => r.original_task_id = None, 5 => r.original_operation_id = None,
                6 => r.delivery_expectation_id.push('x'), 7 => r.delivery_expectation_digest = "ef".repeat(32),
                8 => r.original_delivery_deadline += 1, 9 => r.consumer_binding_id.push('x'),
                _ => r.consumer_binding_generation += 1,
            }
            assert!(e.join(&sign(&h, &r), &h, &mut s).is_err(), "field {field}"); assert_eq!(s.writes, 1);
        }
    }
    #[test]
    fn consumer01_t06_exact_replay_and_conflict_are_distinct() {
        let (h, mut s, e) = fixture(); let mut r = receipt(&h, &e); let ack = sign(&h, &r);
        assert!(!e.join(&ack, &h, &mut s).unwrap().historical_replay);
        assert!(e.join(&ack, &h, &mut s).unwrap().historical_replay); assert_eq!(s.writes, 2);
        r.kind = ProcessingKind::ProcessingRejected;
        assert_eq!(e.join(&sign(&h, &r), &h, &mut s), Err(DeliveryError::Conflict)); assert_eq!(s.writes, 2);
    }
    #[test]
    fn consumer01_t07_late_future_clock_and_unknown_kind_fail_closed() {
        for field in 0..5 {
            let (mut h, mut s, e) = fixture(); let mut r = receipt(&h, &e);
            if field == 0 { h.now = Ok(251); } else if field == 1 { r.observed_at = 121; }
            else if field == 2 { h.now = Err(DeliveryError::ClockRollback); }
            else if field == 4 { r.observed_at = 101; }
            let mut ack = sign(&h, &r);
            if field == 3 {
                ack.body = ack.body.replace("PROCESSING_STARTED", "WORK_COMPLETED");
                ack.signature = h.key.sign(ack.signing_payload().as_bytes()).to_bytes();
            }
            assert!(e.join(&ack, &h, &mut s).is_err()); assert_eq!(s.writes, 1);
        }
    }
    #[test]
    fn consumer01_t08_signed_processing_and_rejection_never_mean_work_started() {
        for kind in [ProcessingKind::ProcessingStarted, ProcessingKind::ProcessingRejected] {
            let (h, mut s, e) = fixture(); let mut r = receipt(&h, &e); r.kind = kind.clone();
            let joined = e.join(&sign(&h, &r), &h, &mut s).unwrap();
            assert_eq!(joined.kind, kind); assert_eq!(joined.work_started, "UNKNOWN");
        }
    }
    #[test]
    fn consumer01_t09_one_recipient_cannot_satisfy_another() {
        let (mut h, mut s, a) = fixture(); let ack = sign(&h, &receipt(&h, &a));
        let mut original = a.original.clone(); original.recipient = "DELIVERY#other".into();
        h.now = Ok(100); let b = RegisteredExpectation::register(original, &h, &mut s).unwrap(); h.now = Ok(120);
        assert!(a.join(&ack, &h, &mut s).is_ok());
        assert_eq!(b.join(&ack, &h, &mut s), Err(DeliveryError::Correlation));
    }
    #[test]
    fn consumer01_t10_timeout_preserves_original_without_new_effect() {
        let (mut h, mut s, e) = fixture(); let ack = sign(&h, &receipt(&h, &e)); h.now = Ok(300);
        assert_eq!(e.join(&ack, &h, &mut s), Err(DeliveryError::Expired));
        assert_eq!(s.writes, 1); assert_eq!(e.original.message_id, "original"); assert_eq!(e.original.deadline, 250);
    }
    #[test]
    fn consumer01_t11_crash_boundaries_require_durable_readback_and_no_replay_effect() {
        let (h, mut s, e) = fixture(); let ack = sign(&h, &receipt(&h, &e));
        s.fail_before = true; assert_eq!(e.join(&ack, &h, &mut s), Err(DeliveryError::Persistence));
        s.fail_before = false; s.fail_after = true;
        assert_eq!(e.join(&ack, &h, &mut s), Err(DeliveryError::Persistence));
        let reopened = RegisteredExpectation::reopen(e.key(), &s).unwrap();
        let writes = s.writes; assert!(reopened.join(&ack, &h, &mut s).unwrap().historical_replay);
        assert_eq!(s.writes, writes);
        let (h, mut s, e) = fixture(); s.corrupt_readback = true;
        assert_eq!(e.join(&sign(&h, &receipt(&h, &e)), &h, &mut s), Err(DeliveryError::Persistence));
    }
    #[test]
    fn consumer01_t12_existing_seven_field_utf8_transcript_is_preserved() {
        let e = ProcessingEnvelope { id: "a".into(), timestamp: 7, sender: "QA#one".into(),
            recipient: "WORKHORSE#two".into(), room: "#é".into(), task: Some("C".into()), body: "🙂".into(), signature: [0; 64] };
        assert_eq!(e.signing_payload(), "chinwag-bus-sig-v2|1:a|1:7|6:QA#one|13:WORKHORSE#two|3:#é|1:C|4:🙂");
    }
    #[test]
    fn consumer01_t13_task_close_preserves_standing_consumer() {
        let (mut h, mut s, a) = fixture(); let snapshot = consumer_cadence(&h, "QA#target");
        assert_eq!(snapshot.state, ConsumerLifecycle::Active);
        assert_eq!(snapshot.after_task_closed(), snapshot);
        let mut original = a.original.clone(); original.id = "expect-B".into(); original.message_id = "message-B".into(); original.created_at = 120;
        let b = RegisteredExpectation::register(original, &h, &mut s).unwrap();
        let turn = h.binding.turn.as_mut().unwrap(); turn.reference = "turn-B".into(); turn.message_id = "message-B".into();
        turn.observed_at = 121; turn.inbox_read_at = 123; h.now = Ok(124);
        let mut r = receipt(&h, &b); r.observed_at = 124;
        assert!(b.join(&sign(&h, &r), &h, &mut s).is_ok());
    }
    #[test]
    fn consumer01_t14_explicit_cancellation_stays_stopped() {
        let (mut h, _, _) = fixture(); h.binding.revoked = true;
        let snapshot = consumer_cadence(&h, "QA#target");
        assert_eq!(snapshot.state, ConsumerLifecycle::Stopped);
        assert_eq!(snapshot.after_task_closed().state, ConsumerLifecycle::Stopped);
    }
    #[test]
    fn consumer01_t15_recovery_keeps_original_identity_and_deadline() {
        let (mut h, mut s, e) = fixture(); let reopened = RegisteredExpectation::reopen(e.key(), &s).unwrap();
        assert_eq!(reopened.original, e.original); h.binding.conversation = "new-conversation".into();
        assert_eq!(reopened.join(&sign(&h, &receipt(&h, &e)), &h, &mut s), Err(DeliveryError::Correlation));
        assert_eq!(s.writes, 1);
    }
    #[test]
    fn consumer01_t16_expired_lease_cannot_be_renewed_by_timer() {
        let (mut h, _, _) = fixture(); h.now = Ok(401); h.binding.timer_armed = true;
        assert_eq!(consumer_cadence(&h, "QA#target").state, ConsumerLifecycle::Expired);
    }
    #[test]
    fn consumer01_t17_armed_without_actual_turn_is_stale() {
        let (mut h, _, _) = fixture(); h.binding.turn = None;
        let snapshot = consumer_cadence(&h, "QA#target");
        assert!(snapshot.configured_timer_armed); assert_eq!(snapshot.state, ConsumerLifecycle::CadenceStale);
    }
    #[test]
    fn consumer01_t18_public_unsupported_binding_cannot_adopt_fixture_outcome() {
        let (mut h, mut s, e) = fixture(); let ack = sign(&h, &receipt(&h, &e)); e.join(&ack, &h, &mut s).unwrap();
        h.binding = ConsumerBinding::unsupported("QA#target");
        assert_eq!(e.join(&ack, &h, &mut s), Err(DeliveryError::Unsupported));
    }
    #[test]
    fn consumer01_t19_sibling_case_sensitive_instance_is_not_original() {
        let (mut h, mut s, e) = fixture(); let ack = sign(&h, &receipt(&h, &e));
        h.binding.recipient = "QA#Target".into(); h.binding.conversation = "Target".into();
        assert_eq!(e.join(&ack, &h, &mut s), Err(DeliveryError::Correlation));
    }
    #[test]
    fn consumer01_t20_supported_fixture_restores_actual_cadence_without_reissuing_message() {
        let (mut h, mut s, e) = fixture(); h.now = Ok(181); h.binding.generation = 5;
        let turn = h.binding.turn.as_mut().unwrap(); turn.binding_generation = 5;
        turn.reference = "restored-original-turn".into(); turn.observed_at = 178; turn.inbox_read_at = 180;
        assert_eq!(consumer_cadence(&h, "QA#target").state, ConsumerLifecycle::Active);
        let reopened = RegisteredExpectation::reopen(e.key(), &s).unwrap(); let mut r = receipt(&h, &reopened); r.observed_at = 181;
        assert!(reopened.join(&sign(&h, &r), &h, &mut s).is_ok());
        assert_eq!(reopened.original.message_id, "original"); assert_eq!(reopened.original.deadline, 250);
    }
    #[test]
    fn consumer01_oversized_envelope_is_refused_before_payload_allocation() {
        let (h, mut s, e) = fixture(); let mut ack = sign(&h, &receipt(&h, &e));
        ack.sender = "a".repeat(257);
        assert_eq!(e.join(&ack, &h, &mut s), Err(DeliveryError::Bounds)); assert_eq!(s.writes, 1);
    }
}
