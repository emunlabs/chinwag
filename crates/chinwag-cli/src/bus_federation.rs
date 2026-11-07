#![forbid(unsafe_code)]

//! Bounded replay/conflict control for the existing native bus publication.
//!
//! Signature, roster, route and task authorization belong to their existing
//! adapters. This module neither verifies them nor treats `sig_verified` as a
//! grant. Publication, persistence, processing and work start remain distinct.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use subtle::{Choice, ConstantTimeEq};

/// The existing bus message, moved unchanged from the binary route module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusMessage {
    pub id: String,
    pub seq: u64,
    pub ts_unix: u64,
    pub ts_iso: String,
    pub room: String,
    pub sender: String,
    pub sender_cast: String,
    pub sender_endpoint_id: String,
    pub to: Option<String>,
    pub task_id: Option<String>,
    pub body: String,
    pub digest_sha256: String,
    #[serde(default)]
    pub pubkey_ed25519: Option<String>,
    #[serde(default)]
    pub signature_ed25519: Option<String>,
    #[serde(default)]
    pub sig_verified: bool,
}

/// The persistence adapter uses the same original comparison on cache misses
/// and restarts. This compares data only; it performs no verification or grant.
pub fn same_immutable_original(left: &BusMessage, right: &BusMessage) -> bool {
    let witnesses = OriginalWitnesses::from(left).ct_eq(&OriginalWitnesses::from(right));
    bool::from(witnesses)
        && left.id == right.id
        && left.ts_unix == right.ts_unix
        && left.sender == right.sender
        && left.to.as_deref().unwrap_or("") == right.to.as_deref().unwrap_or("")
        && left.room == right.room
        && left.task_id.as_deref().unwrap_or("") == right.task_id.as_deref().unwrap_or("")
        && left.body == right.body
}

struct OriginalWitnesses<'a> {
    public_key: Option<&'a str>,
    signature: Option<&'a str>,
    sender_endpoint_id: &'a str,
    digest: &'a str,
}
impl<'a> From<&'a BusMessage> for OriginalWitnesses<'a> {
    fn from(message: &'a BusMessage) -> Self {
        Self {
            public_key: message.pubkey_ed25519.as_deref(),
            signature: message.signature_ed25519.as_deref(),
            sender_endpoint_id: &message.sender_endpoint_id,
            digest: &message.digest_sha256,
        }
    }
}
fn optional_witness_eq(left: Option<&str>, right: Option<&str>) -> Choice {
    u8::from(left.is_some()).ct_eq(&u8::from(right.is_some()))
        & left
            .unwrap_or("")
            .as_bytes()
            .ct_eq(right.unwrap_or("").as_bytes())
}
impl ConstantTimeEq for OriginalWitnesses<'_> {
    fn ct_eq(&self, other: &Self) -> Choice {
        optional_witness_eq(self.public_key, other.public_key)
            & optional_witness_eq(self.signature, other.signature)
            & self
                .sender_endpoint_id
                .as_bytes()
                .ct_eq(other.sender_endpoint_id.as_bytes())
            & self.digest.as_bytes().ct_eq(other.digest.as_bytes())
    }
}

const MAX_ENTRIES: usize = 4096;
const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_MESSAGE_CONTENT_BYTES: usize = 128 * 1024;

/// Limits describe retained UTF-8 content, not an exact allocator memory count.
/// The entry limit separately bounds map/node overhead. FIFO eviction loses
/// only this optimization: the persistent sink must still detect exact replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressLimits {
    max_entries: usize,
    max_content_bytes: usize,
    max_message_content_bytes: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidIngressLimits;
impl std::fmt::Display for InvalidIngressLimits {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid bounded bus ingress limits")
    }
}
impl std::error::Error for InvalidIngressLimits {}
impl IngressLimits {
    pub fn try_new(
        max_entries: usize,
        max_content_bytes: usize,
        max_message_content_bytes: usize,
    ) -> Result<Self, InvalidIngressLimits> {
        if max_entries == 0
            || max_entries > MAX_ENTRIES
            || max_content_bytes == 0
            || max_content_bytes > MAX_CONTENT_BYTES
            || max_message_content_bytes == 0
            || max_message_content_bytes > MAX_MESSAGE_CONTENT_BYTES
            || max_message_content_bytes > max_content_bytes
        {
            return Err(InvalidIngressLimits);
        }
        Ok(Self {
            max_entries,
            max_content_bytes,
            max_message_content_bytes,
        })
    }
}
impl Default for IngressLimits {
    fn default() -> Self {
        Self {
            max_entries: 1024,
            max_content_bytes: 4 * 1024 * 1024,
            max_message_content_bytes: MAX_MESSAGE_CONTENT_BYTES,
        }
    }
}

/// The original sink must compare immutable signed content, not ID alone.
/// `Stored` means the sink actually completed its stated persistence contract.
/// An uncertain write must return an error, retaining the original for explicit
/// reconciliation. Exact replay/conflict checks must survive cache restart.
pub trait FederationSink {
    type Error;
    fn persist_if_absent(&mut self, message: &BusMessage) -> Result<SinkDisposition, Self::Error>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkDisposition {
    Stored { local_sequence: u64 },
    ExactReplay { local_sequence: u64 },
    Conflict,
}

/// Runs after a confirmed new sink result, at most once in this cache. An
/// adapter can enqueue bounded local-broadcast/peer-forward work here. This is
/// not a processing ACK, a remote persistence receipt, or a worker-start hook.
pub trait FederationEffects {
    type Error;
    fn on_stored(&mut self, message: &BusMessage) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressOutcome {
    Stored { local_sequence: u64 },
    ExactReplay { local_sequence: u64 },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressError<SinkError, EffectsError> {
    Oversize,
    ConflictingOriginal,
    InvalidPersistenceReceipt,
    /// No broadcast or forwarding callback ran. Persistence may be uncertain;
    /// this result does not authorize an automatic retry or a fresh message ID.
    PersistenceUnknown(SinkError),
    /// Storage succeeded and the cache remembers it. Replaying this message
    /// will not repeat the effects callback or manufacture remote delivery.
    EffectsFailedAfterStore {
        local_sequence: u64,
        error: EffectsError,
    },
}

/// These are exactly the seven existing signing inputs, with message ID kept
/// as the map key. The existing transcript maps absent recipient/task to empty
/// strings, so those equivalent representations also compare as exact replay.
/// Key/signature, sender endpoint and message digest remain opaque immutable
/// original witnesses, even where the legacy seven-field signature does not
/// protect a metadata field. No
/// new transcript, hashing convention, signature or key operation is added.
#[derive(Debug, Clone)]
struct SignedContent {
    ts_unix: u64,
    sender: String,
    to: String,
    room: String,
    task_id: String,
    body: String,
    public_key: Option<String>,
    signature: Option<String>,
    sender_endpoint_id: String,
    message_digest: String,
}
impl PartialEq for SignedContent {
    fn eq(&self, other: &Self) -> bool {
        let witnesses = self.witnesses().ct_eq(&other.witnesses());
        bool::from(witnesses)
            && self.ts_unix == other.ts_unix
            && self.sender == other.sender
            && self.to == other.to
            && self.room == other.room
            && self.task_id == other.task_id
            && self.body == other.body
    }
}
impl Eq for SignedContent {}
impl SignedContent {
    fn witnesses(&self) -> OriginalWitnesses<'_> {
        OriginalWitnesses {
            public_key: self.public_key.as_deref(),
            signature: self.signature.as_deref(),
            sender_endpoint_id: &self.sender_endpoint_id,
            digest: &self.message_digest,
        }
    }
    fn from_message(message: &BusMessage) -> Self {
        Self {
            ts_unix: message.ts_unix,
            sender: message.sender.clone(),
            to: message.to.as_deref().unwrap_or("").into(),
            room: message.room.clone(),
            task_id: message.task_id.as_deref().unwrap_or("").into(),
            body: message.body.clone(),
            public_key: message.pubkey_ed25519.clone(),
            signature: message.signature_ed25519.clone(),
            sender_endpoint_id: message.sender_endpoint_id.clone(),
            message_digest: message.digest_sha256.clone(),
        }
    }
    fn content_bytes(message: &BusMessage) -> Option<usize> {
        [
            message.id.as_str(),
            message.id.as_str(), // Map key plus bounded FIFO key.
            message.sender.as_str(),
            message.to.as_deref().unwrap_or(""),
            message.room.as_str(),
            message.task_id.as_deref().unwrap_or(""),
            message.body.as_str(),
            message.pubkey_ed25519.as_deref().unwrap_or(""),
            message.signature_ed25519.as_deref().unwrap_or(""),
            message.sender_endpoint_id.as_str(),
            message.digest_sha256.as_str(),
        ]
        .iter()
        .try_fold(std::mem::size_of::<u64>(), |total, value| {
            total.checked_add(value.len())
        })
    }

    fn complete_copy_bytes(message: &BusMessage) -> Option<usize> {
        // Bound the fresh message clone passed to effects as well as cached
        // signed content. Presentation fields are not replay identity, but an
        // unbounded presentation string must not bypass the allocation bound.
        [
            message.id.as_str(),
            message.ts_iso.as_str(),
            message.room.as_str(),
            message.sender.as_str(),
            message.sender_cast.as_str(),
            message.sender_endpoint_id.as_str(),
            message.to.as_deref().unwrap_or(""),
            message.task_id.as_deref().unwrap_or(""),
            message.body.as_str(),
            message.digest_sha256.as_str(),
            message.pubkey_ed25519.as_deref().unwrap_or(""),
            message.signature_ed25519.as_deref().unwrap_or(""),
        ]
        .iter()
        .try_fold(
            3 * std::mem::size_of::<u64>() + std::mem::size_of::<bool>(),
            |total, value| total.checked_add(value.len()),
        )
    }
}
struct KnownMessage {
    content: SignedContent,
    local_sequence: u64,
    content_bytes: usize,
}

/// Process-local replay memory, never durable consumption or authorization.
/// Callers serialize access to this synchronous core. A persisted sink must
/// independently reject original conflicts after restart or any lost cache.
pub struct BoundedIngress {
    limits: IngressLimits,
    known: BTreeMap<String, KnownMessage>,
    fifo: VecDeque<String>,
    retained_content_bytes: usize,
}
impl BoundedIngress {
    pub fn new(limits: IngressLimits) -> Self {
        Self {
            limits,
            known: BTreeMap::new(),
            fifo: VecDeque::new(),
            retained_content_bytes: 0,
        }
    }
    pub fn retained_entries(&self) -> usize {
        self.known.len()
    }
    pub fn retained_content_bytes(&self) -> usize {
        self.retained_content_bytes
    }

    pub fn ingest<S: FederationSink, E: FederationEffects>(
        &mut self,
        message: &BusMessage,
        sink: &mut S,
        effects: &mut E,
    ) -> Result<IngressOutcome, IngressError<S::Error, E::Error>> {
        let content_bytes = SignedContent::content_bytes(message).ok_or(IngressError::Oversize)?;
        let complete_copy_bytes =
            SignedContent::complete_copy_bytes(message).ok_or(IngressError::Oversize)?;
        if content_bytes > self.limits.max_message_content_bytes
            || complete_copy_bytes > self.limits.max_message_content_bytes
        {
            return Err(IngressError::Oversize);
        }
        let content = SignedContent::from_message(message);
        if let Some(known) = self.known.get(&message.id) {
            return if known.content == content {
                Ok(IngressOutcome::ExactReplay {
                    local_sequence: known.local_sequence,
                })
            } else {
                Err(IngressError::ConflictingOriginal)
            };
        }
        let stored = sink
            .persist_if_absent(message)
            .map_err(IngressError::PersistenceUnknown)?;
        let (local_sequence, fresh) = match stored {
            SinkDisposition::Stored { local_sequence } => (local_sequence, true),
            SinkDisposition::ExactReplay { local_sequence } => (local_sequence, false),
            SinkDisposition::Conflict => return Err(IngressError::ConflictingOriginal),
        };
        if local_sequence == 0 {
            return Err(IngressError::InvalidPersistenceReceipt);
        }
        while self.known.len() >= self.limits.max_entries
            || content_bytes
                > self
                    .limits
                    .max_content_bytes
                    .saturating_sub(self.retained_content_bytes)
        {
            let oldest = self
                .fifo
                .pop_front()
                .expect("bounded ingress map/FIFO invariant");
            let removed = self
                .known
                .remove(&oldest)
                .expect("bounded ingress FIFO/map invariant");
            self.retained_content_bytes -= removed.content_bytes;
        }
        self.known.insert(
            message.id.clone(),
            KnownMessage {
                content,
                local_sequence,
                content_bytes,
            },
        );
        self.fifo.push_back(message.id.clone());
        self.retained_content_bytes += content_bytes;
        if !fresh {
            return Ok(IngressOutcome::ExactReplay { local_sequence });
        }
        let mut local = message.clone();
        local.seq = local_sequence;
        effects
            .on_stored(&local)
            .map_err(|error| IngressError::EffectsFailedAfterStore {
                local_sequence,
                error,
            })?;
        Ok(IngressOutcome::Stored { local_sequence })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> BusMessage {
        BusMessage {
            id: "bus-original".into(),
            seq: 0,
            ts_unix: 100,
            ts_iso: "display timestamp".into(),
            room: "#eng".into(),
            sender: "DEV#original-instance".into(),
            sender_cast: "■".into(),
            sender_endpoint_id: "unsigned-endpoint-label".into(),
            to: Some("QA#existing-instance".into()),
            task_id: Some("TASK-1".into()),
            body: "original body".into(),
            digest_sha256: "unsigned digest metadata".into(),
            pubkey_ed25519: Some("opaque-key-witness".into()),
            signature_ed25519: Some("opaque-signature-witness".into()),
            sig_verified: false,
        }
    }
    #[derive(Default)]
    struct Sink {
        calls: usize,
        outcome: Option<Result<SinkDisposition, &'static str>>,
    }
    impl FederationSink for Sink {
        type Error = &'static str;
        fn persist_if_absent(&mut self, _: &BusMessage) -> Result<SinkDisposition, Self::Error> {
            self.calls += 1;
            self.outcome
                .take()
                .unwrap_or(Ok(SinkDisposition::Stored { local_sequence: 7 }))
        }
    }
    #[derive(Default)]
    struct Effects {
        sequences: Vec<u64>,
        fail: bool,
    }
    impl FederationEffects for Effects {
        type Error = &'static str;
        fn on_stored(&mut self, message: &BusMessage) -> Result<(), Self::Error> {
            self.sequences.push(message.seq);
            if self.fail { Err("queue full") } else { Ok(()) }
        }
    }
    fn core() -> BoundedIngress {
        BoundedIngress::new(IngressLimits::default())
    }

    #[test]
    fn first_store_then_exact_replay_runs_sink_and_effects_once() {
        let mut ingress = core();
        let mut sink = Sink::default();
        let mut effects = Effects::default();
        let message = message();
        assert_eq!(
            ingress.ingest(&message, &mut sink, &mut effects),
            Ok(IngressOutcome::Stored { local_sequence: 7 })
        );
        assert_eq!(
            ingress.ingest(&message, &mut sink, &mut effects),
            Ok(IngressOutcome::ExactReplay { local_sequence: 7 })
        );
        assert_eq!(sink.calls, 1);
        assert_eq!(effects.sequences, vec![7]);
        assert_eq!(ingress.retained_entries(), 1);
    }
    #[test]
    fn every_signed_field_or_key_witness_conflict_precedes_sink_and_fanout() {
        for field in 0..10 {
            let mut ingress = core();
            let mut sink = Sink::default();
            let mut effects = Effects::default();
            let original = message();
            ingress.ingest(&original, &mut sink, &mut effects).unwrap();
            let mut changed = original.clone();
            match field {
                0 => changed.body.push('!'),
                1 => changed.to = Some("QA#other-instance".into()),
                2 => changed.room = "#qa".into(),
                3 => changed.task_id = Some("TASK-2".into()),
                4 => changed.ts_unix += 1,
                5 => changed.sender = "DEV#other-instance".into(),
                6 => changed.pubkey_ed25519 = Some("other-key".into()),
                7 => changed.signature_ed25519 = Some("other-signature".into()),
                8 => changed.sender_endpoint_id = "different-original-endpoint".into(),
                9 => changed.digest_sha256 = "different-original-digest".into(),
                _ => unreachable!(),
            }
            assert_eq!(
                ingress.ingest(&changed, &mut sink, &mut effects),
                Err(IngressError::ConflictingOriginal),
                "field {field}"
            );
            assert!(!same_immutable_original(&original, &changed));
            assert_eq!(sink.calls, 1);
            assert_eq!(effects.sequences, vec![7]);
        }
    }
    #[test]
    fn unsigned_sequence_and_display_metadata_do_not_create_an_original() {
        let mut ingress = core();
        let mut sink = Sink::default();
        let mut effects = Effects::default();
        let original = message();
        ingress.ingest(&original, &mut sink, &mut effects).unwrap();
        let mut replay = original;
        replay.seq = u64::MAX;
        replay.ts_iso = "a different display".into();
        replay.sender_cast = "●".into();
        replay.sig_verified = true;
        assert!(same_immutable_original(&message(), &replay));
        assert_eq!(
            ingress.ingest(&replay, &mut sink, &mut effects),
            Ok(IngressOutcome::ExactReplay { local_sequence: 7 })
        );
        assert_eq!(sink.calls, 1);
        assert_eq!(effects.sequences, vec![7]);
    }
    #[test]
    fn absent_and_empty_optional_signed_fields_match_the_existing_transcript() {
        let mut ingress = core();
        let mut sink = Sink::default();
        let mut effects = Effects::default();
        let mut original = message();
        original.to = None;
        original.task_id = None;
        ingress.ingest(&original, &mut sink, &mut effects).unwrap();
        let mut replay = original;
        replay.to = Some(String::new());
        replay.task_id = Some(String::new());
        assert_eq!(
            ingress.ingest(&replay, &mut sink, &mut effects),
            Ok(IngressOutcome::ExactReplay { local_sequence: 7 })
        );
        assert_eq!(sink.calls, 1);
        assert_eq!(effects.sequences.len(), 1);
    }
    #[test]
    fn absent_and_empty_key_or_signature_witnesses_are_distinct() {
        for key_witness in [true, false] {
            let mut ingress = core();
            let mut sink = Sink::default();
            let mut effects = Effects::default();
            let mut original = message();
            original.pubkey_ed25519 = None;
            original.signature_ed25519 = None;
            ingress.ingest(&original, &mut sink, &mut effects).unwrap();
            let mut changed = original.clone();
            if key_witness {
                changed.pubkey_ed25519 = Some(String::new());
            } else {
                changed.signature_ed25519 = Some(String::new());
            }
            assert!(!same_immutable_original(&original, &changed));
            assert_eq!(
                ingress.ingest(&changed, &mut sink, &mut effects),
                Err(IngressError::ConflictingOriginal)
            );
            assert_eq!(sink.calls, 1);
            assert_eq!(effects.sequences.len(), 1);
        }
    }
    #[test]
    fn original_id_is_part_of_identity_without_changing_its_wire_format() {
        let mut ingress = core();
        let mut sink = Sink::default();
        let mut effects = Effects::default();
        let original = message();
        ingress.ingest(&original, &mut sink, &mut effects).unwrap();
        let mut other = original;
        other.id = "bus-other-original".into();
        assert!(matches!(
            ingress.ingest(&other, &mut sink, &mut effects),
            Ok(IngressOutcome::Stored { .. })
        ));
        assert_eq!(sink.calls, 2);
        assert_eq!(effects.sequences.len(), 2);
    }
    #[test]
    fn bounded_fifo_eviction_rechecks_persistent_original_and_never_refanouts_replay() {
        let mut ingress = BoundedIngress::new(IngressLimits::try_new(1, 1024, 1024).unwrap());
        let mut sink = Sink::default();
        let mut effects = Effects::default();
        let original = message();
        ingress.ingest(&original, &mut sink, &mut effects).unwrap();
        let mut next = original.clone();
        next.id = "another".into();
        ingress.ingest(&next, &mut sink, &mut effects).unwrap();
        sink.outcome = Some(Ok(SinkDisposition::ExactReplay { local_sequence: 7 }));
        assert!(matches!(
            ingress.ingest(&original, &mut sink, &mut effects),
            Ok(IngressOutcome::ExactReplay { .. })
        ));
        assert_eq!(sink.calls, 3);
        assert_eq!(effects.sequences.len(), 2);
        assert_eq!(ingress.retained_entries(), 1);
    }
    #[test]
    fn aggregate_content_limit_evicts_oldest_without_growing_memory() {
        let original = message();
        let bytes = SignedContent::content_bytes(&original).unwrap();
        let budget = bytes.max(SignedContent::complete_copy_bytes(&original).unwrap());
        let mut ingress = BoundedIngress::new(IngressLimits::try_new(10, budget, budget).unwrap());
        let mut sink = Sink::default();
        let mut effects = Effects::default();
        ingress.ingest(&original, &mut sink, &mut effects).unwrap();
        let mut next = original;
        next.id = "other-origin".into();
        ingress.ingest(&next, &mut sink, &mut effects).unwrap();
        assert_eq!(ingress.retained_content_bytes(), bytes);
        assert_eq!(sink.calls, 2);
        assert_eq!(effects.sequences.len(), 2);
        assert_eq!(ingress.retained_entries(), 1);
    }
    #[test]
    fn oversized_content_is_refused_before_cloning_into_the_cache_or_sink() {
        let mut ingress = BoundedIngress::new(IngressLimits::try_new(2, 1024, 128).unwrap());
        let mut sink = Sink::default();
        let mut effects = Effects::default();
        let mut oversized = message();
        oversized.body = "x".repeat(1024);
        assert_eq!(
            ingress.ingest(&oversized, &mut sink, &mut effects),
            Err(IngressError::Oversize)
        );
        assert_eq!(sink.calls, 0);
        assert!(effects.sequences.is_empty());
        assert_eq!(ingress.retained_entries(), 0);
    }
    #[test]
    fn oversized_display_metadata_is_not_a_memory_bound_bypass() {
        let mut ingress = BoundedIngress::new(IngressLimits::try_new(2, 1024, 1024).unwrap());
        let mut sink = Sink::default();
        let mut effects = Effects::default();
        let mut oversized = message();
        oversized.ts_iso = "x".repeat(1024);
        assert_eq!(
            ingress.ingest(&oversized, &mut sink, &mut effects),
            Err(IngressError::Oversize)
        );
        assert_eq!(sink.calls, 0);
        assert!(effects.sequences.is_empty());
    }
    #[test]
    fn zero_sequence_is_not_a_successful_persistence_receipt() {
        let mut ingress = core();
        let mut sink = Sink {
            calls: 0,
            outcome: Some(Ok(SinkDisposition::Stored { local_sequence: 0 })),
        };
        let mut effects = Effects::default();
        assert_eq!(
            ingress.ingest(&message(), &mut sink, &mut effects),
            Err(IngressError::InvalidPersistenceReceipt)
        );
        assert!(effects.sequences.is_empty());
        assert_eq!(ingress.retained_entries(), 0);
    }
    #[test]
    fn sink_failure_has_no_broadcast_or_fanout_and_never_claims_nonpersistence() {
        let mut ingress = core();
        let mut sink = Sink {
            calls: 0,
            outcome: Some(Err("original persistence uncertain")),
        };
        let mut effects = Effects::default();
        assert_eq!(
            ingress.ingest(&message(), &mut sink, &mut effects),
            Err(IngressError::PersistenceUnknown(
                "original persistence uncertain"
            ))
        );
        assert_eq!(sink.calls, 1);
        assert!(effects.sequences.is_empty());
        assert_eq!(ingress.retained_entries(), 0);
    }
    #[test]
    fn sink_conflict_after_cache_restart_never_runs_effects() {
        let mut ingress = core();
        let mut sink = Sink {
            calls: 0,
            outcome: Some(Ok(SinkDisposition::Conflict)),
        };
        let mut effects = Effects::default();
        assert_eq!(
            ingress.ingest(&message(), &mut sink, &mut effects),
            Err(IngressError::ConflictingOriginal)
        );
        assert!(effects.sequences.is_empty());
        assert_eq!(ingress.retained_entries(), 0);
    }
    #[test]
    fn persistent_exact_replay_after_cache_restart_never_runs_effects() {
        let mut ingress = core();
        let mut sink = Sink {
            calls: 0,
            outcome: Some(Ok(SinkDisposition::ExactReplay { local_sequence: 99 })),
        };
        let mut effects = Effects::default();
        assert_eq!(
            ingress.ingest(&message(), &mut sink, &mut effects),
            Ok(IngressOutcome::ExactReplay { local_sequence: 99 })
        );
        assert!(effects.sequences.is_empty());
        assert_eq!(ingress.retained_entries(), 1);
    }
    #[test]
    fn effect_queue_failure_retains_stored_original_without_automatic_fanout_retry() {
        let mut ingress = core();
        let mut sink = Sink::default();
        let mut effects = Effects {
            sequences: vec![],
            fail: true,
        };
        assert_eq!(
            ingress.ingest(&message(), &mut sink, &mut effects),
            Err(IngressError::EffectsFailedAfterStore {
                local_sequence: 7,
                error: "queue full"
            })
        );
        assert_eq!(
            ingress.ingest(&message(), &mut sink, &mut effects),
            Ok(IngressOutcome::ExactReplay { local_sequence: 7 })
        );
        assert_eq!(sink.calls, 1);
        assert_eq!(effects.sequences, vec![7]);
    }
    #[test]
    fn invalid_limit_profiles_and_untrusted_verified_flag_are_not_approval_knobs() {
        for limits in [
            (0, 100, 100),
            (MAX_ENTRIES + 1, 100, 100),
            (1, 0, 1),
            (1, 100, 101),
            (1, MAX_CONTENT_BYTES + 1, 100),
        ] {
            assert!(IngressLimits::try_new(limits.0, limits.1, limits.2).is_err());
        }
        let original = message();
        assert!(!original.sig_verified);
        // This pure core deliberately does not authenticate even a test message.
        // The network adapter must call its existing verifier before this API.
        let mut ingress = core();
        let mut sink = Sink::default();
        let mut effects = Effects::default();
        assert!(ingress.ingest(&original, &mut sink, &mut effects).is_ok());
    }
}
