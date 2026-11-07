//! Historical, single-attempt remote publication observations. This bounded
//! process-local cache is neither an outbox nor evidence of recipient processing.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemotePublication {
    pub peer_endpoint_id: String,
    pub remote_sequence: u64,
    pub room: String,
    pub configuration_id: String,
    pub configuration_generation: u64,
    pub acknowledged_at_unix: u64,
    pub selected_transport: String,
    pub remote_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "outcome",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum FederationObservation {
    PublishOnly { forwarding: String },
    RemoteJournalAcknowledged { receipt: RemotePublication },
    Unknown { phase: String },
}

/// No persistence or automatic replay. Eviction/restart means UNKNOWN, never
/// proof that delivery did not happen. Positive historical facts are immutable.
pub struct ReceiptCache {
    capacity: usize,
    entries: BTreeMap<(String, String), FederationObservation>,
    order: VecDeque<(String, String)>,
}
impl ReceiptCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }
    pub fn begin(&mut self, id: &str, digest: &str, forwarding: bool) {
        let key = (id.to_owned(), digest.to_owned());
        if self.capacity == 0 || self.entries.contains_key(&key) {
            return;
        }
        while self.entries.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(
            key,
            FederationObservation::PublishOnly {
                forwarding: if forwarding {
                    "QUEUED_SINGLE_ATTEMPT"
                } else {
                    "NOT_QUEUED"
                }
                .into(),
            },
        );
    }
    pub fn finish(&mut self, id: &str, digest: &str, result: FederationObservation) {
        if let Some(old) = self.entries.get_mut(&(id.to_owned(), digest.to_owned()))
            && matches!(old, FederationObservation::PublishOnly { .. })
        {
            *old = result;
        }
    }
    pub fn get(&self, id: &str, digest: &str) -> FederationObservation {
        self.entries
            .get(&(id.to_owned(), digest.to_owned()))
            .cloned()
            .unwrap_or_else(|| FederationObservation::Unknown {
                phase: "NOT_RETAINED_OR_NOT_OBSERVED".into(),
            })
    }
}
pub fn valid_receipt_query(id: &str, digest: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn positive() -> FederationObservation {
        FederationObservation::RemoteJournalAcknowledged {
            receipt: RemotePublication {
                peer_endpoint_id: "peer".into(),
                remote_sequence: 7,
                room: "#eng".into(),
                configuration_id: "cfg".into(),
                configuration_generation: 1,
                acknowledged_at_unix: 1000,
                selected_transport: "relay".into(),
                remote_address: "https://relay.invalid/".into(),
            },
        }
    }
    #[test]
    fn exact_original_and_digest_are_required_and_missing_is_unknown() {
        let mut cache = ReceiptCache::new(2);
        cache.begin("one", "digest1", true);
        cache.finish("one", "digest2", positive());
        assert!(matches!(
            cache.get("one", "digest1"),
            FederationObservation::PublishOnly { .. }
        ));
        assert!(matches!(
            cache.get("one", "digest2"),
            FederationObservation::Unknown { .. }
        ));
        cache.finish("one", "digest1", positive());
        assert_eq!(cache.get("one", "digest1"), positive());
    }
    #[test]
    fn replay_and_later_unknown_cannot_replace_historical_storage_ack() {
        let mut cache = ReceiptCache::new(2);
        cache.begin("one", "digest", true);
        cache.finish("one", "digest", positive());
        cache.begin("one", "digest", true);
        cache.finish(
            "one",
            "digest",
            FederationObservation::Unknown {
                phase: "expired".into(),
            },
        );
        assert_eq!(cache.get("one", "digest"), positive());
    }
    #[test]
    fn eviction_restart_and_lost_ack_do_not_claim_nondelivery_or_retry() {
        let mut cache = ReceiptCache::new(1);
        cache.begin("one", "digest", true);
        cache.finish(
            "one",
            "digest",
            FederationObservation::Unknown {
                phase: "lost_ack".into(),
            },
        );
        cache.begin("two", "digest", true);
        assert!(matches!(
            cache.get("one", "digest"),
            FederationObservation::Unknown { .. }
        ));
        assert!(matches!(
            ReceiptCache::new(1).get("two", "digest"),
            FederationObservation::Unknown { .. }
        ));
        let mut disabled = ReceiptCache::new(0);
        disabled.begin("one", "digest", true);
        assert!(matches!(
            disabled.get("one", "digest"),
            FederationObservation::Unknown { .. }
        ));
    }
    #[test]
    fn query_shape_is_bounded_and_has_no_message_or_secret_fields() {
        assert!(valid_receipt_query("bus-100-abcd", &"a".repeat(64)));
        assert!(!valid_receipt_query("a\nb", &"a".repeat(64)));
        assert!(!valid_receipt_query("bus-1", &"G".repeat(64)));
        assert!(!valid_receipt_query(&"a".repeat(129), &"a".repeat(64)));
        let data = serde_json::to_string(&positive()).unwrap();
        for forbidden in ["session", "nonce", "signature", "body", "private"] {
            assert!(!data.contains(forbidden));
        }
    }
}
