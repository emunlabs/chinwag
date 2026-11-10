//! Durable delivery/quota transitions. Host effects are outside this module.
#![forbid(unsafe_code)]
use crate::{
    bus_federation::BusMessage,
    bus_wait_grant::HostGrant,
    bus_wait_message::{classify_body, hash, verify_original},
    bus_wait_store::Witness,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryState {
    Received,
    WakeRequestedQuotaReserved,
    HostCallDispatching,
    PendingActiveTurn,
    HostAdmitted,
    HostTurnStarted,
    HeldUncertainPreAckOutcome,
    HeldUncertainHostOutcome,
}
impl DeliveryState {
    pub fn held(self) -> bool {
        matches!(
            self,
            Self::HeldUncertainPreAckOutcome | Self::HeldUncertainHostOutcome
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub delivery_id: String,
    pub admission_request_id: String,
    pub state: DeliveryState,
    pub messages: Vec<BusMessage>,
    pub handoff_token_sha256: Option<String>,
    pub quota_reserved: bool,
    pub quota_charged: bool,
    pub admission_id: Option<String>,
    pub turn_id: Option<String>,
    pub first_seen_at_unix: u64,
    pub host_admitted_at_unix: Option<u64>,
    pub host_turn_started_at_unix: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completed {
    pub delivery_id: String,
    pub admission_request_id: String,
    pub turn_id: String,
    pub token_sha256: String,
    pub witnesses: Vec<Witness>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub schema: String,
    pub actor: String,
    pub grant_id: String,
    pub authority_epoch: u64,
    pub grant_digest_sha256: String,
    pub version: u64,
    pub max_turns_quota: u64,
    pub turns_used: u64,
    pub turns_reserved: u64,
    pub backlog_policy: String,
    pub last_scanned_seq: u64,
    pub last_scanned_id: String,
    pub last_scanned_digest: String,
    pub last_scanned_inode: u64,
    pub last_scanned_line1_digest: String,
    pub pending_deliveries: Vec<Delivery>,
    pub completed_recent_digests: Vec<Witness>,
    pub completed_deliveries: Vec<Completed>,
}
impl Cursor {
    pub fn new(grant: &HostGrant, grant_digest: String, backlog_policy: String) -> Self {
        Self {
            schema: "chinwag.bus.durable-cursor-and-quota.v4".into(),
            actor: grant.actor.clone(),
            grant_id: grant.grant_id.clone(),
            authority_epoch: grant.authority_epoch,
            grant_digest_sha256: grant_digest,
            version: 0,
            max_turns_quota: grant.max_turns_quota,
            turns_used: 0,
            turns_reserved: 0,
            backlog_policy,
            last_scanned_seq: 0,
            last_scanned_id: String::new(),
            last_scanned_digest: String::new(),
            last_scanned_inode: 0,
            last_scanned_line1_digest: String::new(),
            pending_deliveries: vec![],
            completed_recent_digests: vec![],
            completed_deliveries: vec![],
        }
    }
    pub fn validate(&self, grant: &HostGrant, grant_digest: &str) -> Result<(), String> {
        if self.schema != "chinwag.bus.durable-cursor-and-quota.v4"
            || self.actor != grant.actor
            || self.grant_id != grant.grant_id
            || self.grant_digest_sha256 != grant_digest
            || self.authority_epoch != grant.authority_epoch
            || self.max_turns_quota != grant.max_turns_quota
            || self.turns_used.saturating_add(self.turns_reserved) > self.max_turns_quota
            || self
                .pending_deliveries
                .iter()
                .map(|p| p.messages.len())
                .sum::<usize>()
                > 64
            || self
                .pending_deliveries
                .iter()
                .any(|p| p.messages.is_empty() || p.messages.len() > 16)
            || self.completed_recent_digests.len() > 1024
            || self.completed_deliveries.len() > 128
        {
            return Err("CURSOR_OR_QUOTA_INVARIANT".into());
        }
        Ok(())
    }
    fn seen(&self, message: &BusMessage) -> Result<bool, String> {
        for witness in &self.completed_recent_digests {
            if witness.id == message.id {
                return if witness.digest == message.digest_sha256 {
                    Ok(true)
                } else {
                    Err("ORIGINAL_ID_CONFLICT".into())
                };
            }
        }
        for old in self.pending_deliveries.iter().flat_map(|p| &p.messages) {
            if old.id == message.id {
                return if old.digest_sha256 == message.digest_sha256 {
                    Ok(true)
                } else {
                    Err("ORIGINAL_ID_CONFLICT".into())
                };
            }
        }
        Ok(false)
    }
    /// Preparation runs without a state lock. The caller persists via a version
    /// CAS before stdout. Rejected or out-of-scope rows never become deliveries.
    pub fn scan(
        &mut self,
        rows: &[BusMessage],
        grant: &HostGrant,
        now: u64,
    ) -> Result<bool, String> {
        let pending = self
            .pending_deliveries
            .iter()
            .map(|p| p.messages.len())
            .sum::<usize>();
        if pending >= 64 {
            return Err("BACKPRESSURE_PENDING_FULL".into());
        }
        let mut batch = vec![];
        let mut bytes = 0;
        let before = self.last_scanned_seq;
        for message in rows.iter().filter(|m| m.seq > before) {
            if batch.len() >= 16 || pending + batch.len() >= 64 {
                break;
            }
            let eligible = verify_original(message).is_ok()
                && message.to.as_deref() == Some(self.actor.as_str())
                && message.sender != self.actor
                && grant.allowed_rooms.contains(&message.room)
                && message
                    .task_id
                    .as_ref()
                    .is_some_and(|task| grant.allowed_tasks.contains(task))
                && classify_body(&message.body, grant.allow_legacy_plaintext)
                    .is_ok_and(|body| body.event_kind.wakes());
            if eligible && !self.seen(message)? {
                let size = serde_json::to_vec(message)
                    .map_err(|_| "MESSAGE_ENCODING")?
                    .len();
                if bytes + size > 250 * 1024 {
                    break;
                }
                bytes += size;
                batch.push(message.clone());
            }
            self.last_scanned_seq = message.seq;
            self.last_scanned_id = message.id.clone();
            self.last_scanned_digest = message.digest_sha256.clone();
        }
        if !batch.is_empty() {
            let witnesses = batch
                .iter()
                .map(|m| format!("{}:{}", m.id, m.digest_sha256))
                .collect::<Vec<_>>()
                .join("|");
            let delivery_id = hash(
                format!(
                    "chinwag-delivery-v1|{}|{}|{witnesses}",
                    self.actor, self.grant_digest_sha256
                )
                .as_bytes(),
            );
            let admission_request_id = format!(
                "admreq-{}",
                &hash(format!("chinwag-admission-req-v1|{}|{delivery_id}", self.actor).as_bytes())
                    [..32]
            );
            self.pending_deliveries.push(Delivery {
                delivery_id,
                admission_request_id,
                state: DeliveryState::Received,
                messages: batch,
                handoff_token_sha256: None,
                quota_reserved: false,
                quota_charged: false,
                admission_id: None,
                turn_id: None,
                first_seen_at_unix: now,
                host_admitted_at_unix: None,
                host_turn_started_at_unix: None,
            });
        }
        Ok(self.last_scanned_seq != before)
    }
    pub fn reserve(&mut self, index: usize, token_hash: String) -> Result<(), String> {
        let delivery = self
            .pending_deliveries
            .get_mut(index)
            .ok_or("UNKNOWN_DELIVERY")?;
        if delivery.state != DeliveryState::Received {
            return Err("DELIVERY_NOT_READY".into());
        }
        if !delivery.quota_reserved && !delivery.quota_charged {
            if self.turns_used.saturating_add(self.turns_reserved) >= self.max_turns_quota {
                return Err("WAKE_HELD_ENROLLMENT_INACTIVE".into());
            }
            self.turns_reserved += 1;
            delivery.quota_reserved = true;
        }
        delivery.handoff_token_sha256 = Some(token_hash);
        delivery.state = DeliveryState::WakeRequestedQuotaReserved;
        Ok(())
    }
    /// Without a supported correlated host lookup, recovery preserves quota and
    /// messages and holds UNKNOWN, including the pre-admission-ACK cut point.
    pub fn hold_uncertain(&mut self, index: usize) -> Result<(), String> {
        let delivery = self
            .pending_deliveries
            .get_mut(index)
            .ok_or("UNKNOWN_DELIVERY")?;
        delivery.state =
            if delivery.quota_charged || delivery.state == DeliveryState::PendingActiveTurn {
                DeliveryState::HeldUncertainHostOutcome
            } else {
                DeliveryState::HeldUncertainPreAckOutcome
            };
        Ok(())
    }
    pub fn acknowledge(
        &mut self,
        index: usize,
        state: &str,
        admission: Option<&str>,
        turn: Option<&str>,
        now: u64,
    ) -> Result<bool, String> {
        let delivery = self
            .pending_deliveries
            .get_mut(index)
            .ok_or("UNKNOWN_DELIVERY")?;
        if delivery.state.held() {
            return Err("OWNER_RECONCILIATION_REQUIRED".into());
        }
        let target = match state {
            "HOST_CALL_DISPATCHING" => DeliveryState::HostCallDispatching,
            "PENDING_ACTIVE_TURN" => DeliveryState::PendingActiveTurn,
            "HOST_ADMITTED" => DeliveryState::HostAdmitted,
            "HOST_TURN_STARTED" => DeliveryState::HostTurnStarted,
            "PROCESSED" => DeliveryState::HostTurnStarted,
            _ => return Err("INVALID_DELIVERY_TRANSITION".into()),
        };
        if admission.is_some_and(|s| s.is_empty() || s.len() > 160)
            || turn.is_some_and(|s| s.is_empty() || s.len() > 160)
        {
            return Err("INVALID_HOST_WITNESS".into());
        }
        if delivery
            .admission_id
            .as_deref()
            .zip(admission)
            .is_some_and(|(a, b)| a != b)
            || delivery
                .turn_id
                .as_deref()
                .zip(turn)
                .is_some_and(|(a, b)| a != b)
        {
            return Err("HOST_WITNESS_CONFLICT".into());
        }
        if state == "PROCESSED" {
            if delivery.state != DeliveryState::HostTurnStarted
                || turn != delivery.turn_id.as_deref()
            {
                return Err("UNOBSERVED_TURN_COMPLETION".into());
            }
            let completed = Completed {
                delivery_id: delivery.delivery_id.clone(),
                admission_request_id: delivery.admission_request_id.clone(),
                turn_id: delivery.turn_id.clone().ok_or("TURN_ID_REQUIRED")?,
                token_sha256: delivery
                    .handoff_token_sha256
                    .clone()
                    .ok_or("TOKEN_REQUIRED")?,
                witnesses: delivery
                    .messages
                    .iter()
                    .map(|m| Witness {
                        id: m.id.clone(),
                        digest: m.digest_sha256.clone(),
                    })
                    .collect(),
            };
            self.completed_recent_digests
                .extend(completed.witnesses.clone());
            if self.completed_recent_digests.len() > 1024 {
                self.completed_recent_digests
                    .drain(..self.completed_recent_digests.len() - 1024);
            }
            self.completed_deliveries.push(completed);
            if self.completed_deliveries.len() > 128 {
                self.completed_deliveries.remove(0);
            }
            self.pending_deliveries.remove(index);
            return Ok(true);
        }
        let permitted = match (delivery.state, target) {
            (
                DeliveryState::WakeRequestedQuotaReserved,
                DeliveryState::HostCallDispatching
                | DeliveryState::PendingActiveTurn
                | DeliveryState::HostAdmitted,
            ) => true,
            (
                DeliveryState::HostCallDispatching,
                DeliveryState::PendingActiveTurn | DeliveryState::HostAdmitted,
            ) => true,
            (
                DeliveryState::PendingActiveTurn,
                DeliveryState::HostAdmitted | DeliveryState::HostTurnStarted,
            ) => true,
            (DeliveryState::HostAdmitted, DeliveryState::HostTurnStarted) => true,
            (a, b) => a == b,
        };
        if !permitted {
            return Err("INVALID_DELIVERY_TRANSITION".into());
        }
        if matches!(
            target,
            DeliveryState::PendingActiveTurn
                | DeliveryState::HostAdmitted
                | DeliveryState::HostTurnStarted
        ) && admission.is_none()
        {
            return Err("ADMISSION_ID_REQUIRED".into());
        }
        if target == DeliveryState::HostTurnStarted && turn.is_none() {
            return Err("TURN_ID_REQUIRED".into());
        }
        let changed = delivery.state != target;
        if matches!(
            target,
            DeliveryState::HostAdmitted | DeliveryState::HostTurnStarted
        ) && !delivery.quota_charged
        {
            if !delivery.quota_reserved || self.turns_reserved == 0 {
                return Err("QUOTA_INVARIANT".into());
            }
            self.turns_reserved -= 1;
            self.turns_used += 1;
            delivery.quota_reserved = false;
            delivery.quota_charged = true;
            delivery.host_admitted_at_unix = Some(now);
        }
        delivery.state = target;
        if let Some(admission) = admission {
            delivery.admission_id = Some(admission.into());
        }
        if let Some(turn) = turn {
            delivery.turn_id = Some(turn.into());
            delivery.host_turn_started_at_unix.get_or_insert(now);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cursor() -> Cursor {
        serde_json::from_value(serde_json::json!({"schema":"chinwag.bus.durable-cursor-and-quota.v4",
            "actor":"WORKHORSE#test","grant_id":"grant","authority_epoch":1,"grant_digest_sha256":"hash",
            "version":0,"max_turns_quota":1,"turns_used":0,"turns_reserved":0,"backlog_policy":"ExplicitWatermarkSeq",
            "last_scanned_seq":0,"last_scanned_id":"","last_scanned_digest":"","last_scanned_inode":0,
            "last_scanned_line1_digest":"","pending_deliveries":[],"completed_recent_digests":[],"completed_deliveries":[]})).unwrap()
    }
    fn pending() -> Delivery {
        Delivery {
            delivery_id: "a".repeat(64),
            admission_request_id: "request".into(),
            state: DeliveryState::Received,
            messages: vec![],
            handoff_token_sha256: None,
            quota_reserved: false,
            quota_charged: false,
            admission_id: None,
            turn_id: None,
            first_seen_at_unix: 1,
            host_admitted_at_unix: None,
            host_turn_started_at_unix: None,
        }
    }
    #[test]
    fn lost_ack_holds_reserved_quota_and_never_reemits() {
        for state in [
            DeliveryState::WakeRequestedQuotaReserved,
            DeliveryState::HostCallDispatching,
        ] {
            let mut c = cursor();
            c.pending_deliveries.push(pending());
            c.reserve(0, "token".into()).unwrap();
            c.pending_deliveries[0].state = state;
            let mut recovered: Cursor =
                serde_json::from_slice(&serde_json::to_vec(&c).unwrap()).unwrap();
            recovered.hold_uncertain(0).unwrap();
            assert_eq!(recovered.turns_reserved, 1);
            assert_eq!(recovered.turns_used, 0);
            assert_eq!(
                recovered.pending_deliveries[0].state,
                DeliveryState::HeldUncertainPreAckOutcome
            );
            assert!(recovered.reserve(0, "other".into()).is_err());
            assert!(
                recovered
                    .acknowledge(0, "HOST_ADMITTED", Some("a"), None, 2)
                    .is_err()
            );
        }
    }
    #[test]
    fn queued_admission_charges_once_and_completion_requires_actual_start() {
        let mut c = cursor();
        c.pending_deliveries.push(pending());
        c.reserve(0, "token".into()).unwrap();
        c.acknowledge(0, "PENDING_ACTIVE_TURN", Some("a"), None, 2)
            .unwrap();
        assert_eq!((c.turns_reserved, c.turns_used), (1, 0));
        assert!(
            c.acknowledge(0, "PROCESSED", Some("a"), Some("t"), 2)
                .is_err()
        );
        c.acknowledge(0, "HOST_ADMITTED", Some("a"), None, 3)
            .unwrap();
        assert!(
            !c.acknowledge(0, "HOST_ADMITTED", Some("a"), None, 3)
                .unwrap()
        );
        assert_eq!((c.turns_reserved, c.turns_used), (0, 1));
        assert!(
            c.acknowledge(0, "HOST_TURN_STARTED", Some("different"), Some("t"), 4)
                .is_err()
        );
        c.acknowledge(0, "HOST_TURN_STARTED", Some("a"), Some("t"), 4)
            .unwrap();
        c.acknowledge(0, "PROCESSED", Some("a"), Some("t"), 5)
            .unwrap();
        assert!(c.pending_deliveries.is_empty());
        assert_eq!(c.completed_deliveries.len(), 1);
        c.pending_deliveries.push(pending());
        assert!(c.reserve(0, "token2".into()).is_err());
    }
}
