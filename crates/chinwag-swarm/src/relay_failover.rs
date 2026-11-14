// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Multi-Region QUIC / `WSS :443` Relay Health Scoring, Ordered Endpoint Fallback,
//! 128-Packet Sliding Replay Window, and `Ed25519` Session Resumption (`CHWG-0200`).
//!
//! Guarantees sub-second switchover across direct `LAN mDNS`, direct `QUIC`, and
//! ordered regional `WSS :443` relays during regional blackholes without dropping
//! monotonic replay-window state or re-transmitting acknowledged frames.

use crate::relay_policy::{PolicyError, RelayPolicy};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use iroh::{EndpointAddr, EndpointId, RelayUrl};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use subtle::ConstantTimeEq;

/// Sliding anti-replay window width in sequence numbers (`128` packets).
pub const REPLAY_WINDOW_BITS: u64 = 128;

/// Default per-candidate dial timeout (ms) enabling sub-second multi-region failover.
pub const DEFAULT_CANDIDATE_DIAL_TIMEOUT_MS: u64 = 250;

/// Base quarantine cooldown (ms) applied when a regional relay fails or times out.
pub const BASE_OUTAGE_COOLDOWN_MS: u64 = 1_000;

/// Maximum exponential quarantine backoff cap (ms) for an unreachable region.
pub const MAX_OUTAGE_COOLDOWN_MS: u64 = 30_000;

/// Failure penalty (ms-equivalent) added per consecutive failure when ranking regions.
pub const FAILURE_SCORE_PENALTY_MS: u64 = 250;

const RESUMPTION_TICKET_DOMAIN: &[u8] = b"chinwag-swarm-session-resumption/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FailoverError {
    #[error("sequence number 0 is reserved and invalid")]
    ZeroSequence,
    #[error("packet sequence {sequence} is outside the 128-slot replay window (highest={highest})")]
    StaleSequence { sequence: u64, highest: u64 },
    #[error("duplicate replayed sequence number {0} rejected")]
    DuplicateReplay(u64),
    #[error("timestamp {packet_micros} outside allowed skew window around {now_micros}")]
    TimestampSkew { packet_micros: u64, now_micros: u64 },
    #[error("relay policy error: {0}")]
    Policy(#[from] PolicyError),
    #[error("unknown relay endpoint `{0}` not present in approved policy")]
    UnknownRelayEndpoint(String),
    #[error("all direct QUIC and regional WSS :443 candidates failed within failover budget")]
    AllCandidatesExhausted { attempted: usize },
    #[error("session resumption ticket verification failed: {0}")]
    ResumptionRejected(&'static str),
}

// ============================================================================
// 1. 128-Slot Sliding Anti-Replay Window (Committed Post-Signature Only)
// ============================================================================

/// Constant-space 128-packet sliding replay window inspired by RFC 6479 / IPSec.
///
/// Bit `0` of `bitmap` represents `highest_seq`; bit `d` (`1..128`) represents
/// `highest_seq - d`. Callers MUST run `check_unseen` prior to signature
/// verification and commit `record_verified` ONLY after `K1` (+ `K2`) `Ed25519`
/// `verify_strict` succeeds so forged packets can never advance the window!
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReplayWindow {
    highest_seq: u64,
    bitmap: u128,
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            highest_seq: 0,
            bitmap: 0,
        }
    }

    /// Initializes the replay window at a known resumed sequence checkpoint
    /// (`1..=last_acked_seq` marked as already processed).
    pub fn from_resumed_checkpoint(last_acked_seq: u64) -> Self {
        if last_acked_seq == 0 {
            return Self::new();
        }
        let filled_bits = last_acked_seq.min(REPLAY_WINDOW_BITS);
        let bitmap = if filled_bits == 128 {
            u128::MAX
        } else {
            (1u128 << filled_bits) - 1
        };
        Self {
            highest_seq: last_acked_seq,
            bitmap,
        }
    }

    pub const fn highest_seq(&self) -> u64 {
        self.highest_seq
    }

    /// Read-only check verifying `seq` (`>= 1`) has not been seen and is not stale.
    /// Does NOT mutate window state.
    pub fn check_unseen(&self, seq: u64) -> Result<(), FailoverError> {
        if seq == 0 {
            return Err(FailoverError::ZeroSequence);
        }
        if self.highest_seq == 0 || seq > self.highest_seq {
            return Ok(());
        }
        let diff = self.highest_seq - seq;
        if diff >= REPLAY_WINDOW_BITS {
            return Err(FailoverError::StaleSequence {
                sequence: seq,
                highest: self.highest_seq,
            });
        }
        let mask = 1u128 << diff;
        if (self.bitmap & mask) != 0 {
            return Err(FailoverError::DuplicateReplay(seq));
        }
        Ok(())
    }

    /// Commits a cryptographically verified `seq` into the sliding window.
    pub fn record_verified(&mut self, seq: u64) -> Result<(), FailoverError> {
        self.check_unseen(seq)?;
        if self.highest_seq == 0 {
            self.highest_seq = seq;
            self.bitmap = 1;
            return Ok(());
        }
        if seq > self.highest_seq {
            let shift = seq - self.highest_seq;
            if shift >= REPLAY_WINDOW_BITS {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest_seq = seq;
        } else {
            let diff = self.highest_seq - seq;
            self.bitmap |= 1u128 << diff;
        }
        Ok(())
    }
}

/// Validates packet timestamp freshness against `max_skew_micros` using saturating diff.
pub fn validate_timestamp_window(
    packet_unix_micros: u64,
    now_unix_micros: u64,
    max_skew_micros: u64,
) -> Result<(), FailoverError> {
    if packet_unix_micros == 0 || packet_unix_micros.abs_diff(now_unix_micros) > max_skew_micros {
        return Err(FailoverError::TimestampSkew {
            packet_micros: packet_unix_micros,
            now_micros: now_unix_micros,
        });
    }
    Ok(())
}

// ============================================================================
// 2. Multi-Region Relay Health Scorer & Quarantine Circuit Breaker
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEndpointHealth {
    pub url: RelayUrl,
    pub configured_priority: usize,
    pub ewma_rtt_ms: u64,
    pub consecutive_failures: u32,
    pub quarantined_until_ms: Option<u64>,
    pub total_successes: u64,
    pub total_failures: u64,
}

impl RelayEndpointHealth {
    fn new(url: RelayUrl, configured_priority: usize) -> Self {
        Self {
            url,
            configured_priority,
            // Seed initial RTT slightly staggered by operator priority (`20ms`, `25ms`, ...)
            // so untouched endpoints follow deterministic manifest order until probed.
            ewma_rtt_ms: 20 + (configured_priority as u64) * 5,
            consecutive_failures: 0,
            quarantined_until_ms: None,
            total_successes: 0,
            total_failures: 0,
        }
    }

    pub fn is_quarantined(&self, now_ms: u64) -> bool {
        self.quarantined_until_ms
            .is_some_and(|until| now_ms < until)
    }

    /// Composite lower-is-better health score (`ewma_rtt_ms + failures * 250`).
    pub fn composite_score(&self) -> u64 {
        self.ewma_rtt_ms.saturating_add(
            u64::from(self.consecutive_failures).saturating_mul(FAILURE_SCORE_PENALTY_MS),
        )
    }
}

/// Deterministic integer health scorer for multi-region `WSS :443` relays.
#[derive(Debug, Clone)]
pub struct RelayHealthScorer {
    endpoints: BTreeMap<String, RelayEndpointHealth>,
    ordered_keys: Vec<String>,
}

impl RelayHealthScorer {
    pub fn from_policy(policy: &RelayPolicy) -> Self {
        let urls = policy.ordered_relay_urls();
        let mut endpoints = BTreeMap::new();
        let mut ordered_keys = Vec::with_capacity(urls.len());
        for (idx, url) in urls.into_iter().enumerate() {
            let key = url.as_str().to_owned();
            ordered_keys.push(key.clone());
            endpoints.insert(key, RelayEndpointHealth::new(url, idx));
        }
        Self {
            endpoints,
            ordered_keys,
        }
    }

    /// Records a verified round-trip probe or successful data-plane exchange,
    /// clearing any active outage quarantine and updating integer EWMA RTT.
    pub fn record_success(
        &mut self,
        url: &RelayUrl,
        sample_rtt_ms: u64,
    ) -> Result<(), FailoverError> {
        let state = self
            .endpoints
            .get_mut(url.as_str())
            .ok_or_else(|| FailoverError::UnknownRelayEndpoint(url.as_str().to_owned()))?;
        let clamped_rtt = sample_rtt_ms.max(1);
        state.ewma_rtt_ms = if state.total_successes == 0 {
            clamped_rtt
        } else {
            (state
                .ewma_rtt_ms
                .saturating_mul(3)
                .saturating_add(clamped_rtt))
                / 4
        };
        state.consecutive_failures = 0;
        state.quarantined_until_ms = None;
        state.total_successes = state.total_successes.saturating_add(1);
        Ok(())
    }

    /// Records a transport timeout, TCP reset, or regional HTTP/WSS 5xx outage,
    /// quarantining the region with bounded exponential backoff (`1s..=30s`).
    pub fn record_outage(&mut self, url: &RelayUrl, now_ms: u64) -> Result<u64, FailoverError> {
        let state = self
            .endpoints
            .get_mut(url.as_str())
            .ok_or_else(|| FailoverError::UnknownRelayEndpoint(url.as_str().to_owned()))?;
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.total_failures = state.total_failures.saturating_add(1);
        let shift = state.consecutive_failures.saturating_sub(1).min(5);
        let cooldown = (BASE_OUTAGE_COOLDOWN_MS << shift).min(MAX_OUTAGE_COOLDOWN_MS);
        let until = now_ms.saturating_add(cooldown);
        state.quarantined_until_ms = Some(until);
        Ok(until)
    }

    pub fn inspect(&self, url: &RelayUrl) -> Option<&RelayEndpointHealth> {
        self.endpoints.get(url.as_str())
    }

    /// Returns all configured regional relays ordered strictly by:
    /// 1. Non-quarantined (`healthy`) before quarantined (`outage`),
    /// 2. Lowest `composite_score()` (`ewma_rtt_ms + failure_penalty`),
    /// 3. Original operator-configured priority index.
    pub fn ranked_relays(&self, now_ms: u64) -> Vec<RelayUrl> {
        let mut items: Vec<&RelayEndpointHealth> = self
            .ordered_keys
            .iter()
            .filter_map(|k| self.endpoints.get(k))
            .collect();
        items.sort_by_key(|ep| {
            (
                ep.is_quarantined(now_ms),
                ep.composite_score(),
                ep.configured_priority,
            )
        });
        items.into_iter().map(|ep| ep.url.clone()).collect()
    }

    /// Returns only currently non-quarantined relays; if all regions are simultaneously
    /// quarantined (global local Wi-Fi blip), falls back to the full ranked ring so
    /// recovery probes can still proceed without deadlocking.
    pub fn healthy_or_fallback_relays(&self, now_ms: u64) -> Vec<RelayUrl> {
        let healthy: Vec<RelayUrl> = self
            .ranked_relays(now_ms)
            .into_iter()
            .filter(|u| {
                self.endpoints
                    .get(u.as_str())
                    .is_some_and(|ep| !ep.is_quarantined(now_ms))
            })
            .collect();
        if healthy.is_empty() {
            self.ranked_relays(now_ms)
        } else {
            healthy
        }
    }
}

// ============================================================================
// 3. Ordered Endpoint Fallback (LAN mDNS -> Direct QUIC -> Regional WSS :443)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportCandidate {
    /// Same-subnet `LAN mDNS` / loopback direct `QUIC` (`0` relay latency, `0` credits).
    DirectLanQuic(SocketAddr),
    /// Public / Tailscale / NAT-traversed direct `QUIC` socket.
    DirectWanQuic(SocketAddr),
    /// Outbound-only `WSS :443` zero-knowledge blind relay in an approved region.
    RelayWss443(RelayUrl),
}

/// Ordered multi-path endpoint selector and sub-second failover executor.
#[derive(Debug, Clone)]
pub struct OrderedEndpointFallback {
    policy: RelayPolicy,
    scorer: RelayHealthScorer,
    candidate_timeout: Duration,
}

impl OrderedEndpointFallback {
    pub fn new(policy: RelayPolicy) -> Self {
        let scorer = RelayHealthScorer::from_policy(&policy);
        Self {
            policy,
            scorer,
            candidate_timeout: Duration::from_millis(DEFAULT_CANDIDATE_DIAL_TIMEOUT_MS),
        }
    }

    pub fn with_candidate_timeout(mut self, timeout: Duration) -> Self {
        self.candidate_timeout = timeout.max(Duration::from_millis(10));
        self
    }

    pub fn scorer(&self) -> &RelayHealthScorer {
        &self.scorer
    }

    pub fn scorer_mut(&mut self) -> &mut RelayHealthScorer {
        &mut self.scorer
    }

    /// Produces the deterministic connection attempt order:
    /// 1. `DirectLanQuic` (`loopback` / RFC 1918 / link-local / ULA sockets),
    /// 2. `DirectWanQuic` (routable direct sockets),
    /// 3. `RelayWss443` ordered by live `RelayHealthScorer` score at `now_ms`.
    pub fn ordered_candidates(
        &self,
        lan_addrs: &[SocketAddr],
        wan_addrs: &[SocketAddr],
        now_ms: u64,
    ) -> Vec<TransportCandidate> {
        let mut out = Vec::with_capacity(
            lan_addrs.len() + wan_addrs.len() + self.policy.ordered_relay_urls().len(),
        );
        for &addr in lan_addrs {
            let cand = TransportCandidate::DirectLanQuic(addr);
            if !out.contains(&cand) {
                out.push(cand);
            }
        }
        for &addr in wan_addrs {
            let cand = TransportCandidate::DirectWanQuic(addr);
            if !out.contains(&cand) {
                out.push(cand);
            }
        }
        for relay in self.scorer.ranked_relays(now_ms) {
            out.push(TransportCandidate::RelayWss443(relay));
        }
        out
    }

    /// Attaches only currently healthy (or fallback) regional relays to a verified
    /// peer's `EndpointAddr` while preserving all direct IP sockets.
    pub fn attach_healthy_peer(
        &self,
        peer: EndpointAddr,
        expected_peer: EndpointId,
        now_ms: u64,
    ) -> Result<EndpointAddr, FailoverError> {
        if !self.policy.has_relay() {
            return Ok(self.policy.attach_verified_peer(peer, expected_peer)?);
        }
        let healthy = self.scorer.healthy_or_fallback_relays(now_ms);
        Ok(self
            .policy
            .attach_verified_peer_with_order(peer, expected_peer, Some(&healthy))?)
    }

    /// Executes bounded async failover across `ordered_candidates`, enforcing
    /// `self.candidate_timeout` on each step so an unresponsive blackholed region
    /// triggers sub-second fallback and automatic quarantine!
    pub async fn connect_with_failover<T, E, F, Fut>(
        &mut self,
        lan_addrs: &[SocketAddr],
        wan_addrs: &[SocketAddr],
        now_ms: u64,
        mut dial_fn: F,
    ) -> Result<(TransportCandidate, T), FailoverError>
    where
        F: FnMut(TransportCandidate) -> Fut,
        Fut: Future<Output = Result<(T, u64), E>>,
    {
        let candidates = self.ordered_candidates(lan_addrs, wan_addrs, now_ms);
        if candidates.is_empty() {
            return Err(FailoverError::AllCandidatesExhausted { attempted: 0 });
        }

        let attempted = candidates.len();
        for cand in candidates {
            let outcome = tokio::time::timeout(self.candidate_timeout, dial_fn(cand.clone())).await;
            match outcome {
                Ok(Ok((conn, observed_rtt_ms))) => {
                    if let TransportCandidate::RelayWss443(ref url) = cand {
                        let _ = self.scorer.record_success(url, observed_rtt_ms);
                    }
                    return Ok((cand, conn));
                }
                Ok(Err(_)) | Err(_) => {
                    if let TransportCandidate::RelayWss443(ref url) = cand {
                        let _ = self.scorer.record_outage(url, now_ms);
                    }
                }
            }
        }

        Err(FailoverError::AllCandidatesExhausted { attempted })
    }
}

// ============================================================================
// 4. Signed Sub-Second Session Resumption Ticket (`Ed25519 verify_strict`)
// ============================================================================

/// Cryptographically signed session resumption state allowing an interrupted
/// encrypted stream to resume immediately on a surviving regional relay from
/// `last_acked_seq + 1` without resetting replay state or re-handshaking from zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionResumptionTicketV1 {
    pub peer_id: [u8; 32],
    pub session_epoch: u64,
    pub last_acked_seq: u64,
    pub transcript_sha256: [u8; 32],
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub issuer_pubkey: [u8; 32],
    pub signature_hex: String,
}

impl SessionResumptionTicketV1 {
    pub fn issue(
        peer_id: [u8; 32],
        session_epoch: u64,
        last_acked_seq: u64,
        transcript_sha256: [u8; 32],
        issued_unix_ms: u64,
        ttl_ms: u64,
        issuer_signing_key: &SigningKey,
    ) -> Result<Self, FailoverError> {
        if session_epoch == 0 || ttl_ms == 0 {
            return Err(FailoverError::ResumptionRejected(
                "session_epoch and ttl_ms must be non-zero",
            ));
        }
        let vk = issuer_signing_key.verifying_key();
        if vk.is_weak() {
            return Err(FailoverError::ResumptionRejected("weak issuer Ed25519 key"));
        }
        let expires_unix_ms = issued_unix_ms.saturating_add(ttl_ms);
        let issuer_pubkey = vk.to_bytes();
        let preimage = ticket_preimage(
            &peer_id,
            session_epoch,
            last_acked_seq,
            &transcript_sha256,
            issued_unix_ms,
            expires_unix_ms,
            &issuer_pubkey,
        );
        let sig = issuer_signing_key.sign(&preimage);
        Ok(Self {
            peer_id,
            session_epoch,
            last_acked_seq,
            transcript_sha256,
            issued_unix_ms,
            expires_unix_ms,
            issuer_pubkey,
            signature_hex: hex::encode(sig.to_bytes()),
        })
    }

    /// Strictly verifies the `Ed25519` ticket signature, pinned issuer key, peer
    /// binding, transcript commitment, monotonic epoch, and expiry before resuming.
    pub fn verify_and_resume(
        &self,
        expected_issuer_pubkey: &[u8; 32],
        expected_peer_id: &[u8; 32],
        expected_transcript_sha256: &[u8; 32],
        min_session_epoch: u64,
        now_unix_ms: u64,
    ) -> Result<ReplayWindow, FailoverError> {
        if self.session_epoch == 0 || self.session_epoch < min_session_epoch {
            return Err(FailoverError::ResumptionRejected(
                "stale or zero session_epoch",
            ));
        }
        if now_unix_ms > self.expires_unix_ms || self.expires_unix_ms <= self.issued_unix_ms {
            return Err(FailoverError::ResumptionRejected(
                "session resumption ticket expired",
            ));
        }
        if !bool::from(self.issuer_pubkey.ct_eq(expected_issuer_pubkey)) {
            return Err(FailoverError::ResumptionRejected(
                "issuer Ed25519 key mismatch",
            ));
        }
        if !bool::from(self.peer_id.ct_eq(expected_peer_id)) {
            return Err(FailoverError::ResumptionRejected("peer_id mismatch"));
        }
        if !bool::from(self.transcript_sha256.ct_eq(expected_transcript_sha256)) {
            return Err(FailoverError::ResumptionRejected(
                "session transcript SHA-256 mismatch",
            ));
        }
        let vk = VerifyingKey::from_bytes(&self.issuer_pubkey)
            .map_err(|_| FailoverError::ResumptionRejected("invalid issuer Ed25519 key"))?;
        if vk.is_weak() {
            return Err(FailoverError::ResumptionRejected(
                "weak small-order issuer Ed25519 key",
            ));
        }
        let sig_raw = hex::decode(&self.signature_hex)
            .map_err(|_| FailoverError::ResumptionRejected("malformed ticket signature hex"))?;
        let sig_arr: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| FailoverError::ResumptionRejected("invalid ticket signature length"))?;
        let preimage = ticket_preimage(
            &self.peer_id,
            self.session_epoch,
            self.last_acked_seq,
            &self.transcript_sha256,
            self.issued_unix_ms,
            self.expires_unix_ms,
            &self.issuer_pubkey,
        );
        vk.verify_strict(&preimage, &Signature::from_bytes(&sig_arr))
            .map_err(|_| {
                FailoverError::ResumptionRejected("Ed25519 verify_strict rejected ticket")
            })?;

        Ok(ReplayWindow::from_resumed_checkpoint(self.last_acked_seq))
    }
}

fn ticket_preimage(
    peer_id: &[u8; 32],
    session_epoch: u64,
    last_acked_seq: u64,
    transcript_sha256: &[u8; 32],
    issued_unix_ms: u64,
    expires_unix_ms: u64,
    issuer_pubkey: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(168);
    out.extend_from_slice(RESUMPTION_TICKET_DOMAIN);
    out.extend_from_slice(peer_id);
    out.extend_from_slice(&session_epoch.to_be_bytes());
    out.extend_from_slice(&last_acked_seq.to_be_bytes());
    out.extend_from_slice(transcript_sha256);
    out.extend_from_slice(&issued_unix_ms.to_be_bytes());
    out.extend_from_slice(&expires_unix_ms.to_be_bytes());
    out.extend_from_slice(issuer_pubkey);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_accepts_out_of_order_within_128_and_rejects_replays_or_stale() {
        let mut win = ReplayWindow::new();
        assert_eq!(win.check_unseen(0), Err(FailoverError::ZeroSequence));

        win.record_verified(1).unwrap();
        win.record_verified(5).unwrap();
        win.record_verified(3).unwrap();
        assert_eq!(win.highest_seq(), 5);

        assert_eq!(win.check_unseen(3), Err(FailoverError::DuplicateReplay(3)));
        assert_eq!(win.check_unseen(5), Err(FailoverError::DuplicateReplay(5)));
        assert!(win.check_unseen(2).is_ok());
        assert!(win.check_unseen(4).is_ok());

        // Jump ahead to 200 -> 200 - 128 = 72; sequence 72 is now outside the 128-bit window, 73 is inside
        win.record_verified(200).unwrap();
        assert!(matches!(
            win.check_unseen(72),
            Err(FailoverError::StaleSequence {
                sequence: 72,
                highest: 200
            })
        ));
        assert!(win.check_unseen(73).is_ok());
        win.record_verified(73).unwrap();
        assert_eq!(
            win.check_unseen(73),
            Err(FailoverError::DuplicateReplay(73))
        );
    }

    #[tokio::test]
    async fn endpoint_fallback_quarantines_blackholed_region_and_switches_sub_second() {
        let regions = [
            "https://us-east.relay-example.invalid/",
            "https://eu-west.relay-example.invalid/",
            "https://ap-northeast.relay-example.invalid/",
        ];
        let policy = RelayPolicy::from_multi_region_manifest(&regions, &regions).unwrap();
        let mut fallback =
            OrderedEndpointFallback::new(policy).with_candidate_timeout(Duration::from_millis(60));

        let lan: SocketAddr = "192.168.1.20:9000".parse().unwrap();
        let now_ms = 1_790_000_000_000u64;

        let start = std::time::Instant::now();
        let (winner, banner) = fallback
            .connect_with_failover(&[lan], &[], now_ms, |cand| async move {
                match cand {
                    TransportCandidate::DirectLanQuic(_) => {
                        Err::<(&'static str, u64), _>("lan_unreachable")
                    }
                    TransportCandidate::RelayWss443(ref u)
                        if u.as_str() == "https://us-east.relay-example.invalid/" =>
                    {
                        // Simulate regional outage blackhole exceeding candidate_timeout
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        Ok(("never_reached", 999))
                    }
                    TransportCandidate::RelayWss443(ref u)
                        if u.as_str() == "https://eu-west.relay-example.invalid/" =>
                    {
                        Ok(("connected_eu_west", 28))
                    }
                    _ => Err("unused"),
                }
            })
            .await
            .expect("failover must succeed on eu-west");

        assert!(
            start.elapsed() < Duration::from_millis(500),
            "switchover took {:?}, expected sub-second",
            start.elapsed()
        );
        assert_eq!(banner, "connected_eu_west");
        assert_eq!(
            winner,
            TransportCandidate::RelayWss443(
                "https://eu-west.relay-example.invalid/".parse().unwrap()
            )
        );

        // Verify `us-east` is now quarantined and `eu-west` ranks #1 on subsequent attempts!
        let ranked = fallback.scorer().ranked_relays(now_ms + 100);
        assert_eq!(ranked[0].as_str(), "https://eu-west.relay-example.invalid/");
        assert_eq!(
            ranked.last().unwrap().as_str(),
            "https://us-east.relay-example.invalid/"
        );

        // After quarantine cooldown expires (`> 1000ms`) and `us-east` recovers with 12ms RTT, it re-enters #1
        let us_url: RelayUrl = "https://us-east.relay-example.invalid/".parse().unwrap();
        fallback
            .scorer_mut()
            .record_success(&us_url, 12)
            .expect("record recovery");
        let recovered_rank = fallback.scorer().ranked_relays(now_ms + 2_000);
        assert_eq!(
            recovered_rank[0].as_str(),
            "https://us-east.relay-example.invalid/"
        );
    }

    #[test]
    fn session_resumption_ticket_enforces_ed25519_verify_strict_and_restores_replay_checkpoint() {
        let sk = SigningKey::from_bytes(&[0x77u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let peer_id = [0x12u8; 32];
        let transcript = [0xab; 32];
        let now_ms = 1_790_000_000_000u64;

        let ticket =
            SessionResumptionTicketV1::issue(peer_id, 3, 42, transcript, now_ms, 60_000, &sk)
                .unwrap();

        let mut resumed_win = ticket
            .verify_and_resume(&pk, &peer_id, &transcript, 3, now_ms + 500)
            .unwrap();
        assert_eq!(resumed_win.highest_seq(), 42);
        // Frames `<= 42` were already acked before the outage and MUST be rejected as replays!
        assert_eq!(
            resumed_win.check_unseen(42),
            Err(FailoverError::DuplicateReplay(42))
        );
        assert_eq!(
            resumed_win.check_unseen(1),
            Err(FailoverError::DuplicateReplay(1))
        );
        // Frame `43` seamlessly continues on the new regional relay!
        resumed_win.record_verified(43).unwrap();
        assert_eq!(resumed_win.highest_seq(), 43);

        // Expired ticket fails closed
        assert!(
            ticket
                .verify_and_resume(&pk, &peer_id, &transcript, 3, now_ms + 60_001)
                .is_err()
        );

        // Downgraded epoch fails closed
        assert!(
            ticket
                .verify_and_resume(&pk, &peer_id, &transcript, 4, now_ms + 100)
                .is_err()
        );

        // Tampered `last_acked_seq` rejected by Ed25519 `verify_strict`
        let mut tampered = ticket;
        tampered.last_acked_seq = 10;
        assert!(
            tampered
                .verify_and_resume(&pk, &peer_id, &transcript, 3, now_ms + 100)
                .is_err()
        );
    }
}
