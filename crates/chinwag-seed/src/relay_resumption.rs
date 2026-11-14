// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Multi-Region Encrypted Capsule Stream Failover & Sub-Second Session Resumption
//! (`CHWG-0200` · `SignedHpkeBlobV1` + `zstd` + `ReplayWindow` + `SessionResumptionTicketV1`).
//!
//! Ensures flight-recorder seed capsules and multi-chunk artifact streams stay
//! encrypted and uninterrupted across regional `WSS :443` relay blackholes while
//! enforcing `K1 + K2` `Ed25519` verify-before-decrypt before any `X25519-MLKEM768`
//! decapsulation or bounded single-frame `zstd` decompression.

use chinwag_swarm::relay_failover::{
    FailoverError, OrderedEndpointFallback, ReplayWindow, SessionResumptionTicketV1,
    TransportCandidate,
};
use chinwag_swarm::relay_policy::RelayPolicy;
use chinwag_swarm::signed_hpke::{
    DEFAULT_MAX_CLOCK_SKEW_MICROS, OriginKeyRing, RelayKeyRing, RelaySignaturePolicy,
    SealBlobParams, SignedHpkeError, XWING_PUBLIC_KEY_BYTES, countersign_relay_blob_k2,
    derive_blinded_coalesce_tag, seal_for_blind_relay_transit, seal_signed_hpke_blob_v1,
    verify_and_open_with_decap_counter,
};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use zeroize::Zeroizing;

/// Upper bound (`8 MiB`) on uncompressed capsule chunk bytes per frame (`zip-bomb` defense).
pub const MAX_CAPSULE_CHUNK_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;

const ZSTD_CAPSULE_MAGIC: &[u8; 4] = b"CWZS";

#[derive(Debug, thiserror::Error)]
pub enum CapsuleResumptionError {
    #[error("capsule chunk exceeds 8 MiB uncompressed limit")]
    ChunkTooLarge,
    #[error("zstd capsule framing or bounded decompression failed")]
    Compression,
    #[error("SignedHpkeBlobV1 cryptographic verification failed: {0}")]
    SignedHpke(#[from] SignedHpkeError),
    #[error("multi-region failover or resumption error: {0}")]
    Failover(#[from] FailoverError),
}

/// Input parameters for sealing a compressed capsule frame into `SignedHpkeBlobV1`.
pub struct CapsuleSealParams<'a> {
    pub origin_k1: &'a ed25519_dalek::SigningKey,
    pub recipient_xwing_pk: &'a [u8; XWING_PUBLIC_KEY_BYTES],
    pub shared_room_secret: &'a [u8; 32],
    pub capsule_topic: &'a [u8],
    pub sequence: u64,
    pub timestamp_unix_micros: u64,
    pub chunk_plaintext: &'a [u8],
    pub direct_p2p: bool,
}

/// Compresses a capsule chunk (`CWZS` + `u32 BE` uncompressed length + single-frame `zstd`)
/// and seals it inside a `1,408`-byte-framed `SignedHpkeBlobV1` envelope.
pub fn seal_compressed_capsule_frame(
    params: CapsuleSealParams<'_>,
) -> Result<Vec<u8>, CapsuleResumptionError> {
    if params.chunk_plaintext.len() > MAX_CAPSULE_CHUNK_PLAINTEXT_BYTES {
        return Err(CapsuleResumptionError::ChunkTooLarge);
    }
    let plain_len_u32 = u32::try_from(params.chunk_plaintext.len())
        .map_err(|_| CapsuleResumptionError::ChunkTooLarge)?;
    let zstd_bytes = zstd::stream::encode_all(Cursor::new(params.chunk_plaintext), 3)
        .map_err(|_| CapsuleResumptionError::Compression)?;

    let mut framed = Zeroizing::new(Vec::with_capacity(8 + zstd_bytes.len()));
    framed.extend_from_slice(ZSTD_CAPSULE_MAGIC);
    framed.extend_from_slice(&plain_len_u32.to_be_bytes());
    framed.extend_from_slice(&zstd_bytes);

    let t_coalesce = derive_blinded_coalesce_tag(params.shared_room_secret, params.capsule_topic);
    let seal_params = SealBlobParams {
        origin_signing_key_k1: params.origin_k1,
        recipient_xwing_public: params.recipient_xwing_pk,
        t_coalesce,
        sequence: params.sequence,
        timestamp_unix_micros: params.timestamp_unix_micros,
        plaintext: framed.as_slice(),
    };
    if params.direct_p2p {
        Ok(seal_signed_hpke_blob_v1(seal_params, None)?)
    } else {
        Ok(seal_for_blind_relay_transit(seal_params)?)
    }
}

/// Verifies `K1 + K2` `Ed25519` signatures and `ReplayWindow` BEFORE `X25519-MLKEM768`
/// decapsulation, then performs strictly bounded single-frame `zstd` decompression.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_open_compressed_capsule_frame(
    wire: &[u8],
    origin_ring: &OriginKeyRing,
    relay_policy: RelaySignaturePolicy<'_>,
    recipient_xwing_secret: &[u8; 32],
    replay_window: &mut ReplayWindow,
    now_unix_micros: u64,
    decap_counter: Option<&AtomicUsize>,
) -> Result<(u64, Zeroizing<Vec<u8>>), CapsuleResumptionError> {
    let opened = verify_and_open_with_decap_counter(
        wire,
        origin_ring,
        relay_policy,
        recipient_xwing_secret,
        replay_window,
        now_unix_micros,
        DEFAULT_MAX_CLOCK_SKEW_MICROS,
        decap_counter,
    )?;

    if opened.plaintext.len() < 8 || &opened.plaintext[0..4] != ZSTD_CAPSULE_MAGIC {
        return Err(CapsuleResumptionError::Compression);
    }
    let declared_len = u32::from_be_bytes(opened.plaintext[4..8].try_into().unwrap()) as usize;
    if declared_len > MAX_CAPSULE_CHUNK_PLAINTEXT_BYTES {
        return Err(CapsuleResumptionError::ChunkTooLarge);
    }

    let zstd_slice = &opened.plaintext[8..];
    let mut decoder = zstd::stream::read::Decoder::with_buffer(Cursor::new(zstd_slice))
        .map_err(|_| CapsuleResumptionError::Compression)?
        .single_frame();
    let mut out = Zeroizing::new(Vec::with_capacity(declared_len));
    decoder
        .by_ref()
        .take((declared_len + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|_| CapsuleResumptionError::Compression)?;
    if out.len() != declared_len || decoder.finish().position() != zstd_slice.len() as u64 {
        return Err(CapsuleResumptionError::Compression);
    }
    Ok((opened.sequence, out))
}

/// Stateful receiver tracking monotonic capsule sequence acknowledgments, rolling
/// transcript SHA-256 commitments, and signed `SessionResumptionTicketV1` checkpoints
/// across regional `WSS :443` failover events.
pub struct ResumableCapsuleReceiver {
    peer_id: [u8; 32],
    session_epoch: u64,
    replay_window: ReplayWindow,
    transcript_sha256: [u8; 32],
    origin_ring: OriginKeyRing,
    relay_ring: RelayKeyRing,
    recipient_xwing_secret: Zeroizing<[u8; 32]>,
}

impl ResumableCapsuleReceiver {
    pub fn new(
        peer_id: [u8; 32],
        session_epoch: u64,
        origin_ring: OriginKeyRing,
        relay_ring: RelayKeyRing,
        recipient_xwing_secret: Zeroizing<[u8; 32]>,
    ) -> Self {
        Self {
            peer_id,
            session_epoch,
            replay_window: ReplayWindow::new(),
            transcript_sha256: [0u8; 32],
            origin_ring,
            relay_ring,
            recipient_xwing_secret,
        }
    }

    pub fn ingest_cloud_relay_frame(
        &mut self,
        wire: &[u8],
        now_unix_micros: u64,
        decap_counter: Option<&AtomicUsize>,
    ) -> Result<(u64, Zeroizing<Vec<u8>>), CapsuleResumptionError> {
        let (seq, plain) = verify_and_open_compressed_capsule_frame(
            wire,
            &self.origin_ring,
            RelaySignaturePolicy::RequireCloudK2(&self.relay_ring),
            &self.recipient_xwing_secret,
            &mut self.replay_window,
            now_unix_micros,
            decap_counter,
        )?;
        let mut h = Sha256::new();
        h.update(self.transcript_sha256);
        h.update(seq.to_be_bytes());
        h.update(Sha256::digest(plain.as_slice()));
        self.transcript_sha256 = h.finalize().into();
        Ok((seq, plain))
    }

    pub fn issue_resumption_ticket(
        &self,
        issued_unix_ms: u64,
        ttl_ms: u64,
        issuer_sk: &ed25519_dalek::SigningKey,
    ) -> Result<SessionResumptionTicketV1, CapsuleResumptionError> {
        Ok(SessionResumptionTicketV1::issue(
            self.peer_id,
            self.session_epoch,
            self.replay_window.highest_seq(),
            self.transcript_sha256,
            issued_unix_ms,
            ttl_ms,
            issuer_sk,
        )?)
    }

    /// Resumes on a failover region using a verified `SessionResumptionTicketV1`,
    /// bumping `session_epoch` and restoring the exact anti-replay checkpoint.
    pub fn apply_verified_resumption(
        &mut self,
        ticket: &SessionResumptionTicketV1,
        expected_issuer_pk: &[u8; 32],
        now_unix_ms: u64,
    ) -> Result<u64, CapsuleResumptionError> {
        let restored_window = ticket.verify_and_resume(
            expected_issuer_pk,
            &self.peer_id,
            &self.transcript_sha256,
            self.session_epoch,
            now_unix_ms,
        )?;
        self.replay_window = restored_window;
        self.session_epoch = ticket.session_epoch.saturating_add(1);
        Ok(ticket.last_acked_seq)
    }

    pub fn highest_acked_seq(&self) -> u64 {
        self.replay_window.highest_seq()
    }
}

/// Helper re-exporting blind-relay `K2` counter-signing + endpoint failover selection
/// for end-to-end integration callers and cleanroom tests.
pub fn build_multi_region_fallback(policy: RelayPolicy) -> OrderedEndpointFallback {
    OrderedEndpointFallback::new(policy)
}

pub fn blind_relay_countersign(
    wire: Vec<u8>,
    origin_ring: &OriginKeyRing,
    relay_k2: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, CapsuleResumptionError> {
    Ok(countersign_relay_blob_k2(wire, origin_ring, relay_k2)?)
}

pub fn candidate_is_cloud_relay(candidate: &TransportCandidate) -> bool {
    matches!(candidate, TransportCandidate::RelayWss443(_))
}

pub fn split_direct_lan_and_wan(addrs: &[SocketAddr]) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
    let mut lan = Vec::new();
    let mut wan = Vec::new();
    for &addr in addrs {
        let is_local = match addr.ip() {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unicast_link_local()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
            }
        };
        if is_local {
            lan.push(addr);
        } else {
            wan.push(addr);
        }
    }
    (lan, wan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chinwag_swarm::signed_hpke::generate_xwing_keypair;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    #[tokio::test]
    async fn capsule_stream_survives_mid_stream_regional_outage_with_sub_second_resumption_and_zero_unverified_decap()
     {
        let regions = [
            "https://us-east.capsule-relay.invalid/",
            "https://eu-central.capsule-relay.invalid/",
        ];
        let policy = RelayPolicy::from_multi_region_manifest(&regions, &regions).unwrap();
        let mut fallback =
            build_multi_region_fallback(policy).with_candidate_timeout(Duration::from_millis(50));

        let origin_sk = SigningKey::from_bytes(&[0x15u8; 32]);
        let us_relay_k2 = SigningKey::from_bytes(&[0x25u8; 32]);
        let eu_relay_k2 = SigningKey::from_bytes(&[0x35u8; 32]);
        let ticket_issuer_sk = SigningKey::from_bytes(&[0x45u8; 32]);
        let ticket_issuer_pk = ticket_issuer_sk.verifying_key().to_bytes();

        let (recipient_sk, recipient_pk) = generate_xwing_keypair().unwrap();

        let mut origin_ring = OriginKeyRing::new();
        origin_ring
            .enroll(origin_sk.verifying_key().to_bytes())
            .unwrap();
        let mut relay_ring = RelayKeyRing::new();
        relay_ring
            .enroll(us_relay_k2.verifying_key().to_bytes())
            .unwrap();
        relay_ring
            .enroll(eu_relay_k2.verifying_key().to_bytes())
            .unwrap();

        let peer_id = [0x88u8; 32];
        let room_secret = [0x77u8; 32];
        let now_ms = 1_790_000_000_000u64;
        let now_micros = now_ms * 1_000;

        let mut receiver = ResumableCapsuleReceiver::new(
            peer_id,
            1,
            origin_ring.clone(),
            relay_ring,
            recipient_sk,
        );
        let decap_counter = AtomicUsize::new(0);

        // Phase 1: Connect via primary `us-east` relay and deliver chunks 1 & 2
        let (active_path, _) = fallback
            .connect_with_failover(&[], &[], now_ms, |cand| async move {
                let _ = cand;
                Ok::<(&'static str, u64), &'static str>(("us-east-live", 18))
            })
            .await
            .unwrap();
        assert!(candidate_is_cloud_relay(&active_path));

        for (seq, text) in [
            (1u64, &b"capsule-part-1"[..]),
            (2u64, &b"capsule-part-2"[..]),
        ] {
            let sealed = seal_compressed_capsule_frame(CapsuleSealParams {
                origin_k1: &origin_sk,
                recipient_xwing_pk: &recipient_pk,
                shared_room_secret: &room_secret,
                capsule_topic: b"seed-vault-sync",
                sequence: seq,
                timestamp_unix_micros: now_micros,
                chunk_plaintext: text,
                direct_p2p: false,
            })
            .unwrap();
            let k2_wire = blind_relay_countersign(sealed, &origin_ring, &us_relay_k2).unwrap();
            let (got_seq, got_plain) = receiver
                .ingest_cloud_relay_frame(&k2_wire, now_micros, Some(&decap_counter))
                .unwrap();
            assert_eq!(got_seq, seq);
            assert_eq!(got_plain.as_slice(), text);
        }
        assert_eq!(decap_counter.load(Ordering::SeqCst), 2);

        // Issue signed resumption ticket at `last_acked_seq = 2` before `us-east` suffers a regional outage!
        let ticket = receiver
            .issue_resumption_ticket(now_ms, 30_000, &ticket_issuer_sk)
            .unwrap();
        assert_eq!(ticket.last_acked_seq, 2);

        // Phase 2: `us-east` goes completely dark -> `connect_with_failover` switches to `eu-central` in <100ms!
        let switch_start = std::time::Instant::now();
        let (failover_path, _) = fallback
            .connect_with_failover(&[], &[], now_ms + 200, |cand| async move {
                match cand {
                    TransportCandidate::RelayWss443(ref u)
                        if u.as_str() == "https://us-east.capsule-relay.invalid/" =>
                    {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        Err::<(&'static str, u64), _>("us-east-outage")
                    }
                    TransportCandidate::RelayWss443(ref u)
                        if u.as_str() == "https://eu-central.capsule-relay.invalid/" =>
                    {
                        Ok(("eu-central-live", 31))
                    }
                    _ => Err("unexpected"),
                }
            })
            .await
            .unwrap();
        assert!(switch_start.elapsed() < Duration::from_millis(500));
        assert_eq!(
            failover_path,
            TransportCandidate::RelayWss443(
                "https://eu-central.capsule-relay.invalid/".parse().unwrap()
            )
        );

        let resumed_from = receiver
            .apply_verified_resumption(&ticket, &ticket_issuer_pk, now_ms + 250)
            .unwrap();
        assert_eq!(resumed_from, 2);

        // Verify replayed chunk 2 on `eu-central` is rejected BEFORE HPKE decapsulation!
        let dup_seq2 = seal_compressed_capsule_frame(CapsuleSealParams {
            origin_k1: &origin_sk,
            recipient_xwing_pk: &recipient_pk,
            shared_room_secret: &room_secret,
            capsule_topic: b"seed-vault-sync",
            sequence: 2,
            timestamp_unix_micros: now_micros + 250_000,
            chunk_plaintext: b"capsule-part-2",
            direct_p2p: false,
        })
        .unwrap();
        let dup_seq2_k2 = blind_relay_countersign(dup_seq2, &origin_ring, &eu_relay_k2).unwrap();
        assert!(
            receiver
                .ingest_cloud_relay_frame(&dup_seq2_k2, now_micros + 250_000, Some(&decap_counter))
                .is_err()
        );
        assert_eq!(
            decap_counter.load(Ordering::SeqCst),
            2,
            "duplicate replayed frame after regional failover must NOT trigger HPKE decapsulation"
        );

        // Verify tampered ciphertext on `eu-central` is rejected BEFORE HPKE decapsulation!
        let mut tampered_seq3 = blind_relay_countersign(
            seal_compressed_capsule_frame(CapsuleSealParams {
                origin_k1: &origin_sk,
                recipient_xwing_pk: &recipient_pk,
                shared_room_secret: &room_secret,
                capsule_topic: b"seed-vault-sync",
                sequence: 3,
                timestamp_unix_micros: now_micros + 300_000,
                chunk_plaintext: b"capsule-part-3",
                direct_p2p: false,
            })
            .unwrap(),
            &origin_ring,
            &eu_relay_k2,
        )
        .unwrap();
        *tampered_seq3.last_mut().unwrap() ^= 0xff;
        assert!(
            receiver
                .ingest_cloud_relay_frame(
                    &tampered_seq3,
                    now_micros + 300_000,
                    Some(&decap_counter)
                )
                .is_err()
        );
        assert_eq!(decap_counter.load(Ordering::SeqCst), 2);

        // Chunk 3 (`seq = 3`) signed by `eu_relay_k2` seamlessly completes the stream!
        let valid_seq3 = blind_relay_countersign(
            seal_compressed_capsule_frame(CapsuleSealParams {
                origin_k1: &origin_sk,
                recipient_xwing_pk: &recipient_pk,
                shared_room_secret: &room_secret,
                capsule_topic: b"seed-vault-sync",
                sequence: 3,
                timestamp_unix_micros: now_micros + 300_000,
                chunk_plaintext: b"capsule-part-3",
                direct_p2p: false,
            })
            .unwrap(),
            &origin_ring,
            &eu_relay_k2,
        )
        .unwrap();
        let (seq3, plain3) = receiver
            .ingest_cloud_relay_frame(&valid_seq3, now_micros + 300_000, Some(&decap_counter))
            .unwrap();
        assert_eq!(seq3, 3);
        assert_eq!(plain3.as_slice(), b"capsule-part-3");
        assert_eq!(decap_counter.load(Ordering::SeqCst), 3);
        assert_eq!(receiver.highest_acked_seq(), 3);
    }

    #[test]
    fn socket_classifier_partitions_lan_and_wan_candidates() {
        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:9000".parse().unwrap(),
            "192.168.10.5:9000".parse().unwrap(),
            "198.51.100.42:9000".parse().unwrap(),
        ];
        let (lan, wan) = split_direct_lan_and_wan(&addrs);
        assert_eq!(lan.len(), 2);
        assert_eq!(wan.len(), 1);
    }
}
