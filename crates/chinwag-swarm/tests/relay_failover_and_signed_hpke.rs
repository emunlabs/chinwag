// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use chinwag_swarm::relay_failover::{
    BASE_OUTAGE_COOLDOWN_MS, FailoverError, MAX_CANDIDATE_DIAL_TIMEOUT_MS, MAX_OUTAGE_COOLDOWN_MS,
    OrderedEndpointFallback, ReplayWindow, SessionResumptionTicketV1, TransportCandidate,
};
use chinwag_swarm::relay_policy::RelayPolicy;
use chinwag_swarm::signed_hpke::{
    DEFAULT_MAX_CLOCK_SKEW_MICROS, OriginKeyRing, RelayKeyRing, RelaySignaturePolicy,
    SIGNED_HPKE_FIXED_FRAME_BYTES, SealBlobParams, SignedHpkeError, compute_crc32c,
    countersign_relay_blob_k2, derive_xwing_keypair_deterministic, generate_xwing_keypair,
    seal_for_blind_relay_transit, seal_signed_hpke_blob_v1, verify_and_open_with_decap_counter,
};
use ed25519_dalek::SigningKey;
use iroh::RelayUrl;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[test]
fn ietf_draft_hpke_pq_03_0x647a_xwing_keypair_kat_matches_published_vector() {
    let raw_json =
        include_str!("../../chinwag-ci/tests/vectors/hpke-pq-x25519-mlkem768-0x647a-base.json");
    let doc: Value = serde_json::from_str(raw_json).expect("parse KAT JSON");
    let vec0 = &doc["vectors"][0];
    let ikm_r_hex = vec0["ikmR"].as_str().unwrap();
    let expected_sk_hex = vec0["skRm"].as_str().unwrap();
    let expected_pk_hex = vec0["pkRm"].as_str().unwrap();

    let ikm_r: [u8; 32] = hex::decode(ikm_r_hex).unwrap().try_into().unwrap();
    let (sk_rm, pk_rm) = derive_xwing_keypair_deterministic(&ikm_r);
    assert_eq!(hex::encode(&sk_rm[..]), expected_sk_hex);
    assert_eq!(hex::encode(pk_rm), expected_pk_hex);
}

#[test]
fn exhaustive_tamper_matrix_guarantees_zero_hpke_decapsulations_before_k1_and_k2_verify() {
    let k1 = SigningKey::from_bytes(&[0x12u8; 32]);
    let k2 = SigningKey::from_bytes(&[0x24u8; 32]);
    let (recipient_sk, recipient_pk) = generate_xwing_keypair().unwrap();

    let mut origin_ring = OriginKeyRing::new();
    origin_ring.enroll(k1.verifying_key().to_bytes()).unwrap();
    let mut relay_ring = RelayKeyRing::new();
    relay_ring.enroll(k2.verifying_key().to_bytes()).unwrap();

    let now_micros = 1_790_000_000_000_000u64;
    let valid = seal_signed_hpke_blob_v1(
        SealBlobParams {
            origin_signing_key_k1: &k1,
            recipient_xwing_public: &recipient_pk,
            t_coalesce: [0x5au8; 32],
            sequence: 10,
            timestamp_unix_micros: now_micros,
            plaintext: b"verified zero-knowledge payload",
        },
        Some(&k2),
    )
    .unwrap();
    assert_eq!(valid.len(), SIGNED_HPKE_FIXED_FRAME_BYTES + 31);

    // Reject weak small-order Ed25519 torsion point `[1, 0, ..., 0]` on both K1 and K2 rings
    let mut weak_point = [0u8; 32];
    weak_point[0] = 1;
    assert_eq!(
        origin_ring.enroll(weak_point),
        Err(SignedHpkeError::UnknownOriginSigner)
    );
    assert_eq!(
        relay_ring.enroll(weak_point),
        Err(SignedHpkeError::RelaySignatureInvalid)
    );

    let decap_counter = AtomicUsize::new(0);
    let mut replay = ReplayWindow::new();

    let recompute_crc = |buf: &mut [u8]| {
        let crc = compute_crc32c(&buf[0..1380]);
        buf[1380..1384].copy_from_slice(&crc.to_be_bytes());
    };

    // 1. Truncated frame
    assert_eq!(
        verify_and_open_with_decap_counter(
            &valid[..1407],
            &origin_ring,
            RelaySignaturePolicy::RequireCloudK2(&relay_ring),
            &recipient_sk,
            &mut replay,
            now_micros,
            DEFAULT_MAX_CLOCK_SKEW_MICROS,
            Some(&decap_counter),
        ),
        Err(SignedHpkeError::InvalidFrameLength)
    );

    // 2. Magic byte mutation
    let mut bad_magic = valid.clone();
    bad_magic[0] ^= 0x01;
    assert_eq!(
        verify_and_open_with_decap_counter(
            &bad_magic,
            &origin_ring,
            RelaySignaturePolicy::RequireCloudK2(&relay_ring),
            &recipient_sk,
            &mut replay,
            now_micros,
            DEFAULT_MAX_CLOCK_SKEW_MICROS,
            Some(&decap_counter),
        ),
        Err(SignedHpkeError::UnsupportedHeaderSuite)
    );

    // 3. KEM ID downgrade attempt (`0x647a` -> `0x0020` classical X25519)
    let mut kem_downgrade = valid.clone();
    kem_downgrade[12..14].copy_from_slice(&0x0020u16.to_be_bytes());
    recompute_crc(&mut kem_downgrade);
    assert_eq!(
        verify_and_open_with_decap_counter(
            &kem_downgrade,
            &origin_ring,
            RelaySignaturePolicy::RequireCloudK2(&relay_ring),
            &recipient_sk,
            &mut replay,
            now_micros,
            DEFAULT_MAX_CLOCK_SKEW_MICROS,
            Some(&decap_counter),
        ),
        Err(SignedHpkeError::UnsupportedHeaderSuite)
    );

    // 4. CRC-32C bit flip
    let mut bad_crc = valid.clone();
    bad_crc[1383] ^= 0x01;
    assert_eq!(
        verify_and_open_with_decap_counter(
            &bad_crc,
            &origin_ring,
            RelaySignaturePolicy::RequireCloudK2(&relay_ring),
            &recipient_sk,
            &mut replay,
            now_micros,
            DEFAULT_MAX_CLOCK_SKEW_MICROS,
            Some(&decap_counter),
        ),
        Err(SignedHpkeError::HeaderCrcMismatch)
    );

    // 5. Expired timestamp outside 5-minute skew window
    assert!(matches!(
        verify_and_open_with_decap_counter(
            &valid,
            &origin_ring,
            RelaySignaturePolicy::RequireCloudK2(&relay_ring),
            &recipient_sk,
            &mut replay,
            now_micros + DEFAULT_MAX_CLOCK_SKEW_MICROS + 1,
            DEFAULT_MAX_CLOCK_SKEW_MICROS,
            Some(&decap_counter),
        ),
        Err(SignedHpkeError::ReplayOrFreshness(
            FailoverError::TimestampSkew { .. }
        ))
    ));

    // 6. Poly1305 AEAD tag bit flip (`1392..1408`) caught by K1 `OriginSigV1` BEFORE HPKE!
    let mut bad_tag = valid.clone();
    bad_tag[1395] ^= 0x04;
    assert_eq!(
        verify_and_open_with_decap_counter(
            &bad_tag,
            &origin_ring,
            RelaySignaturePolicy::RequireCloudK2(&relay_ring),
            &recipient_sk,
            &mut replay,
            now_micros,
            DEFAULT_MAX_CLOCK_SKEW_MICROS,
            Some(&decap_counter),
        ),
        Err(SignedHpkeError::OriginSignatureInvalid)
    );

    // 7. Blind-relay `countersign_relay_blob_k2` rejects unauthenticated K1 frame at the edge
    let mut forged_edge = seal_for_blind_relay_transit(SealBlobParams {
        origin_signing_key_k1: &k1,
        recipient_xwing_public: &recipient_pk,
        t_coalesce: [0x11u8; 32],
        sequence: 11,
        timestamp_unix_micros: now_micros,
        plaintext: b"edge check",
    })
    .unwrap();
    *forged_edge.last_mut().unwrap() ^= 0x01;
    assert_eq!(
        countersign_relay_blob_k2(forged_edge, &origin_ring, &k2),
        Err(SignedHpkeError::OriginSignatureInvalid)
    );

    // Confirm ZERO XWing decapsulations occurred across all 7 adversarial checks!
    assert_eq!(decap_counter.load(Ordering::SeqCst), 0);
    assert_eq!(replay.highest_seq(), 0);
}

#[tokio::test]
async fn four_region_failover_orders_lan_wan_then_health_scored_relays_with_exponential_quarantine()
{
    let regions = [
        "https://us-east.mesh-example.invalid/",
        "https://us-west.mesh-example.invalid/",
        "https://eu-west.mesh-example.invalid/",
        "https://ap-south.mesh-example.invalid/",
    ];
    let policy = RelayPolicy::from_multi_region_manifest(&regions, &regions).unwrap();
    let capped = OrderedEndpointFallback::new(policy.clone())
        .with_candidate_timeout(Duration::from_secs(10));
    assert_eq!(
        capped.candidate_timeout(),
        Duration::from_millis(MAX_CANDIDATE_DIAL_TIMEOUT_MS)
    );
    assert!(capped.candidate_timeout() < Duration::from_millis(250));

    let mut fb =
        OrderedEndpointFallback::new(policy).with_candidate_timeout(Duration::from_millis(40));

    let lan: SocketAddr = "10.0.0.12:9100".parse().unwrap();
    let wan: SocketAddr = "203.0.113.55:9100".parse().unwrap();
    let now_ms = 1_790_000_000_000u64;

    let initial = fb.ordered_candidates(&[lan], &[wan], now_ms);
    assert_eq!(initial[0], TransportCandidate::DirectLanQuic(lan));
    assert_eq!(initial[1], TransportCandidate::DirectWanQuic(wan));
    assert_eq!(
        initial[2],
        TransportCandidate::RelayWss443(regions[0].parse().unwrap())
    );

    // Trigger repeated outages on `us-east` to verify bounded exponential quarantine (`1s -> 2s -> 4s ... <= 30s`)
    let us_east: RelayUrl = regions[0].parse().unwrap();
    let until_1 = fb.scorer_mut().record_outage(&us_east, now_ms).unwrap();
    assert_eq!(until_1, now_ms + BASE_OUTAGE_COOLDOWN_MS);
    let until_2 = fb.scorer_mut().record_outage(&us_east, now_ms).unwrap();
    assert_eq!(until_2, now_ms + BASE_OUTAGE_COOLDOWN_MS * 2);
    for _ in 0..8 {
        let u = fb.scorer_mut().record_outage(&us_east, now_ms).unwrap();
        assert!(u <= now_ms + MAX_OUTAGE_COOLDOWN_MS);
    }

    // Quarantined `us-east` MUST NOT appear in `ordered_candidates` before cooldown expires!
    let active_ring = fb.ordered_candidates(&[lan], &[wan], now_ms + 100);
    assert!(
        !active_ring.contains(&TransportCandidate::RelayWss443(us_east.clone())),
        "quarantined relay must be excluded from dial candidates during active cooldown"
    );

    // Simulate simultaneous failure of LAN, WAN, and `us-west`, landing on `eu-west` (`us-east` skipped by quarantine)
    let dialed_us_east = AtomicUsize::new(0);
    let (chosen, label) = fb
        .connect_with_failover(&[lan], &[wan], now_ms + 100, |cand| {
            let counter_ref = &dialed_us_east;
            async move {
                match cand {
                    TransportCandidate::RelayWss443(ref u)
                        if u.as_str() == "https://us-east.mesh-example.invalid/" =>
                    {
                        counter_ref.fetch_add(1, Ordering::SeqCst);
                        Err::<(&'static str, u64), &'static str>("quarantined_should_not_dial")
                    }
                    TransportCandidate::RelayWss443(ref u)
                        if u.as_str() == "https://eu-west.mesh-example.invalid/" =>
                    {
                        Ok(("eu-west-ok", 22))
                    }
                    _ => Err("unreachable"),
                }
            }
        })
        .await
        .unwrap();
    assert_eq!(dialed_us_east.load(Ordering::SeqCst), 0);
    assert_eq!(label, "eu-west-ok");
    assert_eq!(
        chosen,
        TransportCandidate::RelayWss443(regions[2].parse().unwrap())
    );
}

#[test]
fn resumption_ticket_rejects_transcript_divergence_and_peer_mismatch() {
    let sk = SigningKey::from_bytes(&[0x81u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let peer_a = [0xaa; 32];
    let peer_b = [0xbb; 32];
    let transcript_1 = [0x11; 32];
    let transcript_2 = [0x22; 32];

    let win = ReplayWindow::from_resumed_checkpoint(100);
    let ticket =
        SessionResumptionTicketV1::issue(peer_a, 2, &win, transcript_1, 10_000, 5_000, &sk)
            .unwrap();
    assert!(
        ticket
            .verify_and_resume(&pk, &peer_b, &transcript_1, 2, 11_000)
            .is_err()
    );
    assert!(
        ticket
            .verify_and_resume(&pk, &peer_a, &transcript_2, 2, 11_000)
            .is_err()
    );
}
