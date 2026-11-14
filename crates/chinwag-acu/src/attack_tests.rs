// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Mandatory negative, known-answer, and adversarial regression tests (`CHWG-0283` §4.2) covering
//! Slices A–F (`ePrint v2`, `CHWG-PAT-11B-v2`, and `Chinwag UI v5` PRD `v1.3` `F-01`–`F-03`).

use crate::*;
use bls12_381::{G1Affine, G1Projective, G2Affine, Gt, Scalar, pairing};
use ed25519_dalek::SigningKey;
use ff::Field;
use rand_core::OsRng;
use std::collections::BTreeMap;

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn test_rfc9380_appendix_k1_expand_message_xmd_sha256_kats() {
    let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";

    // Published RFC 9380 Appendix K.1 vector 1: msg = "", len_in_bytes = 32
    let out_empty_32 = expand_message_xmd_sha256(b"", dst, 32).unwrap();
    assert_eq!(
        out_empty_32.as_slice(),
        decode_hex("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235").as_slice()
    );

    // Published RFC 9380 Appendix K.1 vector 2: msg = "abc", len_in_bytes = 32
    let out_abc_32 = expand_message_xmd_sha256(b"abc", dst, 32).unwrap();
    assert_eq!(
        out_abc_32.as_slice(),
        decode_hex("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615").as_slice()
    );

    // Published RFC 9380 Appendix K.1 vector 3: msg = "abc", len_in_bytes = 128
    let out_abc_128 = expand_message_xmd_sha256(b"abc", dst, 128).unwrap();
    assert_eq!(
        out_abc_128.as_slice(),
        decode_hex(concat!(
            "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a",
            "647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635",
            "bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00",
            "058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"
        ))
        .as_slice()
    );

    // RFC 9380 §5.3.3 oversized DST (> 255 bytes -> H("H2C-OVERSIZE-DST-" || dst))
    let long_dst = b"QUUX-V01-CS02-with-expander-SHA256-128-0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
    assert_eq!(long_dst.len(), 259);
    let out_long_dst = expand_message_xmd_sha256(b"abc", long_dst, 32).unwrap();
    assert_eq!(
        out_long_dst.as_slice(),
        decode_hex("9b5f0d9cfa472a1ee17251c22cb4a84111c67d9bbb3a8f81e451177082b2ef1a").as_slice()
    );

    // Boundary rejections: empty DST and ell > 255 (`len_in_bytes > 8160`)
    assert!(expand_message_xmd_sha256(b"abc", b"", 32).is_err());
    assert!(expand_message_xmd_sha256(b"abc", dst, 0).is_err());
    assert!(expand_message_xmd_sha256(b"abc", dst, 8161).is_err());
}

#[test]
fn test_gt_canonical_bytes_kat_and_distinct_elements() {
    // Multiplicative identity 1 in F_p^12: c0.c0.c0 = 1, all other 11 F_p limbs = 0.
    let id_bytes = gt_canonical_bytes(&Gt::identity()).unwrap();
    assert_eq!(id_bytes.len(), GT_CANONICAL_BYTES);
    assert_eq!(id_bytes[47], 1u8);
    assert!(id_bytes[..47].iter().all(|&b| b == 0));
    assert!(id_bytes[48..].iter().all(|&b| b == 0));

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let gt_1 = pairing(&g1, &g2);
    let gt_2 = pairing(
        &G1Affine::from(G1Projective::from(g1) * Scalar::from(2u64)),
        &g2,
    );
    let b1 = gt_canonical_bytes(&gt_1).unwrap();
    let b1_repeat = gt_canonical_bytes(&gt_1).unwrap();
    let b2 = gt_canonical_bytes(&gt_2).unwrap();
    assert_eq!(&*b1, &*b1_repeat);
    assert_ne!(&*b1, &*b2);
    assert_ne!(&*b1, &*id_bytes);
    use sha2::Digest;
    const EXPECTED_GT_GEN_CANONICAL_SHA256: [u8; 32] = [
        0x06, 0xfa, 0x58, 0x8b, 0x89, 0xfd, 0xfb, 0x03, 0x4d, 0xbc, 0x1c, 0x16, 0x3e, 0xcb, 0x3d,
        0xfa, 0xc2, 0x28, 0xf5, 0x52, 0xb6, 0x43, 0xc7, 0x29, 0x4c, 0xc5, 0xf2, 0xc4, 0xdc, 0x17,
        0x0b, 0x84,
    ];
    let b1_sha256: [u8; 32] = sha2::Sha256::digest(*b1).into();
    assert_eq!(b1_sha256, EXPECTED_GT_GEN_CANONICAL_SHA256);
}

#[test]
fn test_acu_sk_alone_cannot_recover_payload_key() {
    let mut rng = OsRng;
    let (sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
    let (_sk_agent, pk_agent) = SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
    let (_sk_archive, pk_archive) =
        SeatSecretKey::generate(DEFAULT_MESSAGE_ARCHIVE_ID, &mut rng).unwrap();

    let mut seat_keys = BTreeMap::new();
    for pk in [&pk_acu, &pk_agent, &pk_archive] {
        seat_keys.insert(pk.seat_id.clone(), (*pk).clone());
    }

    let secret_msg = b"top-secret root cause protected against compromised ACU";
    let payload = EncryptedCiPayload::encrypt_with_acu_and_archive(
        secret_msg,
        &pk_acu,
        &pk_agent,
        &pk_archive,
        "emunlabs/chinwag",
        "CHWG-0283-ACU-BLIND",
        &mut rng,
    )
    .unwrap();

    // 1. ACU holds ZERO post-quantum capsules (`project_non_acu` strips ACU completely).
    assert!(
        payload
            .decapsulate_pq_shares_for_seat(&sk_acu)
            .unwrap()
            .is_empty()
    );
    let pq_hdr = payload.pq_header.as_ref().unwrap();
    assert!(pq_hdr.rows.iter().all(|r| r.seat_id != DEFAULT_CISO_ACU_ID));

    // 2. Every SbcSlot has `col_offset >= 1` (zero V_0 = s*G1 sealed anywhere!).
    for slot in &payload.acu_ciphertext.sbc_slots {
        assert!(slot.col_offset >= 1);
    }

    // 3. ACU's own partial decryption share alone fails `acu_combine` (`PolicyNotSatisfied`).
    let d_acu = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[0],
        &sk_acu,
        payload.acu_ciphertext.policy_epoch,
    );
    assert_eq!(
        acu_combine(
            &payload.acu_ciphertext,
            std::slice::from_ref(&d_acu),
            &seat_keys
        ),
        Err(AcuError::PolicyNotSatisfied)
    );
    assert_eq!(
        acu_combine_unverified(&payload.acu_ciphertext, std::slice::from_ref(&d_acu)),
        Err(AcuError::PolicyNotSatisfied)
    );

    // 4. Subtracting `d_acu.share_g1` (or any scalar multiple `{1, 2, -1}`) directly from `c0_g1`
    // never yields the true `K_GT`!
    let k_scalar = Scalar::from(987_654_321u64);
    let known_g1 = G1Projective::generator() * k_scalar;
    let tree = EncryptedCiPayload::build_acu_recipient_or_archive_policy(
        DEFAULT_CISO_ACU_ID,
        DEFAULT_AGENT_BRANCH_ID,
        DEFAULT_MESSAGE_ARCHIVE_ID,
    );
    let mat = LsssMatrix::from_tree(&tree).unwrap();
    let (raw_ct, true_k_gt) =
        acu_encrypt_with_g1(&known_g1, &mat, &seat_keys, &pk_acu, &mut rng).unwrap();
    let raw_d_acu = acu_partial_decrypt_at_epoch(&raw_ct.rows[0], &sk_acu, raw_ct.policy_epoch);
    for mult in [
        Scalar::ONE,
        -Scalar::ONE,
        Scalar::from(2u64),
        -Scalar::from(2u64),
    ] {
        let guess = pairing(
            &G1Affine::from(raw_ct.c0_g1 - raw_d_acu.share_g1 * mult),
            &G2Affine::generator(),
        );
        assert_ne!(guess, true_k_gt);
    }
}

#[test]
fn test_mode_a_and_mode_b_dleq_reject_forged_share_with_valid_pk_schnorr() {
    let mut rng = OsRng;
    let (sk_agent, pk_agent) = SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
    let (_sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_REVOCATION_ACU_ID, &mut rng).unwrap();

    let payload = EncryptedCiPayload::encrypt_split_key_with_acu(
        b"dleq soundness check",
        &pk_agent,
        &pk_acu,
        "emunlabs/chinwag",
        "CHWG-0283-DLEQ-SOUNDNESS",
        &mut rng,
    )
    .unwrap();
    let row = &payload.acu_ciphertext.rows[0];

    let mut seat_keys = BTreeMap::new();
    seat_keys.insert(pk_agent.seat_id.clone(), pk_agent.clone());
    seat_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());

    // Custodian knows `sk_agent` (so can produce valid Schnorr proofs on `G_1 -> pk_agent`),
    // yet tries to forge a bogus `share_g1 = c1 - (sk_agent + 1) * c2`!
    for mode in [DleqMode::Compact, DleqMode::Batchable] {
        let honest = acu_partial_decrypt_with_mode(
            row,
            &sk_agent,
            payload.acu_ciphertext.policy_epoch,
            mode,
        );
        assert!(acu_verify_partial_share(row, &pk_agent, &honest));

        // Wire round-trip check (`CHWGSHR2` magic, 48B G1 + 64B Compact or 128B Batchable proof)
        let wire = honest.to_bytes();
        assert_eq!(&wire[..8], b"CHWGSHR2");
        let decoded = PartialDecryptionShare::from_bytes(&wire).unwrap();
        assert_eq!(decoded, honest);

        let mut forged = honest.clone();
        forged.share_g1 = row.c1 - row.c2 * (sk_agent.sk + Scalar::ONE);
        assert!(!acu_verify_partial_share(row, &pk_agent, &forged));

        if mode == DleqMode::Batchable {
            assert!(!batch_verify_partial_shares(
                &payload.acu_ciphertext.object_digest,
                payload.acu_ciphertext.policy_epoch,
                &payload.acu_ciphertext.rows,
                &seat_keys,
                std::slice::from_ref(&forged),
            ));
        }
    }
}

#[test]
fn test_mode_b_binary_split_isolates_corrupted_row() {
    let mut rng = OsRng;
    let (_sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();

    let mut sks = Vec::new();
    let mut pks = Vec::new();
    let mut seat_keys = BTreeMap::new();
    seat_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());
    let mut leaves = Vec::new();
    for idx in 0..8usize {
        let id = format!("custodian:{idx}");
        let (sk, pk) = SeatSecretKey::generate(&id, &mut rng).unwrap();
        leaves.push(AccessTree::Leaf(id.clone()));
        seat_keys.insert(id, pk.clone());
        sks.push(sk);
        pks.push(pk);
    }

    let tree = AccessTree::Threshold {
        threshold: 5,
        children: leaves,
    };
    let payload = EncryptedCiPayload::encrypt(
        b"5-of-8 batchable DLEQ fault isolation",
        &tree,
        &seat_keys,
        &pk_acu,
        "emunlabs/chinwag",
        "CHWG-0283-BATCH-ISOLATE",
        &mut rng,
    )
    .unwrap();

    let mut shares: Vec<PartialDecryptionShare> = (0..5usize)
        .map(|i| {
            acu_partial_decrypt_with_mode(
                &payload.acu_ciphertext.rows[i],
                &sks[i],
                payload.acu_ciphertext.policy_epoch,
                DleqMode::Batchable,
            )
        })
        .collect();

    // 1. All 5 honest Mode-B shares pass batch verification with 0 invalid indices.
    assert!(batch_verify_partial_shares(
        &payload.acu_ciphertext.object_digest,
        payload.acu_ciphertext.policy_epoch,
        &payload.acu_ciphertext.rows,
        &seat_keys,
        &shares,
    ));
    assert!(
        isolate_invalid_partial_shares(
            &payload.acu_ciphertext.object_digest,
            payload.acu_ciphertext.policy_epoch,
            &payload.acu_ciphertext.rows,
            &seat_keys,
            &shares,
            &mut rng,
        )
        .is_empty()
    );

    // 2. Corrupt ONLY share #3 (`custodian:3`) -> binary split pinpoints `[3]`!
    let mut one_corrupted = shares.clone();
    one_corrupted[3].share_g1 += G1Projective::generator();
    assert!(!batch_verify_partial_shares(
        &payload.acu_ciphertext.object_digest,
        payload.acu_ciphertext.policy_epoch,
        &payload.acu_ciphertext.rows,
        &seat_keys,
        &one_corrupted,
    ));
    let bad = isolate_invalid_partial_shares(
        &payload.acu_ciphertext.object_digest,
        payload.acu_ciphertext.policy_epoch,
        &payload.acu_ciphertext.rows,
        &seat_keys,
        &one_corrupted,
        &mut rng,
    );
    assert_eq!(bad, vec![3]);

    // 3. Cancelation attack (`+G1` on share #1, `-G1` on share #4): independent per-row `(alpha_j, beta_j)`
    // randomizers defeat naive sum cancelation and pinpoint `[1, 4]`!
    shares[1].share_g1 += G1Projective::generator();
    shares[4].share_g1 -= G1Projective::generator();
    assert!(!batch_verify_partial_shares(
        &payload.acu_ciphertext.object_digest,
        payload.acu_ciphertext.policy_epoch,
        &payload.acu_ciphertext.rows,
        &seat_keys,
        &shares,
    ));
    let bad = isolate_invalid_partial_shares(
        &payload.acu_ciphertext.object_digest,
        payload.acu_ciphertext.policy_epoch,
        &payload.acu_ciphertext.rows,
        &seat_keys,
        &shares,
        &mut rng,
    );
    assert_eq!(bad, vec![1, 4]);
}

#[test]
fn test_row_randomness_pok_blocks_cross_object_c2_copy_oracle_and_request_id_replay_fence() {
    let mut rng = OsRng;
    let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
    let acu_ed25519_sk = SigningKey::from_bytes(&[0x61u8; 32]);
    let (_agent_sk, agent_pk) = SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
    let agent_ed25519_sk = SigningKey::from_bytes(&[0x62u8; 32]);

    let mut registry = AllowedSignersRegistry::new();
    registry
        .register_seat(
            DEFAULT_CISO_ACU_ID,
            acu_ed25519_sk.verifying_key(),
            acu_pk.clone(),
        )
        .unwrap();
    registry
        .register_seat(
            DEFAULT_AGENT_BRANCH_ID,
            agent_ed25519_sk.verifying_key(),
            agent_pk.clone(),
        )
        .unwrap();

    let victim_payload = EncryptedCiPayload::encrypt_split_key_with_acu(
        b"victim object 1",
        &agent_pk,
        &acu_pk,
        "emunlabs/chinwag",
        "CHWG-0283-VICTIM-OBJ",
        &mut rng,
    )
    .unwrap();
    let attacker_payload = EncryptedCiPayload::encrypt_split_key_with_acu(
        b"attacker object 2",
        &agent_pk,
        &acu_pk,
        "emunlabs/chinwag",
        "CHWG-0283-ATTACKER-OBJ",
        &mut rng,
    )
    .unwrap();

    // 1. Cross-object `c2` copy oracle: attacker copies `(c1, c2, row_pok)` from `victim_payload`
    // into `attacker_payload` (different `object_digest`)! `RowPok` rejects immediately (`InvalidRowPok`).
    let mut cross_ct = attacker_payload.acu_ciphertext.clone();
    let mut copied_row = victim_payload.acu_ciphertext.rows[1].clone();
    copied_row.object_digest = cross_ct.object_digest;
    cross_ct.rows[1] = copied_row.clone();

    let mut ciso = CisoAcuFatClient::new(acu_sk, acu_pk, acu_ed25519_sk);
    let cross_req = AcuShareRequest::create_signed(
        "req-cross-obj-c2",
        DEFAULT_AGENT_BRANCH_ID,
        DEFAULT_CISO_ACU_ID,
        "emunlabs/chinwag",
        "CHWG-0283-ATTACKER-OBJ",
        1,
        cross_ct,
        copied_row,
        1_793_900_001_000,
        &agent_ed25519_sk,
    );
    assert_eq!(
        ciso.handle_iroh_share_request(&cross_req, &registry),
        Err(AcuError::InvalidRowPok)
    );

    // 2. Request-ID Replay Fence (`ePrint v2` §7):
    // - Exact retry of `"req-idempotent-1"` returns cached identical response.
    // - Reusing `"req-idempotent-1"` on a different ciphertext (`victim_payload` vs `attacker_payload`)
    //   MUST fail closed with `Err(AcuError::ReplayConflict)`!
    // - Once the requester is revoked (`instant_revoke`), replaying `"req-idempotent-1"` MUST fail
    //   with `Err(AcuError::SeatRevoked)` rather than serving the cached share!
    let valid_req = AcuShareRequest::create_signed(
        "req-idempotent-1",
        DEFAULT_AGENT_BRANCH_ID,
        DEFAULT_CISO_ACU_ID,
        "emunlabs/chinwag",
        "CHWG-0283-VICTIM-OBJ",
        1,
        victim_payload.acu_ciphertext.clone(),
        victim_payload.acu_ciphertext.rows[1].clone(),
        1_793_900_002_000,
        &agent_ed25519_sk,
    );
    let resp_1 = ciso
        .handle_iroh_share_request(&valid_req, &registry)
        .unwrap();
    let resp_retry = ciso
        .handle_iroh_share_request(&valid_req, &registry)
        .unwrap();
    assert_eq!(resp_1, resp_retry);

    let conflicting_req = AcuShareRequest::create_signed(
        "req-idempotent-1",
        DEFAULT_AGENT_BRANCH_ID,
        DEFAULT_CISO_ACU_ID,
        "emunlabs/chinwag",
        "CHWG-0283-ATTACKER-OBJ",
        1,
        attacker_payload.acu_ciphertext.clone(),
        attacker_payload.acu_ciphertext.rows[1].clone(),
        1_793_900_003_000,
        &agent_ed25519_sk,
    );
    assert_eq!(
        ciso.handle_iroh_share_request(&conflicting_req, &registry),
        Err(AcuError::ReplayConflict)
    );

    ciso.instant_revoke(DEFAULT_AGENT_BRANCH_ID);
    assert_eq!(
        ciso.handle_iroh_share_request(&valid_req, &registry),
        Err(AcuError::SeatRevoked(DEFAULT_AGENT_BRANCH_ID.to_string()))
    );
}

#[test]
fn test_escalate_threshold_nested_subtree_and_blocks_cached_epoch1_share() {
    let mut rng = OsRng;
    let (sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
    let (sk_a1, pk_a1) = SeatSecretKey::generate("seat:a1", &mut rng).unwrap();
    let (sk_a2, pk_a2) = SeatSecretKey::generate("seat:a2", &mut rng).unwrap();
    let (sk_b, pk_b) = SeatSecretKey::generate("seat:b", &mut rng).unwrap();
    let (sk_c, pk_c) = SeatSecretKey::generate("seat:c", &mut rng).unwrap();

    let mut seat_keys = BTreeMap::new();
    for pk in [&pk_acu, &pk_a1, &pk_a2, &pk_b, &pk_c] {
        seat_keys.insert(pk.seat_id.clone(), (*pk).clone());
    }

    // Policy: `Threshold(2-of-3: [OR(a1, a2), b, c]) AND ACU`
    // Rows: `0: a1`, `1: a2`, `2: b`, `3: c`, `4: ACU`
    let tree = AccessTree::And(vec![
        AccessTree::Threshold {
            threshold: 2,
            children: vec![
                AccessTree::Or(vec![
                    AccessTree::Leaf("seat:a1".to_string()),
                    AccessTree::Leaf("seat:a2".to_string()),
                ]),
                AccessTree::Leaf("seat:b".to_string()),
                AccessTree::Leaf("seat:c".to_string()),
            ],
        },
        AccessTree::Leaf(DEFAULT_CISO_ACU_ID.to_string()),
    ]);

    let mut payload = EncryptedCiPayload::encrypt(
        b"subtree-consistent Vandermonde threshold escalation",
        &tree,
        &seat_keys,
        &pk_acu,
        "emunlabs/chinwag",
        "CHWG-0283-NESTED-ESCALATE",
        &mut rng,
    )
    .unwrap();

    // Cache an Epoch-1 ACU share before escalation.
    let cached_acu_ep1 = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[4],
        &sk_acu,
        payload.acu_ciphertext.policy_epoch,
    );

    // Escalate the `2-of-3` gate covering rows `[0, 1, 2, 3]` by `delta_t = 1` (`2-of-3 -> 3-of-3`).
    escalate_threshold(
        &mut payload.acu_ciphertext,
        &sk_acu,
        &[0, 1, 2, 3],
        1,
        &seat_keys,
        &mut rng,
    )
    .unwrap();
    assert_eq!(payload.acu_ciphertext.policy_epoch, 2);

    // CRITICAL SUBTREE INVARIANT (`ePrint v2` §6.3 Op 2):
    // Both `a1` (row 0) and `a2` (row 1) belong to child 0 (`OR(a1, a2)`) of the `2-of-3` gate,
    // so they MUST share the IDENTICAL appended Vandermonde scalar `1^2 = 1` (not `1` and `4`!),
    // preventing `{a1, a2, b, ACU}` from bypassing `3-of-3` without `c`!
    let last_col = payload.acu_ciphertext.matrix.cols - 1;
    assert_eq!(
        payload.acu_ciphertext.rows[0].matrix_row[last_col],
        payload.acu_ciphertext.rows[1].matrix_row[last_col]
    );
    assert_eq!(
        payload.acu_ciphertext.rows[0].matrix_row[last_col],
        Scalar::from(1u64)
    );
    assert_eq!(
        payload.acu_ciphertext.rows[2].matrix_row[last_col],
        Scalar::from(4u64)
    );
    assert_eq!(
        payload.acu_ciphertext.rows[3].matrix_row[last_col],
        Scalar::from(9u64)
    );

    let d_a1 = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[0],
        &sk_a1,
        payload.acu_ciphertext.policy_epoch,
    );
    let d_a2 = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[1],
        &sk_a2,
        payload.acu_ciphertext.policy_epoch,
    );
    let d_b = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[2],
        &sk_b,
        payload.acu_ciphertext.policy_epoch,
    );
    let d_c = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[3],
        &sk_c,
        payload.acu_ciphertext.policy_epoch,
    );
    let d_acu = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[4],
        &sk_acu,
        payload.acu_ciphertext.policy_epoch,
    );

    let mut pq_all = payload.decapsulate_pq_shares_for_seat(&sk_a1).unwrap();
    pq_all.extend(payload.decapsulate_pq_shares_for_seat(&sk_a2).unwrap());
    pq_all.extend(payload.decapsulate_pq_shares_for_seat(&sk_b).unwrap());
    pq_all.extend(payload.decapsulate_pq_shares_for_seat(&sk_c).unwrap());

    // `{a1, a2, b, ACU}` (missing `c`!) MUST fail `PolicyNotSatisfied`!
    assert_eq!(
        payload.decrypt(
            &[d_a1.clone(), d_a2.clone(), d_b.clone(), d_acu.clone()],
            &pq_all,
            &seat_keys
        ),
        Err(AcuError::PolicyNotSatisfied)
    );

    // Replaying relabeled `cached_acu_ep1` at Epoch 2 fails closed!
    let mut relabeled_acu = cached_acu_ep1;
    relabeled_acu.policy_epoch = 2;
    assert_eq!(
        payload.decrypt_unverified(
            &[d_a2.clone(), d_b.clone(), d_c.clone(), relabeled_acu],
            &pq_all
        ),
        Err(AcuError::AeadFailure)
    );

    // Legitimate `{a2, b, c, ACU}` at Epoch 2 succeeds!
    assert_eq!(
        payload
            .decrypt(&[d_a2, d_b, d_c, d_acu], &pq_all, &seat_keys)
            .unwrap(),
        b"subtree-consistent Vandermonde threshold escalation"
    );
}

#[test]
fn test_revoke_refuses_unsatisfiable_2_of_2_self_lockout_and_insert_span_exclusion() {
    let mut rng = OsRng;
    let (sk_agent, pk_agent) = SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
    let (sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_REVOCATION_ACU_ID, &mut rng).unwrap();
    let (_sk_bypass, pk_bypass) = SeatSecretKey::generate("branch:bypass", &mut rng).unwrap();

    let mut seat_keys = BTreeMap::new();
    seat_keys.insert(pk_agent.seat_id.clone(), pk_agent.clone());
    seat_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());
    seat_keys.insert(pk_bypass.seat_id.clone(), pk_bypass);

    let mut payload = EncryptedCiPayload::encrypt_split_key_with_acu(
        b"guardrails test",
        &pk_agent,
        &pk_acu,
        "emunlabs/chinwag",
        "CHWG-0283-GUARDRAILS",
        &mut rng,
    )
    .unwrap();

    // 1. `revoke_and_rerandomize` refuses accidental 2-of-2 self-lockout (`PolicyUnsatisfiableAfterRevocation`).
    assert_eq!(
        revoke_and_rerandomize(
            &mut payload.acu_ciphertext,
            &sk_acu,
            &[DEFAULT_AGENT_BRANCH_ID],
            &seat_keys,
            &mut rng,
        ),
        Err(AcuError::PolicyUnsatisfiableAfterRevocation)
    );
    assert_eq!(payload.acu_ciphertext.policy_epoch, 1);

    // 2. Non-ACU span exclusion: inserting `[1, 0]` for a non-ACU seat on `agent AND acu` would let
    // `branch:bypass` span `e_0 = (1, 0)` WITHOUT `ACU`, so `insert_authorized_seat` rejects with
    // `Err(AcuError::SlotSpanExposesSecret)`!
    let c0 =
        CoalitionInsertionRowShare::issue_for_row(&payload.acu_ciphertext, 0, &sk_agent).unwrap();
    let c1 =
        CoalitionInsertionRowShare::issue_for_row(&payload.acu_ciphertext, 1, &sk_acu).unwrap();
    assert_eq!(
        insert_authorized_seat(
            &mut payload.acu_ciphertext,
            &sk_acu,
            "branch:bypass",
            vec![Scalar::ONE, Scalar::ZERO],
            &[c0, c1],
            &seat_keys,
            &mut rng,
        ),
        Err(AcuError::SlotSpanExposesSecret)
    );
}

#[test]
fn test_lsss_pq_threshold_and_rotate_pq_key_zero_c1_reencryption() {
    let mut rng = OsRng;
    let (sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
    let (sk_a, pk_a) = SeatSecretKey::generate("seat:pq-a", &mut rng).unwrap();
    let (sk_b, pk_b) = SeatSecretKey::generate("seat:pq-b", &mut rng).unwrap();
    let (sk_c, pk_c) = SeatSecretKey::generate("seat:pq-c", &mut rng).unwrap();

    // Verify FIPS 203 `ML-KEM-768` out-of-modulus byte & Curve25519 low-order point rejections:
    let mut bad_xwing = *pk_a.pq_pk.as_bytes();
    // Set X25519 tail (`1184..1216`) to all-zero low-order point -> rejected!
    bad_xwing[XWING_MLKEM768_PK_BYTES..].fill(0);
    assert!(SeatPqPublicKey::from_bytes(&bad_xwing).is_err());

    // Set first 12-bit pair in `ML-KEM-768` `ek_M` (`0..3`) to `0xFF, 0xFF, 0xFF` (`d_0 = 4095 >= q = 3329`) -> rejected!
    let mut bad_mlkem = *pk_a.pq_pk.as_bytes();
    bad_mlkem[0] = 0xFF;
    bad_mlkem[1] = 0xFF;
    bad_mlkem[2] = 0xFF;
    assert!(SeatPqPublicKey::from_bytes(&bad_mlkem).is_err());

    let mut seat_keys = BTreeMap::new();
    for pk in [&pk_acu, &pk_a, &pk_b, &pk_c] {
        seat_keys.insert(pk.seat_id.clone(), (*pk).clone());
    }

    // Policy: `ACU AND Threshold(2-of-3: [pq-a, pq-b, pq-c])`
    let tree = AccessTree::And(vec![
        AccessTree::Leaf(DEFAULT_CISO_ACU_ID.to_string()),
        AccessTree::Threshold {
            threshold: 2,
            children: vec![
                AccessTree::Leaf("seat:pq-a".to_string()),
                AccessTree::Leaf("seat:pq-b".to_string()),
                AccessTree::Leaf("seat:pq-c".to_string()),
            ],
        },
    ]);

    let large_payload = vec![0xA5u8; 64 * 1024];
    let mut payload = EncryptedCiPayload::encrypt(
        &large_payload,
        &tree,
        &seat_keys,
        &pk_acu,
        "emunlabs/chinwag",
        "CHWG-0283-ROTATE-PQ-KEY",
        &mut rng,
    )
    .unwrap();

    let c1_before = payload.aead_ciphertext.clone();
    let nonce_before = payload.nonce;
    let aad_before = payload.associated_data.clone();
    let immutable_hash_before = payload.immutable_aead_blake3();
    let wrapped_dek_before = payload.wrapped_dek;

    // 1. PqLsssHeader has 3 rows (`pq-a, pq-b, pq-c`) and 0 ACU rows; 1 PQ share fails `PolicyNotSatisfied`!
    let pq_hdr = payload.pq_header.as_ref().unwrap();
    assert_eq!(pq_hdr.rows.len(), 3);
    assert_eq!(pq_hdr.matrix.cols, 2);

    let d_acu_ep1 = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[0],
        &sk_acu,
        payload.acu_ciphertext.policy_epoch,
    );
    let d_a_ep1 = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[1],
        &sk_a,
        payload.acu_ciphertext.policy_epoch,
    );
    let d_b_ep1 = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[2],
        &sk_b,
        payload.acu_ciphertext.policy_epoch,
    );
    let pq_a_ep1 = payload.decapsulate_pq_shares_for_seat(&sk_a).unwrap();
    let pq_b_ep1 = payload.decapsulate_pq_shares_for_seat(&sk_b).unwrap();

    assert_eq!(
        payload.decrypt(
            &[d_acu_ep1.clone(), d_a_ep1.clone(), d_b_ep1.clone()],
            &pq_a_ep1,
            &seat_keys
        ),
        Err(AcuError::PolicyNotSatisfied)
    );

    let mut pq_ab_ep1 = pq_a_ep1.clone();
    pq_ab_ep1.extend(pq_b_ep1);

    // 2. Run `rotate_pq_key` (`ePrint v2` §6.3 Op 4): re-wraps 48-byte `wrapped_dek` with ZERO C_1 re-encryption!
    payload
        .rotate_pq_key(
            &pk_acu,
            &[d_acu_ep1, d_a_ep1, d_b_ep1],
            &pq_ab_ep1,
            &seat_keys,
            &mut rng,
        )
        .unwrap();

    assert_eq!(payload.dek_wrap_epoch, 2);
    assert_eq!(payload.acu_ciphertext.policy_epoch, 2);
    assert_ne!(payload.wrapped_dek, wrapped_dek_before);
    assert_eq!(payload.aead_ciphertext, c1_before);
    assert_eq!(payload.nonce, nonce_before);
    assert_eq!(payload.associated_data, aad_before);
    assert_eq!(payload.immutable_aead_blake3(), immutable_hash_before);

    // Cached Epoch-1 PQ shares fail with `EpochMismatch { expected: 2, actual: 1 }`.
    let d_acu_ep2 = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[0],
        &sk_acu,
        payload.acu_ciphertext.policy_epoch,
    );
    let d_b_ep2 = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[2],
        &sk_b,
        payload.acu_ciphertext.policy_epoch,
    );
    let d_c_ep2 = acu_partial_decrypt_at_epoch(
        &payload.acu_ciphertext.rows[3],
        &sk_c,
        payload.acu_ciphertext.policy_epoch,
    );
    assert_eq!(
        payload.decrypt(
            &[d_acu_ep2.clone(), d_b_ep2.clone(), d_c_ep2.clone()],
            &pq_ab_ep1,
            &seat_keys
        ),
        Err(AcuError::EpochMismatch {
            expected: 2,
            actual: 1,
        })
    );

    // Fresh Epoch-2 `{pq-b, pq-c} + ACU` recovers the 64 KiB payload cleanly!
    let mut pq_bc_ep2 = payload.decapsulate_pq_shares_for_seat(&sk_b).unwrap();
    pq_bc_ep2.extend(payload.decapsulate_pq_shares_for_seat(&sk_c).unwrap());
    let recovered = payload
        .decrypt(&[d_acu_ep2, d_b_ep2, d_c_ep2], &pq_bc_ep2, &seat_keys)
        .unwrap();
    assert_eq!(recovered, large_payload);
}

#[test]
fn test_acu_envelope_v2_hash_chain_survives_in_place_revocation_and_selective_merkle_export() {
    let mut rng = OsRng;
    let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
    let acu_ed_sk = SigningKey::from_bytes(&[0x71u8; 32]);
    let (_agent_sk, agent_pk) = SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
    let agent_ed_sk = SigningKey::from_bytes(&[0x72u8; 32]);
    let (archive_sk, archive_pk) =
        SeatSecretKey::generate(DEFAULT_MESSAGE_ARCHIVE_ID, &mut rng).unwrap();
    let archive_ed_sk = SigningKey::from_bytes(&[0x73u8; 32]);
    let repo_archive_signing_key = SigningKey::from_bytes(&[0x74u8; 32]);

    let mut registry = AllowedSignersRegistry::new();
    registry
        .register_seat(
            DEFAULT_CISO_ACU_ID,
            acu_ed_sk.verifying_key(),
            acu_pk.clone(),
        )
        .unwrap();
    registry
        .register_seat(
            DEFAULT_AGENT_BRANCH_ID,
            agent_ed_sk.verifying_key(),
            agent_pk.clone(),
        )
        .unwrap();
    registry
        .register_seat(
            DEFAULT_MESSAGE_ARCHIVE_ID,
            archive_ed_sk.verifying_key(),
            archive_pk.clone(),
        )
        .unwrap();

    let route_key = [0x91u8; 32];
    let index_key = [0x92u8; 32];

    let mut chain = Vec::with_capacity(3);
    let mut prev_link = [0u8; 32];

    for seq in 1..=3u64 {
        let inner = SealedAuthorMessage::seal_and_sign(
            DEFAULT_AGENT_BRANCH_ID,
            format!("msg-{seq}"),
            1_794_000_000_000 + seq,
            format!("secret flow step {seq}").into_bytes(),
            &agent_ed_sk,
        );
        let inner_bytes = inner.to_bytes();

        let payload = EncryptedCiPayload::encrypt_with_acu_and_archive(
            &inner_bytes,
            &acu_pk,
            &agent_pk,
            &archive_pk,
            "emunlabs/chinwag",
            &format!("CHWG-FLOW-RUN-{seq}"),
            &mut rng,
        )
        .unwrap();

        let meta = EnvelopeMetadataBox {
            flow_run_id: "run-v5-dag-001".to_string(),
            node_id: format!("node-{seq}"),
            sender_seat: DEFAULT_AGENT_BRANCH_ID.to_string(),
            visibility: "org_internal".to_string(),
        };
        let leaves = PublicExportLeaves::new_salted(
            format!("Step {seq} passed Cleanroom Gate").into_bytes(),
            br#"{"duration_ms":420,"credits":1}"#.to_vec(),
            br#"{"private_diff":"@@ -1 +1 @@ secret"}"#.to_vec(),
            br#"{"private_audit":"proprietary context"}"#.to_vec(),
            &mut rng,
        );

        let rec = AcuEnvelopeV2Record::seal(
            seq,
            prev_link,
            &route_key,
            &index_key,
            "emunlabs",
            DEFAULT_AGENT_BRANCH_ID,
            "#flows",
            "CHWG-0283",
            &meta,
            leaves,
            payload,
            DEFAULT_AGENT_BRANCH_ID,
            &agent_ed_sk,
            &repo_archive_signing_key,
            &mut rng,
        )
        .unwrap();
        prev_link = rec.header.chain_link_blake3();
        chain.push(rec);
    }

    // 1. Verify intact 3-record chain (`seq = 1..=3`) and encrypted metadata box (`F-01`, `F-02`, `F-03`).
    verify_envelope_v2_chain(&chain, &repo_archive_signing_key.verifying_key(), &registry).unwrap();
    let opened_meta = chain[1].header.open_metadata_box(&route_key).unwrap();
    assert_eq!(opened_meta.flow_run_id, "run-v5-dag-001");
    assert_eq!(opened_meta.node_id, "node-2");
    assert!(chain[1].header.open_metadata_box(&[0xFFu8; 32]).is_err());

    // 2. Revoke `DEFAULT_AGENT_BRANCH_ID` in-place on `seq = 2` (`chain[1]`) WITHOUT touching `chain[2]` (`seq = 3`)!
    let seq2_link_before = chain[1].header.chain_link_blake3();
    let receipt = chain[1]
        .revoke_and_rerandomize_in_place(
            &acu_sk,
            &[DEFAULT_AGENT_BRANCH_ID],
            &registry,
            &acu_ed_sk,
            &repo_archive_signing_key.verifying_key(),
            &mut rng,
        )
        .unwrap();
    assert_eq!(receipt.seq, 2);
    assert_eq!(receipt.from_epoch, 1);
    assert_eq!(receipt.to_epoch, 2);
    assert_eq!(chain[1].header.chain_link_blake3(), seq2_link_before);

    // Downstream record `seq = 3` (`chain[2]`) STILL verifies cleanly in `verify_envelope_v2_chain`!
    verify_envelope_v2_chain(&chain, &repo_archive_signing_key.verifying_key(), &registry).unwrap();

    // Decrypt evolved `seq = 2` via `ACU + Archive` and verify inner `SeatAuthorSign` (`F-03`)!
    let d_acu = acu_partial_decrypt_at_epoch(
        &chain[1].payload.acu_ciphertext.rows[0],
        &acu_sk,
        chain[1].payload.acu_ciphertext.policy_epoch,
    );
    let d_arch = acu_partial_decrypt_at_epoch(
        &chain[1].payload.acu_ciphertext.rows[1],
        &archive_sk,
        chain[1].payload.acu_ciphertext.policy_epoch,
    );
    let active_keys = registry.active_acu_keys();
    let raw_inner = chain[1]
        .payload
        .decrypt_with_local_key(&[d_acu, d_arch], &archive_sk, &active_keys)
        .unwrap();
    let verified_inner = SealedAuthorMessage::from_bytes_and_verify(&raw_inner, &registry).unwrap();
    assert_eq!(verified_inner.author_seat_id, DEFAULT_AGENT_BRANCH_ID);
    assert_eq!(verified_inner.body, b"secret flow step 2");

    // 3. Selective `--public-safe` Merkle export (`.cwcard` / Slack unfurl):
    let bundle = chain[1].export_public_safe();
    bundle
        .verify(&repo_archive_signing_key.verifying_key())
        .unwrap();
    assert_eq!(bundle.public_summary, b"Step 2 passed Cleanroom Gate");

    // Flipping 1 bit in `public_summary` or `private_subtree_h23` MUST fail Merkle verification!
    let mut bad_summary = bundle.clone();
    bad_summary.public_summary[0] ^= 0x01;
    assert!(
        bad_summary
            .verify(&repo_archive_signing_key.verifying_key())
            .is_err()
    );

    let mut bad_h23 = bundle;
    bad_h23.private_subtree_h23[0] ^= 0x01;
    assert!(
        bad_h23
            .verify(&repo_archive_signing_key.verifying_key())
            .is_err()
    );
}

#[test]
fn test_alistair_f01_rotate_pq_key_authenticates_through_ciso_fat_client_iroh() {
    let mut rng = OsRng;
    let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
    let acu_ed_sk = SigningKey::from_bytes(&[0x81u8; 32]);
    let (sk_a, pk_a) = SeatSecretKey::generate("branch:alpha", &mut rng).unwrap();
    let ed_a = SigningKey::from_bytes(&[0x82u8; 32]);
    let (sk_b, pk_b) = SeatSecretKey::generate("branch:beta", &mut rng).unwrap();
    let ed_b = SigningKey::from_bytes(&[0x83u8; 32]);

    let mut registry = AllowedSignersRegistry::new();
    registry
        .register_seat(
            DEFAULT_CISO_ACU_ID,
            acu_ed_sk.verifying_key(),
            acu_pk.clone(),
        )
        .unwrap();
    registry
        .register_seat("branch:alpha", ed_a.verifying_key(), pk_a.clone())
        .unwrap();
    registry
        .register_seat("branch:beta", ed_b.verifying_key(), pk_b.clone())
        .unwrap();

    let seat_keys = registry.active_acu_keys();
    let tree = AccessTree::And(vec![
        AccessTree::Leaf(DEFAULT_CISO_ACU_ID.to_string()),
        AccessTree::Or(vec![
            AccessTree::Leaf("branch:alpha".to_string()),
            AccessTree::Leaf("branch:beta".to_string()),
        ]),
    ]);

    let secret_msg = b"CHWG-0283 ACU-V2-F01 online iroh share issuance after rotate_pq_key";
    let mut payload = EncryptedCiPayload::encrypt(
        secret_msg,
        &tree,
        &seat_keys,
        &acu_pk,
        "emunlabs/chinwag",
        "CHWG-0283-F01",
        &mut rng,
    )
    .unwrap();

    let mut ciso = CisoAcuFatClient::new(acu_sk, acu_pk.clone(), acu_ed_sk.clone());

    // Epoch 1 online share request + coalition `rotate_pq_key` -> Epoch 2.
    let req_ep1 = AcuShareRequest::create_signed(
        "f01-req-ep1",
        "branch:alpha",
        DEFAULT_CISO_ACU_ID,
        "emunlabs/chinwag",
        "CHWG-0283-F01",
        1,
        payload.acu_ciphertext.clone(),
        payload.acu_ciphertext.rows[0].clone(),
        1_794_100_001,
        &ed_a,
    );
    let resp_ep1 = ciso.handle_iroh_share_request(&req_ep1, &registry).unwrap();
    let d_a_ep1 = acu_partial_decrypt_at_epoch(&payload.acu_ciphertext.rows[1], &sk_a, 1);
    let pq_a_ep1 = payload.decapsulate_pq_shares_for_seat(&sk_a).unwrap();

    let c1_immutable_before = payload.immutable_aead_blake3();
    payload
        .rotate_pq_key(
            &acu_pk,
            &[resp_ep1.partial_share, d_a_ep1],
            &pq_a_ep1,
            &seat_keys,
            &mut rng,
        )
        .unwrap();
    assert_eq!(payload.acu_ciphertext.policy_epoch, 2);
    assert_eq!(payload.dek_wrap_epoch, 2);
    assert_eq!(payload.immutable_aead_blake3(), c1_immutable_before);

    // Blind roundtrip + `verify_authenticity` + online `CisoAcuFatClient::handle_iroh_share_request` MUST succeed!
    let blind_bytes = payload.acu_ciphertext.to_blind_bytes();
    let mut unblinded = AcuCiphertext::from_bytes(&blind_bytes).unwrap();
    // Even before unblinding, canonical bytes roundtrip and `verify_authenticity` on `payload.acu_ciphertext` pass:
    payload
        .acu_ciphertext
        .verify_authenticity(&acu_pk, |id| seat_keys.get(id))
        .unwrap();
    let _ = &mut unblinded;

    let policy_sig_ep2 =
        AcuPolicySignature::sign(DEFAULT_CISO_ACU_ID, &payload.acu_ciphertext, &acu_ed_sk);
    let req_ep2 = AcuShareRequest::create_signed_with_policy_sig(
        "f01-req-ep2",
        "branch:beta",
        DEFAULT_CISO_ACU_ID,
        "emunlabs/chinwag",
        "CHWG-0283-F01",
        2,
        payload.acu_ciphertext.clone(),
        payload.acu_ciphertext.rows[0].clone(),
        Some(policy_sig_ep2),
        1_794_100_002,
        &ed_b,
    );
    let resp_ep2 = ciso.handle_iroh_share_request(&req_ep2, &registry).unwrap();
    resp_ep2
        .verify_by_agent(&payload.acu_ciphertext.rows[0], &registry)
        .unwrap();

    let d_b_ep2 = acu_partial_decrypt_at_epoch(&payload.acu_ciphertext.rows[2], &sk_b, 2);
    let pq_b_ep2 = payload.decapsulate_pq_shares_for_seat(&sk_b).unwrap();
    let decrypted = payload
        .decrypt(&[resp_ep2.partial_share, d_b_ep2], &pq_b_ep2, &seat_keys)
        .unwrap();
    assert_eq!(decrypted, secret_msg);

    // Also verify `insert_authorized_seat` rejects `new_seat_id == acu_seat_id` (`UnauthorizedPolicyOperator`).
    let ins_acu = CoalitionInsertionRowShare::issue_for_row(
        &payload.acu_ciphertext,
        0,
        ciso.acu_secret_key(),
    )
    .unwrap();
    let ins_b =
        CoalitionInsertionRowShare::issue_for_row(&payload.acu_ciphertext, 2, &sk_b).unwrap();
    let row_vec = payload.acu_ciphertext.matrix.rows[2].1.clone();
    let dup_acu_err = ciso.insert_authorized_seat(
        &mut payload.acu_ciphertext,
        DEFAULT_CISO_ACU_ID,
        row_vec,
        &[ins_acu, ins_b],
        &seat_keys,
        &mut rng,
    );
    assert_eq!(dup_acu_err, Err(AcuError::UnauthorizedPolicyOperator));
}

#[test]
fn test_alistair_f02_ciso_fat_client_epoch_floor_blocks_epoch1_rollback_after_escalation_and_lock()
{
    let mut rng = OsRng;
    let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
    let acu_ed_sk = SigningKey::from_bytes(&[0x84u8; 32]);
    let (_sk_a, pk_a) = SeatSecretKey::generate("branch:alpha", &mut rng).unwrap();
    let ed_a = SigningKey::from_bytes(&[0x85u8; 32]);
    let (_sk_b, pk_b) = SeatSecretKey::generate("branch:beta", &mut rng).unwrap();
    let ed_b = SigningKey::from_bytes(&[0x86u8; 32]);

    let mut registry = AllowedSignersRegistry::new();
    registry
        .register_seat(
            DEFAULT_CISO_ACU_ID,
            acu_ed_sk.verifying_key(),
            acu_pk.clone(),
        )
        .unwrap();
    registry
        .register_seat("branch:alpha", ed_a.verifying_key(), pk_a)
        .unwrap();
    registry
        .register_seat("branch:beta", ed_b.verifying_key(), pk_b)
        .unwrap();
    let seat_keys = registry.active_acu_keys();

    // Policy: `(branch:alpha OR branch:beta) AND ACU` (`1-of-2 + ACU` at Epoch 1).
    let tree = AccessTree::And(vec![
        AccessTree::Or(vec![
            AccessTree::Leaf("branch:alpha".to_string()),
            AccessTree::Leaf("branch:beta".to_string()),
        ]),
        AccessTree::Leaf(DEFAULT_CISO_ACU_ID.to_string()),
    ]);
    let payload_ep1 = EncryptedCiPayload::encrypt(
        b"top-secret escalation rollback target",
        &tree,
        &seat_keys,
        &acu_pk,
        "emunlabs/chinwag",
        "CHWG-0283-F02",
        &mut rng,
    )
    .unwrap();

    // Custodian `branch:alpha` caches the genuine Epoch-1 ciphertext before escalation.
    let cached_ct_ep1 = payload_ep1.acu_ciphertext.clone();
    let mut working_ct = payload_ep1.acu_ciphertext;

    let mut ciso = CisoAcuFatClient::new(acu_sk, acu_pk, acu_ed_sk);

    // CISO escalates `(alpha OR beta)` -> `(alpha AND beta)` (`2-of-2 + ACU` at Epoch 2) WITHOUT revoking any seat!
    ciso.escalate_threshold(&mut working_ct, &[0, 1], 1, &seat_keys, &mut rng)
        .unwrap();
    assert_eq!(working_ct.policy_epoch, 2);
    assert_eq!(ciso.epoch_floor_for(&working_ct.object_digest), Some(2));

    // `branch:alpha` replays cached Epoch-1 header in a brand-new `AcuShareRequest` -> MUST fail closed!
    let rollback_req = AcuShareRequest::create_signed(
        "f02-fresh-epoch1-rollback",
        "branch:alpha",
        DEFAULT_CISO_ACU_ID,
        "emunlabs/chinwag",
        "CHWG-0283-F02",
        1,
        cached_ct_ep1,
        working_ct.rows[2].clone(),
        1_794_200_001,
        &ed_a,
    );
    // Use the genuine Epoch-1 ACU row from `payload_ep1` so step 5 passes and step 5b catches the rollback!
    let genuine_rollback_req = AcuShareRequest::create_signed(
        "f02-genuine-epoch1-rollback",
        "branch:alpha",
        DEFAULT_CISO_ACU_ID,
        "emunlabs/chinwag",
        "CHWG-0283-F02",
        1,
        rollback_req.acu_ciphertext.clone(),
        rollback_req.acu_ciphertext.rows[2].clone(),
        1_794_200_002,
        &ed_a,
    );
    let err = ciso.handle_iroh_share_request(&genuine_rollback_req, &registry);
    assert_eq!(
        err,
        Err(AcuError::EpochMismatch {
            expected: 2,
            actual: 1,
        })
    );
    assert_eq!(
        ciso.audit_log().last().unwrap().reason,
        "stale_policy_epoch_rollback"
    );

    // Legitimate Epoch-2 share request succeeds, and subsequent per-object `emergency_lock_and_rerandomize`
    // ratchets floor to `u64::MAX`, blocking Epoch-2 replay even without global seat revocation!
    let ep2_req = AcuShareRequest::create_signed(
        "f02-legit-epoch2",
        "branch:alpha",
        DEFAULT_CISO_ACU_ID,
        "emunlabs/chinwag",
        "CHWG-0283-F02",
        2,
        working_ct.clone(),
        working_ct.rows[2].clone(),
        1_794_200_003,
        &ed_a,
    );
    assert!(ciso.handle_iroh_share_request(&ep2_req, &registry).is_ok());

    let cached_ct_ep2 = working_ct.clone();
    ciso.emergency_lock_and_rerandomize(
        &mut working_ct,
        &["branch:alpha", "branch:beta"],
        &seat_keys,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        ciso.epoch_floor_for(&working_ct.object_digest),
        Some(u64::MAX)
    );

    let post_lock_replay = AcuShareRequest::create_signed(
        "f02-post-lock-epoch2-replay",
        "branch:beta",
        DEFAULT_CISO_ACU_ID,
        "emunlabs/chinwag",
        "CHWG-0283-F02",
        2,
        cached_ct_ep2.clone(),
        cached_ct_ep2.rows[2].clone(),
        1_794_200_004,
        &ed_b,
    );
    assert_eq!(
        ciso.handle_iroh_share_request(&post_lock_replay, &registry),
        Err(AcuError::EpochMismatch {
            expected: u64::MAX,
            actual: 2,
        })
    );
}

#[test]
fn test_alistair_f03_f04_escalate_then_rotate_pq_key_enforces_2_of_3_pq_threshold_and_envelope_v2_auth()
 {
    let mut rng = OsRng;
    let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
    let acu_ed_sk = SigningKey::from_bytes(&[0x91u8; 32]);
    let (sk_1, pk_1) = SeatSecretKey::generate("custodian:one", &mut rng).unwrap();
    let ed_1 = SigningKey::from_bytes(&[0x92u8; 32]);
    let (sk_2, pk_2) = SeatSecretKey::generate("custodian:two", &mut rng).unwrap();
    let ed_2 = SigningKey::from_bytes(&[0x93u8; 32]);
    let (sk_3, pk_3) = SeatSecretKey::generate("custodian:three", &mut rng).unwrap();
    let ed_3 = SigningKey::from_bytes(&[0x94u8; 32]);
    let repo_archive_sk = SigningKey::from_bytes(&[0x95u8; 32]);

    let mut registry = AllowedSignersRegistry::new();
    registry
        .register_seat(
            DEFAULT_CISO_ACU_ID,
            acu_ed_sk.verifying_key(),
            acu_pk.clone(),
        )
        .unwrap();
    registry
        .register_seat("custodian:one", ed_1.verifying_key(), pk_1)
        .unwrap();
    registry
        .register_seat("custodian:two", ed_2.verifying_key(), pk_2)
        .unwrap();
    registry
        .register_seat("custodian:three", ed_3.verifying_key(), pk_3)
        .unwrap();
    let seat_keys = registry.active_acu_keys();

    // Epoch 1: `(custodian:one OR custodian:two OR custodian:three) AND ACU` (`1-of-3` non-ACU PQ shares).
    let tree = AccessTree::And(vec![
        AccessTree::Or(vec![
            AccessTree::Leaf("custodian:one".to_string()),
            AccessTree::Leaf("custodian:two".to_string()),
            AccessTree::Leaf("custodian:three".to_string()),
        ]),
        AccessTree::Leaf(DEFAULT_CISO_ACU_ID.to_string()),
    ]);
    let msg = b"Theorem 3(i) 2-of-3 post-quantum threshold enforcement after escalate_threshold + rotate_pq_key";
    let mut payload = EncryptedCiPayload::encrypt(
        msg,
        &tree,
        &seat_keys,
        &acu_pk,
        "emunlabs/chinwag",
        "CHWG-0283-F03",
        &mut rng,
    )
    .unwrap();

    // Epoch 2: Escalate custodian gate from `1-of-3` -> `2-of-3`!
    escalate_threshold(
        &mut payload.acu_ciphertext,
        &acu_sk,
        &[0, 1, 2],
        1,
        &seat_keys,
        &mut rng,
    )
    .unwrap();
    assert_eq!(payload.acu_ciphertext.policy_epoch, 2);

    // Epoch 3: Authorized `2-of-3 + ACU` coalition invokes `rotate_pq_key` to tighten `PqLsssHeader` to `2-of-3`!
    let d_1_ep2 = acu_partial_decrypt_at_epoch(&payload.acu_ciphertext.rows[0], &sk_1, 2);
    let d_2_ep2 = acu_partial_decrypt_at_epoch(&payload.acu_ciphertext.rows[1], &sk_2, 2);
    let d_acu_ep2 = acu_partial_decrypt_at_epoch(&payload.acu_ciphertext.rows[3], &acu_sk, 2);
    let pq_1_ep1 = payload.decapsulate_pq_shares_for_seat(&sk_1).unwrap();

    payload
        .rotate_pq_key(
            &acu_pk,
            &[d_1_ep2, d_2_ep2, d_acu_ep2],
            &pq_1_ep1,
            &seat_keys,
            &mut rng,
        )
        .unwrap();
    assert_eq!(payload.acu_ciphertext.policy_epoch, 3);
    assert_eq!(payload.dek_wrap_epoch, 2);
    assert_eq!(payload.pq_header.as_ref().unwrap().matrix.cols, 2);

    // Sub-threshold quantum adversary holding ONLY 1 custodian's Epoch-2 PQ share MUST fail `PolicyNotSatisfied`!
    let pq_only_1 = payload.decapsulate_pq_shares_for_seat(&sk_1).unwrap();
    assert_eq!(
        find_reconstruction_weights(&payload.pq_header.as_ref().unwrap().matrix, &[0]),
        Err(AcuError::PolicyNotSatisfied)
    );

    let d_1_ep3 = acu_partial_decrypt_at_epoch(&payload.acu_ciphertext.rows[0], &sk_1, 3);
    let d_3_ep3 = acu_partial_decrypt_at_epoch(&payload.acu_ciphertext.rows[2], &sk_3, 3);
    let d_acu_ep3 = acu_partial_decrypt_at_epoch(&payload.acu_ciphertext.rows[3], &acu_sk, 3);
    assert_eq!(
        payload.decrypt(
            &[d_1_ep3.clone(), d_3_ep3.clone(), d_acu_ep3.clone()],
            &pq_only_1,
            &seat_keys
        ),
        Err(AcuError::PolicyNotSatisfied)
    );

    // Full `2-of-3` PQ coalition (`custodian:one + custodian:three`) + pairing shares recovers `msg`!
    let mut pq_1_and_3 = pq_only_1;
    pq_1_and_3.extend(payload.decapsulate_pq_shares_for_seat(&sk_3).unwrap());
    let out = payload
        .decrypt(&[d_1_ep3, d_3_ep3, d_acu_ep3], &pq_1_and_3, &seat_keys)
        .unwrap();
    assert_eq!(out, msg);

    // `ACU-V2-F04`: `AcuEnvelopeV2Record::verify_integrity` MUST reject a `policy_epoch >= 2` header
    // signed by a non-ACU seat (`custodian:one`) even when `C_1` (`aead_immutable_blake3`) is untouched!
    let meta = EnvelopeMetadataBox {
        flow_run_id: "run-f04".to_string(),
        node_id: "node-1".to_string(),
        sender_seat: "custodian:one".to_string(),
        visibility: "org_internal".to_string(),
    };
    let leaves = PublicExportLeaves::new_salted(
        b"pub-0".to_vec(),
        b"pub-1".to_vec(),
        b"priv-2".to_vec(),
        b"priv-3".to_vec(),
        &mut rng,
    );
    let forged_record = AcuEnvelopeV2Record::seal(
        1,
        [0u8; 32],
        &[0xAAu8; 32],
        &[0xBBu8; 32],
        "emunlabs",
        "custodian:one",
        "#flows",
        "CHWG-0283-F04",
        &meta,
        leaves.clone(),
        payload.clone(),
        "custodian:one",
        &ed_1,
        &repo_archive_sk,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        forged_record.verify_integrity(&repo_archive_sk.verifying_key(), &registry),
        Err(AcuError::UnauthorizedPolicyOperator)
    );

    // When signed by `DEFAULT_CISO_ACU_ID` (`acu_seat_id`), `verify_integrity` succeeds cleanly!
    let valid_record = AcuEnvelopeV2Record::seal(
        1,
        [0u8; 32],
        &[0xAAu8; 32],
        &[0xBBu8; 32],
        "emunlabs",
        "custodian:one",
        "#flows",
        "CHWG-0283-F04",
        &meta,
        leaves,
        payload,
        DEFAULT_CISO_ACU_ID,
        &acu_ed_sk,
        &repo_archive_sk,
        &mut rng,
    )
    .unwrap();
    valid_record
        .verify_integrity(&repo_archive_sk.verifying_key(), &registry)
        .unwrap();
}
