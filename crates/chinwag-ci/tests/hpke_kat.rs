// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Public synthetic RFC 9180 and IETF HPKE-PQ (`draft-ietf-hpke-pq-03` /
//! `draft-irtf-cfrg-concrete-hybrid-kems-02`) KAT values, never operator keys.
//! Deterministic entropy exists ONLY in this integration-test binary, never in
//! product code.

use core::convert::Infallible;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, PskBundle, Serializable,
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::{X25519HkdfSha256, XWing},
    rand_core::{TryCryptoRng, TryRng},
};
use serde_json::Value;

struct PublishedIkm<const N: usize>(Option<[u8; N]>);

impl<const N: usize> TryRng for PublishedIkm<N> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("unexpected KAT u32 entropy request")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("unexpected KAT u64 entropy request")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let ikm = self.0.take().expect("published IKM may be used only once");
        assert_eq!(dest.len(), ikm.len());
        dest.copy_from_slice(&ikm);
        Ok(())
    }
}

impl<const N: usize> TryCryptoRng for PublishedIkm<N> {}

fn bytes(v: &Value, field: &str) -> Vec<u8> {
    hex::decode(v[field].as_str().unwrap()).unwrap()
}

#[test]
fn rfc9180_a2_base_and_psk_match_enc_all257_ciphertexts_and_exports() {
    type Kem = X25519HkdfSha256;
    let fixture: Value =
        serde_json::from_str(include_str!("vectors/rfc9180-a2-base-psk.json")).unwrap();
    assert_eq!(fixture["vectors"].as_array().unwrap().len(), 2);
    for v in fixture["vectors"].as_array().unwrap() {
        assert_eq!(
            (
                v["kem_id"].as_u64(),
                v["kdf_id"].as_u64(),
                v["aead_id"].as_u64()
            ),
            (Some(32), Some(1), Some(3))
        );
        let (sk_r, pk_r) = Kem::derive_keypair(&bytes(v, "ikmR"));
        // `x25519-dalek` 3.0 (`hpke` 0.15) stores RFC 7748 clamped scalar bytes;
        // verify exact clamped equality AND that raw unclamped `skRm` deserializes
        // to the identical private key without modifying the RFC 9180 vector file.
        let raw_sk_rm = bytes(v, "skRm");
        let mut clamped_sk_rm = raw_sk_rm.clone();
        clamped_sk_rm[0] &= 248;
        clamped_sk_rm[31] = (clamped_sk_rm[31] & 127) | 64;
        assert_eq!(sk_r.to_bytes().as_slice(), clamped_sk_rm.as_slice());
        let sk_r_deser = <Kem as KemTrait>::PrivateKey::from_bytes(&raw_sk_rm).unwrap();
        assert_eq!(sk_r_deser.to_bytes(), sk_r.to_bytes());
        assert_eq!(pk_r.to_bytes().as_slice(), bytes(v, "pkRm"));
        let mut rng = PublishedIkm::<32>(Some(bytes(v, "ikmE").try_into().unwrap()));
        let psk = if v["mode"] == 1 {
            bytes(v, "psk")
        } else {
            vec![]
        };
        let id = if v["mode"] == 1 {
            bytes(v, "psk_id")
        } else {
            vec![]
        };
        let (s_mode, r_mode) = match v["mode"].as_u64().unwrap() {
            0 => (OpModeS::Base, OpModeR::Base),
            1 => (
                OpModeS::Psk(PskBundle::new(&psk, &id).unwrap()),
                OpModeR::Psk(PskBundle::new(&psk, &id).unwrap()),
            ),
            _ => panic!("unadmitted KAT mode"),
        };
        let (enc, mut sender) = hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &s_mode,
            &pk_r,
            &bytes(v, "info"),
            &mut rng,
        )
        .unwrap();
        assert!(rng.0.is_none());
        assert_eq!(enc.to_bytes().as_slice(), bytes(v, "enc"));
        let mut receiver = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &r_mode,
            &sk_r,
            &enc,
            &bytes(v, "info"),
        )
        .unwrap();
        let records = v["encryptions"].as_array().unwrap();
        assert_eq!(records.len(), 257);
        for record in records {
            let expected = bytes(record, "ct");
            let plaintext = bytes(record, "pt");
            let aad = bytes(record, "aad");
            assert_eq!(sender.seal(&plaintext, &aad).unwrap(), expected);
            assert_eq!(receiver.open(&expected, &aad).unwrap(), plaintext);
        }
        for export in v["exports"].as_array().unwrap() {
            let mut s = vec![0; export["L"].as_u64().unwrap() as usize];
            let mut r = s.clone();
            sender
                .export(&bytes(export, "exporter_context"), &mut s)
                .unwrap();
            receiver
                .export(&bytes(export, "exporter_context"), &mut r)
                .unwrap();
            assert_eq!(s, bytes(export, "exported_value"));
            assert_eq!(r, s);
        }
        let _ = <Kem as KemTrait>::EncappedKey::from_bytes(&bytes(v, "enc")).unwrap();
    }
}

#[test]
fn ietf_hpke_pq_0x647a_x25519_mlkem768_matches_official_kat_and_rejects_component_tampering() {
    assert_eq!(<XWing as KemTrait>::KEM_ID, 0x647a);
    let fixture: Value = serde_json::from_str(include_str!(
        "vectors/hpke-pq-x25519-mlkem768-0x647a-base.json"
    ))
    .unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 1);
    let v = &vectors[0];
    assert_eq!(
        (
            v["mode"].as_u64(),
            v["kem_id"].as_u64(),
            v["kdf_id"].as_u64(),
            v["aead_id"].as_u64(),
            v["suite_id"].as_str(),
        ),
        (
            Some(0),
            Some(0x647a),
            Some(1),
            Some(3),
            Some("48504b45647a00010003")
        )
    );

    let ikm_r = bytes(v, "ikmR");
    let expected_sk = bytes(v, "skRm");
    let expected_pk = bytes(v, "pkRm");
    let expected_enc = bytes(v, "enc");
    let info = bytes(v, "info");
    assert_eq!(expected_sk.len(), 32);
    assert_eq!(expected_pk.len(), 1216);
    assert_eq!(expected_enc.len(), 1120);

    let (sk_r, pk_r) = XWing::derive_keypair(&ikm_r);
    assert_eq!(sk_r.to_bytes().as_slice(), expected_sk.as_slice());
    assert_eq!(pk_r.to_bytes().as_slice(), expected_pk.as_slice());
    let sk_from_bytes = <XWing as KemTrait>::PrivateKey::from_bytes(&expected_sk).unwrap();
    assert_eq!(
        XWing::sk_to_pk(&sk_from_bytes).to_bytes().as_slice(),
        expected_pk.as_slice()
    );

    let mut rng = PublishedIkm::<64>(Some(bytes(v, "ikmE").try_into().unwrap()));
    let (enc, mut sender) = hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk_r,
        &info,
        &mut rng,
    )
    .unwrap();
    assert!(rng.0.is_none());
    assert_eq!(enc.to_bytes().as_slice(), expected_enc.as_slice());

    let mut receiver = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk_r,
        &enc,
        &info,
    )
    .unwrap();
    let records = v["encryptions"].as_array().unwrap();
    assert_eq!(records.len(), 10);
    for record in records {
        let expected_ct = bytes(record, "ct");
        let plaintext = bytes(record, "pt");
        let aad = bytes(record, "aad");
        assert_eq!(sender.seal(&plaintext, &aad).unwrap(), expected_ct);
        assert_eq!(receiver.open(&expected_ct, &aad).unwrap(), plaintext);
    }
    let exports = v["exports"].as_array().unwrap();
    assert_eq!(exports.len(), 5);
    for export in exports {
        let mut s = vec![0; export["L"].as_u64().unwrap() as usize];
        let mut r = s.clone();
        sender
            .export(&bytes(export, "exporter_context"), &mut s)
            .unwrap();
        receiver
            .export(&bytes(export, "exporter_context"), &mut r)
            .unwrap();
        assert_eq!(s, bytes(export, "exported_value"));
        assert_eq!(r, s);
    }

    // Negative tests on BOTH hybrid KEM shares:
    // 1. Mutate byte 0 inside ML-KEM-768 ciphertext share (ct_M: bytes 0..1088).
    // 2. Mutate byte 1088 inside X25519 ephemeral share (ct_X: bytes 1088..1120).
    let first_ct = bytes(&records[0], "ct");
    let first_aad = bytes(&records[0], "aad");
    for tamper_offset in [0_usize, 543, 1087, 1088, 1104, 1119] {
        let mut bad_enc_bytes = expected_enc.clone();
        bad_enc_bytes[tamper_offset] ^= 0x01;
        let bad_enc = <XWing as KemTrait>::EncappedKey::from_bytes(&bad_enc_bytes).unwrap();
        let mut bad_rx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            &sk_r,
            &bad_enc,
            &info,
        )
        .unwrap();
        assert!(
            bad_rx.open(&first_ct, &first_aad).is_err(),
            "tampered enc byte at offset {tamper_offset} must reject"
        );
    }

    // 3. Mutate AAD or info context -> AEAD tag rejection.
    let mut rx_wrong_info = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk_r,
        &enc,
        b"wrong-domain-info",
    )
    .unwrap();
    assert!(rx_wrong_info.open(&first_ct, &first_aad).is_err());

    let mut rx_wrong_aad = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk_r,
        &enc,
        &info,
    )
    .unwrap();
    let mut bad_aad = first_aad.clone();
    bad_aad[0] ^= 0x01;
    assert!(rx_wrong_aad.open(&first_ct, &bad_aad).is_err());

    // 4. Non-canonical FIPS 203 ML-KEM-768 encapsulation key coefficient (>= q = 3329 = 0x0d01)
    // and truncated key/ciphertext lengths must fail deserialization.
    let mut unreduced_pk = expected_pk.clone();
    unreduced_pk[0] = 0x01;
    unreduced_pk[1] = (unreduced_pk[1] & 0xf0) | 0x0d; // coeff_0 = 0x0d01 = 3329
    assert!(<XWing as KemTrait>::PublicKey::from_bytes(&unreduced_pk).is_err());
    assert!(<XWing as KemTrait>::PublicKey::from_bytes(&expected_pk[..1215]).is_err());
    assert!(<XWing as KemTrait>::EncappedKey::from_bytes(&expected_enc[..1119]).is_err());
}
