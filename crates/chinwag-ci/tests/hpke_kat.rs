// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Public synthetic RFC9180 KAT values, never operator keys. This deterministic
//! entropy source exists ONLY in an integration-test binary, not product code.
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, PskBundle, Serializable,
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    rand_core::{CryptoRng, RngCore},
};
use serde_json::Value;

type Kem = X25519HkdfSha256;

struct PublishedIkm(Option<[u8; 32]>);
impl RngCore for PublishedIkm {
    fn next_u32(&mut self) -> u32 {
        panic!("unexpected KAT entropy request")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("unexpected KAT entropy request")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let ikm = self.0.take().expect("published IKM may be used only once");
        assert_eq!(dest.len(), ikm.len());
        dest.copy_from_slice(&ikm);
    }
}
impl CryptoRng for PublishedIkm {}

fn bytes(v: &Value, field: &str) -> Vec<u8> {
    hex::decode(v[field].as_str().unwrap()).unwrap()
}

#[test]
fn rfc9180_a2_base_and_psk_match_enc_all257_ciphertexts_and_exports() {
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
        assert_eq!(sk_r.to_bytes().as_slice(), bytes(v, "skRm"));
        assert_eq!(pk_r.to_bytes().as_slice(), bytes(v, "pkRm"));
        let mut rng = PublishedIkm(Some(bytes(v, "ikmE").try_into().unwrap()));
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
        let (enc, mut sender) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
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
        // Both receiver and sender APIs above are the public pinned crate API.
        // No local primitive, KDF, padding or deterministic product RNG exists.
        let _ = <Kem as KemTrait>::EncappedKey::from_bytes(&bytes(v, "enc")).unwrap();
    }
}
