//! A bounded, two-recipient capsule for this repository's public Genesis record.
//!
//! Encryption does not authenticate authorship or redact input. The signing,
//! peer-review and publication gates must check the flight before attaching it
//! to a commit. This module never writes Git notes or publishes a demo key.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305 as WrapAead, kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;
type PublicKey = <Kem as KemTrait>::PublicKey;
type PrivateKey = <Kem as KemTrait>::PrivateKey;
type EncappedKey = <Kem as KemTrait>::EncappedKey;

pub const HEADER_BYTES: usize = 256;
pub const MAX_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_COMPRESSED_BYTES: usize = MAX_PLAINTEXT_BYTES + 64 * 1024;
pub const MAX_CAPSULE_BYTES: usize = HEADER_BYTES + MAX_COMPRESSED_BYTES + 16;
const MAGIC: &[u8; 8] = b"EMUNVLT1";
const WRAP_BYTES: usize = 48;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("source OID must be a lowercase 40- or 64-digit hex Git object ID")]
    InvalidBinding,
    #[error("capsule is malformed or uses an unsupported format")]
    InvalidFormat,
    #[error("capsule exceeds a size limit")]
    SizeLimit,
    #[error("recipient key is invalid")]
    InvalidKey,
    #[error("capsule authentication failed")]
    Authentication,
    #[error("operating-system entropy is unavailable")]
    Entropy,
    #[error("compression failed")]
    Compression,
}

/// The public demo recipient is confined to Emun's own Chinwag repository.
/// The expected source OID also binds each HPKE wrap to its Git-note target.
#[derive(Clone, Debug)]
pub struct Binding {
    source_oid: String,
}

impl Binding {
    pub fn public_chinwag(source_oid: &str) -> Result<Self, Error> {
        if !matches!(source_oid.len(), 40 | 64)
            || !source_oid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidBinding);
        }
        Ok(Self {
            source_oid: source_oid.to_owned(),
        })
    }

    fn context(&self, slot: Slot) -> Vec<u8> {
        format!(
            "chinwag-vault/v1\0emunlabs/chinwag\0{}\0{}",
            self.source_oid,
            slot.label()
        )
        .into_bytes()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Slot {
    Demo,
    Organization,
}

impl Slot {
    fn offset(self) -> usize {
        match self {
            Self::Demo => 0x30,
            Self::Organization => 0x90,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Demo => "demo-public-repo",
            Self::Organization => "org",
        }
    }
}

/// Used by explicit setup code; the secret has no Debug/Serialize implementation.
pub struct Recipient {
    secret: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

impl Recipient {
    pub fn generate() -> Result<Self, Error> {
        let mut rng = StdRng::try_from_os_rng().map_err(|_| Error::Entropy)?;
        let (secret, public) = Kem::gen_keypair(&mut rng);
        Ok(Self {
            secret: Zeroizing::new(secret.to_bytes().into()),
            public: public.to_bytes().into(),
        })
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

fn key_id(public: &[u8; 32]) -> [u8; 16] {
    let hash = Sha256::digest(public);
    let mut id = [0; 16];
    id.copy_from_slice(&hash[..16]);
    id
}

fn put_u16(header: &mut [u8; HEADER_BYTES], at: usize, value: u16) {
    header[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(header: &mut [u8; HEADER_BYTES], at: usize, value: usize) -> Result<(), Error> {
    let value = u32::try_from(value).map_err(|_| Error::SizeLimit)?;
    header[at..at + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn get_u32(header: &[u8; HEADER_BYTES], at: usize) -> Result<usize, Error> {
    let bytes = header[at..at + 4]
        .try_into()
        .map_err(|_| Error::InvalidFormat)?;
    usize::try_from(u32::from_le_bytes(bytes)).map_err(|_| Error::SizeLimit)
}

fn wrap(
    binding: &Binding,
    slot: Slot,
    public: &[u8; 32],
    key: &[u8; 32],
    header: &mut [u8; HEADER_BYTES],
    rng: &mut StdRng,
) -> Result<(), Error> {
    let public_key = PublicKey::from_bytes(public).map_err(|_| Error::InvalidKey)?;
    let context = binding.context(slot);
    let (enc, mut sender) = hpke::setup_sender::<WrapAead, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &public_key,
        &context,
        rng,
    )
    .map_err(|_| Error::InvalidKey)?;
    let wrapped = sender
        .seal(key, &context)
        .map_err(|_| Error::Authentication)?;
    if wrapped.len() != WRAP_BYTES {
        return Err(Error::InvalidFormat);
    }
    let at = slot.offset();
    header[at..at + 16].copy_from_slice(&key_id(public));
    header[at + 16..at + 48].copy_from_slice(&enc.to_bytes());
    header[at + 48..at + 96].copy_from_slice(&wrapped);
    Ok(())
}

pub fn seal(
    binding: &Binding,
    plaintext: &[u8],
    demo_public: &[u8; 32],
    org_public: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::SizeLimit);
    }
    if demo_public == org_public {
        return Err(Error::InvalidKey);
    }
    let compressed = Zeroizing::new(
        zstd::stream::encode_all(Cursor::new(plaintext), 3).map_err(|_| Error::Compression)?,
    );
    if compressed.len() > MAX_COMPRESSED_BYTES {
        return Err(Error::SizeLimit);
    }
    let mut rng = StdRng::try_from_os_rng().map_err(|_| Error::Entropy)?;
    let mut key = Zeroizing::new([0; 32]);
    rng.fill_bytes(key.as_mut());
    let mut header = [0; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    put_u16(&mut header, 0x08, 1);
    put_u16(&mut header, 0x0a, HEADER_BYTES as u16);
    put_u16(&mut header, 0x0c, 0x0020);
    put_u16(&mut header, 0x0e, 0x0001);
    put_u16(&mut header, 0x10, 0x0003);
    put_u16(&mut header, 0x12, 3);
    put_u32(&mut header, 0x14, plaintext.len())?;
    put_u32(&mut header, 0x18, compressed.len())?;
    put_u32(&mut header, 0x1c, compressed.len() + 16)?;
    rng.fill_bytes(&mut header[0x20..0x2c]);
    header[0x2c] = 1;
    header[0x2d] = 2;
    wrap(
        binding,
        Slot::Demo,
        demo_public,
        &key,
        &mut header,
        &mut rng,
    )?;
    wrap(
        binding,
        Slot::Organization,
        org_public,
        &key,
        &mut header,
        &mut rng,
    )?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::InvalidKey)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&header[0x20..0x2c]),
            Payload {
                msg: &compressed,
                aad: &header,
            },
        )
        .map_err(|_| Error::Authentication)?;
    let mut capsule = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
    capsule.extend_from_slice(&header);
    capsule.extend_from_slice(&ciphertext);
    Ok(capsule)
}

fn validate_header(capsule: &[u8]) -> Result<&[u8; HEADER_BYTES], Error> {
    if capsule.len() < HEADER_BYTES + 16 {
        return Err(Error::InvalidFormat);
    }
    if capsule.len() > MAX_CAPSULE_BYTES {
        return Err(Error::SizeLimit);
    }
    let header: &[u8; HEADER_BYTES] = capsule[..HEADER_BYTES]
        .try_into()
        .map_err(|_| Error::InvalidFormat)?;
    let mut expected = [0; 0x14];
    expected[..8].copy_from_slice(MAGIC);
    for (at, value) in [(8, 1_u16), (10, 256), (12, 0x20), (14, 1), (16, 3), (18, 3)] {
        expected[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    if header[..0x14] != expected || header[0x2c..0x30] != [1, 2, 0, 0] || header[0xf0..] != [0; 16]
    {
        return Err(Error::InvalidFormat);
    }
    let plain = get_u32(header, 0x14)?;
    let compressed = get_u32(header, 0x18)?;
    let ciphertext = get_u32(header, 0x1c)?;
    if plain > MAX_PLAINTEXT_BYTES || compressed > MAX_COMPRESSED_BYTES {
        return Err(Error::SizeLimit);
    }
    if ciphertext != compressed + 16 || capsule.len() != HEADER_BYTES + ciphertext {
        return Err(Error::InvalidFormat);
    }
    Ok(header)
}

pub fn open(
    binding: &Binding,
    slot: Slot,
    secret: &[u8; 32],
    capsule: &[u8],
) -> Result<Vec<u8>, Error> {
    let header = validate_header(capsule)?;
    let secret = PrivateKey::from_bytes(secret).map_err(|_| Error::InvalidKey)?;
    let public: [u8; 32] = Kem::sk_to_pk(&secret).to_bytes().into();
    let at = slot.offset();
    if header[at..at + 16] != key_id(&public) {
        return Err(Error::Authentication);
    }
    let enc = EncappedKey::from_bytes(&header[at + 16..at + 48]).map_err(|_| Error::InvalidKey)?;
    let context = binding.context(slot);
    let mut receiver =
        hpke::setup_receiver::<WrapAead, HkdfSha256, Kem>(&OpModeR::Base, &secret, &enc, &context)
            .map_err(|_| Error::Authentication)?;
    let key = Zeroizing::new(
        receiver
            .open(&header[at + 48..at + 96], &context)
            .map_err(|_| Error::Authentication)?,
    );
    if key.len() != 32 {
        return Err(Error::InvalidFormat);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::InvalidKey)?;
    let compressed = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&header[0x20..0x2c]),
                Payload {
                    msg: &capsule[HEADER_BYTES..],
                    aad: header,
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    if compressed.len() != get_u32(header, 0x18)? {
        return Err(Error::InvalidFormat);
    }
    let expected = get_u32(header, 0x14)?;
    let mut decoder = zstd::stream::read::Decoder::with_buffer(Cursor::new(compressed.as_slice()))
        .map_err(|_| Error::Compression)?
        .single_frame();
    let mut plaintext = Zeroizing::new(Vec::new());
    decoder
        .by_ref()
        .take((expected + 1) as u64)
        .read_to_end(&mut plaintext)
        .map_err(|_| Error::Compression)?;
    if plaintext.len() != expected || decoder.finish().position() != compressed.len() as u64 {
        return Err(Error::InvalidFormat);
    }
    Ok(std::mem::take(&mut *plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding::public_chinwag("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()
    }

    #[test]
    fn both_independent_recipients_recover_the_exact_flight() {
        let demo = Recipient::generate().unwrap();
        let org = Recipient::generate().unwrap();
        let flight = b"synthetic capsule fixture; no live transport claim";
        let capsule = seal(&binding(), flight, &demo.public, &org.public).unwrap();
        assert_eq!(&capsule[..8], MAGIC);
        assert_eq!(u16::from_le_bytes(capsule[10..12].try_into().unwrap()), 256);
        for (slot, key) in [(Slot::Demo, &demo), (Slot::Organization, &org)] {
            assert_eq!(
                open(&binding(), slot, key.secret_bytes(), &capsule).unwrap(),
                flight
            );
        }
    }

    #[test]
    fn every_header_and_ciphertext_byte_is_checked() {
        let demo = Recipient::generate().unwrap();
        let org = Recipient::generate().unwrap();
        let capsule = seal(&binding(), b"tamper fixture", &demo.public, &org.public).unwrap();
        for index in 0..capsule.len() {
            let mut damaged = capsule.clone();
            damaged[index] ^= 1;
            assert!(
                open(&binding(), Slot::Demo, demo.secret_bytes(), &damaged).is_err(),
                "byte {index}"
            );
        }
    }

    #[test]
    fn cannot_swap_note_targets_slots_or_keys() {
        let demo = Recipient::generate().unwrap();
        let org = Recipient::generate().unwrap();
        let wrong = Recipient::generate().unwrap();
        let capsule = seal(&binding(), b"binding fixture", &demo.public, &org.public).unwrap();
        let other_commit =
            Binding::public_chinwag("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        assert!(open(&other_commit, Slot::Demo, demo.secret_bytes(), &capsule).is_err());
        assert!(
            open(
                &binding(),
                Slot::Organization,
                demo.secret_bytes(),
                &capsule
            )
            .is_err()
        );
        assert!(open(&binding(), Slot::Demo, wrong.secret_bytes(), &capsule).is_err());
    }

    #[test]
    fn malformed_lengths_truncation_and_append_are_rejected() {
        let demo = Recipient::generate().unwrap();
        let org = Recipient::generate().unwrap();
        let capsule = seal(&binding(), b"length fixture", &demo.public, &org.public).unwrap();
        for end in 0..capsule.len() {
            assert!(open(&binding(), Slot::Demo, demo.secret_bytes(), &capsule[..end]).is_err());
        }
        let mut appended = capsule.clone();
        appended.push(0);
        assert!(open(&binding(), Slot::Demo, demo.secret_bytes(), &appended).is_err());
        let mut huge = capsule;
        huge[0x14..0x18].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            open(&binding(), Slot::Demo, demo.secret_bytes(), &huge),
            Err(Error::SizeLimit)
        ));
    }

    #[test]
    fn repeated_sealing_uses_fresh_random_material() {
        let demo = Recipient::generate().unwrap();
        let org = Recipient::generate().unwrap();
        let one = seal(&binding(), b"same flight", &demo.public, &org.public).unwrap();
        let two = seal(&binding(), b"same flight", &demo.public, &org.public).unwrap();
        assert_ne!(one, two);
        assert_ne!(&one[0x20..0x2c], &two[0x20..0x2c]);
        assert_ne!(&one[0x40..0x60], &two[0x40..0x60]);
        assert_ne!(&one[0xa0..0xc0], &two[0xa0..0xc0]);
    }

    #[test]
    fn recipient_and_binding_rules_fail_closed() {
        let demo = Recipient::generate().unwrap();
        assert!(seal(&binding(), b"x", &demo.public, &demo.public).is_err());
        assert!(seal(&binding(), b"x", &[0; 32], &demo.public).is_err());
        for oid in [
            "",
            "HEAD",
            "../key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(Binding::public_chinwag(oid).is_err());
        }
        assert!(Binding::public_chinwag(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn empty_flight_and_maximum_flight_round_trip() {
        let demo = Recipient::generate().unwrap();
        let org = Recipient::generate().unwrap();
        for flight in [vec![], vec![b'x'; MAX_PLAINTEXT_BYTES]] {
            let capsule = seal(&binding(), &flight, &demo.public, &org.public).unwrap();
            assert_eq!(
                open(&binding(), Slot::Demo, demo.secret_bytes(), &capsule).unwrap(),
                flight
            );
        }
        assert!(matches!(
            seal(
                &binding(),
                &vec![0; MAX_PLAINTEXT_BYTES + 1],
                &demo.public,
                &org.public
            ),
            Err(Error::SizeLimit)
        ));
    }
}
