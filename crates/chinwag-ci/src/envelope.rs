// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Reviewed design packet f38bffa2: RFC9180 HPKE0.13 suite(0x20,1,3),
//! ACU AND (Recipient OR Archive). One payload ciphertext; three key wraps.
//! This cryptographic layer supplies no admission, current policy, replay
//! consumption, durable storage, qualified processing or repair authority.
//! Public pins/claims must come from resolved owner-authenticated profiles.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, PskBundle, Serializable,
    aead::ChaCha20Poly1305 as WrapAead, kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;
type Private = <Kem as KemTrait>::PrivateKey;
type Public = <Kem as KemTrait>::PublicKey;
type Encapped = <Kem as KemTrait>::EncappedKey;
pub const MAX_PLAINTEXT_BYTES: usize = 24 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("CI envelope validation or authentication failed")]
    Rejected,
    #[error("CI envelope entropy is unavailable")]
    Entropy,
}

/// These are claimed provenance until compared with independently verified
/// admission, dispatch and immutable command/delivery profile resolutions.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedProvenance {
    pub admission_sha256: [u8; 32],
    pub repository: String,
    pub repository_id: u64,
    pub source_commit: [u8; 20],
    pub workflow_ref: String,
    pub workflow_commit: [u8; 20],
    pub run_id: u64,
    pub run_attempt: u32,
    pub initiating_instance: String,
    pub intent_digest: [u8; 32],
    pub command_profile_sha256: [u8; 32],
    pub delivery_profile_sha256: [u8; 32],
    pub policy_sha256: [u8; 32],
    pub policy_epoch: u64,
}

/// All five KEM identities are distinct; each key has exactly one mode/purpose.
/// The separately authenticated delivery profile commits these exact bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPins {
    pub acu_gate_base: [u8; 32],
    pub recipient_psk: [u8; 32],
    pub archive_psk: [u8; 32],
    pub recipient_response_base: [u8; 32],
    pub archive_response_base: [u8; 32],
    pub acu_signer: [u8; 32],
    pub recipient_receipt_signer: [u8; 32],
    pub archive_receipt_signer: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Destination {
    #[serde(rename = "recipient:initiating-agent")]
    Recipient,
    #[serde(rename = "archive:vault")]
    Archive,
}
impl Destination {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Recipient => b"recipient:initiating-agent",
            Self::Archive => b"archive:vault",
        }
    }
    fn psk_pin(self, pins: &KeyPins) -> &[u8; 32] {
        match self {
            Self::Recipient => &pins.recipient_psk,
            Self::Archive => &pins.archive_psk,
        }
    }
    fn response_pin(self, pins: &KeyPins) -> &[u8; 32] {
        match self {
            Self::Recipient => &pins.recipient_response_base,
            Self::Archive => &pins.archive_response_base,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHeader {
    version: u16,
    suite: [u16; 3],
    policy: String,
    claims: ClaimedProvenance,
    keys: KeyPins,
    runner_signer: [u8; 32],
    nonce: [u8; 12],
    plaintext_bytes: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedSecret {
    enc: [u8; 32],
    ciphertext: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    pre: PreHeader,
    acu_gate_base: WrappedSecret,
    recipient_psk: WrappedSecret,
    archive_psk: WrappedSecret,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    header: Header,
    ciphertext_sha256: [u8; 32],
    ciphertext_bytes: u64,
    signature_hex: String,
}

pub struct SealedEnvelope {
    pub manifest: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
/// Original immutable metadata/ciphertext authenticated against trusted expected
/// pins/claims, not a coordinator admission or current ACU authorization token.
pub struct AuthenticatedEnvelope {
    manifest: Manifest,
    ciphertext: Vec<u8>,
    digest: [u8; 32],
}
impl AuthenticatedEnvelope {
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn claims(&self) -> &ClaimedProvenance {
        &self.manifest.header.pre.claims
    }
    pub fn original_manifest(&self) -> Result<Vec<u8>, EnvelopeError> {
        canonical(&self.manifest)
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn receipt_signing_pin(&self, role: Destination) -> &[u8; 32] {
        match role {
            Destination::Recipient => &self.manifest.header.pre.keys.recipient_receipt_signer,
            Destination::Archive => &self.manifest.header.pre.keys.archive_receipt_signer,
        }
    }
    pub fn complete_storage_blob(&self) -> Result<Vec<u8>, EnvelopeError> {
        let manifest = self.original_manifest()?;
        let mut bytes = b"CHWGCE01".to_vec();
        bytes.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.ciphertext.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&manifest);
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }
}

/// Parse only, never authenticate. Length bounds precede copying; metadata,
/// wraps and signature share the same durable object commit as the ciphertext.
pub fn parse_storage_blob(bytes: &[u8]) -> Result<SealedEnvelope, EnvelopeError> {
    if bytes.len() < 20 || &bytes[..8] != b"CHWGCE01" {
        return Err(EnvelopeError::Rejected);
    }
    let manifest = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| EnvelopeError::Rejected)?,
    ) as usize;
    let ciphertext = u64::from_be_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| EnvelopeError::Rejected)?,
    );
    if manifest == 0
        || manifest > MAX_MANIFEST_BYTES
        || ciphertext < 17
        || ciphertext > (MAX_PLAINTEXT_BYTES + 16) as u64
    {
        return Err(EnvelopeError::Rejected);
    }
    let end = 20 + manifest + ciphertext as usize;
    if bytes.len() != end {
        return Err(EnvelopeError::Rejected);
    }
    Ok(SealedEnvelope {
        manifest: bytes[20..20 + manifest].to_vec(),
        ciphertext: bytes[20 + manifest..].to_vec(),
    })
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, EnvelopeError> {
    serde_json::to_vec(value).map_err(|_| EnvelopeError::Rejected)
}
fn hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}
fn domain(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}
fn nonzero_secret(secret: &[u8]) -> bool {
    secret.len() == 32 && !bool::from(secret.ct_eq(&[0; 32]))
}
fn secret() -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(&mut key[..]).map_err(|_| EnvelopeError::Entropy)?;
    if !nonzero_secret(&key[..]) {
        return Err(EnvelopeError::Entropy);
    }
    Ok(key)
}
fn generate_kem() -> Result<(Private, [u8; 32]), EnvelopeError> {
    let seed = secret()?;
    let (sk, pk) = Kem::derive_keypair(&seed[..]);
    Ok((sk, pk.to_bytes().into()))
}

fn checked_kem_public(bytes: &[u8; 32], rng: &mut StdRng) -> Result<Public, EnvelopeError> {
    // Protocol encoding rule: one canonical little-endian field element < p.
    // RFC7748 permits masking/reduction; this profile rejects aliases so byte
    // commitments and role separation cannot encode one key two ways. This is
    // encoding validation only; all group operations stay in pinned HPKE.
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    if bytes.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less {
        return Err(EnvelopeError::Rejected);
    }
    let public = Public::from_bytes(bytes).map_err(|_| EnvelopeError::Rejected)?;
    // from_bytes only checks length. The crate's DHKEM encapsulation rejects
    // non-contributory/low-order public keys. Discard the fresh, zeroize-on-drop
    // shared secret and encapsulation; this is not a mode-changing key wrap.
    let _ = Kem::encap(&public, None, rng).map_err(|_| EnvelopeError::Rejected)?;
    Ok(public)
}
fn validate_pre(pre: &PreHeader) -> Result<(), EnvelopeError> {
    let c = &pre.claims;
    if pre.version != 1
        || pre.suite != [32, 1, 3]
        || pre.policy != "ACU AND (Recipient OR Archive)"
        || pre.plaintext_bytes == 0
        || pre.plaintext_bytes > MAX_PLAINTEXT_BYTES as u64
        || c.repository.is_empty()
        || c.repository.len() > 201
        || c.repository_id == 0
        || c.workflow_ref.is_empty()
        || c.workflow_ref.len() > 1024
        || c.initiating_instance.is_empty()
        || c.initiating_instance.len() > 193
        || c.run_id == 0
        || c.run_attempt == 0
        || c.policy_epoch == 0
    {
        return Err(EnvelopeError::Rejected);
    }
    for digest in [
        c.admission_sha256,
        c.intent_digest,
        c.command_profile_sha256,
        c.delivery_profile_sha256,
        c.policy_sha256,
    ] {
        if digest == [0; 32] {
            return Err(EnvelopeError::Rejected);
        }
    }
    let k = &pre.keys;
    let kem = [
        k.acu_gate_base,
        k.recipient_psk,
        k.archive_psk,
        k.recipient_response_base,
        k.archive_response_base,
    ];
    let ed = [
        pre.runner_signer,
        k.acu_signer,
        k.recipient_receipt_signer,
        k.archive_receipt_signer,
    ];
    let mut rng = StdRng::try_from_os_rng().map_err(|_| EnvelopeError::Entropy)?;
    for (i, key) in kem.iter().enumerate() {
        if *key == [0; 32] || kem[..i].contains(key) || ed.contains(key) {
            return Err(EnvelopeError::Rejected);
        }
        checked_kem_public(key, &mut rng)?;
    }
    for (i, key) in ed.iter().enumerate() {
        if ed[..i].contains(key)
            || VerifyingKey::from_bytes(key)
                .map_err(|_| EnvelopeError::Rejected)?
                .is_weak()
        {
            return Err(EnvelopeError::Rejected);
        }
    }
    Ok(())
}
fn wrap(
    mode: OpModeS<Kem>,
    pk: &[u8; 32],
    context: &[u8],
    value: &[u8],
    rng: &mut StdRng,
) -> Result<WrappedSecret, EnvelopeError> {
    let pk = Public::from_bytes(pk).map_err(|_| EnvelopeError::Rejected)?;
    let (enc, mut sender) =
        hpke::setup_sender::<WrapAead, HkdfSha256, Kem, _>(&mode, &pk, context, rng)
            .map_err(|_| EnvelopeError::Rejected)?;
    let ciphertext = sender
        .seal(value, context)
        .map_err(|_| EnvelopeError::Rejected)?;
    if ciphertext.len() != 48 {
        return Err(EnvelopeError::Rejected);
    }
    Ok(WrappedSecret {
        enc: enc.to_bytes().into(),
        ciphertext,
    })
}
fn unwrap(
    mode: OpModeR<Kem>,
    sk: &Private,
    wrapped: &WrappedSecret,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if wrapped.ciphertext.len() != 48 {
        return Err(EnvelopeError::Rejected);
    }
    let enc = Encapped::from_bytes(&wrapped.enc).map_err(|_| EnvelopeError::Rejected)?;
    let mut receiver = hpke::setup_receiver::<WrapAead, HkdfSha256, Kem>(&mode, sk, &enc, context)
        .map_err(|_| EnvelopeError::Rejected)?;
    let value = Zeroizing::new(
        receiver
            .open(&wrapped.ciphertext, context)
            .map_err(|_| EnvelopeError::Rejected)?,
    );
    if !nonzero_secret(&value) {
        return Err(EnvelopeError::Rejected);
    }
    Ok(value)
}
fn psk<'a>(gate: &'a [u8], id: &'a [u8]) -> Result<PskBundle<'a>, EnvelopeError> {
    // Do not allow the library's both-empty case to bypass the ACU gate.
    if !nonzero_secret(gate) || id.len() != 32 {
        return Err(EnvelopeError::Rejected);
    }
    PskBundle::new(gate, id).map_err(|_| EnvelopeError::Rejected)
}
fn wrap_context(pre: &[u8], role: &[u8]) -> Vec<u8> {
    domain(b"chinwag-ci-hpke-wrap-v1\0", &[pre, role])
}
fn psk_id(pre: &[u8]) -> [u8; 32] {
    hash(&domain(b"chinwag-ci-gate-psk-id-v1\0", &[pre]))
}
fn statement(header: &Header, ct_hash: &[u8; 32], ct_len: u64) -> Result<Vec<u8>, EnvelopeError> {
    Ok(domain(
        b"chinwag-ci-envelope-signature-v1\0",
        &[&canonical(header)?, ct_hash, &ct_len.to_be_bytes()],
    ))
}

pub(crate) fn seal(
    signer: &iroh::SecretKey,
    claims: ClaimedProvenance,
    pins: KeyPins,
    plaintext: &[u8],
) -> Result<SealedEnvelope, EnvelopeError> {
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|_| EnvelopeError::Entropy)?;
    let pre = PreHeader {
        version: 1,
        suite: [32, 1, 3],
        policy: "ACU AND (Recipient OR Archive)".into(),
        claims,
        keys: pins,
        runner_signer: *signer.public().as_bytes(),
        nonce,
        plaintext_bytes: plaintext.len() as u64,
    };
    validate_pre(&pre)?;
    let h0 = canonical(&pre)?;
    let key = secret()?;
    let gate = secret()?;
    if bool::from(key[..].ct_eq(&gate[..])) {
        return Err(EnvelopeError::Entropy);
    }
    let id = psk_id(&h0);
    let mut rng = StdRng::try_from_os_rng().map_err(|_| EnvelopeError::Entropy)?;
    let gate_wrap = wrap(
        OpModeS::Base,
        &pre.keys.acu_gate_base,
        &wrap_context(&h0, b"acu:gate-base"),
        &gate[..],
        &mut rng,
    )?;
    let recipient = wrap(
        OpModeS::Psk(psk(&gate[..], &id)?),
        &pre.keys.recipient_psk,
        &wrap_context(&h0, Destination::Recipient.label()),
        &key[..],
        &mut rng,
    )?;
    let archive = wrap(
        OpModeS::Psk(psk(&gate[..], &id)?),
        &pre.keys.archive_psk,
        &wrap_context(&h0, Destination::Archive.label()),
        &key[..],
        &mut rng,
    )?;
    let header = Header {
        pre,
        acu_gate_base: gate_wrap,
        recipient_psk: recipient,
        archive_psk: archive,
    };
    let aad = canonical(&header)?;
    let ciphertext = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| EnvelopeError::Rejected)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::Rejected)?;
    let ct_hash = hash(&ciphertext);
    let ct_len = ciphertext.len() as u64;
    let signature = signer
        .sign(&statement(&header, &ct_hash, ct_len)?)
        .to_bytes();
    let manifest = canonical(&Manifest {
        header,
        ciphertext_sha256: ct_hash,
        ciphertext_bytes: ct_len,
        signature_hex: hex::encode(signature),
    })?;
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(EnvelopeError::Rejected);
    }
    Ok(SealedEnvelope {
        manifest,
        ciphertext,
    })
}

pub fn authenticate(
    manifest: &[u8],
    ciphertext: &[u8],
    expected: &ClaimedProvenance,
    pins: &KeyPins,
    runner_signer: &[u8; 32],
) -> Result<AuthenticatedEnvelope, EnvelopeError> {
    if manifest.len() > MAX_MANIFEST_BYTES || ciphertext.len() > MAX_PLAINTEXT_BYTES + 16 {
        return Err(EnvelopeError::Rejected);
    }
    let parsed: Manifest = serde_json::from_slice(manifest).map_err(|_| EnvelopeError::Rejected)?;
    if canonical(&parsed)? != manifest {
        return Err(EnvelopeError::Rejected);
    }
    validate_pre(&parsed.header.pre)?;
    if &parsed.header.pre.claims != expected
        || &parsed.header.pre.keys != pins
        || &parsed.header.pre.runner_signer != runner_signer
        || parsed.ciphertext_bytes != ciphertext.len() as u64
        || parsed.ciphertext_bytes != parsed.header.pre.plaintext_bytes + 16
        || parsed.ciphertext_sha256 != hash(ciphertext)
        || parsed.signature_hex.len() != 128
    {
        return Err(EnvelopeError::Rejected);
    }
    for wrap in [
        &parsed.header.acu_gate_base,
        &parsed.header.recipient_psk,
        &parsed.header.archive_psk,
    ] {
        if wrap.ciphertext.len() != 48 {
            return Err(EnvelopeError::Rejected);
        }
    }
    let signature = hex::decode(&parsed.signature_hex).map_err(|_| EnvelopeError::Rejected)?;
    if hex::encode(&signature) != parsed.signature_hex {
        return Err(EnvelopeError::Rejected);
    }
    VerifyingKey::from_bytes(runner_signer)
        .map_err(|_| EnvelopeError::Rejected)?
        .verify_strict(
            &statement(
                &parsed.header,
                &parsed.ciphertext_sha256,
                parsed.ciphertext_bytes,
            )?,
            &Signature::from_slice(&signature).map_err(|_| EnvelopeError::Rejected)?,
        )
        .map_err(|_| EnvelopeError::Rejected)?;
    let digest = hash(&domain(b"chinwag-ci-complete-envelope-v1\0", &[manifest]));
    Ok(AuthenticatedEnvelope {
        manifest: parsed,
        ciphertext: ciphertext.to_vec(),
        digest,
    })
}

// Opaque, independently generated mode-specific keys. No seed/key import,
// export, Debug, Clone, serialization or implicit conversion between roles.
pub struct AcuGateKey {
    secret: Private,
    public: [u8; 32],
}
pub struct DestinationKey {
    secret: Private,
    public: [u8; 32],
    role: Destination,
}
pub struct ResponseKey {
    secret: Private,
    public: [u8; 32],
    role: Destination,
}
pub struct GateSecret {
    secret: Zeroizing<Vec<u8>>,
    envelope: [u8; 32],
}
impl AcuGateKey {
    pub fn generate() -> Result<Self, EnvelopeError> {
        let (secret, public) = generate_kem()?;
        Ok(Self { secret, public })
    }
    pub fn public(&self) -> [u8; 32] {
        self.public
    }
    /// The holder must independently authorize the signed request/current
    /// policy and consume replay state BEFORE calling this cryptographic step.
    pub fn unwrap_for_authorized_release(
        &self,
        envelope: &AuthenticatedEnvelope,
    ) -> Result<GateSecret, EnvelopeError> {
        let pre = &envelope.manifest.header.pre;
        if self.public != pre.keys.acu_gate_base {
            return Err(EnvelopeError::Rejected);
        }
        let secret = unwrap(
            OpModeR::Base,
            &self.secret,
            &envelope.manifest.header.acu_gate_base,
            &wrap_context(&canonical(pre)?, b"acu:gate-base"),
        )?;
        Ok(GateSecret {
            secret,
            envelope: envelope.digest,
        })
    }
}
impl DestinationKey {
    pub fn generate(role: Destination) -> Result<Self, EnvelopeError> {
        let (secret, public) = generate_kem()?;
        Ok(Self {
            secret,
            public,
            role,
        })
    }
    pub fn public(&self) -> [u8; 32] {
        self.public
    }
    pub fn open(
        &self,
        envelope: &AuthenticatedEnvelope,
        gate: &GateSecret,
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let header = &envelope.manifest.header;
        if self.public != *self.role.psk_pin(&header.pre.keys) || gate.envelope != envelope.digest {
            return Err(EnvelopeError::Rejected);
        }
        let h0 = canonical(&header.pre)?;
        let id = psk_id(&h0);
        let wrapped = match self.role {
            Destination::Recipient => &header.recipient_psk,
            Destination::Archive => &header.archive_psk,
        };
        let key = unwrap(
            OpModeR::Psk(psk(&gate.secret, &id)?),
            &self.secret,
            wrapped,
            &wrap_context(&h0, self.role.label()),
        )?;
        let aad = canonical(header)?;
        let plaintext = Zeroizing::new(
            ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| EnvelopeError::Rejected)?
                .decrypt(
                    Nonce::from_slice(&header.pre.nonce),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| EnvelopeError::Rejected)?,
        );
        if plaintext.len() as u64 != header.pre.plaintext_bytes {
            return Err(EnvelopeError::Rejected);
        }
        Ok(plaintext)
    }
}
fn response_context(
    envelope: &AuthenticatedEnvelope,
    role: Destination,
    request_digest: &[u8; 32],
) -> Vec<u8> {
    domain(
        b"chinwag-ci-acu-release-base-v1\0",
        &[
            &envelope.digest,
            role.label(),
            role.response_pin(&envelope.manifest.header.pre.keys),
            request_digest,
        ],
    )
}
impl GateSecret {
    /// Ciphertext only; application must separately sign the complete release
    /// statement and bind its nonce/epoch/expiry to the authenticated request.
    pub fn wrap_response(
        &self,
        envelope: &AuthenticatedEnvelope,
        role: Destination,
        request_digest: [u8; 32],
    ) -> Result<WrappedSecret, EnvelopeError> {
        if self.envelope != envelope.digest || request_digest == [0; 32] {
            return Err(EnvelopeError::Rejected);
        }
        let mut rng = StdRng::try_from_os_rng().map_err(|_| EnvelopeError::Entropy)?;
        wrap(
            OpModeS::Base,
            role.response_pin(&envelope.manifest.header.pre.keys),
            &response_context(envelope, role, &request_digest),
            &self.secret,
            &mut rng,
        )
    }
}
impl ResponseKey {
    pub fn generate(role: Destination) -> Result<Self, EnvelopeError> {
        let (secret, public) = generate_kem()?;
        Ok(Self {
            secret,
            public,
            role,
        })
    }
    pub fn public(&self) -> [u8; 32] {
        self.public
    }
    /// Verify the ACU's separately signed current-policy grant first. Successful
    /// Base decryption by itself authenticates no sender or release authority.
    pub fn open_gate_from_verified_grant(
        &self,
        envelope: &AuthenticatedEnvelope,
        request_digest: [u8; 32],
        wrapped: &WrappedSecret,
    ) -> Result<GateSecret, EnvelopeError> {
        if self.public != *self.role.response_pin(&envelope.manifest.header.pre.keys)
            || request_digest == [0; 32]
        {
            return Err(EnvelopeError::Rejected);
        }
        let secret = unwrap(
            OpModeR::Base,
            &self.secret,
            wrapped,
            &response_context(envelope, self.role, &request_digest),
        )?;
        Ok(GateSecret {
            secret,
            envelope: envelope.digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        acu: AcuGateKey,
        recipient: DestinationKey,
        archive: DestinationKey,
        recipient_response: ResponseKey,
        archive_response: ResponseKey,
        signer: iroh::SecretKey,
        claims: ClaimedProvenance,
        pins: KeyPins,
    }
    impl Fixture {
        fn new() -> Self {
            let acu = AcuGateKey::generate().unwrap();
            let recipient = DestinationKey::generate(Destination::Recipient).unwrap();
            let archive = DestinationKey::generate(Destination::Archive).unwrap();
            let recipient_response = ResponseKey::generate(Destination::Recipient).unwrap();
            let archive_response = ResponseKey::generate(Destination::Archive).unwrap();
            let signing = || {
                let seed = secret().unwrap();
                iroh::SecretKey::from_bytes(&seed)
            };
            let signer = signing();
            let pins = KeyPins {
                acu_gate_base: acu.public(),
                recipient_psk: recipient.public(),
                archive_psk: archive.public(),
                recipient_response_base: recipient_response.public(),
                archive_response_base: archive_response.public(),
                acu_signer: *signing().public().as_bytes(),
                recipient_receipt_signer: *signing().public().as_bytes(),
                archive_receipt_signer: *signing().public().as_bytes(),
            };
            let claims = ClaimedProvenance {
                admission_sha256: [1; 32],
                repository: "example/ci-test".into(),
                repository_id: 42,
                source_commit: [2; 20],
                workflow_ref: "example/ci-test/.github/workflows/ci.yml@refs/heads/proof".into(),
                workflow_commit: [3; 20],
                run_id: 100,
                run_attempt: 1,
                initiating_instance: "WORKHORSE#test-instance-1234".into(),
                intent_digest: [4; 32],
                command_profile_sha256: [5; 32],
                delivery_profile_sha256: [6; 32],
                policy_sha256: [7; 32],
                policy_epoch: 1,
            };
            Self {
                acu,
                recipient,
                archive,
                recipient_response,
                archive_response,
                signer,
                claims,
                pins,
            }
        }
        fn seal(&self, plain: &[u8]) -> SealedEnvelope {
            seal(&self.signer, self.claims.clone(), self.pins.clone(), plain).unwrap()
        }
        fn auth(&self, sealed: &SealedEnvelope) -> Result<AuthenticatedEnvelope, EnvelopeError> {
            authenticate(
                &sealed.manifest,
                &sealed.ciphertext,
                &self.claims,
                &self.pins,
                self.signer.public().as_bytes(),
            )
        }
    }

    #[test]
    fn both_destinations_open_the_same_large_ciphertext_only_with_the_acu_gate() {
        let f = Fixture::new();
        let plaintext: Vec<u8> = (0..700_000).map(|i| (i % 251) as u8).collect();
        let sealed = f.seal(&plaintext);
        let env = f.auth(&sealed).unwrap();
        assert_eq!(env.original_manifest().unwrap(), sealed.manifest);
        assert_eq!(env.ciphertext(), sealed.ciphertext);
        let gate = f.acu.unwrap_for_authorized_release(&env).unwrap();
        for (role, response, destination, request) in [
            (
                Destination::Recipient,
                &f.recipient_response,
                &f.recipient,
                [11; 32],
            ),
            (
                Destination::Archive,
                &f.archive_response,
                &f.archive,
                [12; 32],
            ),
        ] {
            let encrypted = gate.wrap_response(&env, role, request).unwrap();
            let delivered = response
                .open_gate_from_verified_grant(&env, request, &encrypted)
                .unwrap();
            assert_eq!(&*destination.open(&env, &delivered).unwrap(), &plaintext);
        }
        assert_eq!(env.claims().run_id, 100);
    }

    #[test]
    fn missing_or_wrong_gate_cannot_open_either_destination_even_in_collusion() {
        let f = Fixture::new();
        let env = f.auth(&f.seal(b"full failure output")).unwrap();
        let h0 = canonical(&env.manifest.header.pre).unwrap();
        let id = psk_id(&h0);
        for gate in [vec![], vec![0; 32], vec![9; 31], vec![9; 33]] {
            assert!(psk(&gate, &id).is_err());
        }
        assert!(psk(&[9; 32], &[]).is_err());
        let wrong = GateSecret {
            secret: Zeroizing::new(vec![9; 32]),
            envelope: env.digest,
        };
        // Giving BOTH destination secrets to this scope still does not produce P.
        assert!(f.recipient.open(&env, &wrong).is_err());
        assert!(f.archive.open(&env, &wrong).is_err());
        let right = f.acu.unwrap_for_authorized_release(&env).unwrap();
        assert!(
            DestinationKey::generate(Destination::Recipient)
                .unwrap()
                .open(&env, &right)
                .is_err()
        );
        // ACU has P but no destination key; its Base-only private key cannot
        // open a destination's PSK-only wrap even if supplied the right P.
        assert!(
            unwrap(
                OpModeR::Psk(psk(&right.secret, &id).unwrap()),
                &f.acu.secret,
                &env.manifest.header.recipient_psk,
                &wrap_context(&h0, Destination::Recipient.label())
            )
            .is_err()
        );
    }

    #[test]
    fn release_ciphertext_is_bound_to_request_role_response_key_and_envelope() {
        let f = Fixture::new();
        let env = f.auth(&f.seal(b"failure one")).unwrap();
        let other = f.auth(&f.seal(b"failure two")).unwrap();
        let gate = f.acu.unwrap_for_authorized_release(&env).unwrap();
        let wrapped = gate
            .wrap_response(&env, Destination::Recipient, [11; 32])
            .unwrap();
        assert!(
            f.archive_response
                .open_gate_from_verified_grant(&env, [11; 32], &wrapped)
                .is_err()
        );
        assert!(
            f.recipient_response
                .open_gate_from_verified_grant(&env, [12; 32], &wrapped)
                .is_err()
        );
        assert!(
            f.recipient_response
                .open_gate_from_verified_grant(&other, [11; 32], &wrapped)
                .is_err()
        );
        assert!(f.archive.open(&other, &gate).is_err());
        assert!(
            gate.wrap_response(&other, Destination::Recipient, [11; 32])
                .is_err()
        );
    }

    #[test]
    fn every_signed_component_and_exact_expected_provenance_is_authenticated() {
        let f = Fixture::new();
        let sealed = f.seal(b"failure output");
        let mut corrupt = sealed.ciphertext.clone();
        corrupt[0] ^= 1;
        assert!(
            authenticate(
                &sealed.manifest,
                &corrupt,
                &f.claims,
                &f.pins,
                f.signer.public().as_bytes()
            )
            .is_err()
        );
        let original: serde_json::Value = serde_json::from_slice(&sealed.manifest).unwrap();
        for path in [
            "/header/pre/claims/run_id",
            "/header/pre/claims/policy_epoch",
            "/header/pre/nonce/0",
            "/header/recipient_psk/ciphertext/0",
            "/header/archive_psk/enc/0",
            "/header/acu_gate_base/ciphertext/0",
            "/ciphertext_bytes",
        ] {
            let mut v = original.clone();
            let field = v.pointer_mut(path).unwrap();
            let n = field.as_u64().unwrap();
            *field = serde_json::json!(n ^ 1);
            let parsed: Manifest = serde_json::from_value(v).unwrap();
            assert!(
                authenticate(
                    &canonical(&parsed).unwrap(),
                    &sealed.ciphertext,
                    &f.claims,
                    &f.pins,
                    f.signer.public().as_bytes()
                )
                .is_err(),
                "{path}"
            );
        }
        let mut different = f.claims.clone();
        different.source_commit[0] ^= 1;
        assert!(
            authenticate(
                &sealed.manifest,
                &sealed.ciphertext,
                &different,
                &f.pins,
                f.signer.public().as_bytes()
            )
            .is_err()
        );
        let mut extra = sealed.manifest.clone();
        extra.push(b' ');
        assert!(
            authenticate(
                &extra,
                &sealed.ciphertext,
                &f.claims,
                &f.pins,
                f.signer.public().as_bytes()
            )
            .is_err()
        );
        let duplicate = String::from_utf8(sealed.manifest.clone())
            .unwrap()
            .replacen("{\"header\":", "{\"ciphertext_bytes\":30,\"header\":", 1);
        assert!(
            authenticate(
                duplicate.as_bytes(),
                &sealed.ciphertext,
                &f.claims,
                &f.pins,
                f.signer.public().as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn all_wraps_are_in_payload_aad_and_cannot_be_transplanted_or_downgraded() {
        let f = Fixture::new();
        let sealed = f.seal(b"failure output");
        let original_env = f.auth(&sealed).unwrap();
        let mut manifest: Manifest = serde_json::from_slice(&sealed.manifest).unwrap();
        // Even a producer-signed corrupt Recipient wrap changes H, so Archive
        // cannot decrypt the original payload under a different authenticated H.
        manifest.header.recipient_psk.ciphertext[0] ^= 1;
        manifest.signature_hex = hex::encode(
            f.signer
                .sign(
                    &statement(
                        &manifest.header,
                        &manifest.ciphertext_sha256,
                        manifest.ciphertext_bytes,
                    )
                    .unwrap(),
                )
                .to_bytes(),
        );
        let corrupt = SealedEnvelope {
            manifest: canonical(&manifest).unwrap(),
            ciphertext: sealed.ciphertext,
        };
        let env = f.auth(&corrupt).unwrap();
        let gate = f.acu.unwrap_for_authorized_release(&env).unwrap();
        assert!(f.archive.open(&env, &gate).is_err());
        let h0 = canonical(&original_env.manifest.header.pre).unwrap();
        // No Base fallback can open either PSK key wrap.
        assert!(
            unwrap(
                OpModeR::Base,
                &f.recipient.secret,
                &original_env.manifest.header.recipient_psk,
                &wrap_context(&h0, Destination::Recipient.label())
            )
            .is_err()
        );
    }

    #[test]
    fn mode_key_aliases_weak_signers_invalid_sizes_and_reused_material_are_refused() {
        let f = Fixture::new();
        let mut pins = f.pins.clone();
        pins.recipient_response_base = pins.recipient_psk;
        assert!(seal(&f.signer, f.claims.clone(), pins, b"test").is_err());
        assert!(seal(&f.signer, f.claims.clone(), f.pins.clone(), b"").is_err());
        let mut pins = f.pins.clone();
        pins.acu_signer = [0; 32];
        assert!(seal(&f.signer, f.claims.clone(), pins, b"test").is_err());
        let first = f.seal(b"same report");
        let second = f.seal(b"same report");
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_ne!(first.manifest, second.manifest);
    }

    #[test]
    fn external_response_pins_must_be_canonical_and_contributory_before_sealing() {
        let f = Fixture::new();
        let mut low_order = [0; 32];
        low_order[0] = 1;
        let mut high_bit_alias = f.pins.recipient_response_base;
        high_bit_alias[31] |= 0x80;
        let mut modulus = [0xff; 32];
        modulus[0] = 0xed;
        modulus[31] = 0x7f;
        for invalid in [low_order, high_bit_alias, modulus] {
            let mut pins = f.pins.clone();
            pins.archive_response_base = invalid;
            assert!(seal(&f.signer, f.claims.clone(), pins, b"failure").is_err());
        }
    }
}
