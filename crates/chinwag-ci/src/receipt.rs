// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! A receipt signs an actual complete-envelope durable readback observation.
//! No relay ACK, decryption, processing, WORM or repair authority is implied.
//! Enrolled child signer is opaque; its owner attests its public role/store pin.

use crate::{
    envelope::{AuthenticatedEnvelope, Destination, EnvelopeError},
    storage::{CiphertextClaim, CiphertextStore, StorageError, StoredBytesObservation},
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
mod admitted;
pub use admitted::verify_admitted;
pub(crate) use admitted::verify_admitted_historical;

#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("CI storage receipt is invalid or outside its enrolled scope")]
    Rejected,
    #[error("CI receipt identity entropy is unavailable")]
    Entropy,
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

pub struct ReceiptSigner {
    secret: iroh::SecretKey,
    role: Destination,
    store_id: [u8; 32],
    store: CiphertextStore,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    version: u16,
    classification: String,
    role: Destination,
    signer: [u8; 32],
    store_id: [u8; 32],
    envelope_digest: [u8; 32],
    admission_sha256: [u8; 32],
    run_id: u64,
    run_attempt: u32,
    policy_sha256: [u8; 32],
    policy_epoch: u64,
    ciphertext_sha256: [u8; 32],
    ciphertext_bytes: u64,
    complete_object_sha256: [u8; 32],
    complete_object_bytes: u64,
    object: String,
    created_inode_confirmed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedReceipt {
    statement: Statement,
    signature_hex: String,
}
pub struct VerifiedStorageReceipt {
    role: Destination,
    store_id: [u8; 32],
    envelope: [u8; 32],
    object: CiphertextClaim,
    created_inode_confirmed: bool,
}
impl VerifiedStorageReceipt {
    pub fn role(&self) -> Destination {
        self.role
    }
    pub fn store_id(&self) -> &[u8; 32] {
        &self.store_id
    }
    pub fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope
    }
    pub fn object_claim(&self) -> CiphertextClaim {
        self.object
    }
    pub fn created_inode_confirmed(&self) -> bool {
        self.created_inode_confirmed
    }
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn claim(bytes: &[u8]) -> CiphertextClaim {
    CiphertextClaim {
        sha256: hash(bytes),
        bytes: bytes.len() as u64,
    }
}
fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, ReceiptError> {
    serde_json::to_vec(v).map_err(|_| ReceiptError::Rejected)
}
fn signed_bytes(v: &Statement) -> Result<Vec<u8>, ReceiptError> {
    let bytes = canonical(v)?;
    let mut input = b"chinwag-ci-durable-storage-receipt-v1\0".to_vec();
    input.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    input.extend_from_slice(&bytes);
    Ok(input)
}
impl ReceiptSigner {
    pub(crate) fn sign_release_request(
        &self,
        statement: &crate::acu::RequestStatement,
    ) -> Result<String, crate::acu::AcuError> {
        if statement.role != self.role
            || statement.signer != self.public()
            || statement.store_id != self.store_id
        {
            return Err(crate::acu::AcuError::Rejected);
        }
        Ok(hex::encode(
            self.secret
                .sign(&crate::acu::request_payload(statement)?)
                .to_bytes(),
        ))
    }
    pub(crate) fn from_owner_seed(
        role: Destination,
        store_id: [u8; 32],
        store: CiphertextStore,
        seed: &[u8; 32],
    ) -> Result<Self, ReceiptError> {
        if store_id == [0; 32] {
            return Err(ReceiptError::Rejected);
        }
        Ok(Self {
            secret: iroh::SecretKey::from_bytes(seed),
            role,
            store_id,
            store,
        })
    }
    pub(crate) fn read_complete_object(
        &self,
        receipt: &VerifiedStorageReceipt,
    ) -> Result<Vec<u8>, ReceiptError> {
        if receipt.role != self.role || receipt.store_id != self.store_id {
            return Err(ReceiptError::Rejected);
        }
        Ok(self.store.read_existing(receipt.object_claim())?)
    }
    /// Owner enrolls the returned public key together with this store ID and
    /// capability. The signer can never be redirected to an arbitrary store.
    pub fn generate(
        role: Destination,
        store_id: [u8; 32],
        store: CiphertextStore,
    ) -> Result<Self, ReceiptError> {
        if store_id == [0; 32] {
            return Err(ReceiptError::Rejected);
        }
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(&mut seed[..]).map_err(|_| ReceiptError::Entropy)?;
        Ok(Self {
            secret: iroh::SecretKey::from_bytes(&seed),
            role,
            store_id,
            store,
        })
    }
    pub fn public(&self) -> [u8; 32] {
        *self.secret.public().as_bytes()
    }
    fn observation_statement(
        &self,
        envelope: &AuthenticatedEnvelope,
        blob: &[u8],
        observation: StoredBytesObservation,
    ) -> Result<Statement, ReceiptError> {
        if self.public() != *envelope.receipt_signing_pin(self.role) {
            return Err(ReceiptError::Rejected);
        }
        let object = claim(blob);
        if observation.sha256() != hex::encode(object.sha256) || observation.bytes() != object.bytes
        {
            return Err(ReceiptError::Rejected);
        }
        let c = envelope.claims();
        let statement = Statement {
            version: 1,
            classification: "DURABLE_COMPLETE_ENVELOPE_READBACK_OBSERVATION_ONLY".into(),
            role: self.role,
            signer: self.public(),
            store_id: self.store_id,
            envelope_digest: *envelope.digest(),
            admission_sha256: c.admission_sha256,
            run_id: c.run_id,
            run_attempt: c.run_attempt,
            policy_sha256: c.policy_sha256,
            policy_epoch: c.policy_epoch,
            ciphertext_sha256: hash(envelope.ciphertext()),
            ciphertext_bytes: envelope.ciphertext().len() as u64,
            complete_object_sha256: object.sha256,
            complete_object_bytes: object.bytes,
            object: observation.object().into(),
            created_inode_confirmed: observation.created_inode_confirmed(),
        };
        Ok(statement)
    }
    fn sign_observation(
        &self,
        envelope: &AuthenticatedEnvelope,
        blob: &[u8],
        observation: StoredBytesObservation,
    ) -> Result<Vec<u8>, ReceiptError> {
        let statement = self.observation_statement(envelope, blob, observation)?;
        let signature_hex = hex::encode(self.secret.sign(&signed_bytes(&statement)?).to_bytes());
        canonical(&SignedReceipt {
            statement,
            signature_hex,
        })
    }
    /// No overwrite or silent resend. AlreadyExists and uncertain creation are
    /// explicit failures; exact observation reconciliation is a separate call.
    pub fn persist(&self, envelope: &AuthenticatedEnvelope) -> Result<Vec<u8>, ReceiptError> {
        if self.public() != *envelope.receipt_signing_pin(self.role) {
            return Err(ReceiptError::Rejected);
        }
        let bytes = envelope.complete_storage_blob()?;
        let observation = self.store.persist_ciphertext_claim(claim(&bytes), &bytes)?;
        self.sign_observation(envelope, &bytes, observation)
    }
    pub fn reconcile_existing(
        &self,
        envelope: &AuthenticatedEnvelope,
    ) -> Result<Vec<u8>, ReceiptError> {
        if self.public() != *envelope.receipt_signing_pin(self.role) {
            return Err(ReceiptError::Rejected);
        }
        let bytes = envelope.complete_storage_blob()?;
        let object = claim(&bytes);
        if self.store.read_existing(object)? != bytes {
            return Err(ReceiptError::Rejected);
        }
        let observation = self.store.observe_existing(object)?;
        self.sign_observation(envelope, &bytes, observation)
    }
}

pub fn verify(
    bytes: &[u8],
    envelope: &AuthenticatedEnvelope,
    role: Destination,
    store_id: [u8; 32],
) -> Result<VerifiedStorageReceipt, ReceiptError> {
    verify_with_object(
        bytes,
        envelope,
        role,
        store_id,
        claim(&envelope.complete_storage_blob()?),
    )
}
fn verify_with_object(
    bytes: &[u8],
    envelope: &AuthenticatedEnvelope,
    role: Destination,
    store_id: [u8; 32],
    object: CiphertextClaim,
) -> Result<VerifiedStorageReceipt, ReceiptError> {
    if bytes.len() > 16384 || store_id == [0; 32] {
        return Err(ReceiptError::Rejected);
    }
    let signed: SignedReceipt =
        serde_json::from_slice(bytes).map_err(|_| ReceiptError::Rejected)?;
    if canonical(&signed)? != bytes {
        return Err(ReceiptError::Rejected);
    }
    let s = &signed.statement;
    let c = envelope.claims();
    if s.version != 1
        || s.classification != "DURABLE_COMPLETE_ENVELOPE_READBACK_OBSERVATION_ONLY"
        || s.role != role
        || s.signer != *envelope.receipt_signing_pin(role)
        || s.store_id != store_id
        || s.envelope_digest != *envelope.digest()
        || s.admission_sha256 != c.admission_sha256
        || s.run_id != c.run_id
        || s.run_attempt != c.run_attempt
        || s.policy_sha256 != c.policy_sha256
        || s.policy_epoch != c.policy_epoch
        || s.ciphertext_sha256 != hash(envelope.ciphertext())
        || s.ciphertext_bytes != envelope.ciphertext().len() as u64
        || s.complete_object_sha256 != object.sha256
        || s.complete_object_bytes != object.bytes
        || s.object != format!("{}.cwcipher", hex::encode(object.sha256))
        || signed.signature_hex.len() != 128
    {
        return Err(ReceiptError::Rejected);
    }
    let signature = hex::decode(&signed.signature_hex).map_err(|_| ReceiptError::Rejected)?;
    if hex::encode(&signature) != signed.signature_hex {
        return Err(ReceiptError::Rejected);
    }
    VerifyingKey::from_bytes(envelope.receipt_signing_pin(role))
        .map_err(|_| ReceiptError::Rejected)?
        .verify_strict(
            &signed_bytes(s)?,
            &Signature::from_slice(&signature).map_err(|_| ReceiptError::Rejected)?,
        )
        .map_err(|_| ReceiptError::Rejected)?;
    Ok(VerifiedStorageReceipt {
        role,
        store_id,
        envelope: *envelope.digest(),
        object,
        created_inode_confirmed: s.created_inode_confirmed,
    })
}
