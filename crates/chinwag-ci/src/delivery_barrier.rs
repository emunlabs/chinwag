// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Public receipt metadata only. Ciphertext and plaintext never traverse this
//! HTTP path. Both three-layer destination signatures must verify against the
//! same current admitted artifact already recovered from local native custody.
use crate::{
    authorization::{self, AdmissionBoundEnvelope},
    envelope::Destination,
    profile::{BoundProfiles, RegisteredJob},
    receipt,
    storage::CiphertextClaim,
    transport::{CI_ALPN, SelectedRelayWitness},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DualDeliveryRequest {
    pub version: u16,
    pub run_id: u64,
    pub run_attempt: u32,
    pub envelope_digest: [u8; 32],
    pub object: CiphertextClaim,
    pub recipient_receipt_hex: String,
    pub archive_receipt_hex: String,
    pub recipient_path: SelectedRelayWitness,
    pub archive_path: SelectedRelayWitness,
}
#[derive(Clone, Serialize)]
pub struct VerifiedDualDelivery {
    classification: &'static str,
    run_id: u64,
    run_attempt: u32,
    envelope_digest: [u8; 32],
    object: CiphertextClaim,
    receipt_set_sha256: [u8; 32],
}
#[derive(Debug, thiserror::Error)]
#[error("dual native delivery proof is missing, mismatched or unverified")]
pub struct DualDeliveryError;
fn checked<T, E>(v: Result<T, E>) -> Result<T, DualDeliveryError> {
    v.map_err(|_| DualDeliveryError)
}
fn path(p: &SelectedRelayWitness, peer: [u8; 32], relay: &str) -> bool {
    p.peer_endpoint_id == hex::encode(peer)
        && p.alpn.as_bytes() == CI_ALPN
        && p.selected_transport == "relay"
        && p.relay_origin == relay
}
impl VerifiedDualDelivery {
    pub fn matches(
        &self,
        run: u64,
        attempt: u32,
        envelope: [u8; 32],
        object: CiphertextClaim,
    ) -> bool {
        self.run_id == run
            && self.run_attempt == attempt
            && self.envelope_digest == envelope
            && self.object.sha256 == object.sha256
            && self.object.bytes == object.bytes
    }
    pub fn receipt_set_digest(&self) -> [u8; 32] {
        self.receipt_set_sha256
    }
}
pub fn verify(
    request: &DualDeliveryRequest,
    e: &AdmissionBoundEnvelope,
    profiles: &BoundProfiles,
    job: &RegisteredJob,
    now: u64,
) -> Result<VerifiedDualDelivery, DualDeliveryError> {
    let d = profiles.delivery().spec();
    let current = checked(authorization::verify_historical_certificate(
        e.certificate(),
        d.admission_signer,
    ))?;
    let current = checked(current.require_current(now))?;
    checked(profiles.validate_admission(&current, job, now))?;
    verify_pair(
        request,
        e,
        job.run_id,
        job.run_attempt,
        d.recipient.transport,
        d.recipient.store_id,
        d.archive.transport,
        d.archive.store_id,
        &d.relay_origin,
    )
}
#[allow(clippy::too_many_arguments)]
fn verify_pair(
    request: &DualDeliveryRequest,
    e: &AdmissionBoundEnvelope,
    run: u64,
    attempt: u32,
    recipient_peer: [u8; 32],
    recipient_store: [u8; 32],
    archive_peer: [u8; 32],
    archive_store: [u8; 32],
    relay: &str,
) -> Result<VerifiedDualDelivery, DualDeliveryError> {
    let blob = checked(e.complete_admitted_blob())?;
    let object = CiphertextClaim {
        sha256: Sha256::digest(&blob).into(),
        bytes: blob.len() as u64,
    };
    if request.version != 1
        || request.run_id != run
        || request.run_attempt != attempt
        || request.envelope_digest != *e.digest()
        || request.object.sha256 != object.sha256
        || request.object.bytes != object.bytes
        || !path(&request.recipient_path, recipient_peer, relay)
        || !path(&request.archive_path, archive_peer, relay)
    {
        return Err(DualDeliveryError);
    }
    for (encoded, role, store) in [
        (
            &request.recipient_receipt_hex,
            Destination::Recipient,
            recipient_store,
        ),
        (
            &request.archive_receipt_hex,
            Destination::Archive,
            archive_store,
        ),
    ] {
        if encoded.len() > crate::transport::MAX_RECEIPT_BYTES * 2 {
            return Err(DualDeliveryError);
        }
        let b = checked(hex::decode(encoded))?;
        if hex::encode(&b) != *encoded {
            return Err(DualDeliveryError);
        }
        let r = checked(receipt::verify_native_admitted(&b, e, role, store, relay))?;
        if r.object_claim().sha256 != object.sha256
            || r.object_claim().bytes != object.bytes
            || !r.created_inode_confirmed()
        {
            return Err(DualDeliveryError);
        }
    }
    let encoded = checked(serde_json::to_vec(request))?;
    Ok(VerifiedDualDelivery {
        classification: "SIX_DESTINATION_SIGNATURES_AND_NATIVE_CUSTODY_VERIFIED_NOT_READ_OR_WORK_STARTED",
        run_id: run,
        run_attempt: attempt,
        envelope_digest: *e.digest(),
        object,
        receipt_set_sha256: Sha256::digest(encoded).into(),
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn fixture_verify_pair(
    request: &DualDeliveryRequest,
    e: &AdmissionBoundEnvelope,
    recipient_peer: [u8; 32],
    archive_peer: [u8; 32],
    relay: &str,
) -> bool {
    verify_pair(
        request,
        e,
        100,
        1,
        recipient_peer,
        [21; 32],
        archive_peer,
        [22; 32],
        relay,
    )
    .is_ok()
}
