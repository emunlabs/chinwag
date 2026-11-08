// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Destination signature joins actual pinned native ingress with durable storage.
use super::*;
use crate::{
    authorization::{self as auth, AdmissionBoundEnvelope},
    transport::{CI_ALPN, SelectedRelayWitness},
};
const DOMAIN: &[u8] = b"chinwag-ci-native-admitted-ingress-v1\0";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    version: u16,
    role: Destination,
    store_id: [u8; 32],
    envelope_digest: [u8; 32],
    certificate_sha256: [u8; 32],
    before: PathStatement,
    after_receive: PathStatement,
    durable_receipt_hex: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    statement: Statement,
    signature_hex: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathStatement {
    peer_endpoint_id: String,
    alpn: String,
    selected_transport: String,
    relay_origin: String,
}
impl From<&SelectedRelayWitness> for PathStatement {
    fn from(p: &SelectedRelayWitness) -> Self {
        Self {
            peer_endpoint_id: p.peer_endpoint_id.clone(),
            alpn: p.alpn.clone(),
            selected_transport: p.selected_transport.clone(),
            relay_origin: p.relay_origin.clone(),
        }
    }
}
fn path_ok(path: &PathStatement, expected: [u8; 32], relay: &str) -> bool {
    path.peer_endpoint_id == hex::encode(expected)
        && path.alpn.as_bytes() == CI_ALPN
        && path.selected_transport == "relay"
        && path.relay_origin == relay
}
fn peer(e: &AdmissionBoundEnvelope, role: Destination) -> [u8; 32] {
    match role {
        Destination::Recipient => e.admission_record().agent_transport_key,
        Destination::Archive => e.admission_record().archive_transport_key,
    }
}
impl ReceiptSigner {
    pub(crate) fn persist_native_admitted(
        &self,
        e: &AdmissionBoundEnvelope,
        claim: &crate::transport::ReceivedCiphertextClaim,
        relay: &str,
    ) -> Result<Vec<u8>, ReceiptError> {
        let body = e
            .complete_storage_blob()
            .map_err(|_| ReceiptError::Rejected)?;
        if !claim.matches_original(e.certificate(), &body) {
            return Err(ReceiptError::Rejected);
        }
        let before = PathStatement::from(&claim.path_before);
        let after_receive = PathStatement::from(&claim.path_after_receive);
        if !path_ok(&before, peer(e, self.role), relay)
            || !path_ok(&after_receive, peer(e, self.role), relay)
        {
            return Err(ReceiptError::Rejected);
        }
        let durable_receipt_hex = hex::encode(self.persist_admitted(e)?);
        let statement = Statement {
            version: 1,
            role: self.role,
            store_id: self.store_id,
            envelope_digest: *e.digest(),
            certificate_sha256: Sha256::digest(e.certificate()).into(),
            before,
            after_receive,
            durable_receipt_hex,
        };
        let signature_hex = hex::encode(
            self.secret
                .sign(&auth::signing_bytes(DOMAIN, &statement).map_err(|_| ReceiptError::Rejected)?)
                .to_bytes(),
        );
        let bytes = auth::canonical(&Signed {
            statement,
            signature_hex,
        })
        .map_err(|_| ReceiptError::Rejected)?;
        let blob = e
            .complete_admitted_blob()
            .map_err(|_| ReceiptError::Rejected)?;
        self.persist_receipt_sidecar(
            CiphertextClaim {
                sha256: Sha256::digest(&blob).into(),
                bytes: blob.len() as u64,
            },
            &bytes,
            true,
        )?;
        Ok(bytes)
    }
}
pub fn verify_native_admitted(
    bytes: &[u8],
    e: &AdmissionBoundEnvelope,
    role: Destination,
    store_id: [u8; 32],
    relay: &str,
) -> Result<VerifiedStorageReceipt, ReceiptError> {
    let signed: Signed = auth::parse(bytes).map_err(|_| ReceiptError::Rejected)?;
    let s = &signed.statement;
    if bytes.len() > crate::transport::MAX_RECEIPT_BYTES
        || s.version != 1
        || s.role != role
        || s.store_id != store_id
        || s.envelope_digest != *e.digest()
        || s.certificate_sha256 != <[u8; 32]>::from(Sha256::digest(e.certificate()))
        || !path_ok(&s.before, peer(e, role), relay)
        || !path_ok(&s.after_receive, peer(e, role), relay)
    {
        return Err(ReceiptError::Rejected);
    }
    auth::verify_signature(
        DOMAIN,
        s,
        &signed.signature_hex,
        *e.receipt_signing_pin(role),
    )
    .map_err(|_| ReceiptError::Rejected)?;
    let receipt = hex::decode(&s.durable_receipt_hex).map_err(|_| ReceiptError::Rejected)?;
    super::verify_admitted(&receipt, e, role, store_id)
}

#[cfg(test)]
pub(crate) fn assert_canonical_native_signature_tamper_refused(
    bytes: &[u8],
    e: &AdmissionBoundEnvelope,
    role: Destination,
    store: [u8; 32],
    relay: &str,
) {
    let mut v: Signed = auth::parse(bytes).unwrap();
    let first = v.statement.durable_receipt_hex.as_bytes()[0];
    v.statement
        .durable_receipt_hex
        .replace_range(..1, if first == b'0' { "1" } else { "0" });
    let changed = auth::canonical(&v).unwrap();
    let _: Signed = auth::parse(&changed).unwrap();
    assert!(verify_native_admitted(&changed, e, role, store, relay).is_err());
}
