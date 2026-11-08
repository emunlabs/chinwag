// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! A completed admitted artifact includes its original owner certificate. An
//! independently signed private sidecar records live ingress/durable readback.
//! Cold historical recovery requires both; bare expired certificates confer no
//! publication authority. All clock observations remain ordinary host clocks.

use super::*;
use crate::{
    admission::AdmissionRecord,
    authorization::{self as auth, AdmissionBoundEnvelope},
};
#[cfg(target_os = "macos")]
use rustix::fd::AsFd;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use std::{
    fs::File,
    io::{Read, Write},
};
const DOMAIN: &[u8] = b"chinwag-ci-admitted-artifact-storage-ingress-v1\0";
const MAX_RECEIPT: usize = 16 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmittedStatement {
    version: u16,
    classification: String,
    storage_receipt: SignedReceipt,
    admission_issuer: [u8; 32],
    certificate_sha256: [u8; 32],
    authenticated_ingress_unix: u64,
    storage_observed_unix: u64,
    clock_classification: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmittedReceipt {
    statement: AdmittedStatement,
    signature_hex: String,
}
fn private(file: &File) -> Result<Stat, ReceiptError> {
    let s = fs::fstat(file).map_err(|_| ReceiptError::Rejected)?;
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_uid != rustix::process::geteuid().as_raw()
        || s.st_nlink != 1
        || s.st_mode & 0o7777 != 0o600
        || s.st_size < 1
        || s.st_size as u64 > MAX_RECEIPT as u64
    {
        return Err(ReceiptError::Rejected);
    }
    #[cfg(target_os = "macos")]
    crate::macos_acl::require_absent(file.as_fd()).map_err(|_| ReceiptError::Rejected)?;
    Ok(s)
}
fn sidecar_name(object: CiphertextClaim) -> String {
    format!("{}.ingress-receipt.json", hex::encode(object.sha256))
}
impl ReceiptSigner {
    fn read_ingress_sidecar(&self, object: CiphertextClaim) -> Result<Vec<u8>, ReceiptError> {
        self.store.check()?;
        let name = sidecar_name(object);
        let file = File::from(
            fs::openat(
                self.store.directory(),
                &name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ReceiptError::Rejected)?,
        );
        let start = private(&file)?;
        let mut bytes = Vec::with_capacity(start.st_size as usize);
        (&file)
            .take(MAX_RECEIPT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ReceiptError::Rejected)?;
        file.sync_all().map_err(|_| ReceiptError::Rejected)?;
        let end = private(&file)?;
        let named = fs::statat(self.store.directory(), &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ReceiptError::Rejected)?;
        if bytes.len() != start.st_size as usize
            || end.st_size != start.st_size
            || end.st_dev != start.st_dev
            || end.st_ino != start.st_ino
            || named.st_dev != end.st_dev
            || named.st_ino != end.st_ino
            || named.st_size != end.st_size
        {
            return Err(ReceiptError::Rejected);
        }
        fs::fsync(self.store.directory()).map_err(|_| ReceiptError::Rejected)?;
        self.store.check()?;
        Ok(bytes)
    }
    fn persist_ingress_sidecar(
        &self,
        object: CiphertextClaim,
        bytes: &[u8],
    ) -> Result<(), ReceiptError> {
        self.store.check()?;
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT {
            return Err(ReceiptError::Rejected);
        }
        let name = sidecar_name(object);
        let mode = Mode::RUSR | Mode::WUSR;
        let fd = fs::openat(
            self.store.directory(),
            &name,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            mode,
        )
        .map_err(|_| ReceiptError::Storage(StorageError::CreatedButUnconfirmed))?;
        fs::fchmod(&fd, mode)
            .map_err(|_| ReceiptError::Storage(StorageError::CreatedButUnconfirmed))?;
        let mut file = File::from(fd);
        file.write_all(bytes)
            .map_err(|_| ReceiptError::Storage(StorageError::CreatedButUnconfirmed))?;
        file.sync_all()
            .map_err(|_| ReceiptError::Storage(StorageError::CreatedButUnconfirmed))?;
        let created = private(&file)?;
        fs::fsync(self.store.directory())
            .map_err(|_| ReceiptError::Storage(StorageError::CreatedButUnconfirmed))?;
        if self.read_ingress_sidecar(object)? != bytes {
            return Err(ReceiptError::Storage(StorageError::CreatedButUnconfirmed));
        }
        let named = fs::statat(self.store.directory(), &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ReceiptError::Rejected)?;
        if named.st_dev != created.st_dev
            || named.st_ino != created.st_ino
            || named.st_size != created.st_size
        {
            return Err(ReceiptError::Storage(StorageError::CreatedButUnconfirmed));
        }
        Ok(())
    }
    /// Original live ingress only, with current validity rechecked immediately
    /// before creation. Failure after either creation is held, never retried.
    pub fn persist_admitted(
        &self,
        envelope: &AdmissionBoundEnvelope,
    ) -> Result<Vec<u8>, ReceiptError> {
        self.persist_admitted_clock(envelope, || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .map_err(|_| ReceiptError::Rejected)
        })
    }
    #[cfg(test)]
    pub(crate) fn persist_admitted_fixture(
        &self,
        envelope: &AdmissionBoundEnvelope,
        before: u64,
        after: u64,
    ) -> Result<Vec<u8>, ReceiptError> {
        let mut values = [before, after].into_iter();
        self.persist_admitted_clock(envelope, || values.next().ok_or(ReceiptError::Rejected))
    }
    fn persist_admitted_clock(
        &self,
        envelope: &AdmissionBoundEnvelope,
        mut clock: impl FnMut() -> Result<u64, ReceiptError>,
    ) -> Result<Vec<u8>, ReceiptError> {
        let now = clock()?;
        let r = envelope.admission_record();
        if !envelope.is_current_ingress()
            || now < envelope.ingress_unix()
            || now < r.usable_from_unix
            || now >= r.expires_unix
            || self.public() != *envelope.receipt_signing_pin(self.role)
        {
            return Err(ReceiptError::Rejected);
        }
        let blob = envelope
            .complete_admitted_blob()
            .map_err(|_| ReceiptError::Rejected)?;
        let object = claim(&blob);
        let observation = self.store.persist_ciphertext_claim(object, &blob)?;
        let finish = || -> Result<Vec<u8>, ReceiptError> {
            // This observation is AFTER actual durable object readback. Never
            // sign a pre-write time as proof of completion within the lease.
            let completed = clock()?;
            if completed < now || completed >= r.expires_unix {
                return Err(ReceiptError::Rejected);
            }
            let inner = self.sign_observation(envelope, &blob, observation)?;
            let storage_receipt: SignedReceipt =
                serde_json::from_slice(&inner).map_err(|_| ReceiptError::Rejected)?;
            let statement = AdmittedStatement {
                version: 1,
                classification: "DURABLE_ADMITTED_ARTIFACT_HOST_CLOCK_INGRESS_OBSERVATION_ONLY"
                    .into(),
                storage_receipt,
                admission_issuer: envelope.admission_issuer(),
                certificate_sha256: hash(envelope.certificate()),
                authenticated_ingress_unix: envelope.ingress_unix(),
                storage_observed_unix: completed,
                clock_classification: "ORDINARY_OWNER_HOST_CLOCK_NOT_K2".into(),
            };
            let signature_hex = hex::encode(
                self.secret
                    .sign(
                        &auth::signing_bytes(DOMAIN, &statement)
                            .map_err(|_| ReceiptError::Rejected)?,
                    )
                    .to_bytes(),
            );
            let receipt = canonical(&AdmittedReceipt {
                statement,
                signature_hex,
            })?;
            self.persist_ingress_sidecar(object, &receipt)?;
            Ok(receipt)
        };
        finish().map_err(|_| ReceiptError::Storage(StorageError::CreatedButUnconfirmed))
    }
    /// Returns encrypted/public bytes only; the caller must independently
    /// verify the complete certificate/envelope/receipt through recovery API.
    pub(crate) fn read_admitted_object(
        &self,
        object: CiphertextClaim,
    ) -> Result<(Vec<u8>, Vec<u8>), ReceiptError> {
        let blob = self.store.read_existing(object)?;
        let receipt = self.read_ingress_sidecar(object)?;
        Ok((blob, receipt))
    }
}
pub fn verify_admitted(
    bytes: &[u8],
    envelope: &AdmissionBoundEnvelope,
    role: Destination,
    store_id: [u8; 32],
) -> Result<VerifiedStorageReceipt, ReceiptError> {
    let blob = envelope
        .complete_admitted_blob()
        .map_err(|_| ReceiptError::Rejected)?;
    Ok(verify_admitted_historical(
        bytes,
        envelope,
        envelope.certificate(),
        envelope.admission_issuer(),
        envelope.admission_record(),
        role,
        store_id,
        &blob,
    )?
    .0)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_admitted_historical(
    bytes: &[u8],
    envelope: &AuthenticatedEnvelope,
    certificate: &[u8],
    issuer: [u8; 32],
    admission: &AdmissionRecord,
    role: Destination,
    store_id: [u8; 32],
    blob: &[u8],
) -> Result<(VerifiedStorageReceipt, u64), ReceiptError> {
    if bytes.is_empty() || bytes.len() > MAX_RECEIPT {
        return Err(ReceiptError::Rejected);
    }
    let receipt: AdmittedReceipt = auth::parse(bytes).map_err(|_| ReceiptError::Rejected)?;
    let s = &receipt.statement;
    if s.version != 1
        || s.classification != "DURABLE_ADMITTED_ARTIFACT_HOST_CLOCK_INGRESS_OBSERVATION_ONLY"
        || s.admission_issuer != issuer
        || s.certificate_sha256 != hash(certificate)
        || s.clock_classification != "ORDINARY_OWNER_HOST_CLOCK_NOT_K2"
        || s.authenticated_ingress_unix < admission.usable_from_unix
        || s.authenticated_ingress_unix >= admission.expires_unix
        || s.storage_observed_unix < s.authenticated_ingress_unix
        || s.storage_observed_unix >= admission.expires_unix
    {
        return Err(ReceiptError::Rejected);
    }
    let verified = verify_with_object(
        &canonical(&s.storage_receipt)?,
        envelope,
        role,
        store_id,
        claim(blob),
    )?;
    auth::verify_signature(
        DOMAIN,
        s,
        &receipt.signature_hex,
        *envelope.receipt_signing_pin(role),
    )
    .map_err(|_| ReceiptError::Rejected)?;
    Ok((verified, s.authenticated_ingress_unix))
}
