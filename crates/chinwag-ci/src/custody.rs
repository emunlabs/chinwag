// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! New owner-held CI keys only, through opaque operations. No raw key export,
//! Debug/serialization, argv/env seeds, existing Mac signing-key import, key-file
//! hashes, permission repair or implicit rotation. Public enrollment is separate
//! from native owner attestation. Same-UID host compromise is outside this MVP.

use crate::{
    envelope::{
        AcuGateKey, AuthenticatedEnvelope, Destination, DestinationKey, EnvelopeError, GateSecret,
        ResponseKey, WrappedSecret,
    },
    receipt::{ReceiptError, ReceiptSigner, VerifiedStorageReceipt},
    storage::CiphertextStore,
    transport::{CiPair, TransferError},
};
use iroh::{EndpointId, SecretKey};
use rustix::{
    fd::AsFd,
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    ops::Deref,
    path::Path,
    sync::Arc,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerRole {
    Recipient,
    Archive,
    Acu,
    Admission,
}
impl OwnerRole {
    fn tag(self) -> u8 {
        match self {
            Self::Recipient => 1,
            Self::Archive => 2,
            Self::Acu => 3,
            Self::Admission => 4,
        }
    }
    fn seeds(self) -> usize {
        match self {
            Self::Recipient | Self::Archive => 4,
            Self::Acu => 2,
            Self::Admission => 1,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Recipient => "recipient-rolekeys-v1.cikey",
            Self::Archive => "archive-rolekeys-v1.cikey",
            Self::Acu => "acu-rolekeys-v1.cikey",
            Self::Admission => "admission-rolekeys-v1.cikey",
        }
    }
    fn destination(self) -> Option<Destination> {
        match self {
            Self::Recipient => Some(Destination::Recipient),
            Self::Archive => Some(Destination::Archive),
            _ => None,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicDestination {
    pub role: Destination,
    pub store_id: [u8; 32],
    pub store_binding: [u8; 32],
    pub psk: [u8; 32],
    pub response_base: [u8; 32],
    pub receipt_signer: [u8; 32],
    /// Explicit dual-purpose enrollment of the same owner signing identity.
    /// Release requests and storage receipts use distinct signature domains
    /// and typed operations. No arbitrary signing permission is implied.
    pub release_request_signer: [u8; 32],
    pub transport: [u8; 32],
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PublicEnrollment {
    Destination(PublicDestination),
    Acu {
        gate_base: [u8; 32],
        signer: [u8; 32],
    },
    Admission {
        signer: [u8; 32],
    },
}
#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    #[error("CI owner custody is missing, changed, malformed or not private")]
    Held,
    #[error("CI owner custody already exists; no replacement or implicit key rotation")]
    AlreadyExists,
    #[error("CI owner custody has another active owner")]
    Busy,
    #[error("CI owner custody creation is uncertain; preserve it for reconciliation")]
    CreationUnknown,
    #[error("CI owner custody entropy is unavailable")]
    Entropy,
    #[error("CI owner custody operation does not match its enrolled role")]
    Role,
    #[error("CI owner transport key already had its one bind attempt")]
    AlreadyBound,
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
    #[error(transparent)]
    Transport(#[from] TransferError),
}
const MAGIC: &[u8; 8] = b"CWCIKEY1";
const HEADER: usize = 75;
const MAX_BUNDLE_BYTES: usize = HEADER + 4 * 32;
struct Guard {
    directory: CiphertextStore,
    file: File,
    role: OwnerRole,
    bytes: usize,
    store_binding: [u8; 32],
}
impl Drop for Guard {
    fn drop(&mut self) {
        // Close-on-exec descriptors can transiently share a fork's open-file
        // description. The LAST actual owner explicitly releases its own lock;
        // an unrelated inherited FD must not extend that owner's lifetime.
        let _ = fs::flock(&self.file, FlockOperation::NonBlockingUnlock);
    }
}
impl Guard {
    fn check(&self) -> Result<(), CustodyError> {
        self.directory.check().map_err(|_| CustodyError::Held)?;
        let observed = private_file(&self.file)?;
        let named = fs::statat(
            self.directory.directory(),
            self.role.name(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| CustodyError::Held)?;
        if !is_private(&named)
            || named.st_dev != observed.st_dev
            || named.st_ino != observed.st_ino
            || named.st_size != observed.st_size
            || observed.st_size as u64 != self.bytes as u64
        {
            return Err(CustodyError::Held);
        }
        Ok(())
    }
}
fn is_private(s: &Stat) -> bool {
    FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
        && s.st_uid == rustix::process::geteuid().as_raw()
        && s.st_nlink == 1
        && s.st_mode & 0o7777 == 0o600
}
fn private_file(file: impl AsFd) -> Result<Stat, CustodyError> {
    let s = fs::fstat(&file).map_err(|_| CustodyError::Held)?;
    if !is_private(&s) {
        return Err(CustodyError::Held);
    }
    #[cfg(target_os = "macos")]
    crate::macos_acl::require_absent(file.as_fd()).map_err(|_| CustodyError::Held)?;
    Ok(s)
}
struct Material {
    seeds: Vec<Zeroizing<[u8; 32]>>,
}
fn decode(
    bytes: &[u8],
    role: OwnerRole,
    owner_context: [u8; 32],
    store_binding: [u8; 32],
) -> Result<Material, CustodyError> {
    if bytes.len() != HEADER + role.seeds() * 32
        || &bytes[..8] != MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10] != role.tag()
        || bytes[11..43] != owner_context
        || bytes[43..75] != store_binding
    {
        return Err(CustodyError::Held);
    }
    let mut seeds: Vec<Zeroizing<[u8; 32]>> = Vec::with_capacity(role.seeds());
    for bytes in bytes[HEADER..].chunks_exact(32) {
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(bytes);
        if bool::from(seed[..].ct_eq(&[0; 32]))
            || seeds.iter().any(|old| bool::from(old[..].ct_eq(&seed[..])))
        {
            return Err(CustodyError::Held);
        }
        seeds.push(seed);
    }
    Ok(Material { seeds })
}
fn read_material(
    guard: &Guard,
    owner_context: [u8; 32],
) -> Result<(Material, Zeroizing<[u8; MAX_BUNDLE_BYTES]>), CustodyError> {
    guard.check()?;
    let fd = fs::openat(
        guard.directory.directory(),
        guard.role.name(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CustodyError::Held)?;
    let before = private_file(&fd)?;
    let owned = private_file(&guard.file)?;
    if before.st_dev != owned.st_dev
        || before.st_ino != owned.st_ino
        || before.st_size as u64 != guard.bytes as u64
    {
        return Err(CustodyError::Held);
    }
    let mut file = File::from(fd);
    // Fixed buffers never reallocate while holding private seed bytes.
    let mut bytes = Zeroizing::new([0; MAX_BUNDLE_BYTES]);
    file.read_exact(&mut bytes[..guard.bytes])
        .map_err(|_| CustodyError::Held)?;
    let mut extra = Zeroizing::new([0; 1]);
    if file.read(&mut extra[..]).map_err(|_| CustodyError::Held)? != 0 {
        return Err(CustodyError::Held);
    }
    file.sync_all().map_err(|_| CustodyError::Held)?;
    private_file(&file)?;
    guard.check()?;
    let material = decode(
        &bytes[..guard.bytes],
        guard.role,
        owner_context,
        guard.store_binding,
    )?;
    Ok((material, bytes))
}
fn create(
    path: &Path,
    role: OwnerRole,
    owner_context: [u8; 32],
    store_binding: [u8; 32],
) -> Result<(Arc<Guard>, Material), CustodyError> {
    if owner_context == [0; 32] {
        return Err(CustodyError::Role);
    }
    let directory = CiphertextStore::open(path).map_err(|_| CustodyError::Held)?;
    let mode = Mode::RUSR | Mode::WUSR;
    let fd = fs::openat(
        directory.directory(),
        role.name(),
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        mode,
    )
    .map_err(|e| {
        if e == rustix::io::Errno::EXIST {
            CustodyError::AlreadyExists
        } else {
            CustodyError::Held
        }
    })?;
    let write = || -> Result<(Arc<Guard>, Material), CustodyError> {
        fs::fchmod(&fd, mode).map_err(|_| CustodyError::CreationUnknown)?;
        private_file(&fd)?;
        fs::flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|_| CustodyError::Busy)?;
        let size = HEADER + role.seeds() * 32;
        let mut bytes = Zeroizing::new([0; MAX_BUNDLE_BYTES]);
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = role.tag();
        bytes[11..43].copy_from_slice(&owner_context);
        bytes[43..75].copy_from_slice(&store_binding);
        getrandom::fill(&mut bytes[HEADER..size]).map_err(|_| CustodyError::Entropy)?;
        decode(&bytes[..size], role, owner_context, store_binding)?;
        let mut file = File::from(fd);
        file.write_all(&bytes[..size])
            .map_err(|_| CustodyError::CreationUnknown)?;
        file.sync_all().map_err(|_| CustodyError::CreationUnknown)?;
        fs::fsync(directory.directory()).map_err(|_| CustodyError::CreationUnknown)?;
        let guard = Arc::new(Guard {
            directory,
            file,
            role,
            bytes: size,
            store_binding,
        });
        let (material, readback) = read_material(&guard, owner_context)?;
        if !bool::from(bytes[..size].ct_eq(&readback[..size])) {
            return Err(CustodyError::CreationUnknown);
        }
        guard.check()?;
        Ok((guard, material))
    };
    write().map_err(|_| CustodyError::CreationUnknown)
}
fn open(
    path: &Path,
    role: OwnerRole,
    owner_context: [u8; 32],
    store_binding: [u8; 32],
) -> Result<(Arc<Guard>, Material), CustodyError> {
    if owner_context == [0; 32] {
        return Err(CustodyError::Role);
    }
    let directory = CiphertextStore::open(path).map_err(|_| CustodyError::Held)?;
    let fd = fs::openat(
        directory.directory(),
        role.name(),
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CustodyError::Held)?;
    private_file(&fd)?;
    fs::flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|_| CustodyError::Busy)?;
    let guard = Arc::new(Guard {
        directory,
        file: File::from(fd),
        role,
        bytes: HEADER + role.seeds() * 32,
        store_binding,
    });
    let (material, _) = read_material(&guard, owner_context)?;
    Ok((guard, material))
}
enum Keys {
    Destination {
        role: Destination,
        store_id: [u8; 32],
        psk: DestinationKey,
        response: ResponseKey,
        receipt: Box<ReceiptSigner>,
        transport: Option<SecretKey>,
        transport_public: [u8; 32],
    },
    Acu {
        gate: AcuGateKey,
        signer: SecretKey,
    },
    Admission {
        signer: SecretKey,
    },
}
pub struct OwnerCustody {
    guard: Arc<Guard>,
    keys: Keys,
}
fn enrolled_store_binding(
    role: OwnerRole,
    owner_context: [u8; 32],
    store: Option<&(CiphertextStore, [u8; 32])>,
) -> Result<[u8; 32], CustodyError> {
    match (role.destination(), store) {
        (Some(_), Some((store, id))) if *id != [0; 32] => {
            let physical = store.directory_binding().map_err(|_| CustodyError::Held)?;
            let mut h = Sha256::new();
            h.update(b"chinwag-ci-custody-store-enrollment-v1\0");
            h.update([role.tag()]);
            h.update(owner_context);
            h.update(id);
            h.update(physical);
            Ok(h.finalize().into())
        }
        (None, None) => Ok([0; 32]),
        _ => Err(CustodyError::Role),
    }
}
impl OwnerCustody {
    /// Only a record actually committed by AdmissionLedger can be certified;
    /// this owner exposes no arbitrary-signing or raw-key operation.
    pub fn certify_admission(
        &self,
        admission: &crate::admission::CommittedAdmission,
    ) -> Result<Vec<u8>, CustodyError> {
        self.guard.check()?;
        let Keys::Admission { signer } = &self.keys else {
            return Err(CustodyError::Role);
        };
        crate::authorization::certify(admission, signer).map_err(|_| CustodyError::Held)
    }
    fn assemble(
        guard: Arc<Guard>,
        material: Material,
        store: Option<(CiphertextStore, [u8; 32])>,
    ) -> Result<Self, CustodyError> {
        let role = guard.role;
        let s = &material.seeds;
        let keys = if let Some(role) = role.destination() {
            let (store, store_id) = store.ok_or(CustodyError::Role)?;
            let transport = SecretKey::from_bytes(&s[3]);
            let transport_public = *transport.public().as_bytes();
            Keys::Destination {
                role,
                store_id,
                psk: DestinationKey::from_owner_seed(role, &s[0]),
                response: ResponseKey::from_owner_seed(role, &s[1]),
                receipt: Box::new(ReceiptSigner::from_owner_seed(
                    role, store_id, store, &s[2],
                )?),
                transport: Some(transport),
                transport_public,
            }
        } else {
            if store.is_some() {
                return Err(CustodyError::Role);
            }
            match role {
                OwnerRole::Acu => Keys::Acu {
                    gate: AcuGateKey::from_owner_seed(&s[0]),
                    signer: SecretKey::from_bytes(&s[1]),
                },
                OwnerRole::Admission => Keys::Admission {
                    signer: SecretKey::from_bytes(&s[0]),
                },
                _ => return Err(CustodyError::Role),
            }
        };
        Ok(Self { guard, keys })
    }
    pub fn create_new(
        path: &Path,
        role: OwnerRole,
        owner_context: [u8; 32],
        store: Option<(CiphertextStore, [u8; 32])>,
    ) -> Result<Self, CustodyError> {
        // Persist the actual anchored directory binding. A caller cannot reopen
        // these same keys over another directory by merely repeating store_id.
        let binding = enrolled_store_binding(role, owner_context, store.as_ref())?;
        let (guard, material) = create(path, role, owner_context, binding)?;
        Self::assemble(guard, material, store)
    }
    pub fn open_enrolled(
        path: &Path,
        role: OwnerRole,
        owner_context: [u8; 32],
        store: Option<(CiphertextStore, [u8; 32])>,
        expected: &PublicEnrollment,
    ) -> Result<Self, CustodyError> {
        let binding = enrolled_store_binding(role, owner_context, store.as_ref())?;
        let (guard, material) = open(path, role, owner_context, binding)?;
        let custody = Self::assemble(guard, material, store)?;
        if &custody.public_enrollment()? != expected {
            return Err(CustodyError::Held);
        }
        Ok(custody)
    }
    pub fn public_enrollment(&self) -> Result<PublicEnrollment, CustodyError> {
        self.guard.check()?;
        Ok(match &self.keys {
            Keys::Destination {
                role,
                store_id,
                psk,
                response,
                receipt,
                transport_public,
                ..
            } => PublicEnrollment::Destination(PublicDestination {
                role: *role,
                store_id: *store_id,
                store_binding: self.guard.store_binding,
                psk: psk.public(),
                response_base: response.public(),
                receipt_signer: receipt.public(),
                release_request_signer: receipt.public(),
                transport: *transport_public,
            }),
            Keys::Acu { gate, signer } => PublicEnrollment::Acu {
                gate_base: gate.public(),
                signer: *signer.public().as_bytes(),
            },
            Keys::Admission { signer } => PublicEnrollment::Admission {
                signer: *signer.public().as_bytes(),
            },
        })
    }
    pub async fn bind_destination_pair(
        &mut self,
        peer: EndpointId,
        selected: &str,
        approved: &str,
    ) -> Result<CustodiedPair, CustodyError> {
        self.guard.check()?;
        let Keys::Destination { transport, .. } = &mut self.keys else {
            return Err(CustodyError::Role);
        };
        let key = transport.take().ok_or(CustodyError::AlreadyBound)?;
        let pair = CiPair::bind(key, peer, selected, approved).await?;
        Ok(CustodiedPair {
            pair,
            _guard: self.guard.clone(),
        })
    }
    pub fn persist(&self, envelope: &AuthenticatedEnvelope) -> Result<Vec<u8>, CustodyError> {
        self.guard.check()?;
        let Keys::Destination { receipt, .. } = &self.keys else {
            return Err(CustodyError::Role);
        };
        Ok(receipt.persist(envelope)?)
    }
    pub fn reconcile_existing(
        &self,
        envelope: &AuthenticatedEnvelope,
    ) -> Result<Vec<u8>, CustodyError> {
        self.guard.check()?;
        let Keys::Destination { receipt, .. } = &self.keys else {
            return Err(CustodyError::Role);
        };
        Ok(receipt.reconcile_existing(envelope)?)
    }
    pub fn read_complete_object(
        &self,
        receipt: &VerifiedStorageReceipt,
    ) -> Result<Vec<u8>, CustodyError> {
        self.guard.check()?;
        let Keys::Destination {
            receipt: signer, ..
        } = &self.keys
        else {
            return Err(CustodyError::Role);
        };
        Ok(signer.read_complete_object(receipt)?)
    }
    /// Crypto operation only: caller must first verify current policy and the
    /// signed request and durably consume release replay state.
    pub fn gate_for_authorized_release(
        &self,
        envelope: &AuthenticatedEnvelope,
    ) -> Result<GateSecret, CustodyError> {
        self.guard.check()?;
        let Keys::Acu { gate, .. } = &self.keys else {
            return Err(CustodyError::Role);
        };
        Ok(gate.unwrap_for_authorized_release(envelope)?)
    }
    /// The independently signed ACU response/current policy must be verified by
    /// the application first. HPKE-Base alone authenticates no releasing sender.
    pub fn open_gate_from_authorized_response(
        &self,
        envelope: &AuthenticatedEnvelope,
        request: [u8; 32],
        wrapped: &WrappedSecret,
    ) -> Result<GateSecret, CustodyError> {
        self.guard.check()?;
        let Keys::Destination { response, .. } = &self.keys else {
            return Err(CustodyError::Role);
        };
        Ok(response.open_gate_from_verified_grant(envelope, request, wrapped)?)
    }
    pub fn open_payload_with_gate(
        &self,
        envelope: &AuthenticatedEnvelope,
        gate: &GateSecret,
    ) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
        self.guard.check()?;
        let Keys::Destination { psk, .. } = &self.keys else {
            return Err(CustodyError::Role);
        };
        Ok(psk.open(envelope, gate)?)
    }
}
/// Owner must await close and join its callback children. The file lock remains
/// held even if OwnerCustody is dropped while its endpoint is still owned here.
pub struct CustodiedPair {
    pair: CiPair,
    _guard: Arc<Guard>,
}
impl Deref for CustodiedPair {
    type Target = CiPair;
    fn deref(&self) -> &CiPair {
        &self.pair
    }
}
impl CustodiedPair {
    pub async fn close(self) {
        self.pair.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        envelope::{self, ClaimedProvenance, KeyPins},
        receipt,
        runner_identity::RunnerIdentity,
    };
    use std::os::unix::fs::PermissionsExt;
    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    fn store(dir: &tempfile::TempDir, id: u8) -> Option<(CiphertextStore, [u8; 32])> {
        Some((
            CiphertextStore::open(&dir.path().canonicalize().unwrap()).unwrap(),
            [id; 32],
        ))
    }
    #[test]
    fn final_owner_drop_releases_its_lock_despite_an_inherited_descriptor() {
        let vault = dir();
        let path = vault.path().canonicalize().unwrap();
        let owner = OwnerCustody::create_new(&path, OwnerRole::Admission, [10; 32], None).unwrap();
        let public = owner.public_enrollment().unwrap();
        // Models a transient fork-inherited open-file description, without
        // reading/exporting key bytes or starting a child/service.
        let inherited = rustix::io::dup(&owner.guard.file).unwrap();
        drop(owner);
        let reopened =
            OwnerCustody::open_enrolled(&path, OwnerRole::Admission, [10; 32], None, &public)
                .unwrap();
        drop(reopened);
        drop(inherited);
    }
    #[test]
    fn reopening_the_same_keys_cannot_redirect_the_owner_enrolled_store() {
        let vault = dir();
        let objects = dir();
        let other = dir();
        let path = vault.path().canonicalize().unwrap();
        let owner =
            OwnerCustody::create_new(&path, OwnerRole::Recipient, [10; 32], store(&objects, 21))
                .unwrap();
        let public = owner.public_enrollment().unwrap();
        drop(owner);
        assert!(matches!(
            OwnerCustody::open_enrolled(
                &path,
                OwnerRole::Recipient,
                [10; 32],
                store(&other, 21),
                &public
            ),
            Err(CustodyError::Held)
        ));
        OwnerCustody::open_enrolled(
            &path,
            OwnerRole::Recipient,
            [10; 32],
            store(&objects, 21),
            &public,
        )
        .unwrap();
    }
    #[test]
    fn all_opaque_owner_roles_reopen_with_the_same_public_enrollment_without_rotation() {
        for role in [
            OwnerRole::Recipient,
            OwnerRole::Archive,
            OwnerRole::Acu,
            OwnerRole::Admission,
        ] {
            let vault = dir();
            let objects = dir();
            let path = vault.path().canonicalize().unwrap();
            let destination = || {
                if role.destination().is_some() {
                    store(&objects, 21)
                } else {
                    None
                }
            };
            let owner = OwnerCustody::create_new(&path, role, [10; 32], destination()).unwrap();
            let public = owner.public_enrollment().unwrap();
            assert!(matches!(
                OwnerCustody::open_enrolled(&path, role, [10; 32], destination(), &public),
                Err(CustodyError::Busy)
            ));
            assert!(matches!(
                OwnerCustody::create_new(&path, role, [10; 32], destination()),
                Err(CustodyError::AlreadyExists)
            ));
            drop(owner);
            let reopened =
                OwnerCustody::open_enrolled(&path, role, [10; 32], destination(), &public).unwrap();
            assert!(reopened.public_enrollment().unwrap() == public);
            drop(reopened);
            assert!(matches!(
                OwnerCustody::open_enrolled(&path, role, [11; 32], destination(), &public),
                Err(CustodyError::Held)
            ));
            let unrelated = PublicEnrollment::Admission {
                signer: RunnerIdentity::generate()
                    .unwrap()
                    .public_keys()
                    .signing_ed25519,
            };
            assert!(matches!(
                OwnerCustody::open_enrolled(&path, role, [10; 32], destination(), &unrelated),
                Err(CustodyError::Held)
            ));
        }
    }
    #[test]
    fn missing_partial_symlink_hardlink_and_unsafe_modes_are_refused_without_repair() {
        let vault = dir();
        let path = vault.path().canonicalize().unwrap();
        let owner = OwnerCustody::create_new(&path, OwnerRole::Acu, [10; 32], None).unwrap();
        let public = owner.public_enrollment().unwrap();
        let file = path.join(OwnerRole::Acu.name());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(owner.public_enrollment(), Err(CustodyError::Held)));
        drop(owner);
        assert!(matches!(
            OwnerCustody::open_enrolled(&path, OwnerRole::Acu, [10; 32], None, &public),
            Err(CustodyError::Held)
        ));
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = path.join("owned-hardlink-fixture");
        std::fs::hard_link(&file, &link).unwrap();
        assert!(matches!(
            OwnerCustody::open_enrolled(&path, OwnerRole::Acu, [10; 32], None, &public),
            Err(CustodyError::Held)
        ));
        std::fs::remove_file(&link).unwrap();
        let moved = path.join("owned-original-fixture");
        std::fs::rename(&file, &moved).unwrap();
        assert!(matches!(
            OwnerCustody::open_enrolled(&path, OwnerRole::Acu, [10; 32], None, &public),
            Err(CustodyError::Held)
        ));
        std::os::unix::fs::symlink(&moved, &file).unwrap();
        assert!(matches!(
            OwnerCustody::open_enrolled(&path, OwnerRole::Acu, [10; 32], None, &public),
            Err(CustodyError::Held)
        ));
        std::fs::remove_file(&file).unwrap();
        // A newly malformed fixture is not read as private seed material.
        let mut partial = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file)
            .unwrap();
        partial.write_all(b"incomplete public fixture").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            OwnerCustody::open_enrolled(&path, OwnerRole::Acu, [10; 32], None, &public),
            Err(CustodyError::Held)
        ));
    }
    #[test]
    fn ciphertext_and_customer_keys_remain_recoverable_after_owner_drop_and_reopen() {
        let vr = dir();
        let va = dir();
        let vg = dir();
        let sr = dir();
        let sa = dir();
        let pr = vr.path().canonicalize().unwrap();
        let pa = va.path().canonicalize().unwrap();
        let pg = vg.path().canonicalize().unwrap();
        let root =
            OwnerCustody::create_new(&pr, OwnerRole::Recipient, [10; 32], store(&sr, 21)).unwrap();
        let archive =
            OwnerCustody::create_new(&pa, OwnerRole::Archive, [11; 32], store(&sa, 22)).unwrap();
        let acu = OwnerCustody::create_new(&pg, OwnerRole::Acu, [12; 32], None).unwrap();
        let er = root.public_enrollment().unwrap();
        let ea = archive.public_enrollment().unwrap();
        let eg = acu.public_enrollment().unwrap();
        let PublicEnrollment::Destination(r) = &er else {
            panic!("recipient enrollment")
        };
        let PublicEnrollment::Destination(a) = &ea else {
            panic!("archive enrollment")
        };
        let PublicEnrollment::Acu { gate_base, signer } = &eg else {
            panic!("ACU enrollment")
        };
        let keys = KeyPins {
            acu_gate_base: *gate_base,
            recipient_psk: r.psk,
            archive_psk: a.psk,
            recipient_response_base: r.response_base,
            archive_response_base: a.response_base,
            acu_signer: *signer,
            recipient_receipt_signer: r.receipt_signer,
            archive_receipt_signer: a.receipt_signer,
        };
        let claims = ClaimedProvenance {
            admission_sha256: [1; 32],
            repository: "example/ci-test".into(),
            repository_id: 42,
            source_commit: [2; 20],
            workflow_ref: "example/ci-test/.github/workflows/ci.yml@refs/heads/test".into(),
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
        let runner = RunnerIdentity::generate().unwrap();
        let payload = vec![0x59; 30000];
        let sealed = runner
            .seal_failure(claims.clone(), keys.clone(), &payload)
            .unwrap();
        let env = envelope::authenticate(
            &sealed.manifest,
            &sealed.ciphertext,
            &claims,
            &keys,
            &runner.public_keys().signing_ed25519,
        )
        .unwrap();
        let rr = receipt::verify(
            &root.persist(&env).unwrap(),
            &env,
            Destination::Recipient,
            [21; 32],
        )
        .unwrap();
        let ra = receipt::verify(
            &archive.persist(&env).unwrap(),
            &env,
            Destination::Archive,
            [22; 32],
        )
        .unwrap();
        drop(root);
        drop(archive);
        drop(acu);
        let root =
            OwnerCustody::open_enrolled(&pr, OwnerRole::Recipient, [10; 32], store(&sr, 21), &er)
                .unwrap();
        let archive =
            OwnerCustody::open_enrolled(&pa, OwnerRole::Archive, [11; 32], store(&sa, 22), &ea)
                .unwrap();
        let acu = OwnerCustody::open_enrolled(&pg, OwnerRole::Acu, [12; 32], None, &eg).unwrap();
        for (owner, role, receipt, nonce) in [
            (&root, Destination::Recipient, &rr, [21; 32]),
            (&archive, Destination::Archive, &ra, [22; 32]),
        ] {
            let bytes = owner.read_complete_object(receipt).unwrap();
            let stored = envelope::parse_storage_blob(&bytes).unwrap();
            let env = envelope::authenticate(
                &stored.manifest,
                &stored.ciphertext,
                &claims,
                &keys,
                &runner.public_keys().signing_ed25519,
            )
            .unwrap();
            // This fixture tests custody+crypto recovery; it does not stand in
            // for the later signed-current-policy/replay grant protocol.
            let gate = acu.gate_for_authorized_release(&env).unwrap();
            let encrypted = gate.wrap_response(&env, role, nonce).unwrap();
            let recovered = owner
                .open_gate_from_authorized_response(&env, nonce, &encrypted)
                .unwrap();
            assert_eq!(
                &*owner.open_payload_with_gate(&env, &recovered).unwrap(),
                &payload
            );
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn a_darwin_read_acl_is_refused_even_with_mode_0600() {
        let vault = dir();
        let path = vault.path().canonicalize().unwrap();
        let owner = OwnerCustody::create_new(&path, OwnerRole::Admission, [10; 32], None).unwrap();
        let file = path.join(OwnerRole::Admission.name());
        let result = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&file)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(matches!(owner.public_enrollment(), Err(CustodyError::Held)));
    }
}
