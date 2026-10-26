//! Process-local write lease. Not a coordinator reservation and not a socket probe.

use std::{path::Path, time::Instant};

use super::ClaimService;
use crate::room::now_unix;

/// Fixed categories only. Display and Debug carry no session, path, actor, or receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LeaseError {
    #[error("write lease unavailable")]
    Unavailable,
    #[error("write lease expired")]
    Expired,
    #[error("write path is outside the active lease")]
    Path,
    #[error("write session is not the observed attach")]
    Session,
}

pub(super) struct ActiveLease {
    actor: [u8; 32],
    session: String,
    issued: u64,
    expiry: u64,
    mono_deadline: Instant,
}

impl ActiveLease {
    pub(super) fn new(
        actor: [u8; 32],
        session: String,
        issued: u64,
        expiry: u64,
        mono_deadline: Instant,
    ) -> Self {
        Self {
            actor,
            session,
            issued,
            expiry,
            mono_deadline,
        }
    }
}

/// Borrow of the owning service. No public constructor, clone, or serializer.
pub struct WriteWitness<'a> {
    service: &'a ClaimService,
}

impl<'a> WriteWitness<'a> {
    pub(super) fn from_service(service: &'a ClaimService) -> Self {
        Self { service }
    }

    /// Exact `CLAIM_FILE` path, this process's lease, actor, observed attach, and both clocks.
    pub fn validate(&self, path: &Path) -> Result<(), LeaseError> {
        let wall = now_unix().map_err(|_| LeaseError::Unavailable)?;
        self.validate_at(path, wall, Instant::now())
    }

    pub(super) fn validate_at(
        &self,
        path: &Path,
        wall: u64,
        now: Instant,
    ) -> Result<(), LeaseError> {
        if self.service.closed {
            return Err(LeaseError::Unavailable);
        }
        let Some(lease) = &self.service.lease else {
            return Err(LeaseError::Unavailable);
        };
        if path.as_os_str() != super::CLAIM_FILE {
            return Err(LeaseError::Path);
        }
        if lease.actor != self.service.identity.ssh_public_bytes() {
            return Err(LeaseError::Unavailable);
        }
        let attached = self.service.current_session()?;
        if attached != lease.session {
            return Err(LeaseError::Session);
        }
        if wall < lease.issued || wall >= lease.expiry || now >= lease.mono_deadline {
            return Err(LeaseError::Expired);
        }
        Ok(())
    }
}
