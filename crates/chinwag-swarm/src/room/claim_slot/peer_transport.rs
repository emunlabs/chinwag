//! Explicit operator access to the existing live session's pinned data plane.
//! No room startup, claim submission, lease reconstruction, or recovery occurs.

use super::{AttemptPhase, ClaimService, StoredOutcome};
use crate::transport::DataPlane;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerError {
    #[error("peer transport service is closed")]
    Closed,
    #[error("peer transport requires this process's verified live session")]
    Unavailable,
    #[error("peer transport journal validation failed")]
    Journal,
    #[error("peer transport has no fresh authenticated peer record")]
    PeerRecord,
    #[error("peer transport startup failed; do not restart it")]
    Transport,
}

impl ClaimService {
    fn peer_preflight(&self) -> Result<(), PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        let attempt = self
            .journal
            .load()
            .map_err(|_| PeerError::Journal)?
            .ok_or(PeerError::Unavailable)?;
        if attempt.phase() != AttemptPhase::Verified {
            return Err(PeerError::Unavailable);
        }
        if !matches!(
            self.journal
                .stored_outcome(&attempt)
                .map_err(|_| PeerError::Journal)?,
            Some(StoredOutcome::Verified { .. })
        ) {
            return Err(PeerError::Unavailable);
        }
        let room = self.room.as_ref().ok_or(PeerError::Unavailable)?;
        let session = room
            .attached_session_id()
            .map_err(|_| PeerError::PeerRecord)?;
        let endpoint = self.endpoint.as_ref().ok_or(PeerError::Unavailable)?;
        if session != attempt.prepared().signed().request.session
            || room.other != self.peer
            || endpoint.id() != self.identity.endpoint_id()
            || self.peer == endpoint.id()
        {
            return Err(PeerError::Unavailable);
        }
        Ok(())
    }

    /// Prepare only the already attached session. A stored verified report
    /// without that live room refuses. The one initial peer read and router
    /// start are sticky on error or cancellation; neither is retried here.
    /// Starting the router replaces the endpoint's ALPN list with gossip and
    /// blobs. Existing claim-only modes never call this operator method.
    pub async fn prepare_peer_transport(&mut self) -> Result<(), PeerError> {
        self.peer_preflight()?;
        let room = self.room.as_mut().ok_or(PeerError::Unavailable)?;
        if room.peer_expiry.is_some() {
            // An expired record is not permission to refresh it.
            self.peer_recv_once = true;
        } else if !self.peer_recv_once {
            self.peer_recv_once = true;
            room.receive_peer()
                .await
                .map_err(|_| PeerError::PeerRecord)?;
        }
        room.require_fresh_peer()
            .map_err(|_| PeerError::PeerRecord)?;
        if !self.peer_start_once {
            self.peer_start_once = true;
            let endpoint = self.endpoint.as_ref().ok_or(PeerError::Unavailable)?;
            self.peer_plane = Some(
                DataPlane::start(endpoint.clone(), self.peer).map_err(|_| PeerError::Transport)?,
            );
        }
        if self.peer_plane.is_none() {
            return Err(PeerError::Transport);
        }
        self.peer_plane()?;
        Ok(())
    }

    /// Passive cache data only; no journal validation, freshness or authority.
    pub fn cached_peer_ips(&self) -> Option<crate::transport::BoundedIps> {
        self.room.as_ref().and_then(|room| room.cached_peer_ips())
    }

    /// Point-in-time access, not a durable freshness or write permit. The
    /// operator must retain the service mutex and recheck before each later
    /// network stage. The caller must not shut down this borrowed data plane.
    pub fn peer_plane(&self) -> Result<&DataPlane, PeerError> {
        self.peer_preflight()?;
        self.room
            .as_ref()
            .ok_or(PeerError::Unavailable)?
            .require_fresh_peer()
            .map_err(|_| PeerError::PeerRecord)?;
        self.peer_plane.as_ref().ok_or(PeerError::Unavailable)
    }
}
