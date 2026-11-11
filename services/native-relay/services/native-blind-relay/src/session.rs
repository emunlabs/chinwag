//! All bounds survive Durable Object hibernation through socket attachments.
use crate::protocol::{EndpointId, Failure};
use serde::{Deserialize, Serialize};

pub const AUTH_TIMEOUT_MS: u64 = 5_000;
pub const SESSION_LIFETIME_MS: u64 = 30 * 60 * 1_000;
pub const PING_INTERVAL_MS: u64 = 15_000;
pub const PONG_TIMEOUT_MS: u64 = 10_000;
pub const MAX_CONNECTIONS: usize = 6;
pub const MAX_PENDING: usize = 4;
pub const MAX_ADMISSIONS_PER_MINUTE: u32 = 30;
pub const MAX_FRAMES_PER_SECOND: u32 = 256;
pub const MAX_BYTES_PER_SECOND: u64 = 1024 * 1024;
pub const MAX_SESSION_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub version: u8,
    pub opened_ms: u64,
    pub challenge: Option<[u8; 16]>,
    pub endpoint: Option<EndpointId>,
    pub expires_ms: u64,
    pub window_ms: u64,
    pub window_frames: u32,
    pub window_bytes: u64,
    pub total_bytes: u64,
    pub last_ping_ms: u64,
    pub pending_ping: Option<[u8; 8]>,
    pub pong_deadline_ms: u64,
    pub closed: bool,
}

impl Session {
    pub fn pending(challenge: [u8; 16], now: u64) -> Self {
        Self {
            version: 1,
            opened_ms: now,
            challenge: Some(challenge),
            endpoint: None,
            expires_ms: now.saturating_add(AUTH_TIMEOUT_MS),
            window_ms: now,
            window_frames: 0,
            window_bytes: 0,
            total_bytes: 0,
            last_ping_ms: now,
            pending_ping: None,
            pong_deadline_ms: 0,
            closed: false,
        }
    }

    pub fn check_live(&self, now: u64) -> Result<(), Failure> {
        if self.closed || self.version != 1 || now < self.opened_ms || now < self.window_ms {
            return Err(Failure::State);
        }
        if now >= self.expires_ms || (self.pending_ping.is_some() && now >= self.pong_deadline_ms) {
            return Err(Failure::Expired);
        }
        match (self.challenge.is_some(), self.endpoint.is_some()) {
            (true, false) | (false, true) => Ok(()),
            _ => Err(Failure::State),
        }
    }

    /// Consume the one-time challenge before authentication confirmation is sent.
    pub fn authenticate(&mut self, endpoint: EndpointId, now: u64) -> Result<(), Failure> {
        self.check_live(now)?;
        if self.challenge.take().is_none() || self.endpoint.is_some() {
            return Err(Failure::State);
        }
        self.endpoint = Some(endpoint);
        self.expires_ms = now.saturating_add(SESSION_LIFETIME_MS);
        Ok(())
    }

    pub fn charge(&mut self, bytes: usize, now: u64) -> Result<(), Failure> {
        self.check_live(now)?;
        if self.endpoint.is_none() {
            return Err(Failure::Unauthorized);
        }
        if now - self.window_ms >= 1_000 {
            self.window_ms = now;
            self.window_bytes = 0;
            self.window_frames = 0;
        }
        let bytes = u64::try_from(bytes).map_err(|_| Failure::Budget)?;
        let next_bytes = self
            .window_bytes
            .checked_add(bytes)
            .ok_or(Failure::Budget)?;
        let next_total = self.total_bytes.checked_add(bytes).ok_or(Failure::Budget)?;
        if self.window_frames >= MAX_FRAMES_PER_SECOND
            || next_bytes > MAX_BYTES_PER_SECOND
            || next_total > MAX_SESSION_BYTES
        {
            return Err(Failure::Budget);
        }
        self.window_frames += 1;
        self.window_bytes = next_bytes;
        self.total_bytes = next_total;
        Ok(())
    }

    pub fn pong(&mut self, data: [u8; 8]) -> Result<(), Failure> {
        if self.pending_ping != Some(data) {
            return Err(Failure::Malformed);
        }
        self.pending_ping = None;
        self.pong_deadline_ms = 0;
        Ok(())
    }

    pub fn next_deadline(&self) -> u64 {
        let mut next = self.expires_ms;
        if self.endpoint.is_some() {
            next = next.min(if self.pending_ping.is_some() {
                self.pong_deadline_ms
            } else {
                self.last_ping_ms.saturating_add(PING_INTERVAL_MS)
            });
        }
        next
    }
}
