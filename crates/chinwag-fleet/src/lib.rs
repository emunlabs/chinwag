// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Topology-independent fleet policy, explicit dispatch and leased isolation.
//!
//! A manifest is policy, never a roster compiled into the dispatch mechanism.
//! Resolution checks every gate before executing an authentication preflight or
//! a child process. Unsupported target/driver implementations fail closed.
#![forbid(unsafe_code)]

pub mod driver;
pub mod isolation;
pub mod keys;
pub mod manifest;
pub mod skills;
pub mod topology;

pub use driver::*;
pub use isolation::*;
pub use keys::*;
pub use manifest::*;
pub use skills::*;
pub use topology::*;

/// Errors are stable policy categories suitable for machine-readable diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum FleetPolicyError {
    #[error("UnknownSeat: {0}")]
    UnknownSeat(String),
    #[error("UnknownTaskProfile: {0}")]
    UnknownTaskProfile(String),
    #[error("RetiredOrPausedSeat: {0}")]
    RetiredOrPausedSeat(String),
    #[error("ProviderDenied: {0}")]
    ProviderDenied(String),
    #[error("EgressViolation: {0}")]
    EgressViolation(String),
    #[error("RoomAclDenied: {0}")]
    RoomAclDenied(String),
    #[error("TargetNodeUnavailable: {0}")]
    TargetNodeUnavailable(String),
    #[error("DriverBinaryMissing: {0}")]
    DriverBinaryMissing(String),
    #[error("BareSeatAddressRejected: {0}")]
    BareSeatAddressRejected(String),
    #[error("KeyBijectionFailed: {0}")]
    KeyBijectionFailed(String),
    #[error("ForbiddenSkill: {0}")]
    ForbiddenSkill(String),
    #[error("MissingSkill: {0}")]
    MissingSkill(String),
    #[error("RepoHoldActive: {0}")]
    RepoHoldActive(String),
    #[error("OverlappingClaim: {0}")]
    OverlappingClaim(String),
    #[error("WriteScopeDenied: {0}")]
    WriteScopeDenied(String),
    #[error("InvalidManifest: {0}")]
    InvalidManifest(String),
    #[error("UnsupportedDriver: {0}")]
    UnsupportedDriver(String),
    #[error("DriverExecutionFailed: {0}")]
    DriverExecutionFailed(String),
    #[error("IsolationFailed: {0}")]
    IsolationFailed(String),
    #[error("Io: {0}")]
    Io(#[from] std::io::Error),
}

pub type FleetResult<T> = Result<T, FleetPolicyError>;
