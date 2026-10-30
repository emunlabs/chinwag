//! Fixed human steering for one explicitly delegated Codex app-server stream.
//!
//! The host must already own and initialize the exclusively delegated IO and
//! explicitly authorize its one thread. This crate starts no process or turn,
//! adopts no editor session and provides no generic RPC, network or model API.

mod connection;
mod controller;
mod journal;
mod record;
mod wire;

pub use connection::{
    CodexSteerConnection, ConnectionOwner, HumanSteerGrant, ObservedActiveTurn, OwnerControlScope,
    PreparedSteer,
};
pub use controller::SteerController;
pub use record::{Evidence, MAX_OPERATIONS, MAX_TEXT_BYTES, Receipt, SavedSteer, SteerError};

pub type Result<T> = std::result::Result<T, SteerError>;
