//! Human-controlled Codex work and exact active-turn steering.
//!
//! The legacy controller accepts already initialized exclusively delegated IO.
//! The explicit human-work port initializes one declared owner Unix connection
//! and starts one fresh task only after consumed human intent. No process is
//! spawned, no GUI session is adopted, and no generic RPC interface is exposed.
mod admission;

mod connection;
mod controller;
mod journal;
mod record;
pub(crate) mod unix_wire;
mod wire;
pub(crate) mod work_bootstrap;

pub use connection::{
    CodexSteerConnection, ConnectionOwner, HumanSteerGrant, ObservedActiveTurn, OwnerControlScope,
    PreparedSteer,
};
pub use controller::SteerController;
pub use record::{Evidence, MAX_OPERATIONS, MAX_TEXT_BYTES, Receipt, SavedSteer, SteerError};

pub type Result<T> = std::result::Result<T, SteerError>;

mod work;
mod work_api;
mod work_journal;
mod work_socket;
pub use work::open_work_service;
pub use work_api::{
    HumanWorkPort, PreparedWorkSteer, RuntimePolicyDeclaration, WorkActionKind, WorkConfig,
    WorkPhase, WorkSnapshot, WorkStartReceipt, WorkSubmission,
};
