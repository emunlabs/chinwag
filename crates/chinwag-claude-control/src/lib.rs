//! One explicit human-owned Claude stream-json session. No GUI/session adoption,
//! provider repair, generic RPC, automatic replay or OS termination is provided.
mod admission;
mod api;
mod binary;
mod journal;
mod service;
mod wire;
pub use api::*;
pub use service::open_work_service;
#[cfg(feature = "test-support")]
pub mod test_support;
