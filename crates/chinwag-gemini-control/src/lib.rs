//! One explicit configured-runtime Gemini ACP owner; no existing-session adoption or implicit approval.
mod admission;
mod api;
mod binary;
mod journal;
mod service;
mod wire;
pub use api::*;
pub use service::open_work_service;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
