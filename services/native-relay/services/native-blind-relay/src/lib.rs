//! The protocol core is native-testable. Cloudflare bindings compile only for WASM.
pub mod protocol;
pub mod session;

#[cfg(target_arch = "wasm32")]
mod runtime;
