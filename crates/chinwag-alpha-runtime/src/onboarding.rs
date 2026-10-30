//! Human-triggered exact native opening. The cache is host-local observation;
//! the durable request journal prevents retries, not connector admission.

use chinwag_bus_client::OnboardingStatus;
use chinwag_client_discovery::{Installation, InventorySnapshot};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OnboardingError {
    #[error("native opening request or observation is invalid")]
    Invalid,
    #[error("request identifier is already bound to a different installation")]
    Conflict,
    #[error("another native opening is active; this request has not started")]
    Busy,
    #[error("native opening is unavailable")]
    Unavailable,
    #[error("native opening journal is unavailable; no automatic retry is permitted")]
    Storage,
}

pub fn disabled_status() -> OnboardingStatus {
    OnboardingStatus {
        schema: "chinwag-native-onboarding/v1".into(),
        native_open_allowed: false,
        openable_installation_ids: Vec::new(),
    }
}

/// Byte-identical to the public discovery projection, including host/boot scope.
pub(crate) fn observed_installation_id(
    process: &InventorySnapshot,
    installation: &Installation,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"chinwag-installed-observation/v1\0");
    for field in [
        process.host.label.as_bytes(),
        process.host.boot_uuid.as_bytes(),
        installation.id.as_bytes(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    format!("{:x}", hash.finalize())
}

mod native;
pub use native::OnboardingService;
