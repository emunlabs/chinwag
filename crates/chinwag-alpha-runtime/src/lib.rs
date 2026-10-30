use chinwag_bus_client::{SendReceipt, SendRequest};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

pub mod connector_export;
pub mod discovery;
pub mod launcher;
mod mcp_binary;
pub mod onboarding;
pub mod server;
pub mod signed;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Rejected(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("storage outcome uncertain; validate the ledger and restart before publishing: {0}")]
    StorageUncertain(String),
    #[error("send outcome uncertain; do not resend automatically: {0}")]
    SendUncertain(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, RuntimeError>;

/// Only explicit human UI sends may call this boundary. No background sender.
pub trait SignedSender: Send + Sync {
    fn send(&self, request: &SendRequest) -> Result<SendReceipt>;
}

#[derive(Clone)]
pub enum RuntimeMode {
    Isolated {
        data_dir: PathBuf,
    },
    Shared {
        ledger: PathBuf,
        signed_sender: Option<Arc<dyn SignedSender>>,
        journal_dir: Option<PathBuf>,
    },
}
#[derive(Clone)]
pub struct RuntimeConfig {
    pub bind: SocketAddr,
    pub mode: RuntimeMode,
}
