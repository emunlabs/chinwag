//! Pure owner-declared Cursor setup payload. This never reads client settings,
//! discovers a binary, resolves DNS, or executes the supplied command.

use crate::mcp_config::{self, ConfigError, SERVER_NAME};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::path::PathBuf;
use url::Url;

const INSTALL_URL: &str = "cursor://anysphere.cursor-deeplink/mcp/install";

/// Opaque configuration for Cursor's human-approved MCP installation prompt.
/// It supplies only the fixed read-only native inbox command and arguments.
/// Binary ownership, type, mode and replacement checks belong to the host.
/// No filesystem or network operation occurs during construction.
///
/// The generated URL deliberately has no public accessor or deserializer.
///
/// ```compile_fail
/// use chinwag_native_launch::CursorMcpInstall;
/// fn extract(spec: CursorMcpInstall) { let _uri = spec.install_uri; }
/// ```
///
/// ```compile_fail
/// use chinwag_native_launch::CursorMcpInstall;
/// let _spec = serde_json::from_str::<CursorMcpInstall>("{}");
/// ```
pub struct CursorMcpInstall {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    install_uri: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CursorMcpInstallError {
    #[error("Cursor MCP binary must be a bounded normalized absolute path without interpolation")]
    InvalidBinary,
    #[error("Cursor MCP endpoint must be a bounded HTTP loopback origin without credentials")]
    InvalidEndpoint,
    #[error("could not encode the fixed Cursor MCP setup configuration")]
    InvalidConfiguration,
}

impl CursorMcpInstall {
    pub fn new(binary: PathBuf, endpoint: String) -> Result<Self, CursorMcpInstallError> {
        let config = mcp_config::stdio_config(&binary, &endpoint).map_err(|error| match error {
            ConfigError::InvalidBinary => CursorMcpInstallError::InvalidBinary,
            ConfigError::InvalidEndpoint => CursorMcpInstallError::InvalidEndpoint,
        })?;
        // Cursor's install-link config is the inner server value; the server
        // name is a separate query field. There is no mcpServers/name wrapper.
        let json =
            serde_json::to_vec(&config).map_err(|_| CursorMcpInstallError::InvalidConfiguration)?;
        let encoded = STANDARD.encode(json);
        let mut install =
            Url::parse(INSTALL_URL).map_err(|_| CursorMcpInstallError::InvalidConfiguration)?;
        install
            .query_pairs_mut()
            .append_pair("name", SERVER_NAME)
            .append_pair("config", &encoded);
        Ok(Self {
            install_uri: install.into(),
        })
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn install_uri(&self) -> &str {
        &self.install_uri
    }
}

#[cfg(test)]
mod tests;
