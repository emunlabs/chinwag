//! Pure VS Code MCP install URI; no settings read, discovery or execution.

use crate::mcp_config::{self, ConfigError, SERVER_NAME};
use std::path::PathBuf;

const INSTALL_URL: &str = "vscode:mcp/install?";

/// Opaque, fixed-scope configuration for VS Code's human installation prompt.
/// The host owns binary validation, exact application selection and consent.
/// OS opening acknowledgement proves no client approval or MCP connection.
///
/// ```compile_fail
/// use chinwag_native_launch::VsCodeMcpInstall;
/// fn extract(spec: VsCodeMcpInstall) { let _uri = spec.install_uri; }
/// ```
///
/// ```compile_fail
/// use chinwag_native_launch::VsCodeMcpInstall;
/// let _spec = serde_json::from_str::<VsCodeMcpInstall>("{}");
/// ```
pub struct VsCodeMcpInstall {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    install_uri: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum VsCodeMcpInstallError {
    #[error("VS Code MCP binary must be a bounded normalized absolute path without interpolation")]
    InvalidBinary,
    #[error("VS Code MCP endpoint must be a bounded HTTP loopback origin without credentials")]
    InvalidEndpoint,
    #[error("could not encode the fixed VS Code MCP setup configuration")]
    InvalidConfiguration,
}

impl VsCodeMcpInstall {
    pub fn new(binary: PathBuf, endpoint: String) -> Result<Self, VsCodeMcpInstallError> {
        let mut config =
            mcp_config::stdio_config(&binary, &endpoint).map_err(|error| match error {
                ConfigError::InvalidBinary => VsCodeMcpInstallError::InvalidBinary,
                ConfigError::InvalidEndpoint => VsCodeMcpInstallError::InvalidEndpoint,
            })?;
        config
            .as_object_mut()
            .ok_or(VsCodeMcpInstallError::InvalidConfiguration)?
            .insert("name".into(), SERVER_NAME.into());
        let bytes =
            serde_json::to_vec(&config).map_err(|_| VsCodeMcpInstallError::InvalidConfiguration)?;
        // VS Code documents encodeURIComponent(JSON.stringify(config)), with
        // the whole JSON as the query. This is neither form data nor Base64.
        let mut install_uri = String::with_capacity(INSTALL_URL.len() + bytes.len() * 3);
        install_uri.push_str(INSTALL_URL);
        for byte in bytes {
            if byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
                )
            {
                install_uri.push(char::from(byte));
            } else {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                install_uri.push('%');
                install_uri.push(char::from(HEX[usize::from(byte >> 4)]));
                install_uri.push(char::from(HEX[usize::from(byte & 15)]));
            }
        }
        Ok(Self { install_uri })
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn install_uri(&self) -> &str {
        &self.install_uri
    }
}

#[cfg(test)]
mod tests;
