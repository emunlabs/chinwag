//! Pure owner-declared Cursor setup payload. This never reads client settings,
//! discovers a binary, resolves DNS, or executes the supplied command.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{net::IpAddr, path::PathBuf};
use url::Url;

const SERVER_NAME: &str = "chinwag-native-inbox-mgmt";
const INSTALL_URL: &str = "cursor://anysphere.cursor-deeplink/mcp/install";
const MAX_COMMAND_BYTES: usize = 4096;
const MAX_ENDPOINT_BYTES: usize = 256;

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
        let command = binary
            .to_str()
            .filter(|text| {
                !text.is_empty()
                    && text.len() <= MAX_COMMAND_BYTES
                    && text.trim() == *text
                    && !text
                        .chars()
                        .any(|c| c.is_control() || matches!(c, '$' | '`'))
            })
            .ok_or(CursorMcpInstallError::InvalidBinary)?;
        let normalized: PathBuf = binary.components().collect();
        if !crate::canonical_absolute(&binary)
            || binary.file_name().is_none()
            || normalized.as_os_str() != binary.as_os_str()
        {
            return Err(CursorMcpInstallError::InvalidBinary);
        }
        let endpoint = loopback_origin(&endpoint)?;
        // Cursor's install-link config is the inner server value; the server
        // name is a separate query field. There is no mcpServers/name wrapper.
        let config = serde_json::json!({
            "type": "stdio",
            "command": command,
            "args": ["--bus-url", endpoint.as_str(), "--allow-room", "#mgmt", "--lease-seconds", "900"]
        });
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

fn loopback_origin(endpoint: &str) -> Result<Url, CursorMcpInstallError> {
    let invalid = || CursorMcpInstallError::InvalidEndpoint;
    if endpoint.is_empty()
        || endpoint.len() > MAX_ENDPOINT_BYTES
        || endpoint.trim() != endpoint
        || endpoint
            .chars()
            .any(|c| c.is_control() || matches!(c, '$' | '`' | '\\'))
    {
        return Err(invalid());
    }
    let after_scheme = endpoint.strip_prefix("http://").ok_or_else(invalid)?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .ok_or_else(invalid)?;
    if !matches!(&after_scheme[authority.len()..], "" | "/") {
        return Err(invalid());
    }
    let mut url = Url::parse(endpoint).map_err(|_| invalid())?;
    if url.scheme() != "http"
        || authority.contains('@')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() == Some(0)
    {
        return Err(invalid());
    }
    match url.host_str() {
        Some("localhost") => url.set_host(Some("127.0.0.1")).map_err(|_| invalid())?,
        Some(host) => {
            if !host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
            {
                return Err(invalid());
            }
        }
        None => return Err(invalid()),
    }
    Ok(url)
}

#[cfg(test)]
mod tests;
