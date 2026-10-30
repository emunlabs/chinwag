//! Shared pure validation for owner-declared, fixed-scope MCP setup payloads.

use std::{net::IpAddr, path::Path};
use url::Url;

pub(super) const SERVER_NAME: &str = "chinwag-native-inbox-mgmt";
pub(super) const MAX_COMMAND_BYTES: usize = 4096;
pub(super) const MAX_ENDPOINT_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConfigError {
    InvalidBinary,
    InvalidEndpoint,
}

pub(super) fn stdio_config(
    binary: &Path,
    endpoint: &str,
) -> Result<serde_json::Value, ConfigError> {
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
        .ok_or(ConfigError::InvalidBinary)?;
    let normalized: std::path::PathBuf = binary.components().collect();
    if !crate::canonical_absolute(binary)
        || binary.file_name().is_none()
        || normalized.as_os_str() != binary.as_os_str()
    {
        return Err(ConfigError::InvalidBinary);
    }
    let endpoint = loopback_origin(endpoint)?;
    Ok(serde_json::json!({
        "type": "stdio",
        "command": command,
        "args": ["--bus-url", endpoint.as_str(), "--allow-room", "#mgmt", "--lease-seconds", "900"]
    }))
}

fn loopback_origin(endpoint: &str) -> Result<Url, ConfigError> {
    let invalid = || ConfigError::InvalidEndpoint;
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
