//! Shared pure validation for owner-declared, fixed-scope MCP setup payloads.

use std::{net::IpAddr, path::Path};
use url::Url;

pub(super) const SERVER_NAME: &str = "chinwag-native-inbox-mgmt";
pub(super) const MAX_COMMAND_BYTES: usize = 4096;
pub(super) const MAX_ENDPOINT_BYTES: usize = 256;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum FixedMcpConfigError {
    #[error("MCP binary must be a bounded normalized absolute path without interpolation")]
    InvalidBinary,
    #[error("MCP endpoint must be a bounded HTTP loopback origin without credentials")]
    InvalidEndpoint,
}

pub(super) use FixedMcpConfigError as ConfigError;

/// Validated owner-declared read-only inbox configuration. Construction performs
/// no I/O and does not establish binary ownership or a connector grant. Arguments
/// are fixed to the native #mgmt inbox with a 900-second process admission lease.
/// Vendor packaging may generate its own documented command substitution; this
/// configuration never accepts interpolation or an arbitrary command override.
///
/// ```compile_fail
/// use chinwag_native_launch::FixedMcpConfig;
/// let _config = serde_json::from_str::<FixedMcpConfig>("{}");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedMcpConfig {
    command: String,
    endpoint: String,
    args: [String; 6],
}

impl FixedMcpConfig {
    pub fn new(binary: &Path, endpoint: &str) -> Result<Self, FixedMcpConfigError> {
        let command = validated_command(binary)?;
        let endpoint = loopback_origin(endpoint)?.to_string();
        let args = [
            "--bus-url".into(),
            endpoint.clone(),
            "--allow-room".into(),
            "#mgmt".into(),
            "--lease-seconds".into(),
            "900".into(),
        ];
        Ok(Self {
            command,
            endpoint,
            args,
        })
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn server_name(&self) -> &'static str {
        SERVER_NAME
    }
}

fn validated_command(binary: &Path) -> Result<String, ConfigError> {
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
    Ok(command.into())
}

pub(super) fn stdio_config(
    binary: &Path,
    endpoint: &str,
) -> Result<serde_json::Value, ConfigError> {
    let config = FixedMcpConfig::new(binary, endpoint)?;
    Ok(serde_json::json!({
        "type": "stdio",
        "command": config.command(),
        "args": config.args()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_config_preserves_fixed_wire_and_normalizes_only_loopback_origin() {
        let binary = Path::new("/owned/server/chinwag-bus-mcp");
        let config = FixedMcpConfig::new(binary, "http://localhost:44346").unwrap();
        assert_eq!(config.command(), "/owned/server/chinwag-bus-mcp");
        assert_eq!(config.endpoint(), "http://127.0.0.1:44346/");
        assert_eq!(config.server_name(), "chinwag-native-inbox-mgmt");
        assert_eq!(
            config.args(),
            [
                "--bus-url",
                "http://127.0.0.1:44346/",
                "--allow-room",
                "#mgmt",
                "--lease-seconds",
                "900"
            ]
        );
        assert_eq!(
            stdio_config(binary, "http://localhost:44346").unwrap(),
            serde_json::json!({
                "type": "stdio", "command": config.command(), "args": config.args()
            })
        );
    }

    #[test]
    fn typed_config_rejects_vendor_substitution_and_nonfixed_routes() {
        for command in [
            "${__dirname}/server/chinwag-bus-mcp",
            "/owned/../server",
            "/owned//server",
            "/owned/server/",
            "/owned/`server`",
            "relative/server",
        ] {
            assert_eq!(
                FixedMcpConfig::new(Path::new(command), "http://127.0.0.1:44346").unwrap_err(),
                FixedMcpConfigError::InvalidBinary
            );
        }
        for endpoint in [
            "https://127.0.0.1:44346",
            "http://127.0.0.1:44346/api",
            "http://user@127.0.0.1:44346",
            "http://127.0.0.1:44346/?x=1",
            "http://192.0.2.1:44346",
            "http://127.0.0.1:0",
        ] {
            assert_eq!(
                FixedMcpConfig::new(Path::new("/owned/server"), endpoint).unwrap_err(),
                FixedMcpConfigError::InvalidEndpoint
            );
        }
    }
}
