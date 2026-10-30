//! Bounded public observations of this runtime's owner-held HTTP MCP binding.
//! These facts authenticate no named client and expose no capability secret.

use std::io::Read;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{BusClient, ClientError};

const STATUS_PATH: &str = "/api/onboarding/mcp-http/status";
pub const MAX_MCP_HTTP_STATUS_BYTES: usize = 4096;
const SERVER_PREFIX: &str = "chinwag-native-inbox-mgmt-http-";
const INPUT_PREFIX: &str = "chinwag-http-token-";
const INVALID: &str = "invalid runtime MCP status response";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeMcpStatus {
    pub ok: bool,
    pub schema: String,
    pub binding_authority: McpHttpBindingAuthority,
    pub transport: McpHttpTransportObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_offer: Option<HttpMcpSetupOffer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpHttpBindingAuthority {
    OwnerLocalHttpCapabilityUnattributed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpHttpTransportObservation {
    pub schema: String,
    pub connection_observation: McpConnectionObservation,
    pub session_started: bool,
    pub session_closed: bool,
    pub transport_worker_joined: bool,
    pub reader_worker_joined: bool,
    pub client_identity: McpHttpClientIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpHttpClientIdentity {
    UnattributedOwnerHttpCapability,
}

/// Independent atomic observations, rather than an ordered connection ladder.
/// Prepared output proves neither client receipt nor a named client identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConnectionObservation {
    pub schema: String,
    #[serde(deserialize_with = "required_protocol")]
    pub negotiated_protocol: Option<McpProtocolVersion>,
    pub initialized_notification_seen: bool,
    pub catalogue_outputs_prepared: u64,
    pub read_windows_prepared: u64,
    pub lease_expired: bool,
    pub admission_closed: bool,
    pub input_eof_seen: bool,
    pub input_error_seen: bool,
    pub protocol_end: McpProtocolEnd,
    pub owner_close_requested: bool,
    pub worker_state: McpWorkerState,
    pub output_evidence: McpOutputEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpProtocolVersion {
    #[serde(rename = "2025-06-18")]
    June2025,
    #[serde(rename = "2025-11-25")]
    November2025,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpProtocolEnd {
    NotObserved,
    Closed,
    Cancelled,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpWorkerState {
    DrainNotObserved,
    Drained,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpOutputEvidence {
    PreparedOnly,
}

/// A public, non-secret offer for the original enrollment. The nonce labels
/// configuration names; it is not the bearer token and cannot grant access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpMcpSetupOffer {
    pub url: String,
    pub server_name: String,
    pub input_id: String,
}

impl HttpMcpSetupOffer {
    /// Pure validation and fixed-name construction. The owner supplies its
    /// original 16-byte enrollment nonce as 32 lowercase hexadecimal digits.
    pub fn new(endpoint: &str, nonce: &str) -> Result<Self, ClientError> {
        let url = canonical_offer_url(endpoint)
            .filter(|_| valid_nonce(nonce))
            .ok_or_else(|| {
                ClientError::InvalidRequest("invalid runtime MCP setup offer inputs".into())
            })?;
        Ok(Self {
            url,
            server_name: format!("{SERVER_PREFIX}{nonce}"),
            input_id: format!("{INPUT_PREFIX}{nonce}"),
        })
    }

    pub fn validate(&self) -> Result<(), ClientError> {
        let nonce = self
            .server_name
            .strip_prefix(SERVER_PREFIX)
            .filter(|nonce| valid_nonce(nonce));
        let input_nonce = self.input_id.strip_prefix(INPUT_PREFIX);
        let endpoint = self.url.strip_suffix("api/mcp");
        if nonce.is_none()
            || nonce != input_nonce
            || endpoint.and_then(canonical_offer_url).as_deref() != Some(self.url.as_str())
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// VS Code's supported manual configuration. A password prompt supplies
    /// the owner capability; there is no bearer value, command or default here.
    pub fn vscode_configuration(&self) -> Result<Value, ClientError> {
        self.validate()?;
        Ok(json!({
            "servers": {
                (self.server_name.clone()): {
                    "type": "http",
                    "url": self.url,
                    "headers": {"Authorization": format!("Bearer ${{input:{}}}", self.input_id)}
                }
            },
            "inputs": [{
                "type": "promptString",
                "id": self.input_id,
                "description": "Enter the Chinwag HTTP capability supplied by the runtime owner",
                "password": true
            }]
        }))
    }
}

impl RuntimeMcpStatus {
    pub fn validate(&self) -> Result<(), ClientError> {
        if !self.ok
            || self.schema != "chinwag-runtime-owned-mcp/v1"
            || self.transport.schema != "chinwag-owner-http-inbox/v1"
            || self.transport.connection_observation.schema
                != "chinwag-mcp-connection-observation/v1"
            || self.transport.reader_worker_joined
                != (self.transport.connection_observation.worker_state == McpWorkerState::Drained)
        {
            return Err(invalid());
        }
        if let Some(offer) = &self.setup_offer {
            offer.validate()?;
        }
        Ok(())
    }

    pub fn validate_for(&self, endpoint: &str) -> Result<(), ClientError> {
        self.validate()?;
        if let Some(offer) = &self.setup_offer
            && canonical_offer_url(endpoint).as_deref() != Some(offer.url.as_str())
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Historical observations remain valid after expiry or use. Only an
    /// unused, open sample can be offered for an explicit setup action.
    pub fn usable_setup_offer(&self) -> Option<&HttpMcpSetupOffer> {
        let observation = &self.transport.connection_observation;
        if self.validate().is_err()
            || self.transport.session_started
            || self.transport.session_closed
            || observation.lease_expired
            || observation.admission_closed
        {
            return None;
        }
        self.setup_offer.as_ref()
    }
}

impl BusClient {
    /// One explicit GET only. No scan, MCP initialization, tool read, token
    /// access, installation or retry occurs. A 404 cannot distinguish disabled
    /// support from an older runtime, so it is returned as no observation.
    pub fn mcp_http_status(&self) -> Result<Option<RuntimeMcpStatus>, ClientError> {
        let mut response = self
            .http
            .get(self.endpoint(STATUS_PATH))
            .header("X-Chinwag-Onboarding-Intent", "1")
            .send()
            .map_err(|_| ClientError::InvalidResponse("runtime MCP status unavailable".into()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(ClientError::HttpStatus {
                status: response.status().as_u16(),
                detail: "runtime MCP status unavailable".into(),
            });
        }
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take((MAX_MCP_HTTP_STATUS_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                ClientError::InvalidResponse("runtime MCP status response unavailable".into())
            })?;
        if bytes.len() > MAX_MCP_HTTP_STATUS_BYTES {
            return Err(ClientError::ResponseTooLarge {
                limit: MAX_MCP_HTTP_STATUS_BYTES,
            });
        }
        let status: RuntimeMcpStatus = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        status.validate_for(self.normalized_endpoint())?;
        Ok(Some(status))
    }
}

fn invalid() -> ClientError {
    ClientError::InvalidResponse(INVALID.into())
}

fn required_protocol<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<McpProtocolVersion>, D::Error> {
    Option::deserialize(deserializer)
}
fn valid_nonce(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn canonical_offer_url(endpoint: &str) -> Option<String> {
    if endpoint.len() > 256 {
        return None;
    }
    let url = Url::parse(endpoint).ok()?;
    if url.as_str() != endpoint
        || url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port() == Some(0)
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(format!("{endpoint}api/mcp"))
}
