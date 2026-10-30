//! A bounded, blocking client for the loopback Chinwag UI workbench.
//!
//! Call these methods on a background worker. A failed send can have reached the
//! bus even when no valid receipt returns; the client never retries a request.

use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use reqwest::Url;
use reqwest::blocking::{Client, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod discovery;
mod onboarding;
pub use discovery::{
    ClientInventory, ClientKind, DiscoveredClient, DiscoveryCoverage, DiscoveryState,
    InstallationCoverage, InstallationInventory, InstallationLocation, InstallationState,
    InstalledClient, is_public_installation_version,
};
pub use onboarding::{NativeOpenReceipt, NativeOpenRequest, NativeOpenState, OnboardingStatus};

pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_MESSAGE_LIMIT: usize = 200;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
// The signed CLI has a bounded eight-second publication attempt. Give its
// explicit uncertain/success receipt time to arrive; never retry a POST.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusMessage {
    pub id: String,
    pub seq: u64,
    pub ts_iso: String,
    pub room: String,
    pub sender: String,
    pub body: String,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub sig_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusAck {
    pub ok: bool,
    pub seq: u64,
    pub message_id: String,
    pub transport: String,
    pub room: String,
    #[serde(default)]
    pub sig_verified: bool,
    pub subscribers_notified: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendRequest {
    pub sender: String,
    pub room: String,
    pub body: String,
    pub to: Option<String>,
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendReceipt {
    pub message: BusMessage,
    pub ack: BusAck,
}

impl SendReceipt {
    pub fn validate_for(&self, request: &SendRequest) -> Result<(), ClientError> {
        validate_receipt(true, self, request, normalize_sender(&request.sender))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationState {
    Delivered(Box<SendReceipt>),
    Pending,
    Uncertain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendOperation {
    pub request_id: String,
    pub state: OperationState,
}

/// An identity for one explicit send, generated before publication and retained
/// by callers across lost responses. This never reads a signer or seat key.
pub fn new_request_id() -> Result<String, ClientError> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| {
            ClientError::InvalidRequest(format!("could not create request ID: {error}"))
        })?;
    let mut id = String::from("ui-");
    use std::fmt::Write as _;
    for byte in bytes {
        write!(&mut id, "{byte:02x}").expect("formatting into a String cannot fail");
    }
    Ok(id)
}

pub fn validate_request_id(id: &str) -> Result<(), ClientError> {
    if !(16..=100).contains(&id.len())
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ClientError::InvalidRequest(
            "request ID must contain 16..100 ASCII letters, digits, underscores or hyphens".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid loopback endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("HTTP request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("HTTP {status}: {detail}")]
    HttpStatus { status: u16, detail: String },
    #[error("response exceeded the {limit}-byte limit")]
    ResponseTooLarge { limit: usize },
    #[error("could not read response: {0}")]
    ResponseRead(#[from] std::io::Error),
    #[error("invalid response JSON: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("invalid bus response: {0}")]
    InvalidResponse(String),
    #[error("send outcome unknown; do not resend automatically: {reason}")]
    SendOutcomeUnknown { reason: String },
    #[error(
        "application opening outcome unknown; check its receipt before opening again: {reason}"
    )]
    NativeOpenOutcomeUnknown { reason: String },
}

impl ClientError {
    /// True means the POST may have been persisted without a usable receipt.
    pub fn send_outcome_unknown(&self) -> bool {
        matches!(self, Self::SendOutcomeUnknown { .. })
    }

    fn for_send(self) -> Self {
        // Preserve boundary rejections such as the operator-only 403. A timeout
        // without a receipt (including HTTP 408) still needs reconciliation.
        if matches!(
            self,
            Self::HttpStatus { status: 400..=499, .. } if !matches!(self, Self::HttpStatus { status: 408, .. })
        ) {
            self
        } else {
            Self::SendOutcomeUnknown {
                reason: self.to_string(),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct BusClient {
    base_url: Url,
    http: Client,
}

#[derive(Serialize)]
struct WireSend<'a> {
    sender: &'a str,
    room: &'a str,
    body: &'a str,
    to: &'a Option<String>,
    task_id: &'a Option<String>,
    wake: bool,
}

#[derive(Deserialize)]
struct WireReceipt {
    ok: bool,
    message: BusMessage,
    ack: BusAck,
    request_id: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct WireOperation {
    ok: bool,
    request_id: String,
    state: String,
    receipt: Option<SendReceipt>,
    error: Option<String>,
}

impl BusClient {
    pub fn new(base_url: &str) -> Result<Self, ClientError> {
        let mut url = Url::parse(base_url)
            .map_err(|_| ClientError::InvalidEndpoint("expected an HTTP loopback URL".into()))?;
        let authority = base_url
            .split_once("://")
            .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
            .unwrap_or_default();
        if url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || authority.contains('@')
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(ClientError::InvalidEndpoint(
                "use http://localhost:PORT or a loopback IP, with no credentials, path, query or fragment"
                    .into(),
            ));
        }
        match url.host_str() {
            Some("localhost") => {
                // Pin localhost rather than trusting DNS or the hosts file.
                url.set_host(Some("127.0.0.1")).map_err(|_| {
                    ClientError::InvalidEndpoint("could not pin localhost to loopback".into())
                })?;
            }
            Some(host) => {
                let address = host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>();
                if !address.is_ok_and(|address| address.is_loopback()) {
                    return Err(ClientError::InvalidEndpoint(
                        "only localhost and literal loopback IP addresses are accepted".into(),
                    ));
                }
            }
            None => return Err(ClientError::InvalidEndpoint("missing loopback host".into())),
        }
        let http = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()?;
        Ok(Self {
            base_url: url,
            http,
        })
    }

    /// The validated, normalized route used by this client; contains no credentials.
    pub fn normalized_endpoint(&self) -> &str {
        self.base_url.as_str()
    }

    pub fn status(&self) -> Result<serde_json::Value, ClientError> {
        read_json(self.http.get(self.endpoint("/api/bus/status")).send()?)
    }

    pub fn messages(&self, room: &str, limit: usize) -> Result<Vec<BusMessage>, ClientError> {
        validate_room(room)?;
        if !(1..=MAX_MESSAGE_LIMIT).contains(&limit) {
            return Err(ClientError::InvalidRequest(format!(
                "message limit must be between 1 and {MAX_MESSAGE_LIMIT}"
            )));
        }
        let mut url = self.endpoint("/api/bus/messages");
        // The existing workbench decodes %20 but does not decode form '+'.
        url.set_query(Some(&format!(
            "room={}&limit={limit}",
            percent_encode(room)
        )));
        let messages: Vec<BusMessage> = read_json(self.http.get(url).send()?)?;
        if messages.len() > limit {
            return Err(ClientError::InvalidResponse(
                "message response exceeded the requested count".into(),
            ));
        }
        for message in &messages {
            validate_message(message, room)?;
        }
        Ok(messages)
    }

    pub fn send(&self, request: &SendRequest) -> Result<SendReceipt, ClientError> {
        self.send_with_id(request, &new_request_id()?)
    }

    pub fn send_with_id(
        &self,
        request: &SendRequest,
        id: &str,
    ) -> Result<SendReceipt, ClientError> {
        validate_request_id(id)?;
        validate_room(&request.room)?;
        let sender = normalize_sender(&request.sender);
        if sender.is_empty() || request.body.trim().is_empty() {
            return Err(ClientError::InvalidRequest(
                "sender and message body must not be empty".into(),
            ));
        }
        for (field, value) in [("to", &request.to), ("task_id", &request.task_id)] {
            if value
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(ClientError::InvalidRequest(format!(
                    "optional {field} must be absent or nonempty"
                )));
            }
        }
        let wire = WireSend {
            sender,
            room: &request.room,
            body: &request.body,
            to: &request.to,
            task_id: &request.task_id,
            wake: false,
        };
        let response = self
            .http
            .post(self.endpoint("/api/bus/send"))
            .header("X-Chinwag-UI-Intent", "1")
            .header("X-Chinwag-Request-Id", id)
            .json(&wire)
            .send()
            .map_err(|error| ClientError::Transport(error).for_send())?;
        let wire: WireReceipt = read_json(response).map_err(ClientError::for_send)?;
        if wire
            .request_id
            .as_deref()
            .is_some_and(|returned| returned != id)
            || wire
                .state
                .as_deref()
                .is_some_and(|state| state != "delivered")
        {
            return Err(ClientError::InvalidResponse(
                "send receipt belongs to another request or has no delivered state".into(),
            )
            .for_send());
        }
        let receipt = SendReceipt {
            message: wire.message,
            ack: wire.ack,
        };
        validate_receipt(wire.ok, &receipt, request, sender).map_err(ClientError::for_send)?;
        Ok(receipt)
    }

    /// Reads an existing attempt only. A missing or uncertain operation is never
    /// converted into another POST, and a bounded read is not absence proof.
    pub fn operation(&self, id: &str) -> Result<SendOperation, ClientError> {
        validate_request_id(id)?;
        let wire: WireOperation = read_json(
            self.http
                .get(self.endpoint(&format!("/api/bus/sends/{id}")))
                .send()?,
        )?;
        if !wire.ok || wire.request_id != id {
            return Err(ClientError::InvalidResponse(
                "send status returned a different request ID or failure".into(),
            ));
        }
        let state = match (wire.state.as_str(), wire.receipt) {
            ("delivered", Some(receipt)) => {
                let request = SendRequest {
                    sender: receipt.message.sender.clone(),
                    room: receipt.message.room.clone(),
                    body: receipt.message.body.clone(),
                    to: receipt.message.to.clone(),
                    task_id: receipt.message.task_id.clone(),
                };
                receipt.validate_for(&request)?;
                OperationState::Delivered(Box::new(receipt))
            }
            ("pending", None) => OperationState::Pending,
            ("uncertain", None) => OperationState::Uncertain(
                wire.error
                    .unwrap_or_else(|| "No validated receipt is available for this attempt".into()),
            ),
            _ => {
                return Err(ClientError::InvalidResponse(
                    "send status has an invalid state/receipt combination".into(),
                ));
            }
        };
        Ok(SendOperation {
            request_id: wire.request_id,
            state,
        })
    }

    fn endpoint(&self, path: &str) -> Url {
        let mut url = self.base_url.clone();
        url.set_path(path);
        url
    }
}

fn validate_room(room: &str) -> Result<(), ClientError> {
    if !room.starts_with('#')
        || room.len() < 2
        || room.len() > 256
        || room != room.trim()
        || room.chars().any(char::is_control)
    {
        return Err(ClientError::InvalidRequest(
            "room must start with #, contain a name, and have no surrounding whitespace or control characters"
                .into(),
        ));
    }
    Ok(())
}

fn normalize_sender(sender: &str) -> &str {
    sender.trim().trim_start_matches(|character: char| {
        character.is_whitespace() || matches!(character, '●' | '■' | '◆')
    })
}

fn validate_message(message: &BusMessage, room: &str) -> Result<(), ClientError> {
    if message.room != room
        || message.id.trim().is_empty()
        || message.sender.trim().is_empty()
        || message.seq == 0
    {
        return Err(ClientError::InvalidResponse(
            "message has the wrong room, empty ID/sender or zero sequence".into(),
        ));
    }
    Ok(())
}

fn validate_receipt(
    ok: bool,
    receipt: &SendReceipt,
    request: &SendRequest,
    sender: &str,
) -> Result<(), ClientError> {
    validate_message(&receipt.message, &request.room)?;
    let ack = &receipt.ack;
    if !ok
        || !ack.ok
        || ack.room != request.room
        || ack.message_id != receipt.message.id
        || ack.seq != receipt.message.seq
        || ack.transport.trim().is_empty()
        || !receipt.message.sender.eq_ignore_ascii_case(sender)
        || (receipt.message.body != request.body && receipt.message.body != request.body.trim())
        || receipt.message.to != request.to
        || receipt.message.task_id != request.task_id
    {
        return Err(ClientError::InvalidResponse(
            "send acknowledgment does not confirm the requested message, room, ID and sequence"
                .into(),
        ));
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(mut response: Response) -> Result<T, ClientError> {
    let status = response.status();
    let mut bytes = Vec::new();
    let read_result = response
        .by_ref()
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes);
    if !status.is_success() {
        let detail = if bytes.len() > MAX_RESPONSE_BYTES {
            format!("error response exceeded the {MAX_RESPONSE_BYTES}-byte limit")
        } else if let Err(error) = read_result {
            format!("could not read error response: {error}")
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };
        return Err(ClientError::HttpStatus {
            status: status.as_u16(),
            detail,
        });
    }
    read_result?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ClientError::ResponseTooLarge {
            limit: MAX_RESPONSE_BYTES,
        });
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 15) as usize]));
        }
    }
    encoded
}
