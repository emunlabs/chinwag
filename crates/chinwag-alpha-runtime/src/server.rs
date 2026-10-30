//! Loopback HTTP boundary for the isolated alpha ledger and bounded fleet reads.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as RoutePath, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chinwag_bus_client::{BusMessage, SendReceipt, SendRequest};
use chinwag_connector_registry::{Limits, Registry};
use chinwag_connectors::{BuiltinConnector, ConnectorHost};
use rustix::fs::{FlockOperation, OFlags, flock};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::discovery::{
    DiscoveryFailure, DiscoveryService, InventorySource, NativeInventorySource,
};
use crate::onboarding::OnboardingService;
use crate::{Result, RuntimeConfig, RuntimeError, RuntimeMode, SignedSender};

mod journal;
mod onboarding;
use journal::AttemptJournal;

pub const LOCAL_TRANSPORT: &str = "local-jsonl-alpha (unsigned, isolated)";
pub const SHARED_TRANSPORT: &str = "local-ledger-read-only";
const MAX_REQUEST: usize = 20_000;
const MAX_BODY: usize = 16_000;
const MAX_LEDGER: u64 = 32 * 1024 * 1024;
const MAX_TAIL: u64 = 1024 * 1024;
const MAX_RESPONSE: usize = 900_000;
const ROOMS: [&str; 4] = ["#mgmt", "#eng", "#qa", "#alpha"];

#[derive(Clone)]
struct AppState(
    Arc<Backend>,
    Arc<DiscoveryService>,
    Option<Arc<OnboardingService>>,
    Option<Arc<OnboardingService>>,
    Option<Arc<OnboardingService>>,
);

enum Backend {
    Local {
        ledger: Mutex<LocalLedger>,
        journal: Mutex<AttemptJournal>,
        publication: Mutex<()>,
    },
    Shared {
        ledger: PathBuf,
        signer: Option<Arc<dyn SignedSender>>,
        last_query: Mutex<Option<Value>>,
        publication: Mutex<()>,
        journal: Option<Mutex<AttemptJournal>>,
    },
}

/// Constructing a router acquires the isolated ledger lock or validates the
/// configured shared path. It never invokes a signer or starts another process.
pub fn router(config: RuntimeConfig) -> Result<Router> {
    router_with_discovery(config, Arc::new(NativeInventorySource))
}

/// Opt-in only: the caller owns the target host's serviced native main loop.
/// A service is never constructed implicitly by the default router.
pub fn router_with_onboarding(
    config: RuntimeConfig,
    service: Arc<OnboardingService>,
) -> Result<Router> {
    router_with_components(
        config,
        Arc::new(NativeInventorySource),
        Some(service),
        None,
        None,
    )
}

fn router_with_discovery(
    config: RuntimeConfig,
    source: Arc<dyn InventorySource>,
) -> Result<Router> {
    router_with_components(config, source, None, None, None)
}

fn router_with_components(
    config: RuntimeConfig,
    source: Arc<dyn InventorySource>,
    onboarding: Option<Arc<OnboardingService>>,
    cursor_mcp: Option<Arc<OnboardingService>>,
    vscode_mcp: Option<Arc<OnboardingService>>,
) -> Result<Router> {
    router_with_shared_host(config, source, onboarding, cursor_mcp, vscode_mcp, None)
}

fn router_with_shared_host(
    config: RuntimeConfig,
    source: Arc<dyn InventorySource>,
    onboarding: Option<Arc<OnboardingService>>,
    cursor_mcp: Option<Arc<OnboardingService>>,
    vscode_mcp: Option<Arc<OnboardingService>>,
    host: Option<Arc<Mutex<ConnectorHost>>>,
) -> Result<Router> {
    if config.bind.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(RuntimeError::Invalid("bind must be 127.0.0.1".into()));
    }
    let backend = match config.mode {
        RuntimeMode::Isolated { data_dir } => {
            let ledger = LocalLedger::open(data_dir.clone())?;
            let journal = AttemptJournal::open(data_dir.join("send-journal"))?;
            Backend::Local {
                ledger: Mutex::new(ledger),
                journal: Mutex::new(journal),
                publication: Mutex::new(()),
            }
        }
        RuntimeMode::Shared {
            ledger,
            signed_sender,
            journal_dir,
        } => {
            read_shared(&ledger)?;
            let journal = match (signed_sender.is_some(), journal_dir) {
                (true, Some(directory)) => Some(Mutex::new(AttemptJournal::open(directory)?)),
                (true, None) => {
                    return Err(RuntimeError::Invalid(
                        "a separate owned journal directory is required for signed mode".into(),
                    ));
                }
                (false, None) => None,
                (false, Some(_)) => {
                    return Err(RuntimeError::Invalid(
                        "read-only mode must not create an operation journal".into(),
                    ));
                }
            };
            Backend::Shared {
                ledger,
                signer: signed_sender,
                last_query: Mutex::new(None),
                publication: Mutex::new(()),
                journal,
            }
        }
    };
    let send_route = if matches!(&backend, Backend::Shared { signer: None, .. }) {
        axum::routing::post(deny_post)
    } else {
        axum::routing::post(send)
    };
    Ok(Router::new()
        .route("/api/bus/status", get(status).post(deny_post))
        .route("/api/bus/messages", get(messages).post(deny_post))
        .route("/api/bus/send", send_route)
        .route("/api/bus/sends/{id}", get(send_lookup).post(deny_post))
        .route(
            "/api/bus/clients",
            get(discover_clients)
                .head(deny_discovery_method)
                .fallback(deny_discovery_method),
        )
        .route(
            "/api/onboarding/status",
            get(onboarding::status)
                .head(onboarding::deny_get_method)
                .fallback(onboarding::deny_get_method),
        )
        .route(
            "/api/onboarding/open",
            axum::routing::post(onboarding::open).fallback(onboarding::deny_post_method),
        )
        .route(
            "/api/onboarding/opens/{id}",
            get(onboarding::lookup)
                .head(onboarding::deny_get_method)
                .fallback(onboarding::deny_get_method),
        )
        .route(
            "/api/onboarding/cursor-mcp/status",
            get(onboarding::cursor_status)
                .head(onboarding::deny_get_method)
                .fallback(onboarding::deny_get_method),
        )
        .route(
            "/api/onboarding/cursor-mcp/setup",
            axum::routing::post(onboarding::cursor_setup).fallback(onboarding::deny_post_method),
        )
        .route(
            "/api/onboarding/cursor-mcp/setups/{id}",
            get(onboarding::cursor_lookup)
                .head(onboarding::deny_get_method)
                .fallback(onboarding::deny_get_method),
        )
        .route(
            "/api/onboarding/vscode-mcp/status",
            get(onboarding::vscode_status)
                .head(onboarding::deny_get_method)
                .fallback(onboarding::deny_get_method),
        )
        .route(
            "/api/onboarding/vscode-mcp/setup",
            axum::routing::post(onboarding::vscode_setup).fallback(onboarding::deny_post_method),
        )
        .route(
            "/api/onboarding/vscode-mcp/setups/{id}",
            get(onboarding::vscode_lookup)
                .head(onboarding::deny_get_method)
                .fallback(onboarding::deny_get_method),
        )
        .fallback(fallback)
        .layer(DefaultBodyLimit::max(MAX_REQUEST))
        .with_state(AppState(
            Arc::new(backend),
            Arc::new(match host {
                Some(host) => DiscoveryService::with_shared_host(source, host),
                None => DiscoveryService::new(source),
            }),
            onboarding,
            cursor_mcp,
            vscode_mcp,
        )))
}

pub async fn serve(config: RuntimeConfig) -> Result<()> {
    serve_optional_onboarding(config, None, None, None).await
}

pub async fn serve_with_onboarding(
    config: RuntimeConfig,
    service: Arc<OnboardingService>,
) -> Result<()> {
    serve_optional_onboarding(config, Some(service), None, None).await
}

/// Each controller is explicitly constructed by the target-host owner.
pub async fn serve_with_native_actions(
    config: RuntimeConfig,
    onboarding: Option<Arc<OnboardingService>>,
    cursor_mcp: Option<Arc<OnboardingService>>,
    vscode_mcp: Option<Arc<OnboardingService>>,
) -> Result<()> {
    serve_optional_onboarding(config, onboarding, cursor_mcp, vscode_mcp).await
}

/// Explicit owner opt-in. The default server creates neither a capability file
/// nor an HTTP inbox. Existing clients and stdio children are never attached.
pub async fn serve_with_http_mcp(
    config: RuntimeConfig,
    onboarding: Option<Arc<OnboardingService>>,
    cursor_mcp: Option<Arc<OnboardingService>>,
    vscode_mcp: Option<Arc<OnboardingService>>,
    capability_file: PathBuf,
) -> Result<()> {
    if config.bind.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)
        || config.bind.port() == 0
        || !matches!(
            &config.mode,
            RuntimeMode::Shared {
                signed_sender: None,
                ..
            }
        )
    {
        return Err(RuntimeError::Invalid(
            "HTTP MCP requires a fixed loopback read-only shared runtime".into(),
        ));
    }
    let registry = Registry::new(Limits {
        max_grants: 1,
        max_bindings: 1,
        max_lease: Duration::from_secs(900),
    })
    .map_err(|_| RuntimeError::Unavailable("runtime connector host unavailable".into()))?;
    let mut host = ConnectorHost::new(registry);
    host.set_enabled(BuiltinConnector::NativeClients, true)
        .map_err(|_| RuntimeError::Unavailable("runtime connector host unavailable".into()))?;
    let host = Arc::new(Mutex::new(host));
    let shared_host = host.clone();
    let bind = config.bind;
    let app = tokio::task::spawn_blocking(move || {
        router_with_shared_host(
            config,
            Arc::new(NativeInventorySource),
            onboarding,
            cursor_mcp,
            vscode_mcp,
            Some(shared_host),
        )
    })
    .await
    .map_err(|_| RuntimeError::Unavailable("runtime initialization worker failed".into()))??;
    // Reserve the exact endpoint before issuing any capability. An occupied
    // listener is preserved and cannot cause a grant or file to be issued.
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let owner = match crate::mcp::HttpMcpOwner::start(
        &format!("http://{bind}"),
        host,
        &capability_file,
    )
    .await
    {
        Ok(owner) => Some(Arc::new(owner)),
        Err(_) => {
            eprintln!(
                "chinwag-alpha-runtime: HTTP MCP initialization unavailable; bus continues with HTTP MCP disabled; no existing capability was adopted or repaired"
            );
            None
        }
    };
    let app = match &owner {
        Some(owner) => app.merge(http_mcp_routes(owner.transport(), http_mcp_authority(bind))),
        None => app,
    };
    let shutdown_owner = owner.clone();
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            // Retire sessions and their SSE bodies before axum waits for
            // graceful connection completion. Only actual joins prove drain.
            if let Some(owner) = shutdown_owner {
                let _ = owner.shutdown().await;
            }
        })
        .await;
    if let Some(owner) = owner {
        owner.shutdown().await.map_err(|_| {
            RuntimeError::Unavailable("HTTP MCP owner cleanup could not be confirmed".into())
        })?;
    }
    result?;
    Ok(())
}

fn http_mcp_authority(bind: std::net::SocketAddr) -> String {
    if bind.port() == 80 {
        bind.ip().to_string()
    } else {
        bind.to_string()
    }
}

fn http_mcp_routes(inbox: Arc<chinwag_bus_mcp::http::HttpInbox>, authority: String) -> Router {
    let transport = inbox.clone();
    Router::new()
        .route(
            "/api/mcp",
            axum::routing::any(move |request: axum::extract::Request| {
                let transport = transport.clone();
                async move { transport.handle(request).await }
            }),
        )
        .route(
            "/api/onboarding/mcp-http/status",
            get(move |headers: HeaderMap, uri: axum::http::Uri| {
                let inbox = inbox.clone();
                let authority = authority.clone();
                async move {
                    if uri.query().is_some()
                        || headers.contains_key("origin")
                        || headers.get_all("host").iter().count() != 1
                        || headers.get("host").and_then(|value| value.to_str().ok())
                            != Some(authority.as_str())
                        || headers.get_all("x-chinwag-onboarding-intent").iter().count() != 1
                        || headers.get("x-chinwag-onboarding-intent")
                            .and_then(|value| value.to_str().ok()) != Some("1")
                    {
                        return response(StatusCode::FORBIDDEN, json!({"ok":false,"error":"explicit native loopback observation required"}));
                    }
                    response(StatusCode::OK, json!({
                        "ok": true,
                        "schema": "chinwag-runtime-owned-mcp/v1",
                        "binding_authority": "owner_local_http_capability_unattributed",
                        "transport": inbox.lifecycle_snapshot(),
                    }))
                }
            })
            .head(http_mcp_status_method)
            .fallback(http_mcp_status_method),
        )
}

async fn http_mcp_status_method() -> Response {
    response(
        StatusCode::METHOD_NOT_ALLOWED,
        json!({"ok":false,"error":"MCP observation accepts GET only"}),
    )
}

async fn serve_optional_onboarding(
    config: RuntimeConfig,
    onboarding: Option<Arc<OnboardingService>>,
    cursor_mcp: Option<Arc<OnboardingService>>,
    vscode_mcp: Option<Arc<OnboardingService>>,
) -> Result<()> {
    let bind = config.bind;
    let app = tokio::task::spawn_blocking(move || {
        router_with_components(
            config,
            Arc::new(NativeInventorySource),
            onboarding,
            cursor_mcp,
            vscode_mcp,
        )
    })
    .await
    .map_err(|_| RuntimeError::Unavailable("runtime initialization worker failed".into()))??;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn response(status: StatusCode, payload: Value) -> Response {
    (status, [("cache-control", "no-store")], Json(payload)).into_response()
}

fn failure(error: RuntimeError) -> Response {
    let status = match &error {
        RuntimeError::Invalid(_) => StatusCode::BAD_REQUEST,
        RuntimeError::Rejected(_) => StatusCode::FORBIDDEN,
        RuntimeError::SendUncertain(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    response(status, json!({"ok":false, "error":error.to_string()}))
}

async fn blocking<F>(operation: F) -> Response
where
    F: FnOnce() -> Result<Value> + Send + 'static,
{
    blocking_http(move || operation().map(|value| (StatusCode::OK, value))).await
}

async fn blocking_http<F>(operation: F) -> Response
where
    F: FnOnce() -> Result<(StatusCode, Value)> + Send + 'static,
{
    match tokio::task::spawn_blocking(operation).await {
        Ok(Ok((status, value))) => response(status, value),
        Ok(Err(error)) => failure(error),
        Err(_) => failure(RuntimeError::Unavailable(
            "runtime worker failed; outcome may be uncertain".into(),
        )),
    }
}

fn boundary(headers: &HeaderMap) -> Result<()> {
    let hosts = headers.get_all("host");
    if headers.contains_key("origin") || hosts.iter().count() != 1 {
        return Err(RuntimeError::Rejected(
            "native loopback client required".into(),
        ));
    }
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<axum::http::uri::Authority>().ok());
    if !host.is_some_and(|h| matches!(h.host(), "127.0.0.1" | "localhost")) {
        return Err(RuntimeError::Rejected("loopback Host required".into()));
    }
    Ok(())
}

async fn deny_discovery_method() -> Response {
    let mut result = response(
        StatusCode::METHOD_NOT_ALLOWED,
        json!({"ok":false,"error":"client discovery accepts only explicit GET requests"}),
    );
    result
        .headers_mut()
        .insert("allow", "GET".parse().expect("constant HTTP header"));
    result
}

async fn discover_clients(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = boundary(&headers) {
        return failure(error);
    }
    if headers.get_all("x-chinwag-discovery-intent").iter().count() != 1
        || headers
            .get("x-chinwag-discovery-intent")
            .and_then(|header| header.to_str().ok())
            != Some("1")
    {
        return failure(RuntimeError::Rejected(
            "explicit native metadata discovery intent required".into(),
        ));
    }
    let include_details = match headers
        .get_all("x-chinwag-discovery-details")
        .iter()
        .count()
    {
        0 => false,
        1 if headers
            .get("x-chinwag-discovery-details")
            .and_then(|value| value.to_str().ok())
            == Some("1") =>
        {
            true
        }
        _ => {
            return failure(RuntimeError::Rejected(
                "one explicit discovery details version1 is required".into(),
            ));
        }
    };
    blocking_http(move || {
        match state.1.inventory_with_actions(
            &[state.2.as_deref(), state.3.as_deref(), state.4.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        ) {
            Ok(mut inventory) => {
                // Legacy clients deny unknown fields. Only an explicit details
                // negotiation may receive these additive public copy hints.
                if !include_details && let Some(installed) = &mut inventory.installations {
                    for application in &mut installed.apps {
                        application.location = None;
                        application.version = None;
                    }
                }
                let bytes = serde_json::to_vec(&inventory).map_err(json_error)?;
                if bytes.len() > MAX_RESPONSE {
                    return Err(RuntimeError::Unavailable(
                        "client inventory exceeds the response limit".into(),
                    ));
                }
                let value = serde_json::from_slice(&bytes).map_err(json_error)?;
                Ok((StatusCode::OK, value))
            }
            Err(DiscoveryFailure::Busy) => Ok((
                StatusCode::CONFLICT,
                json!({"ok":false,"error":DiscoveryFailure::Busy.to_string()}),
            )),
            Err(error) => Err(RuntimeError::Unavailable(error.to_string())),
        }
    })
    .await
}

async fn status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = boundary(&headers) {
        return failure(error);
    }
    blocking(move || match state.0.as_ref() {
        Backend::Local {
            ledger, journal, ..
        } => {
            let mut value = ledger.lock().map_err(|_| poisoned())?.status();
            let journal_healthy = journal.lock().map_err(|_| poisoned())?.healthy();
            value["journal_healthy"] = json!(journal_healthy);
            value["send_allowed"] = json!(value["send_allowed"] == true && journal_healthy);
            Ok(value)
        }
        Backend::Shared {
            ledger,
            signer,
            last_query,
            journal,
            ..
        } => {
            let snapshot = read_shared(ledger)?;
            let signed = signer.is_some();
            let healthy = journal
                .as_ref()
                .map(|journal| {
                    journal
                        .lock()
                        .map(|journal| journal.healthy())
                        .map_err(|_| poisoned())
                })
                .transpose()?
                .unwrap_or(true);
            Ok(json!({
                "ok":true, "mode":if signed {"fleet-signed-ui"} else {"fleet-ledger-read-only"},
                "transport":SHARED_TRANSPORT, "read_only":!signed,"send_allowed":signed && healthy,
                "storage_healthy":healthy,"journal_healthy":healthy,
                "allowed_senders":if signed {vec!["Brian"]} else {vec![]},
                "signature_verification":"not performed", "signatures_verified":false,
                "network_delivery_verified":false,"agent_wake":false,
                "ledger":ledger,"pid":std::process::id(),"diagnostics":snapshot.diagnostic,
                "last_messages_query":last_query.lock().map_err(|_| poisoned())?.clone()
            }))
        }
    })
    .await
}

fn parse_query(pairs: Vec<(String, String)>) -> Result<(String, usize)> {
    let mut room = None;
    let mut limit = None;
    for (key, value) in pairs {
        match key.as_str() {
            "room" if room.is_none() => room = Some(value),
            "limit" if limit.is_none() => limit = Some(value),
            _ => {
                return Err(RuntimeError::Invalid(
                    "only one room and one limit parameter are accepted".into(),
                ));
            }
        }
    }
    let room = room.unwrap_or_else(|| "#alpha".into());
    let limit = limit
        .unwrap_or_else(|| "100".into())
        .parse::<usize>()
        .map_err(|_| RuntimeError::Invalid("limit must be 1..100".into()))?;
    if !ROOMS.contains(&room.as_str()) || !(1..=100).contains(&limit) {
        return Err(RuntimeError::Invalid(
            "room must be #mgmt, #eng, #qa or #alpha and limit must be 1..100".into(),
        ));
    }
    Ok((room, limit))
}

async fn messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(error) = boundary(&headers) {
        return failure(error);
    }
    let (room, limit) = match parse_query(pairs) {
        Ok(query) => query,
        Err(error) => return failure(error),
    };
    blocking(move || match state.0.as_ref() {
        Backend::Local { ledger, .. } => ledger
            .lock()
            .map_err(|_| poisoned())?
            .messages(&room, limit),
        Backend::Shared {
            ledger, last_query, ..
        } => {
            let snapshot = read_shared(ledger)?;
            let matching: Vec<_> = snapshot
                .messages
                .into_iter()
                .filter(|m| m.room == room)
                .collect();
            let matching_count = matching.len();
            let selected: Vec<_> = matching
                .into_iter()
                .rev()
                .take(limit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let (payload, dropped, bytes) = bound_messages(selected)?;
            let mut diagnostic = serde_json::to_value(&snapshot.diagnostic).map_err(json_error)?;
            diagnostic
                .as_object_mut()
                .ok_or_else(|| RuntimeError::Unavailable("invalid internal diagnostic".into()))?
                .extend(serde_json::Map::from_iter([
                    ("room".into(), json!(room)),
                    ("requested_limit".into(), json!(limit)),
                    (
                        "returned_messages".into(),
                        json!(payload.as_array().map_or(0, Vec::len)),
                    ),
                    ("matching_messages_in_tail".into(), json!(matching_count)),
                    ("count_limited".into(), json!(matching_count > limit)),
                    ("response_messages_dropped".into(), json!(dropped)),
                    ("response_bytes".into(), json!(bytes)),
                    (
                        "complete_room_response".into(),
                        json!(
                            snapshot.diagnostic.complete_ledger_coverage
                                && matching_count <= limit
                                && dropped == 0
                        ),
                    ),
                ]));
            *last_query.lock().map_err(|_| poisoned())? = Some(diagnostic);
            Ok(payload)
        }
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSend {
    sender: String,
    room: String,
    body: String,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    task_id: Option<String>,
    wake: bool,
}

fn validate_send(headers: &HeaderMap, bytes: &[u8], shared: bool) -> Result<SendRequest> {
    boundary(headers)?;
    let intent = headers.get_all("x-chinwag-ui-intent");
    let json_content = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    if intent.iter().count() != 1
        || headers
            .get("x-chinwag-ui-intent")
            .and_then(|v| v.to_str().ok())
            != Some("1")
        || !json_content
    {
        return Err(RuntimeError::Rejected(
            "explicit native JSON intent required".into(),
        ));
    }
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err(RuntimeError::Invalid("bounded request required".into()));
    }
    let request: WireSend = serde_json::from_slice(bytes).map_err(|_| {
        RuntimeError::Invalid("invalid send JSON; wake must be explicitly false".into())
    })?;
    if request.wake {
        return Err(RuntimeError::Rejected("agent wake is disabled".into()));
    }
    let allowed = if shared {
        request.sender == "Brian"
    } else {
        matches!(request.sender.as_str(), "Brian" | "Nic" | "CODEX")
    };
    if !allowed {
        return Err(RuntimeError::Rejected(
            "sender is not allowed in this runtime mode".into(),
        ));
    }
    if !ROOMS.contains(&request.room.as_str())
        || request.body.trim().is_empty()
        || request.body.len() > MAX_BODY
        || request.body.contains('\0')
    {
        return Err(RuntimeError::Invalid(
            "fixed room and nonempty body of at most 16000 UTF-8 bytes required".into(),
        ));
    }
    if [&request.to, &request.task_id].iter().any(|value| {
        value.as_ref().is_some_and(|s| {
            s.trim().is_empty() || s.len() > 256 || s.chars().any(char::is_control)
        })
    }) {
        return Err(RuntimeError::Invalid(
            "optional recipient/task must be nonempty and at most 256 UTF-8 bytes".into(),
        ));
    }
    Ok(SendRequest {
        sender: request.sender,
        room: request.room,
        body: request.body,
        to: request.to,
        task_id: request.task_id,
    })
}

async fn send(State(state): State<AppState>, headers: HeaderMap, bytes: Bytes) -> Response {
    let shared = matches!(state.0.as_ref(), Backend::Shared { .. });
    if matches!(state.0.as_ref(), Backend::Shared { signer: None, .. }) {
        return read_only_denial();
    }
    let request = match validate_send(&headers, &bytes, shared) {
        Ok(value) => value,
        Err(error) => return failure(error),
    };
    let request_id = match request_id(&headers, shared) {
        Ok(id) => id,
        Err(error) => return failure(error),
    };
    blocking_http(move || {
        if let Some(id) = request_id {
            return journaled_send(state.0.as_ref(), &id, &request);
        }
        match state.0.as_ref() {
            Backend::Local { ledger, .. } => Ok((
                StatusCode::OK,
                ledger.lock().map_err(|_| poisoned())?.send(&request)?,
            )),
            _ => Err(RuntimeError::Rejected(
                "a request ID is required for signed publication".into(),
            )),
        }
    })
    .await
}

fn request_id(headers: &HeaderMap, required: bool) -> Result<Option<String>> {
    if !headers.contains_key("x-chinwag-request-id") {
        return if required {
            Err(RuntimeError::Invalid(
                "X-Chinwag-Request-Id is required for signed publication".into(),
            ))
        } else {
            Ok(None)
        };
    }
    if headers.get_all("x-chinwag-request-id").iter().count() != 1 {
        return Err(RuntimeError::Invalid("one request ID is required".into()));
    }
    let id = headers
        .get("x-chinwag-request-id")
        .and_then(|id| id.to_str().ok())
        .ok_or_else(|| RuntimeError::Invalid("invalid request ID".into()))?;
    journal::validate_id(id)?;
    Ok(Some(id.into()))
}

impl Backend {
    fn journal(&self) -> Option<&Mutex<AttemptJournal>> {
        match self {
            Self::Local { journal, .. } => Some(journal),
            Self::Shared { journal, .. } => journal.as_ref(),
        }
    }
    fn publication(&self) -> &Mutex<()> {
        match self {
            Self::Local { publication, .. } | Self::Shared { publication, .. } => publication,
        }
    }
    fn publish(&self, request: &SendRequest) -> Result<SendReceipt> {
        let receipt = match self {
            Self::Local { ledger, .. } => {
                serde_json::from_value(ledger.lock().map_err(|_| poisoned())?.send(request)?)
                    .map_err(|_| {
                        RuntimeError::SendUncertain("local receipt could not be decoded".into())
                    })?
            }
            Self::Shared {
                signer: Some(signer),
                ..
            } => signer.send(request)?,
            _ => return Err(RuntimeError::Rejected("read-only runtime".into())),
        };
        validate_receipt(request, &receipt)?;
        Ok(receipt)
    }
}

fn journaled_send(
    backend: &Backend,
    id: &str,
    request: &SendRequest,
) -> Result<(StatusCode, Value)> {
    let journal = backend
        .journal()
        .ok_or_else(|| RuntimeError::Rejected("read-only runtime".into()))?;
    let cached = journal.lock().map_err(|_| poisoned())?.lookup(id)?;
    if let Some(attempt) = cached {
        return cached_post(attempt, request);
    }
    let Ok(_active) = backend.publication().try_lock() else {
        return Ok((
            StatusCode::CONFLICT,
            json!({"ok":false,"request_id":id,"error":"another publication is currently active; this request has not started"}),
        ));
    };
    let attempt = {
        let mut journal = journal.lock().map_err(|_| poisoned())?;
        if let Some(attempt) = journal.lookup(id)? {
            return cached_post(attempt, request);
        }
        journal.begin(id, request)?
    };
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend.publish(request)))
            .unwrap_or_else(|_| {
                Err(RuntimeError::SendUncertain(
                    "publication worker stopped without a validated receipt".into(),
                ))
            });
    let attempt = journal
        .lock()
        .map_err(|_| poisoned())?
        .finish(attempt, result)?;
    Ok(attempt.post_payload())
}

fn cached_post(attempt: journal::Attempt, request: &SendRequest) -> Result<(StatusCode, Value)> {
    if !attempt.matches(request)? {
        return Ok((
            StatusCode::CONFLICT,
            json!({"ok":false,"error":"request ID is already bound to a different message"}),
        ));
    }
    Ok(attempt.post_payload())
}

async fn send_lookup(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Response {
    if let Err(error) = boundary(&headers).and_then(|()| journal::validate_id(&id)) {
        return failure(error);
    }
    blocking_http(move || {
        let attempt = state
            .0
            .journal()
            .map(|journal| journal.lock().map_err(|_| poisoned())?.lookup(&id))
            .transpose()?
            .flatten();
        Ok(match attempt {
            Some(attempt) => (StatusCode::OK, attempt.lookup_payload()),
            None => (
                StatusCode::NOT_FOUND,
                json!({"ok":false,"request_id":id,"error":"unknown request ID"}),
            ),
        })
    })
    .await
}

fn validate_receipt(request: &SendRequest, receipt: &SendReceipt) -> Result<()> {
    let message = &receipt.message;
    let ack = &receipt.ack;
    if message.id.trim().is_empty()
        || message.seq == 0
        || message.sender != request.sender
        || message.room != request.room
        || !(message.body == request.body || message.body == request.body.trim())
        || message.to != request.to
        || message.task_id != request.task_id
        || !ack.ok
        || ack.message_id != message.id
        || ack.seq != message.seq
        || ack.room != message.room
        || ack.transport.trim().is_empty()
    {
        return Err(RuntimeError::SendUncertain(
            "sender returned a mismatched receipt".into(),
        ));
    }
    Ok(())
}

fn read_only_denial() -> Response {
    let mut result = response(
        StatusCode::METHOD_NOT_ALLOWED,
        json!({"ok":false,"read_only":true,"send_allowed":false,"error":"this adapter never publishes or wakes agents"}),
    );
    result
        .headers_mut()
        .insert("allow", "GET".parse().expect("constant HTTP header"));
    result
}

async fn deny_post(State(state): State<AppState>) -> Response {
    if matches!(state.0.as_ref(), Backend::Shared { signer: None, .. }) {
        read_only_denial()
    } else {
        response(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"ok":false,"error":"POST is supported only at /api/bus/send"}),
        )
    }
}

async fn fallback(State(state): State<AppState>, method: Method) -> Response {
    if method == Method::POST {
        return deny_post(State(state)).await;
    }
    response(
        StatusCode::NOT_FOUND,
        json!({"ok":false,"error":"unknown alpha route"}),
    )
}

fn poisoned() -> RuntimeError {
    RuntimeError::StorageUncertain("runtime lock is poisoned".into())
}
fn json_error(_: serde_json::Error) -> RuntimeError {
    RuntimeError::Unavailable("could not encode runtime JSON".into())
}

fn open_regular(path: &Path, write: bool, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .append(write)
        .create(create)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(RuntimeError::Invalid(
            "ledger must be a regular non-symlink file".into(),
        ));
    }
    Ok(file)
}

struct LedgerLock(File);

impl Drop for LedgerLock {
    fn drop(&mut self) {
        // A child may retain the same file description until exec closes it.
        let _ = flock(&self.0, FlockOperation::Unlock);
    }
}

struct LocalLedger {
    root: PathBuf,
    path: PathBuf,
    _guard: LedgerLock,
    file: File,
    messages: Vec<Value>,
    write_failed: bool,
    bytes: u64,
}

impl LocalLedger {
    fn open(root: PathBuf) -> Result<Self> {
        if !root.is_absolute() {
            return Err(RuntimeError::Invalid(
                "data directory must be absolute".into(),
            ));
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        if !fs::symlink_metadata(&root)?.file_type().is_dir() {
            return Err(RuntimeError::Invalid(
                "data directory must be a non-symlink directory".into(),
            ));
        }
        let guard = open_regular(&root.join("server.lock"), true, true)?;
        flock(&guard, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            RuntimeError::Unavailable("isolated ledger is already owned or cannot be locked".into())
        })?;
        let guard = LedgerLock(guard);
        let path = root.join("messages.jsonl");
        let mut file = open_regular(&path, true, true)?;
        let bytes = file.metadata()?.len();
        if bytes > MAX_LEDGER {
            return Err(RuntimeError::Invalid("alpha ledger exceeds 32 MiB".into()));
        }
        let mut raw = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_LEDGER + 1)
            .read_to_end(&mut raw)?;
        if raw.len() as u64 != bytes || raw.last().is_some_and(|last| *last != b'\n') {
            return Err(RuntimeError::Invalid("incomplete or changed alpha ledger; original bytes preserved; validate before restart".into()));
        }
        let mut messages = Vec::new();
        for line in raw.split_inclusive(|byte| *byte == b'\n') {
            let value: Value = serde_json::from_slice(line).map_err(|_| {
                RuntimeError::Invalid("malformed alpha ledger; original bytes preserved".into())
            })?;
            let message = parse_message(&value)
                .map_err(|_| RuntimeError::Invalid("invalid alpha ledger message".into()))?;
            if message.seq != messages.len() as u64 + 1
                || value.get("sig_verified") != Some(&Value::Bool(false))
            {
                return Err(RuntimeError::Invalid(
                    "invalid alpha ledger sequence/signature state".into(),
                ));
            }
            messages.push(value);
        }
        File::open(&root)?.sync_all()?;
        Ok(Self {
            root,
            path,
            _guard: guard,
            file,
            messages,
            write_failed: false,
            bytes,
        })
    }

    fn status(&self) -> Value {
        json!({"ok":true,"mode":"isolated-local-alpha","transport":LOCAL_TRANSPORT,
            "live_fleet":false,"signed":false,"read_only":false,"send_allowed":!self.write_failed,
            "allowed_senders":["CODEX","Brian","Nic"],"data_dir":self.root,"pid":std::process::id(),
            "total_messages":self.messages.len(),"agent_wake":false,
            "history_complete":!self.write_failed,"storage_healthy":!self.write_failed})
    }

    fn healthy(&self) -> Result<()> {
        if self.write_failed {
            Err(RuntimeError::StorageUncertain(
                "a previous append did not complete; do not resend automatically".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn messages(&self, room: &str, limit: usize) -> Result<Value> {
        self.healthy()?;
        let selected: Vec<_> = self
            .messages
            .iter()
            .filter(|m| m.get("room").and_then(Value::as_str) == Some(room))
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        Ok(bound_messages(selected)?.0)
    }

    fn send(&mut self, request: &SendRequest) -> Result<Value> {
        self.send_with(request, |file, bytes| {
            file.write_all(bytes)?;
            file.sync_all()
        })
    }

    fn send_with<F>(&mut self, request: &SendRequest, persist: F) -> Result<Value>
    where
        F: FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    {
        self.healthy()?;
        let now = chrono::Utc::now();
        let seq = self.messages.len() as u64 + 1;
        let digest = format!("{:x}", Sha256::digest(request.body.as_bytes()));
        let id_digest = format!(
            "{:x}",
            Sha256::digest(format!(
                "{}:{}:{}:{}",
                now.timestamp_nanos_opt().unwrap_or_default(),
                std::process::id(),
                seq,
                digest
            ))
        );
        let message = json!({"id":format!("alpha-{}", &id_digest[..32]),"seq":seq,
            "ts_unix":now.timestamp(),"ts_iso":now.to_rfc3339(),"room":request.room,
            "sender":request.sender,"body":request.body,"to":request.to,"task_id":request.task_id,
            "sender_cast":if request.sender == "CODEX" {"■"} else {"●"},
            "sender_endpoint_id":"isolated-local-alpha","digest_sha256":digest,
            "pubkey_ed25519":null,"signature_ed25519":null,"sig_verified":false});
        let mut encoded = serde_json::to_vec(&message).map_err(json_error)?;
        encoded.push(b'\n');
        if self.bytes + encoded.len() as u64 > MAX_LEDGER {
            return Err(RuntimeError::Invalid(
                "alpha ledger full; preserve/archive it before a new run".into(),
            ));
        }
        self.messages.try_reserve(1).map_err(|_| {
            RuntimeError::Unavailable("not enough memory to append alpha message".into())
        })?;
        let on_disk = fs::symlink_metadata(&self.path)?;
        let opened = self.file.metadata()?;
        if !on_disk.file_type().is_file()
            || on_disk.ino() != opened.ino()
            || on_disk.dev() != opened.dev()
            || opened.len() != self.bytes
        {
            self.write_failed = true;
            return Err(RuntimeError::StorageUncertain(
                "ledger changed outside its owner".into(),
            ));
        }
        // Poison before any persistence can happen. Only the complete durable
        // append plus in-memory reconciliation clears this flag.
        self.write_failed = true;
        persist(&mut self.file, &encoded)
            .map_err(|error| RuntimeError::StorageUncertain(error.to_string()))?;
        self.bytes += encoded.len() as u64;
        self.messages.push(message.clone());
        self.write_failed = false;
        Ok(json!({"ok":true,"message":message,"ack":{
            "ok":true,"seq":seq,"message_id":message["id"],"room":request.room,
            "transport":LOCAL_TRANSPORT,"sig_verified":false,"subscribers_notified":0,
            "daemon_endpoint_id":"isolated-local-alpha"}}))
    }
}

#[derive(Serialize)]
struct Diagnostic {
    observed_at: String,
    file_bytes_at_open: u64,
    tail_start: u64,
    bytes_read: usize,
    byte_limit: u64,
    bounded_tail: bool,
    leading_fragment_discarded: bool,
    trailing_partial_line_skipped: bool,
    malformed_lines_skipped: usize,
    invalid_messages_skipped: usize,
    blank_lines_skipped: usize,
    valid_messages_in_tail: usize,
    changed_during_read: bool,
    complete_ledger_coverage: bool,
    coverage_scope: &'static str,
}

struct Snapshot {
    messages: Vec<BusMessage>,
    diagnostic: Diagnostic,
}

fn parse_message(value: &Value) -> std::result::Result<BusMessage, ()> {
    let mut message: BusMessage = serde_json::from_value(value.clone()).map_err(|_| ())?;
    if message.id.trim().is_empty() || message.seq == 0 || message.sender.trim().is_empty() {
        return Err(());
    }
    // Stored signature assertions are not a cryptographic verification by this reader.
    message.sig_verified = false;
    Ok(message)
}

fn read_shared(path: &Path) -> Result<Snapshot> {
    if !path.is_absolute() {
        return Err(RuntimeError::Invalid(
            "ledger must be an exact absolute path".into(),
        ));
    }
    let mut file = open_regular(path, false, false)?;
    let before = file.metadata()?;
    let start = before.len().saturating_sub(MAX_TAIL);
    file.seek(SeekFrom::Start(start))?;
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take(before.len() - start)
        .read_to_end(&mut raw)?;
    let after = file.metadata()?;
    let mut diagnostic = Diagnostic {
        observed_at: chrono::Utc::now().to_rfc3339(),
        file_bytes_at_open: before.len(),
        tail_start: start,
        bytes_read: raw.len(),
        byte_limit: MAX_TAIL,
        bounded_tail: start > 0,
        leading_fragment_discarded: start > 0,
        trailing_partial_line_skipped: false,
        malformed_lines_skipped: 0,
        invalid_messages_skipped: 0,
        blank_lines_skipped: 0,
        valid_messages_in_tail: 0,
        changed_during_read: before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || raw.len() as u64 != before.len() - start,
        complete_ledger_coverage: false,
        coverage_scope: "complete JSONL records inside the bounded byte window; no network or signature verification",
    };
    let mut records = raw.as_slice();
    if start > 0 {
        records = records
            .iter()
            .position(|b| *b == b'\n')
            .map_or(&[], |position| &records[position + 1..]);
    }
    if !records.is_empty() && !records.ends_with(b"\n") {
        diagnostic.trailing_partial_line_skipped = true;
        records = records
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(&[], |position| &records[..position + 1]);
    }
    let mut messages = Vec::new();
    for line in records.split_inclusive(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            diagnostic.blank_lines_skipped += 1;
            continue;
        }
        match serde_json::from_slice::<Value>(line) {
            Err(_) => diagnostic.malformed_lines_skipped += 1,
            Ok(value) => match parse_message(&value) {
                Ok(message) => messages.push(message),
                Err(_) => diagnostic.invalid_messages_skipped += 1,
            },
        }
    }
    diagnostic.valid_messages_in_tail = messages.len();
    diagnostic.complete_ledger_coverage = !(diagnostic.bounded_tail
        || diagnostic.trailing_partial_line_skipped
        || diagnostic.malformed_lines_skipped > 0
        || diagnostic.invalid_messages_skipped > 0
        || diagnostic.changed_during_read);
    Ok(Snapshot {
        messages,
        diagnostic,
    })
}

fn bound_messages<T: Serialize>(messages: Vec<T>) -> Result<(Value, usize, usize)> {
    let mut payload = serde_json::to_value(messages).map_err(json_error)?;
    let mut dropped = 0;
    loop {
        let bytes = serde_json::to_vec(&payload).map_err(json_error)?.len();
        if bytes <= MAX_RESPONSE {
            return Ok((payload, dropped, bytes));
        }
        payload
            .as_array_mut()
            .ok_or_else(|| RuntimeError::Unavailable("invalid internal message array".into()))?
            .remove(0);
        dropped += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chinwag_bus_client::BusAck;
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;

    #[tokio::test]
    async fn default_router_has_no_http_mcp_or_protocol_observation_route() {
        use tower::ServiceExt;
        let temp = TempDir::new().unwrap();
        let ledger = temp.path().join("messages.jsonl");
        fs::write(&ledger, b"").unwrap();
        let app = router(RuntimeConfig {
            bind: "127.0.0.1:44341".parse().unwrap(),
            mode: RuntimeMode::Shared {
                ledger,
                signed_sender: None,
                journal_dir: None,
            },
        })
        .unwrap();
        for path in ["/api/mcp", "/api/onboarding/mcp-http/status"] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(path)
                        .header("host", "127.0.0.1:44341")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_status_projects_the_original_protocol_holder_without_reading_the_bus() {
        use tower::ServiceExt;
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let bus_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        bus_listener.set_nonblocking(true).unwrap();
        let authority = bus_listener.local_addr().unwrap().to_string();
        let host = Arc::new(Mutex::new(ConnectorHost::new(
            Registry::new(Limits {
                max_grants: 1,
                max_bindings: 1,
                max_lease: Duration::from_secs(900),
            })
            .unwrap(),
        )));
        let capability = root.join("new-capability.json");
        let owner =
            crate::mcp::HttpMcpOwner::start(&format!("http://{authority}"), host, &capability)
                .await
                .unwrap();
        let document: Value = serde_json::from_slice(&fs::read(&capability).unwrap()).unwrap();
        let authorization = document["headers"]["Authorization"].as_str().unwrap();
        let app = http_mcp_routes(owner.transport(), authority.clone());
        let request = |value: Value, session: Option<&str>| {
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri("/api/mcp")
                .header("host", &authority)
                .header("authorization", authorization)
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .header("mcp-protocol-version", "2025-11-25");
            if let Some(session) = session {
                request = request.header("mcp-session-id", session);
            }
            request
                .body(axum::body::Body::from(serde_json::to_vec(&value).unwrap()))
                .unwrap()
        };
        let initialized = app
            .clone()
            .oneshot(request(
                json!({
                    "jsonrpc":"2.0", "id":1, "method":"initialize", "params": {
                        "protocolVersion":"2025-11-25", "capabilities":{},
                        "clientInfo":{"name":"synthetic-runtime-fixture","version":"fixture"}
                    }
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(initialized.status(), StatusCode::OK);
        let session = initialized
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        axum::body::to_bytes(initialized.into_body(), 65_536)
            .await
            .unwrap();
        let catalogue = app.clone().oneshot(request(json!({
            "jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{"_meta":{"progressToken":2}}
        }), Some(&session))).await.unwrap();
        assert_eq!(catalogue.status(), StatusCode::OK);
        axum::body::to_bytes(catalogue.into_body(), 65_536)
            .await
            .unwrap();
        for (method, path, intent, expected) in [
            (
                "GET",
                "/api/onboarding/mcp-http/status",
                false,
                StatusCode::FORBIDDEN,
            ),
            (
                "HEAD",
                "/api/onboarding/mcp-http/status",
                true,
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                "GET",
                "/api/onboarding/mcp-http/status?refresh=1",
                true,
                StatusCode::FORBIDDEN,
            ),
            (
                "GET",
                "/api/onboarding/mcp-http/status",
                true,
                StatusCode::OK,
            ),
        ] {
            let mut request = axum::http::Request::builder()
                .method(method)
                .uri(path)
                .header("host", &authority);
            if intent {
                request = request.header("x-chinwag-onboarding-intent", "1");
            }
            let response = app
                .clone()
                .oneshot(request.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            if expected == StatusCode::OK {
                let bytes = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                let status: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(
                    status["transport"],
                    serde_json::to_value(owner.transport().lifecycle_snapshot()).unwrap()
                );
                assert_eq!(
                    status["transport"]["connection_observation"]["catalogue_outputs_prepared"],
                    1
                );
                assert_eq!(
                    status["transport"]["connection_observation"]["read_windows_prepared"],
                    0
                );
                let text = std::str::from_utf8(&bytes).unwrap();
                assert!(!text.contains(authorization.strip_prefix("Bearer ").unwrap()));
                assert!(!text.contains("synthetic-runtime-fixture"));
                assert!(!text.contains(&session));
            }
        }
        assert!(
            matches!(bus_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        owner.shutdown().await.unwrap();
        assert!(owner.transport().lifecycle_snapshot().reader_worker_joined);
    }

    fn request_value() -> SendRequest {
        SendRequest {
            sender: "Brian".into(),
            room: "#alpha".into(),
            body: "  drive the alpha 🦀  ".into(),
            to: None,
            task_id: None,
        }
    }

    fn record(seq: u64, room: &str, body: &str) -> Value {
        json!({"id":format!("old-{seq}"),"seq":seq,"ts_iso":"2026-10-30T00:00:00Z",
            "sender":"Brian","room":room,"body":body,"to":null,"task_id":null,"sig_verified":false})
    }

    fn write_records(path: &Path, values: &[Value]) {
        let bytes = values
            .iter()
            .map(|v| format!("{}\n", serde_json::to_string(v).unwrap()))
            .collect::<String>();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn isolated_persists_legacy_wire_and_retains_exclusive_ownership() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("messages.jsonl");
        let mut old = record(1, "#alpha", "before Rust");
        old["historical_extra"] = json!("preserved");
        write_records(&path, &[old.clone()]);
        let mut ledger = LocalLedger::open(root.path().into()).unwrap();
        assert!(LocalLedger::open(root.path().into()).is_err());
        let value = ledger.send(&request_value()).unwrap();
        assert_eq!(value["message"]["seq"], 2);
        assert_eq!(value["message"]["body"], request_value().body);
        assert_eq!(value["message"]["sig_verified"], false);
        assert_eq!(value["ack"]["transport"], LOCAL_TRANSPORT);
        assert_eq!(value["ack"]["subscribers_notified"], 0);
        assert_eq!(ledger.messages("#alpha", 100).unwrap()[0], old);
        assert_eq!(ledger.status()["data_dir"], root.path().to_str().unwrap());
        assert_eq!(ledger.status()["storage_healthy"], true);
        assert_eq!(ledger.status()["pid"], std::process::id());
        drop(ledger);
        let reloaded = LocalLedger::open(root.path().into()).unwrap();
        assert_eq!(
            reloaded
                .messages("#alpha", 100)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            reloaded.messages("#alpha", 100).unwrap()[0]["historical_extra"],
            "preserved"
        );
        assert!(fs::read(&path).unwrap().ends_with(b"\n"));
    }

    #[test]
    fn torn_tail_fails_closed_preserves_bytes_and_releases_initialization_lock() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("messages.jsonl");
        let bytes = serde_json::to_vec(&record(1, "#alpha", "not yet committed")).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(LocalLedger::open(root.path().into()).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        write_records(&path, &[record(1, "#alpha", "validated by test")]);
        assert!(LocalLedger::open(root.path().into()).is_ok());
    }

    #[test]
    fn ledger_owner_drop_releases_lock_with_a_retained_file_description() {
        let root = TempDir::new().unwrap();
        let ledger = LocalLedger::open(root.path().into()).unwrap();
        // Models an inherited open-file description retained across an unrelated spawn.
        let inherited = ledger._guard.0.try_clone().unwrap();
        assert!(LocalLedger::open(root.path().into()).is_err());
        drop(ledger);
        let reopened = LocalLedger::open(root.path().into()).unwrap();
        assert_eq!(reopened.status()["storage_healthy"], true);
        drop(inherited);
        assert!(LocalLedger::open(root.path().into()).is_err());
    }

    #[test]
    fn uncertain_sync_poison_prevents_history_and_sequence_reuse_until_restart() {
        let root = TempDir::new().unwrap();
        let mut ledger = LocalLedger::open(root.path().into()).unwrap();
        let error = ledger
            .send_with(&request_value(), |file, bytes| {
                file.write_all(bytes)?;
                Err(std::io::Error::other("injected fsync failure"))
            })
            .unwrap_err();
        assert!(matches!(error, RuntimeError::StorageUncertain(_)));
        assert!(ledger.send(&request_value()).is_err());
        assert!(ledger.messages("#alpha", 100).is_err());
        assert_eq!(ledger.status()["storage_healthy"], false);
        assert_eq!(ledger.status()["history_complete"], false);
        assert_eq!(
            fs::read_to_string(root.path().join("messages.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        drop(ledger);
        let mut restarted = LocalLedger::open(root.path().into()).unwrap();
        assert_eq!(
            restarted.send(&request_value()).unwrap()["message"]["seq"],
            2
        );
    }

    #[test]
    fn partial_append_poison_is_preserved_across_restart() {
        let root = TempDir::new().unwrap();
        let mut ledger = LocalLedger::open(root.path().into()).unwrap();
        assert!(
            ledger
                .send_with(&request_value(), |file, bytes| {
                    file.write_all(&bytes[..bytes.len() / 2])?;
                    Err(std::io::Error::other("injected short append"))
                })
                .is_err()
        );
        assert!(ledger.send(&request_value()).is_err());
        let before = fs::read(root.path().join("messages.jsonl")).unwrap();
        drop(ledger);
        assert!(LocalLedger::open(root.path().into()).is_err());
        assert_eq!(
            fs::read(root.path().join("messages.jsonl")).unwrap(),
            before
        );
    }

    #[test]
    fn external_ledger_change_poison_prevents_false_history() {
        let root = TempDir::new().unwrap();
        let mut ledger = LocalLedger::open(root.path().into()).unwrap();
        fs::write(root.path().join("messages.jsonl"), "external\n").unwrap();
        assert!(matches!(
            ledger.send(&request_value()),
            Err(RuntimeError::StorageUncertain(_))
        ));
        assert!(ledger.messages("#alpha", 10).is_err());
    }

    #[test]
    fn invalid_local_sequences_signatures_and_symlinks_are_rejected() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("messages.jsonl");
        write_records(&path, &[record(2, "#alpha", "gap")]);
        assert!(LocalLedger::open(root.path().into()).is_err());
        let mut signed = record(1, "#alpha", "signed");
        signed["sig_verified"] = json!(true);
        write_records(&path, &[signed]);
        assert!(LocalLedger::open(root.path().into()).is_err());
        fs::remove_file(&path).unwrap();
        let outside = root.path().join("outside");
        fs::write(&outside, b"untouched").unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(LocalLedger::open(root.path().into()).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"untouched");
    }

    #[test]
    fn shared_tail_is_bounded_and_preserves_messages_without_inheriting_signature_claims() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("fleet.jsonl");
        let mut file = File::create(&path).unwrap();
        file.write_all(&vec![b'x'; MAX_TAIL as usize + 23]).unwrap();
        file.write_all(b"\n").unwrap();
        let mut value = record(77, "#mgmt", "shared body 🦀");
        value["sig_verified"] = json!(true);
        writeln!(file, "{value}").unwrap();
        let before = fs::metadata(&path).unwrap();
        let snapshot = read_shared(&path).unwrap();
        assert_eq!(snapshot.messages.len(), 1);
        assert_eq!(snapshot.messages[0].id, "old-77");
        assert_eq!(snapshot.messages[0].seq, 77);
        assert_eq!(snapshot.messages[0].body, "shared body 🦀");
        assert!(!snapshot.messages[0].sig_verified);
        assert_eq!(snapshot.diagnostic.bytes_read, MAX_TAIL as usize);
        assert!(snapshot.diagnostic.bounded_tail);
        assert!(snapshot.diagnostic.leading_fragment_discarded);
        assert!(!snapshot.diagnostic.complete_ledger_coverage);
        let after = fs::metadata(&path).unwrap();
        assert_eq!(before.len(), after.len());
        assert_eq!(before.mtime_nsec(), after.mtime_nsec());
        assert_eq!(before.mode(), after.mode());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn shared_malformed_invalid_and_uncommitted_records_are_counted_and_skipped() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("fleet.jsonl");
        let mut bytes = format!("{}\n", record(4, "#eng", "valid")).into_bytes();
        bytes.extend_from_slice(b"not json\n\xff\n\n{\"id\":\"invalid\",\"seq\":true}\n");
        bytes.extend_from_slice(
            serde_json::to_string(&record(5, "#eng", "partial"))
                .unwrap()
                .as_bytes(),
        );
        fs::write(&path, bytes).unwrap();
        let snapshot = read_shared(&path).unwrap();
        assert_eq!(snapshot.messages.len(), 1);
        assert_eq!(snapshot.diagnostic.malformed_lines_skipped, 2);
        assert_eq!(snapshot.diagnostic.invalid_messages_skipped, 1);
        assert_eq!(snapshot.diagnostic.blank_lines_skipped, 1);
        assert!(snapshot.diagnostic.trailing_partial_line_skipped);
        assert!(!snapshot.diagnostic.complete_ledger_coverage);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert_eq!(read_shared(&path).unwrap().messages.len(), 2);
    }

    #[test]
    fn shared_exact_path_rejects_relative_symlink_directory_and_missing() {
        assert!(read_shared(Path::new("relative.jsonl")).is_err());
        let root = TempDir::new().unwrap();
        assert!(read_shared(root.path()).is_err());
        assert!(read_shared(&root.path().join("missing")).is_err());
        let target = root.path().join("target");
        fs::write(&target, b"").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_shared(&link).is_err());
        assert_eq!(fs::read(target).unwrap(), b"");
    }

    struct Server {
        addr: SocketAddr,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl Server {
        async fn stop(mut self) {
            self.task.abort();
            let _ = (&mut self.task).await;
        }
        async fn start(mode: RuntimeMode) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let app = router(RuntimeConfig { bind: addr, mode }).unwrap();
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self { addr, task }
        }
        async fn start_with_discovery(mode: RuntimeMode, source: Arc<dyn InventorySource>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let app = router_with_discovery(RuntimeConfig { bind: addr, mode }, source).unwrap();
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self { addr, task }
        }
        async fn http(&self, method: &str, path: &str, headers: &str, body: &str) -> (u16, Value) {
            let addr = self.addr;
            let request = format!(
                "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
                body.len()
            );
            tokio::task::spawn_blocking(move || {
                let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream.write_all(request.as_bytes()).unwrap();
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).unwrap();
                let result = String::from_utf8(bytes).unwrap();
                let (head, body) = result.split_once("\r\n\r\n").unwrap();
                let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
                let value = serde_json::from_str(body).unwrap_or_else(|_| json!({"raw":body}));
                (status, value)
            })
            .await
            .unwrap()
        }
    }

    struct FixtureInventory {
        calls: AtomicUsize,
        result: std::result::Result<chinwag_client_discovery::InventorySnapshot, DiscoveryFailure>,
    }
    impl InventorySource for FixtureInventory {
        fn snapshot(
            &self,
        ) -> std::result::Result<chinwag_client_discovery::InventorySnapshot, DiscoveryFailure>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }
    const DISCOVERY_INTENT: &str = "X-Chinwag-Discovery-Intent: 1\r\n";

    #[tokio::test]
    async fn discovery_details_are_negotiated_before_collection_and_preserve_legacy_rows() {
        use axum::body::{Body, to_bytes};
        use axum::http::Request;
        use chinwag_client_discovery::*;
        use tower::ServiceExt;

        struct Source {
            processes: AtomicUsize,
            installations: AtomicUsize,
        }
        impl InventorySource for Source {
            fn snapshot(&self) -> std::result::Result<InventorySnapshot, DiscoveryFailure> {
                self.processes.fetch_add(1, Ordering::SeqCst);
                Ok(crate::discovery::fixture_snapshot())
            }

            fn installed(&self) -> Option<InstalledSnapshot> {
                self.installations.fetch_add(1, Ordering::SeqCst);
                Some(InstalledSnapshot {
                    observed_at_unix_ms: 1_793_398_000_321,
                    installations: vec![Installation {
                        id: "a".repeat(64),
                        family: ClientFamily::GrokBot,
                        kind: InstallationKind::Application,
                        match_basis: catalogue::InstallationMatch::PublicBundleIdentity,
                        canonical_path:
                            "/Users/private-account-marker/Applications/Private-marker-client.app"
                                .into(),
                        observed_paths: vec![
                            "/Users/private-account-marker/Applications/Private-marker-client.app"
                                .into(),
                        ],
                        display_name: "Private-marker-client".into(),
                        bundle_id: Some("private-bundle-marker".into()),
                        version: Some("  v1.2.3-beta+4 (arm64)  ".into()),
                        executable_path:
                            "/Users/private-account-marker/Applications/Private-marker-client.app/Contents/MacOS/Private-marker-client"
                                .into(),
                        executable: ExecutableMetadata {
                            device: 1,
                            inode: 2,
                            size: 100,
                            modified_seconds: 1,
                            modified_nanoseconds: 0,
                            mode: 0o755,
                            format: ExecutableFormat::MachO,
                        },
                        metadata_fingerprint: "private-fingerprint-marker".into(),
                    }],
                    coverage: InstalledCoverage {
                        installation_capacity: 128,
                        ..InstalledCoverage::default()
                    },
                    limitations: vec!["private-install-diagnostic-marker".into()],
                })
            }
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyInstalledClient {
            id: String,
            family: String,
            kind: String,
            running_instances: usize,
            state: String,
        }

        fn request(details: &[&str]) -> Request<Body> {
            let mut request = Request::builder()
                .uri("/api/bus/clients")
                .header("host", "127.0.0.1:44339")
                .header("x-chinwag-discovery-intent", "1")
                .body(Body::empty())
                .unwrap();
            for detail in details {
                request
                    .headers_mut()
                    .append("x-chinwag-discovery-details", detail.parse().unwrap());
            }
            request
        }

        let directory = TempDir::new().unwrap();
        let source = Arc::new(Source {
            processes: AtomicUsize::new(0),
            installations: AtomicUsize::new(0),
        });
        let app = router_with_discovery(
            RuntimeConfig {
                bind: "127.0.0.1:44339".parse().unwrap(),
                mode: RuntimeMode::Isolated {
                    data_dir: directory.path().into(),
                },
            },
            source.clone(),
        )
        .unwrap();

        for details in [
            vec![""],
            vec!["0"],
            vec!["2"],
            vec!["01"],
            vec!["1, 1"],
            vec!["1", "1"],
            vec!["0", "1"],
        ] {
            let response = app.clone().oneshot(request(&details)).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        assert_eq!(source.processes.load(Ordering::SeqCst), 0);
        assert_eq!(source.installations.load(Ordering::SeqCst), 0);

        let response = app.clone().oneshot(request(&[])).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let legacy_bytes = to_bytes(response.into_body(), 20_000).await.unwrap();
        let legacy: Value = serde_json::from_slice(&legacy_bytes).unwrap();
        let row = &legacy["installations"]["apps"][0];
        assert!(row.get("location").is_none());
        assert!(row.get("version").is_none());
        let old_row: LegacyInstalledClient = serde_json::from_value(row.clone()).unwrap();
        assert_eq!(old_row.id.len(), 64);
        assert_eq!(old_row.family, "grok_bot");
        assert_eq!(old_row.kind, "application");
        assert_eq!(old_row.running_instances, 0);
        assert_eq!(old_row.state, "installed_unverified");
        assert_eq!(source.processes.load(Ordering::SeqCst), 1);
        assert_eq!(source.installations.load(Ordering::SeqCst), 1);

        let response = app.oneshot(request(&["1"])).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let detailed_bytes = to_bytes(response.into_body(), 20_000).await.unwrap();
        let detailed: Value = serde_json::from_slice(&detailed_bytes).unwrap();
        let row = &detailed["installations"]["apps"][0];
        assert_eq!(row["id"], old_row.id);
        assert_eq!(row["location"], "user_applications");
        assert_eq!(row["version"], "v1.2.3-beta+4 (arm64)");
        let typed: chinwag_bus_client::ClientInventory =
            serde_json::from_value(detailed.clone()).unwrap();
        typed.validate().unwrap();
        assert_eq!(source.processes.load(Ordering::SeqCst), 2);
        assert_eq!(source.installations.load(Ordering::SeqCst), 2);

        for value in [legacy, detailed] {
            let raw = value.to_string();
            for forbidden in [
                "/Users",
                "/Applications",
                "private-account-marker",
                "Private-marker-client",
                "private-bundle-marker",
                "private-fingerprint-marker",
                "private-install-diagnostic-marker",
                "canonical_path",
                "executable_path",
                "bundle_id",
            ] {
                assert!(
                    !raw.contains(forbidden),
                    "raw metadata escaped: {forbidden}"
                );
            }
        }
    }

    #[tokio::test]
    async fn discovery_http_rejects_method_host_origin_and_intent_before_the_provider() {
        let directory = TempDir::new().unwrap();
        let source = Arc::new(FixtureInventory {
            calls: AtomicUsize::new(0),
            result: Ok(crate::discovery::fixture_snapshot()),
        });
        let server = Server::start_with_discovery(
            RuntimeMode::Isolated {
                data_dir: directory.path().into(),
            },
            source.clone(),
        )
        .await;
        assert_eq!(server.http("GET", "/api/bus/status", "", "").await.0, 200);
        assert_eq!(server.http("GET", "/api/bus/messages", "", "").await.0, 200);
        for headers in [
            "".to_owned(),
            "X-Chinwag-Discovery-Intent: 0\r\n".to_owned(),
            format!("{DISCOVERY_INTENT}{DISCOVERY_INTENT}"),
            format!("{DISCOVERY_INTENT}Origin: https://example.test\r\n"),
            format!("{DISCOVERY_INTENT}Host: example.test\r\n"),
        ] {
            assert_eq!(
                server.http("GET", "/api/bus/clients", &headers, "").await.0,
                403
            );
        }
        for method in ["HEAD", "POST", "PUT", "DELETE", "OPTIONS"] {
            assert_eq!(
                server
                    .http(
                        method,
                        "/api/bus/clients",
                        DISCOVERY_INTENT,
                        "not a JSON request"
                    )
                    .await
                    .0,
                405
            );
        }
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn discovery_http_returns_only_the_sanitized_typed_projection_on_explicit_request() {
        let directory = TempDir::new().unwrap();
        let source = Arc::new(FixtureInventory {
            calls: AtomicUsize::new(0),
            result: Ok(crate::discovery::fixture_snapshot()),
        });
        let server = Server::start_with_discovery(
            RuntimeMode::Isolated {
                data_dir: directory.path().into(),
            },
            source.clone(),
        )
        .await;
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
        let (code, value) = server
            .http("GET", "/api/bus/clients", DISCOVERY_INTENT, "")
            .await;
        assert_eq!(code, 200);
        let inventory: chinwag_bus_client::ClientInventory =
            serde_json::from_value(value.clone()).unwrap();
        inventory.validate().unwrap();
        assert_eq!(inventory.clients.len(), 1);
        assert_eq!(inventory.clients[0].component_count, 2);
        assert_eq!(inventory.coverage.candidate_process_count, 2);
        assert_eq!(inventory.observed_at_unix_ms, 1_793_398_000_123);
        assert_eq!(inventory.host_label, "observed-fixture-host");
        let text = value.to_string();
        for forbidden in [
            "Private-marker-client",
            "private-boot-identity-marker",
            "private-raw-diagnostic-marker",
            "948123",
            "887321",
            "executable",
            "parent_pid",
            "boot_uuid",
            "process_group",
        ] {
            assert!(!text.contains(forbidden));
        }
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn discovery_http_failure_is_safe_and_is_not_an_empty_success() {
        for result in [Err(DiscoveryFailure::Unavailable), {
            let mut invalid = crate::discovery::fixture_snapshot();
            invalid.coverage.sampled_pid_count = 0;
            Ok(invalid)
        }] {
            let directory = TempDir::new().unwrap();
            let source = Arc::new(FixtureInventory {
                calls: AtomicUsize::new(0),
                result,
            });
            let server = Server::start_with_discovery(
                RuntimeMode::Isolated {
                    data_dir: directory.path().into(),
                },
                source.clone(),
            )
            .await;
            let (code, value) = server
                .http("GET", "/api/bus/clients", DISCOVERY_INTENT, "")
                .await;
            assert_eq!(code, 503);
            assert_eq!(value["ok"], false);
            assert!(value.get("clients").is_none());
            assert!(!value.to_string().contains("private"));
            assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        }
    }

    struct HoldingInventory {
        calls: AtomicUsize,
        entered: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl InventorySource for HoldingInventory {
        fn snapshot(
            &self,
        ) -> std::result::Result<chinwag_client_discovery::InventorySnapshot, DiscoveryFailure>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered
                .send(())
                .map_err(|_| DiscoveryFailure::Unavailable)?;
            self.release
                .lock()
                .map_err(|_| DiscoveryFailure::Unavailable)?
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| DiscoveryFailure::Unavailable)?;
            Ok(crate::discovery::fixture_snapshot())
        }
    }

    #[tokio::test]
    async fn overlapping_discovery_returns_busy_without_a_second_source_read() {
        let directory = TempDir::new().unwrap();
        let (entered, waiting) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let source = Arc::new(HoldingInventory {
            calls: AtomicUsize::new(0),
            entered,
            release: Mutex::new(released),
        });
        let server = Arc::new(
            Server::start_with_discovery(
                RuntimeMode::Isolated {
                    data_dir: directory.path().into(),
                },
                source.clone(),
            )
            .await,
        );
        let first = {
            let server = server.clone();
            tokio::spawn(async move {
                server
                    .http("GET", "/api/bus/clients", DISCOVERY_INTENT, "")
                    .await
            })
        };
        tokio::task::spawn_blocking(move || waiting.recv_timeout(Duration::from_secs(3)).unwrap())
            .await
            .unwrap();
        let (code, value) = server
            .http("GET", "/api/bus/clients", DISCOVERY_INTENT, "")
            .await;
        assert_eq!(code, 409);
        assert!(value["error"].as_str().unwrap().contains("already active"));
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        release.send(()).unwrap();
        assert_eq!(first.await.unwrap().0, 200);
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }

    fn wire() -> Value {
        json!({"sender":"Brian","room":"#alpha","body":"human action","wake":false,"to":null,"task_id":null})
    }
    const INTENT: &str = "Content-Type: application/json\r\nX-Chinwag-UI-Intent: 1\r\nX-Chinwag-Request-Id: attempt-alpha-0001\r\n";

    #[tokio::test]
    async fn isolated_http_wire_status_and_native_boundaries() {
        let root = TempDir::new().unwrap();
        let server = Server::start(RuntimeMode::Isolated {
            data_dir: root.path().into(),
        })
        .await;
        let (code, status) = server.http("GET", "/api/bus/status", "", "").await;
        assert_eq!(code, 200);
        assert_eq!(status["mode"], "isolated-local-alpha");
        assert_eq!(status["storage_healthy"], true);
        assert_eq!(status["signed"], false);
        assert_eq!(status["live_fleet"], false);
        assert_eq!(
            server
                .http("POST", "/api/bus/send", "", &wire().to_string())
                .await
                .0,
            403
        );
        assert_eq!(
            server
                .http(
                    "POST",
                    "/api/bus/send",
                    &format!("{INTENT}Origin: https://example.test\r\n"),
                    &wire().to_string()
                )
                .await
                .0,
            403
        );
        assert_eq!(
            server
                .http("GET", "/api/bus/status", "Host: example.test\r\n", "")
                .await
                .0,
            403
        );
        let (code, value) = server
            .http("POST", "/api/bus/send", INTENT, &wire().to_string())
            .await;
        assert_eq!(code, 200);
        assert_eq!(value["ack"]["transport"], LOCAL_TRANSPORT);
        assert_eq!(value["message"]["seq"], 1);
        let (code, history) = server
            .http("GET", "/api/bus/messages?room=%23alpha&limit=1", "", "")
            .await;
        assert_eq!(code, 200);
        assert_eq!(history[0]["id"], value["message"]["id"]);
        assert_eq!(
            server
                .http("GET", "/api/bus/messages?room=%23qa", "", "")
                .await
                .1,
            json!([])
        );
    }

    #[tokio::test]
    async fn shared_http_room_filter_updates_bounds_and_post_denial() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("fleet.jsonl");
        write_records(
            &path,
            &[
                record(1, "#mgmt", "one"),
                record(2, "#qa", "other"),
                record(3, "#mgmt", "three"),
            ],
        );
        let before = fs::read(&path).unwrap();
        let server = Server::start(RuntimeMode::Shared {
            ledger: path.clone(),
            signed_sender: None,
            journal_dir: None,
        })
        .await;
        let (code, status) = server.http("GET", "/api/bus/status", "", "").await;
        assert_eq!(code, 200);
        assert_eq!(status["mode"], "fleet-ledger-read-only");
        assert_eq!(status["read_only"], true);
        assert_eq!(status["send_allowed"], false);
        assert_eq!(status["signatures_verified"], false);
        assert_eq!(status["network_delivery_verified"], false);
        let (code, messages) = server
            .http("GET", "/api/bus/messages?room=%23mgmt&limit=1", "", "")
            .await;
        assert_eq!(code, 200);
        assert_eq!(messages.as_array().unwrap().len(), 1);
        assert_eq!(messages[0]["seq"], 3);
        assert_eq!(
            server
                .http("POST", "/api/bus/send", INTENT, &wire().to_string())
                .await
                .0,
            405
        );
        assert_eq!(server.http("POST", "/anything", "", "").await.0, 405);
        assert_eq!(fs::read(&path).unwrap(), before);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(file, "{}", record(4, "#mgmt", "new append")).unwrap();
        let (_, messages) = server
            .http("GET", "/api/bus/messages?room=%23mgmt&limit=100", "", "")
            .await;
        assert_eq!(messages.as_array().unwrap().len(), 3);
        assert_eq!(messages[2]["seq"], 4);
        for query in [
            "room=%23wrong",
            "limit=0",
            "limit=101",
            "limit=x",
            "room=%23qa&room=%23mgmt",
            "limit=1&limit=2",
            "extra=yes",
        ] {
            assert_eq!(
                server
                    .http("GET", &format!("/api/bus/messages?{query}"), "", "")
                    .await
                    .0,
                400,
                "{query}"
            );
        }
        fs::remove_file(&path).unwrap();
        assert_eq!(
            server
                .http("GET", "/api/bus/messages?room=%23mgmt", "", "")
                .await
                .0,
            503
        );
        assert_eq!(server.http("GET", "/api/bus/status", "", "").await.0, 503);
    }

    #[tokio::test]
    async fn shared_response_cap_reports_dropped_messages_and_incomplete_room_coverage() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("fleet.jsonl");
        write_records(
            &path,
            &[
                record(1, "#mgmt", &"a".repeat(470_000)),
                record(2, "#mgmt", &"b".repeat(470_000)),
            ],
        );
        let server = Server::start(RuntimeMode::Shared {
            ledger: path,
            signed_sender: None,
            journal_dir: None,
        })
        .await;
        let (code, messages) = server
            .http("GET", "/api/bus/messages?room=%23mgmt&limit=100", "", "")
            .await;
        assert_eq!(code, 200);
        assert_eq!(messages.as_array().unwrap().len(), 1);
        assert_eq!(messages[0]["seq"], 2);
        assert!(serde_json::to_vec(&messages).unwrap().len() <= MAX_RESPONSE);
        let (_, status) = server.http("GET", "/api/bus/status", "", "").await;
        assert_eq!(
            status["last_messages_query"]["response_messages_dropped"],
            1
        );
        assert_eq!(
            status["last_messages_query"]["complete_room_response"],
            false
        );
    }

    struct FakeSigner {
        calls: AtomicUsize,
        mismatch: bool,
        uncertain: bool,
    }
    impl SignedSender for FakeSigner {
        fn send(&self, request: &SendRequest) -> Result<SendReceipt> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.uncertain && call == 1 {
                return Err(RuntimeError::SendUncertain("injected lost receipt".into()));
            }
            Ok(SendReceipt {
                message: BusMessage {
                    id: "native-1".into(),
                    seq: 8,
                    ts_iso: "2026-10-30T00:00:00Z".into(),
                    room: request.room.clone(),
                    sender: request.sender.clone(),
                    body: request.body.clone(),
                    to: request.to.clone(),
                    task_id: request.task_id.clone(),
                    sig_verified: true,
                },
                ack: BusAck {
                    ok: true,
                    seq: 8,
                    message_id: if self.mismatch && call == 1 {
                        "wrong"
                    } else {
                        "native-1"
                    }
                    .into(),
                    transport: "actual-native-transport".into(),
                    room: request.room.clone(),
                    sig_verified: true,
                    subscribers_notified: 3,
                },
            })
        }
    }

    #[tokio::test]
    async fn signed_sender_called_only_for_valid_explicit_human_action_and_preserves_receipt() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("fleet.jsonl");
        fs::write(&path, b"").unwrap();
        let signer = Arc::new(FakeSigner {
            calls: AtomicUsize::new(0),
            mismatch: false,
            uncertain: false,
        });
        let server = Server::start(RuntimeMode::Shared {
            ledger: path.clone(),
            signed_sender: Some(signer.clone()),
            journal_dir: Some(root.path().join("journal")),
        })
        .await;
        let (_, status) = server.http("GET", "/api/bus/status", "", "").await;
        assert_eq!(status["mode"], "fleet-signed-ui");
        assert_eq!(status["allowed_senders"], json!(["Brian"]));
        assert_eq!(status["read_only"], false);
        server
            .http("GET", "/api/bus/messages?room=%23alpha", "", "")
            .await;
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
        for (field, value) in [
            ("sender", json!("CODEX")),
            ("sender", json!("Nic")),
            ("wake", json!(true)),
            ("room", json!("#other")),
            ("body", json!(" ")),
            ("to", json!("")),
            ("task_id", json!(" ")),
        ] {
            let mut body = wire();
            body[field] = value;
            assert!(matches!(
                server
                    .http("POST", "/api/bus/send", INTENT, &body.to_string())
                    .await
                    .0,
                400 | 403
            ));
        }
        let mut absent_wake = wire();
        absent_wake.as_object_mut().unwrap().remove("wake");
        assert_eq!(
            server
                .http("POST", "/api/bus/send", INTENT, &absent_wake.to_string())
                .await
                .0,
            400
        );
        assert_eq!(
            server
                .http(
                    "POST",
                    "/api/bus/send",
                    "Content-Type: application/json\r\n",
                    &wire().to_string()
                )
                .await
                .0,
            403
        );
        assert_eq!(
            server.http("POST", "/api/bus/send", INTENT, "{").await.0,
            400
        );
        let mut huge = wire();
        huge["body"] = json!("a".repeat(MAX_BODY + 1));
        assert_eq!(
            server
                .http("POST", "/api/bus/send", INTENT, &huge.to_string())
                .await
                .0,
            400
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
        let (code, receipt) = server
            .http("POST", "/api/bus/send", INTENT, &wire().to_string())
            .await;
        assert_eq!(code, 200);
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(receipt["ack"]["transport"], "actual-native-transport");
        assert_eq!(receipt["ack"]["sig_verified"], true);
        assert_eq!(receipt["ack"]["subscribers_notified"], 3);
        assert_eq!(receipt["message"]["sig_verified"], true);
        let (_, lookup) = server
            .http("GET", "/api/bus/sends/attempt-alpha-0001", "", "")
            .await;
        assert_eq!(lookup["state"], "delivered");
        assert_eq!(lookup["receipt"]["ack"], receipt["ack"]);
        assert_eq!(lookup["receipt"]["message"], receipt["message"]);
        assert_eq!(
            server
                .http("POST", "/api/bus/send", INTENT, &wire().to_string())
                .await
                .0,
            200
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        let mut changed = wire();
        changed["body"] = json!("different content");
        assert_eq!(
            server
                .http("POST", "/api/bus/send", INTENT, &changed.to_string())
                .await
                .0,
            409
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            server
                .http("GET", "/api/bus/sends/unknown-attempt-0001", "", "")
                .await
                .0,
            404
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read(path).unwrap(), b"");
    }

    #[tokio::test]
    async fn signed_uncertainty_and_mismatched_receipts_never_become_positive_ack_or_retry() {
        for (mismatch, uncertain) in [(true, false), (false, true)] {
            let root = TempDir::new().unwrap();
            let path = root.path().join("fleet.jsonl");
            fs::write(&path, b"").unwrap();
            let signer = Arc::new(FakeSigner {
                calls: AtomicUsize::new(0),
                mismatch,
                uncertain,
            });
            let server = Server::start(RuntimeMode::Shared {
                ledger: path,
                signed_sender: Some(signer.clone()),
                journal_dir: Some(root.path().join("journal")),
            })
            .await;
            let (code, value) = server
                .http("POST", "/api/bus/send", INTENT, &wire().to_string())
                .await;
            assert_eq!(code, 502);
            assert_eq!(value["ok"], false);
            assert!(value["error"].as_str().unwrap().contains("uncertain"));
            assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
            let (_, lookup) = server
                .http("GET", "/api/bus/sends/attempt-alpha-0001", "", "")
                .await;
            assert_eq!(lookup["state"], "uncertain");
            assert_eq!(
                server
                    .http("POST", "/api/bus/send", INTENT, &wire().to_string())
                    .await
                    .0,
                502
            );
            assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
            let (_, status) = server.http("GET", "/api/bus/status", "", "").await;
            assert_eq!(status["storage_healthy"], true);
            assert_eq!(status["send_allowed"], true);
            let other_id = INTENT.replace("attempt-alpha-0001", "attempt-alpha-0002");
            assert_eq!(
                server
                    .http("POST", "/api/bus/send", &other_id, &wire().to_string())
                    .await
                    .0,
                200
            );
            assert_eq!(signer.calls.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn nonloopback_bind_is_rejected_before_storage_access() {
        assert!(
            router(RuntimeConfig {
                bind: "0.0.0.0:44339".parse().unwrap(),
                mode: RuntimeMode::Isolated {
                    data_dir: "relative".into()
                }
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn isolated_http_request_id_replay_lookup_and_restart_do_not_duplicate_append() {
        let root = TempDir::new().unwrap();
        let server = Server::start(RuntimeMode::Isolated {
            data_dir: root.path().into(),
        })
        .await;
        let mut message = wire();
        message["sender"] = json!("CODEX");
        let (code, receipt) = server
            .http("POST", "/api/bus/send", INTENT, &message.to_string())
            .await;
        assert_eq!(code, 200);
        assert_eq!(receipt["state"], "delivered");
        assert_eq!(receipt["message"]["sender"], "CODEX");
        assert_eq!(receipt["message"]["sig_verified"], false);
        assert_eq!(
            server
                .http("POST", "/api/bus/send", INTENT, &message.to_string())
                .await
                .1,
            receipt
        );
        let (_, lookup) = server
            .http("GET", "/api/bus/sends/attempt-alpha-0001", "", "")
            .await;
        assert_eq!(lookup["state"], "delivered");
        assert_eq!(lookup["receipt"]["message"], receipt["message"]);
        assert_eq!(
            server.http("GET", "/api/bus/status", "", "").await.1["total_messages"],
            1
        );
        let mut changed = message.clone();
        changed["task_id"] = json!("different metadata");
        assert_eq!(
            server
                .http("POST", "/api/bus/send", INTENT, &changed.to_string())
                .await
                .0,
            409
        );
        let before = fs::read(root.path().join("messages.jsonl")).unwrap();
        server.stop().await;
        let restarted = Server::start(RuntimeMode::Isolated {
            data_dir: root.path().into(),
        })
        .await;
        assert_eq!(
            restarted
                .http("POST", "/api/bus/send", INTENT, &message.to_string())
                .await
                .1,
            receipt
        );
        assert_eq!(
            fs::read(root.path().join("messages.jsonl")).unwrap(),
            before
        );
        let second = INTENT.replace("attempt-alpha-0001", "attempt-alpha-0002");
        assert_eq!(
            restarted
                .http("POST", "/api/bus/send", &second, &message.to_string())
                .await
                .1["message"]["seq"],
            2
        );
        assert_eq!(
            restarted.http("GET", "/api/bus/status", "", "").await.1["total_messages"],
            2
        );
    }

    #[tokio::test]
    async fn request_ids_are_required_for_signed_send_and_validate_before_publication() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("fleet.jsonl");
        fs::write(&path, b"").unwrap();
        let signer = Arc::new(FakeSigner {
            calls: AtomicUsize::new(0),
            mismatch: false,
            uncertain: false,
        });
        let server = Server::start(RuntimeMode::Shared {
            ledger: path,
            signed_sender: Some(signer.clone()),
            journal_dir: Some(root.path().join("journal")),
        })
        .await;
        let native = "Content-Type: application/json\r\nX-Chinwag-UI-Intent: 1\r\n";
        assert_eq!(
            server
                .http("POST", "/api/bus/send", native, &wire().to_string())
                .await
                .0,
            400
        );
        for id in [
            "short".to_owned(),
            "../outside-operation".into(),
            "a".repeat(101),
        ] {
            assert_eq!(
                server
                    .http(
                        "POST",
                        "/api/bus/send",
                        &format!("{native}X-Chinwag-Request-Id: {id}\r\n"),
                        &wire().to_string()
                    )
                    .await
                    .0,
                400
            );
        }
        assert_eq!(
            server.http("GET", "/api/bus/sends/short", "", "").await.0,
            400
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fs::read_dir(root.path().join("journal")).unwrap().count(),
            1
        ); // ownership lock only
    }

    struct BlockingSigner {
        calls: AtomicUsize,
        started: std::sync::mpsc::SyncSender<()>,
        release: Arc<(Mutex<bool>, std::sync::Condvar)>,
        journal: PathBuf,
    }
    impl SignedSender for BlockingSigner {
        fn send(&self, request: &SendRequest) -> Result<SendReceipt> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let persisted: Value = serde_json::from_slice(
                &fs::read(self.journal.join("attempt-alpha-0001.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(persisted["state"], "pending");
            assert_eq!(persisted["request"]["body"], request.body);
            self.started.send(()).unwrap();
            let (lock, condition) = self.release.as_ref();
            let _released = condition
                .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(3), |released| {
                    !*released
                })
                .unwrap();
            FakeSigner {
                calls: AtomicUsize::new(0),
                mismatch: false,
                uncertain: false,
            }
            .send(request)
        }
    }

    #[tokio::test]
    async fn active_attempt_lookup_never_signs_and_only_active_publication_blocks_other_ids() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("fleet.jsonl");
        fs::write(&path, b"").unwrap();
        let (started, received) = std::sync::mpsc::sync_channel(1);
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let signer = Arc::new(BlockingSigner {
            calls: AtomicUsize::new(0),
            started,
            release: release.clone(),
            journal: root.path().join("journal"),
        });
        let server = Arc::new(
            Server::start(RuntimeMode::Shared {
                ledger: path,
                signed_sender: Some(signer.clone()),
                journal_dir: Some(root.path().join("journal")),
            })
            .await,
        );
        let first_server = server.clone();
        let first = tokio::spawn(async move {
            first_server
                .http("POST", "/api/bus/send", INTENT, &wire().to_string())
                .await
        });
        tokio::task::spawn_blocking(move || received.recv_timeout(Duration::from_secs(2)).unwrap())
            .await
            .unwrap();
        let (_, pending) = server
            .http("GET", "/api/bus/sends/attempt-alpha-0001", "", "")
            .await;
        assert_eq!(pending["state"], "pending");
        assert_eq!(
            server
                .http("POST", "/api/bus/send", INTENT, &wire().to_string())
                .await
                .0,
            502
        );
        let second = INTENT.replace("attempt-alpha-0001", "attempt-alpha-0002");
        assert_eq!(
            server
                .http("POST", "/api/bus/send", &second, &wire().to_string())
                .await
                .0,
            409
        );
        assert_eq!(
            server
                .http("GET", "/api/bus/sends/attempt-alpha-0002", "", "")
                .await
                .0,
            404
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        let (lock, condition) = release.as_ref();
        *lock.lock().unwrap() = true;
        condition.notify_all();
        assert_eq!(first.await.unwrap().0, 200);
        assert_eq!(
            server
                .http("GET", "/api/bus/sends/attempt-alpha-0001", "", "")
                .await
                .1["state"],
            "delivered"
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    }
}
