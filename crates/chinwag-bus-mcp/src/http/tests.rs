use super::*;
use rmcp::{
    model::{ClientConfig, Implementation, ProtocolVersion},
    transport::streamable_http_client::{
        StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
    },
};
use std::sync::atomic::AtomicUsize;

const AUTHORITY: &str = "127.0.0.1:43123";
const ENDPOINT: &str = "http://127.0.0.1:43124/";
const TOKEN_BYTES: [u8; 32] = [0xa5; 32];
const VERSION: &str = "2025-11-25";

struct Source {
    calls: Arc<AtomicUsize>,
    entered: Option<oneshot::Sender<()>>,
    release: Option<Receiver<()>>,
}
impl InboxReadSource for Source {
    fn read(&mut self, room: NativeRoom, _limit: usize) -> Result<Vec<BusMessage>, InboxError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(room, NativeRoom::Mgmt);
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
        }
        if let Some(release) = self.release.take() {
            release.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        Ok(vec![BusMessage {
            id: "native-fixture-1".into(),
            seq: 1,
            ts_iso: "2026-10-30T00:00:00Z".into(),
            room: "#mgmt".into(),
            sender: "untrusted-source".into(),
            body: "untrusted inbox body".into(),
            to: None,
            task_id: None,
            sig_verified: false,
        }])
    }
}
struct Fixture {
    http: Arc<HttpInbox>,
    calls: Arc<AtomicUsize>,
    host: Arc<Mutex<ConnectorHost>>,
    binding: BindingView,
}
async fn fixture(
    authority: &str,
    lease: Duration,
    gate: Option<(oneshot::Sender<()>, Receiver<()>)>,
) -> Fixture {
    let mut host = ConnectorHost::new(
        Registry::new(Limits {
            max_grants: 4,
            max_bindings: 4,
            max_lease: MAX_LEASE,
        })
        .unwrap(),
    );
    host.set_enabled(BuiltinConnector::NativeInbox, true)
        .unwrap();
    let connection = ConnectionId::new("fixture-owner-http").unwrap();
    let decision = OwnerLocalDecision::new_http_capability(
        "fixture-explicit-owner",
        connection.clone(),
        Destination::new(ENDPOINT, NativeRoom::Mgmt).unwrap(),
    )
    .unwrap();
    let binding = host
        .admit_local_inbox(decision, &connection, lease, Instant::now())
        .unwrap();
    let host = Arc::new(Mutex::new(host));
    let calls = Arc::new(AtomicUsize::new(0));
    let (entered, release) = match gate {
        Some((entered, release)) => (Some(entered), Some(release)),
        None => (None, None),
    };
    let source = Source {
        calls: calls.clone(),
        entered,
        release,
    };
    let server = InboxServer::start_inner(
        NativeRoom::Mgmt,
        lease,
        Some((host.clone(), binding.clone())),
        move || Ok((Box::new(source), ENDPOINT.into())),
    )
    .await
    .unwrap();
    let http = Arc::new(
        HttpInbox::new(
            server,
            HttpCapability::from_bytes(TOKEN_BYTES),
            HttpInboxConfig {
                allowed_authority: authority.into(),
            },
        )
        .unwrap(),
    );
    Fixture {
        http,
        calls,
        host,
        binding,
    }
}
fn request(
    authority: &str,
    method: &str,
    path: &str,
    value: Value,
    sid: Option<&str>,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, authority)
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", HttpCapability::from_bytes(TOKEN_BYTES).token()),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", VERSION);
    if let Some(sid) = sid {
        request = request.header("mcp-session-id", sid);
    }
    request
        .body(if value.is_null() {
            Body::empty()
        } else {
            Body::from(serde_json::to_vec(&value).unwrap())
        })
        .unwrap()
}
fn init(id: u32) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{"protocolVersion":VERSION,"capabilities":{},"clientInfo":{"name":"raw-peer-do-not-retain","version":"private-peer-label"}}})
}
async fn collect(response: Response) -> Value {
    assert!(
        response.status().is_success(),
        "status {}",
        response.status()
    );
    let bytes = tokio::time::timeout(
        Duration::from_secs(3),
        to_bytes(response.into_body(), wire::MAX_OUTPUT_BYTES),
    )
    .await
    .unwrap()
    .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let data = text
        .lines()
        .find_map(|line| {
            line.strip_prefix("data: ")
                .or_else(|| line.strip_prefix("data:"))
        })
        .unwrap();
    serde_json::from_str(data).unwrap()
}
async fn initialize(http: &HttpInbox) -> String {
    let response = http
        .handle(request(AUTHORITY, "POST", MOUNT_PATH, init(1), None))
        .await;
    let sid = response
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let result = collect(response).await;
    assert_eq!(result["result"]["protocolVersion"], VERSION);
    let response = http
        .handle(request(
            AUTHORITY,
            "POST",
            MOUNT_PATH,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            Some(&sid),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    sid
}

#[tokio::test]
async fn supplied_binding_is_canonical_and_never_creates_another_registry() {
    let fixture = fixture(AUTHORITY, Duration::from_secs(30), None).await;
    let mut forged = fixture.binding.clone();
    forged.authority = AuthorityKind::OwnerLocalStdioUnattributed;
    assert!(Admission::supplied(ENDPOINT, fixture.host.clone(), forged).is_err());
    assert!(
        Admission::supplied(
            "http://127.0.0.1:2/",
            fixture.host.clone(),
            fixture.binding.clone()
        )
        .is_err()
    );
    let before = fixture
        .host
        .lock()
        .unwrap()
        .inspect_binding(fixture.binding.id, Instant::now())
        .unwrap();
    assert_eq!(before, fixture.binding);
    fixture.http.shutdown().await.unwrap();
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .host
            .lock()
            .unwrap()
            .inspect_binding(fixture.binding.id, Instant::now())
            .unwrap()
            .state,
        chinwag_connector_registry::BindingState::Disconnected
    );
}

#[tokio::test]
async fn boundary_rejects_auth_headers_protocol_stateless_and_oversize_without_dispatch() {
    let fixture = fixture(AUTHORITY, Duration::from_secs(30), None).await;
    for kind in [
        "auth",
        "dup_auth",
        "host",
        "dup_host",
        "origin",
        "query",
        "get",
        "head",
        "type",
        "dup_type",
        "dup_protocol",
        "future",
        "meta",
        "discover",
        "oversize",
        "session",
    ] {
        let mut req = request(AUTHORITY, "POST", MOUNT_PATH, init(1), None);
        match kind {
            "auth" => {
                req.headers_mut().remove(header::AUTHORIZATION);
            }
            "dup_auth" => {
                req.headers_mut().append(
                    header::AUTHORIZATION,
                    header::HeaderValue::from_static("Bearer bad"),
                );
            }
            "host" => {
                req.headers_mut().insert(
                    header::HOST,
                    header::HeaderValue::from_static("localhost:43123"),
                );
            }
            "dup_host" => {
                req.headers_mut()
                    .append(header::HOST, header::HeaderValue::from_static(AUTHORITY));
            }
            "origin" => {
                req.headers_mut().insert(
                    header::ORIGIN,
                    header::HeaderValue::from_static("http://127.0.0.1:43123"),
                );
            }
            "query" => {
                *req.uri_mut() = "/api/mcp?extra=1".parse().unwrap();
            }
            "get" => {
                *req.method_mut() = axum::http::Method::GET;
            }
            "head" => {
                *req.method_mut() = axum::http::Method::HEAD;
            }
            "type" => {
                req.headers_mut().insert(
                    header::CONTENT_TYPE,
                    header::HeaderValue::from_static("text/plain"),
                );
            }
            "dup_type" => {
                req.headers_mut().append(
                    header::CONTENT_TYPE,
                    header::HeaderValue::from_static("application/json"),
                );
            }
            "dup_protocol" => {
                req.headers_mut().append(
                    "mcp-protocol-version",
                    header::HeaderValue::from_static(VERSION),
                );
            }
            "future" => {
                req.headers_mut().insert(
                    "mcp-protocol-version",
                    header::HeaderValue::from_static("2026-07-28"),
                );
            }
            "meta" => {
                *req.body_mut()=Body::from(serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":VERSION,"io.modelcontextprotocol/clientCapabilities":{}}}})).unwrap());
            }
            "discover" => {
                *req.body_mut() = Body::from(
                    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"server/discover"}))
                        .unwrap(),
                );
            }
            "oversize" => {
                *req.body_mut() = Body::from(vec![b' '; wire::MAX_INPUT_BYTES + 1]);
            }
            "session" => {
                req.headers_mut().insert(
                    "mcp-session-id",
                    header::HeaderValue::from_static("foreign"),
                );
            }
            _ => unreachable!(),
        }
        let response = fixture.http.handle(req).await;
        assert!(!response.status().is_success(), "{kind}");
        assert!(!fixture.http.lifecycle_snapshot().session_started, "{kind}");
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    }
    fixture.http.shutdown().await.unwrap();
}

#[tokio::test]
async fn real_sdk_dispatch_observations_are_inert_until_one_fixed_room_read() {
    let fixture = fixture(AUTHORITY, Duration::from_secs(30), None).await;
    let sid = initialize(&fixture.http).await;
    let list = collect(
        fixture
            .http
            .handle(request(
                AUTHORITY,
                "POST",
                MOUNT_PATH,
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
                Some(&sid),
            ))
            .await,
    )
    .await;
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 1);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let read=collect(fixture.http.handle(request(AUTHORITY,"POST",MOUNT_PATH,json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":TOOL_NAME,"arguments":{"limit":1}}}),Some(&sid))).await).await;
    let data = &read["result"]["structuredContent"];
    assert_eq!(data["room"], "#mgmt");
    assert_eq!(
        data["authority"],
        "owner_local_http_capability_unattributed"
    );
    assert_eq!(data["connection_observation"]["read_windows_prepared"], 1);
    assert!(serde_json::to_vec(data).unwrap().len() <= wire::MAX_TOOL_DATA_BYTES);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    let snapshot = serde_json::to_string(&fixture.http.lifecycle_snapshot()).unwrap();
    for forbidden in [
        "raw-peer-do-not-retain",
        "private-peer-label",
        HttpCapability::from_bytes(TOKEN_BYTES).token(),
        &sid,
    ] {
        assert!(!snapshot.contains(forbidden));
    }
    let foreign = fixture
        .http
        .handle(request(
            AUTHORITY,
            "POST",
            MOUNT_PATH,
            json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}),
            Some("unknown-session"),
        ))
        .await;
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    let repeat = fixture
        .http
        .handle(request(AUTHORITY, "POST", MOUNT_PATH, init(5), None))
        .await;
    assert!(!repeat.status().is_success());
    let _ = to_bytes(repeat.into_body(), wire::MAX_OUTPUT_BYTES)
        .await
        .unwrap();
    fixture.http.shutdown().await.unwrap();
    let snapshot = fixture.http.lifecycle_snapshot();
    assert!(
        snapshot.session_closed
            && snapshot.transport_worker_joined
            && snapshot.reader_worker_joined
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn response_body_drop_retires_original_session_and_never_reopens_it() {
    let fixture = fixture(AUTHORITY, Duration::from_secs(30), None).await;
    let response = fixture
        .http
        .handle(request(AUTHORITY, "POST", MOUNT_PATH, init(1), None))
        .await;
    assert!(response.status().is_success());
    drop(response);
    assert!(fixture.http.lifecycle_snapshot().session_closed);
    tokio::time::timeout(Duration::from_secs(3), fixture.http.shutdown())
        .await
        .unwrap()
        .unwrap();
    let snapshot = fixture.http.lifecycle_snapshot();
    assert!(snapshot.transport_worker_joined && snapshot.reader_worker_joined);
    let response = fixture
        .http
        .handle(request(AUTHORITY, "POST", MOUNT_PATH, init(2), None))
        .await;
    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn response_slot_lasts_until_body_eof_and_revocation_blocks_future_dispatch() {
    let fixture = fixture(AUTHORITY, Duration::from_secs(30), None).await;
    let sid = initialize(&fixture.http).await;
    let response = fixture
        .http
        .handle(request(
            AUTHORITY,
            "POST",
            MOUNT_PATH,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            Some(&sid),
        ))
        .await;
    let next = fixture
        .http
        .handle(request(
            AUTHORITY,
            "POST",
            MOUNT_PATH,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
            Some(&sid),
        ))
        .await;
    assert_eq!(next.status(), StatusCode::CONFLICT);
    collect(response).await;
    fixture
        .host
        .lock()
        .unwrap()
        .revoke(fixture.binding.grant)
        .unwrap();
    let denied = fixture
        .http
        .handle(request(
            AUTHORITY,
            "POST",
            MOUNT_PATH,
            json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}),
            Some(&sid),
        ))
        .await;
    assert_eq!(denied.status(), StatusCode::GONE);
    fixture.http.shutdown().await.unwrap();
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelled_shutdown_keeps_original_reader_and_transport_join_handles() {
    let (entered, event) = oneshot::channel();
    let (release, gate) = mpsc::sync_channel(1);
    let fixture = fixture(AUTHORITY, Duration::from_secs(30), Some((entered, gate))).await;
    let sid = initialize(&fixture.http).await;
    let response=fixture.http.handle(request(AUTHORITY,"POST",MOUNT_PATH,json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":TOOL_NAME,"arguments":{"limit":1}}}),Some(&sid))).await;
    let reading =
        tokio::spawn(async move { to_bytes(response.into_body(), wire::MAX_OUTPUT_BYTES).await });
    tokio::time::timeout(Duration::from_secs(2), event)
        .await
        .unwrap()
        .unwrap();
    let mut stopping = Box::pin(fixture.http.shutdown());
    assert!(futures::poll!(stopping.as_mut()).is_pending());
    drop(stopping);
    assert!(!fixture.http.lifecycle_snapshot().reader_worker_joined);
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), fixture.http.shutdown())
        .await
        .unwrap()
        .unwrap();
    let _ = reading.await;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert!(fixture.http.lifecycle_snapshot().reader_worker_joined);
    assert!(fixture.http.lifecycle_snapshot().transport_worker_joined);
}

#[tokio::test]
async fn finite_lease_closes_without_any_client_and_has_no_fake_transport_join() {
    let fixture = fixture(AUTHORITY, Duration::from_secs(1), None).await;
    tokio::time::sleep(Duration::from_millis(1050)).await;
    let response = fixture
        .http
        .handle(request(AUTHORITY, "POST", MOUNT_PATH, init(1), None))
        .await;
    assert_eq!(response.status(), StatusCode::GONE);
    fixture.http.shutdown().await.unwrap();
    let snapshot = fixture.http.lifecycle_snapshot();
    assert!(!snapshot.session_started && !snapshot.transport_worker_joined);
    assert!(snapshot.reader_worker_joined && snapshot.connection_observation.lease_expired);
}

#[tokio::test]
async fn actual_sdk_http_client_roundtrip_uses_same_held_observer_and_cleanup() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let fixture = fixture(&authority, Duration::from_secs(30), None).await;
        let http = fixture.http.clone();
        let stop = CancellationToken::new();
        let _stop_on_drop = stop.clone().drop_guard();
        let stopped = stop.clone();
        let app = axum::Router::new().route(
            MOUNT_PATH,
            axum::routing::any(move |request: Request<Body>| {
                let http = http.clone();
                async move { http.handle(request).await }
            }),
        );
        let serving = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(stopped.cancelled_owned())
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let mut config = StreamableHttpClientTransportConfig::with_uri(format!(
            "http://{authority}{MOUNT_PATH}"
        ))
        .auth_header(HttpCapability::from_bytes(TOKEN_BYTES).token())
        .max_concurrent_requests(1);
        config.allow_stateless = false;
        config.reinit_on_expired_session = false;
        config.max_sse_event_size = wire::MAX_OUTPUT_BYTES;
        let transport = StreamableHttpClientTransport::with_client(client, config);
        let config = ClientConfig::new(
            Default::default(),
            Implementation::new("self-reported-fixture", "fixture-version"),
        )
        .with_protocol_version(ProtocolVersion::V_2025_11_25);
        let mut client = config.serve(transport).await.unwrap();
        let tools = client.list_tools(None).await.unwrap();
        assert_eq!(tools.tools.len(), 1);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        let result = client
            .call_tool(
                CallToolRequestParams::new(TOOL_NAME)
                    .with_arguments(json!({"limit":1}).as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        assert_eq!(
            result.structured_content.as_ref().unwrap()["authority"],
            "owner_local_http_capability_unattributed"
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture
                .http
                .lifecycle_snapshot()
                .connection_observation
                .read_windows_prepared,
            1
        );
        client.close().await.unwrap();
        fixture.http.shutdown().await.unwrap();
        assert!(fixture.http.lifecycle_snapshot().transport_worker_joined);
        stop.cancel();
        serving.await.unwrap();
    })
    .await
    .unwrap();
}

#[test]
fn sdk_legacy_progress_correlation_is_accepted_without_discovery_routing_metadata() {
    use rmcp::model::{
        ClientJsonRpcMessage, ClientRequest, GetMeta, ListToolsRequest, NumberOrString,
        ProgressToken, RequestId,
    };
    let mut request = ClientRequest::ListToolsRequest(ListToolsRequest::default());
    request
        .get_meta_mut()
        .set_progress_token(ProgressToken(NumberOrString::Number(7)));
    let value =
        serde_json::to_value(ClientJsonRpcMessage::request(request, RequestId::Number(1))).unwrap();
    assert_eq!(
        value,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"progressToken":7}}})
    );
    assert_eq!(classify(&value, true, Some(VERSION)), Ok(true));
    for meta in [
        json!({"progressToken":"bounded-correlation"}),
        json!({"progressToken":-1}),
    ] {
        let mut value = value.clone();
        value["params"]["_meta"] = meta;
        assert_eq!(classify(&value, true, Some(VERSION)), Ok(true));
    }
    for meta in [
        json!({"progressToken":7,"io.modelcontextprotocol/protocolVersion":VERSION,"io.modelcontextprotocol/clientCapabilities":{}}),
        json!({"io.modelcontextprotocol/protocolVersion":VERSION,"io.modelcontextprotocol/clientCapabilities":{}}),
        json!({"progressToken":true}),
        json!({"progressToken":1.5}),
        json!({"progressToken":{}}),
        json!({"progressToken":"x".repeat(129)}),
        json!({"progressToken":"bad\ncorrelation"}),
    ] {
        let mut value = value.clone();
        value["params"]["_meta"] = meta;
        assert_eq!(classify(&value, true, Some(VERSION)), Err(()));
    }
}

#[tokio::test]
async fn canonical_fence_rejects_revoked_controls_and_delete_before_sdk() {
    for method in [
        "notifications/initialized",
        "notifications/cancelled",
        "DELETE",
    ] {
        for disconnected in [false, true] {
            let fixture = fixture(AUTHORITY, Duration::from_secs(30), None).await;
            let response = fixture
                .http
                .handle(request(AUTHORITY, "POST", MOUNT_PATH, init(1), None))
                .await;
            let sid = response
                .headers()
                .get("mcp-session-id")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            collect(response).await;
            {
                let mut host = fixture.host.lock().unwrap();
                if disconnected {
                    host.disconnect_binding(fixture.binding.id, fixture.binding.generation)
                        .unwrap();
                } else {
                    host.revoke(fixture.binding.grant).unwrap();
                }
            }
            let value = if method == "DELETE" {
                Value::Null
            } else if method == "notifications/cancelled" {
                json!({"jsonrpc":"2.0","method":method,"params":{"requestId":17}})
            } else {
                json!({"jsonrpc":"2.0","method":method})
            };
            let response = fixture
                .http
                .handle(request(
                    AUTHORITY,
                    if method == "DELETE" { "DELETE" } else { "POST" },
                    MOUNT_PATH,
                    value,
                    Some(&sid),
                ))
                .await;
            let status = response.status();
            drop(response);
            fixture.http.shutdown().await.unwrap();
            assert_eq!(
                status,
                StatusCode::GONE,
                "{method}, disconnected={disconnected}"
            );
            assert!(
                !fixture
                    .http
                    .lifecycle_snapshot()
                    .connection_observation
                    .initialized_notification_seen
            );
            assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn canonical_fence_busy_initialized_and_delete_are_nonblocking_conflicts() {
    for method in ["notifications/initialized", "DELETE"] {
        let fixture = fixture(AUTHORITY, Duration::from_secs(30), None).await;
        let sid = initialize(&fixture.http).await;
        let guard = fixture.host.lock().unwrap();
        let value = if method == "DELETE" {
            Value::Null
        } else {
            json!({"jsonrpc":"2.0","method":method})
        };
        let mut dispatch = Box::pin(fixture.http.handle(request(
            AUTHORITY,
            if method == "DELETE" { "DELETE" } else { "POST" },
            MOUNT_PATH,
            value,
            Some(&sid),
        )));
        let status = match dispatch
            .as_mut()
            .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
        {
            Poll::Ready(response) => Some(response.status()),
            Poll::Pending => None,
        };
        drop(dispatch);
        drop(guard);
        fixture.http.shutdown().await.unwrap();
        assert_eq!(status, Some(StatusCode::CONFLICT), "{method}");
    }
}

#[tokio::test]
async fn canonical_fence_busy_cancellation_requests_closure_without_claiming_read_drain() {
    let (entered, event) = oneshot::channel();
    let (release, gate) = mpsc::sync_channel(1);
    let fixture = fixture(AUTHORITY, Duration::from_secs(30), Some((entered, gate))).await;
    let sid = initialize(&fixture.http).await;
    let response=fixture.http.handle(request(AUTHORITY,"POST",MOUNT_PATH,json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":TOOL_NAME,"arguments":{"limit":1}}}),Some(&sid))).await;
    let reading =
        tokio::spawn(async move { to_bytes(response.into_body(), wire::MAX_OUTPUT_BYTES).await });
    tokio::time::timeout(Duration::from_secs(2), event)
        .await
        .unwrap()
        .unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        fixture.http.handle(request(
            AUTHORITY,
            "POST",
            MOUNT_PATH,
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}),
            Some(&sid),
        )),
    )
    .await;
    let status = response.map(|response| response.status()).ok();
    let observed = fixture.http.lifecycle_snapshot();
    release.send(()).unwrap();
    let _ = reading.await;
    fixture.http.shutdown().await.unwrap();
    assert_eq!(status, Some(StatusCode::ACCEPTED));
    assert!(
        observed.session_closed,
        "busy cancellation acknowledges only owner-side closure"
    );
    assert!(
        !observed.reader_worker_joined,
        "the original read still owns its permit"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn canonical_fence_is_rechecked_at_actual_sdk_session_creation() {
    use rmcp::transport::streamable_http_server::SessionManager;
    let fixture = fixture(AUTHORITY, Duration::from_secs(30), None).await;
    let manager = SingleSessionManager::new(fixture.http.control.clone());
    fixture
        .host
        .lock()
        .unwrap()
        .revoke(fixture.binding.grant)
        .unwrap();
    let result = manager.create_session().await;
    let rejected = result.is_err();
    let started = fixture.http.lifecycle_snapshot().session_started;
    if let Ok((id, transport)) = result {
        drop(transport);
        let _ = manager.close_session(&id).await;
    }
    fixture.http.shutdown().await.unwrap();
    assert!(
        rejected,
        "revoke between HTTP fence and SDK creation must not allocate"
    );
    assert!(!started);
}

#[tokio::test]
async fn incoming_gate_is_retained_through_pending_sdk_delete_dispatch() {
    let fixture = fixture(AUTHORITY, Duration::from_secs(30), None).await;
    let sid = initialize(&fixture.http).await;
    // Hold the original reader-join slot so actual SDK DELETE cleanup cannot
    // finish. This changes no host grant and creates no synthetic SDK hook.
    let guard = fixture.http.control.owner.lifetime.worker.lock().await;
    let mut deleting = Box::pin(fixture.http.handle(request(
        AUTHORITY,
        "DELETE",
        MOUNT_PATH,
        Value::Null,
        Some(&sid),
    )));
    assert!(futures::poll!(deleting.as_mut()).is_pending());
    let available = fixture.http.incoming.available_permits();
    drop(guard);
    let response = tokio::time::timeout(Duration::from_secs(3), deleting)
        .await
        .unwrap();
    assert!(response.status().is_success());
    fixture.http.shutdown().await.unwrap();
    assert_eq!(
        available, 0,
        "a control/DELETE dispatch retains the one incoming slot"
    );
    assert_eq!(fixture.http.incoming.available_permits(), 1);
}

#[tokio::test]
async fn irrelevant_credentials_are_rejected_before_any_sdk_dispatch() {
    for name in ["cookie", "proxy-authorization"] {
        let fixture = fixture(AUTHORITY, Duration::from_secs(30), None).await;
        let mut req = request(AUTHORITY, "POST", MOUNT_PATH, init(1), None);
        req.headers_mut().insert(
            name,
            header::HeaderValue::from_static("fixture-unneeded-credential"),
        );
        let response = fixture.http.handle(req).await;
        let status = response.status();
        drop(response);
        fixture.http.shutdown().await.unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN, "{name}");
        assert!(!fixture.http.lifecycle_snapshot().session_started);
    }
}

#[test]
fn http_authority_accepts_only_canonical_loopback_ipv4_including_implicit_port_eighty() {
    for value in ["127.0.0.1", "127.1.2.3", "127.0.0.1:1", "127.0.0.1:44346"] {
        assert!(canonical_authority(value), "{value}");
    }
    for value in [
        "localhost",
        "127.0.0.1:80",
        "127.0.0.1:0",
        "0.0.0.0",
        "192.0.2.1",
        "127.1",
        "0177.0.0.1",
        "[::1]",
        "[::1]:44346",
        "127.0.0.1/",
        "http://127.0.0.1",
        "127.0.0.1:44346 ",
        "user@127.0.0.1",
    ] {
        assert!(!canonical_authority(value), "{value}");
    }
}
