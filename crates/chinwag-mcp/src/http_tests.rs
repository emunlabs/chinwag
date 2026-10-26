//! Once-only private fixtures supplied by the reviewed external operator.
use crate::{
    http_probe::{Phase, Probe},
    repository_http::{AccessSecret, LoopbackAuthority, RepositoryHttp, ScopedHttpResponse},
};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode};
use http_body_util::Full;
use serde_json::{Value, json};
use std::{io::Read, num::NonZeroU16, path::PathBuf};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

struct Fixture {
    repo: PathBuf,
    secret: Zeroizing<[u8; 32]>,
    header: HeaderValue,
}
impl Fixture {
    fn new() -> Self {
        let repo =
            PathBuf::from(std::env::var_os("CHINWAG_HTTP_FIXTURE").expect("new owned fixture"));
        assert!(repo.is_absolute() && repo.join(".chinwag/state.crdb").is_file());
        let mut secret = Zeroizing::new([0u8; 32]);
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(secret.as_mut())
            .unwrap();
        let mut text = Zeroizing::new(String::from("Bearer "));
        use std::fmt::Write;
        for byte in secret.iter() {
            write!(text, "{byte:02x}").unwrap();
        }
        let header = HeaderValue::from_str(&text).unwrap();
        assert_eq!(
            format!("{:?}", AccessSecret::new(*secret)),
            "AccessSecret(<redacted>)"
        );
        Self {
            repo,
            secret,
            header,
        }
    }
    fn open(&self) -> RepositoryHttp {
        RepositoryHttp::open_private_repository(
            self.repo.clone(),
            AccessSecret::new(*self.secret),
            authority(),
        )
        .unwrap()
    }
    fn image(&self) -> Vec<u8> {
        std::fs::read(self.repo.join(".chinwag/state.crdb")).unwrap()
    }
    fn request(&self, method: &str, mut params: Value) -> Request<Full<Bytes>> {
        params
            .as_object_mut()
            .unwrap()
            .insert("_meta".into(), meta());
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("host", "127.0.0.1:43871")
            .header("authorization", self.header.clone())
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method);
        if let Some(name) = name {
            builder = builder.header("mcp-name", name);
        }
        builder
            .body(Full::new(Bytes::from(
                serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":7,"method":method,"params":params}),
                )
                .unwrap(),
            )))
            .unwrap()
    }
    fn tool(&self, name: &str, arguments: Value) -> Request<Full<Bytes>> {
        self.request("tools/call", json!({"name":name,"arguments":arguments}))
    }
}
fn authority() -> LoopbackAuthority {
    LoopbackAuthority::new(NonZeroU16::new(43871).unwrap())
}
fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"Root-private-HTTP-observer","version":"0.0.1"},
        "io.modelcontextprotocol/clientCapabilities":{}
    })
}
fn pin() -> Value {
    json!({"id":"http-pin","thread_id":"http-thread","file_path":"literal context.rs","symbol_hash":"caller-symbol","source_commit":"caller-source","body":"Actual private HTTP SSE context 🌱","created_at_ms":1,"create_thread":{"repo_id":"caller-repo","branch_ref":"refs/heads/main","title":"Original HTTP thread"}})
}
fn expected_thread() -> Value {
    json!({"id":"http-thread","repo_id":"caller-repo","branch_ref":"refs/heads/main","title":"Original HTTP thread","created_at_ms":1,"updated_at_ms":1})
}
fn expected_pin() -> Value {
    let mut pin = pin();
    pin.as_object_mut().unwrap().remove("create_thread");
    pin
}
async fn observe(label: &str, mut response: ScopedHttpResponse<'_>) -> (u16, Option<Value>) {
    let status = response.status().unwrap().as_u16();
    let content_type = response
        .headers()
        .unwrap()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned());
    assert!(response.headers().unwrap().get("mcp-session-id").is_none());
    let mut frames = Vec::new();
    let mut body = Vec::new();
    while let Some(frame) = response.frame().await.expect("original bounded body") {
        frames.push(String::from_utf8(frame.to_vec()).unwrap());
        body.extend_from_slice(&frame);
    }
    let message = if content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("text/event-stream"))
    {
        let text = std::str::from_utf8(&body).unwrap().replace("\r\n", "\n");
        assert!(text.ends_with("\n\n"));
        let data: Vec<_> = text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(data.len(), 1, "one terminal response, no replay stream");
        let value: Value = serde_json::from_str(data[0]).unwrap();
        assert_eq!(value["id"], 7);
        Some(value)
    } else if content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("application/json"))
        && !body.is_empty()
    {
        Some(serde_json::from_slice(&body).unwrap())
    } else {
        None
    };
    eprintln!(
        "ROOT_HTTP_WIRE {}",
        json!({"label":label,"status":status,"content_type":content_type,"literal_response_frames":frames,"original_body_EOF":true})
    );
    (status, message)
}
async fn rpc(
    owner: &mut RepositoryHttp,
    fixture: &Fixture,
    label: &str,
    method: &str,
    params: Value,
) -> Value {
    let response = owner
        .request(fixture.request(method, params))
        .await
        .unwrap();
    assert_eq!(response.status(), Some(StatusCode::OK));
    assert!(
        response.headers().unwrap()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let (status, value) = observe(label, response).await;
    assert_eq!(status, 200);
    value.unwrap()
}
async fn tool(
    owner: &mut RepositoryHttp,
    fixture: &Fixture,
    label: &str,
    name: &str,
    arguments: Value,
) -> Value {
    let reply = rpc(
        owner,
        fixture,
        label,
        "tools/call",
        json!({"name":name,"arguments":arguments}),
    )
    .await;
    assert_eq!(reply["result"]["isError"], false);
    reply["result"]["structuredContent"].clone()
}
async fn quiesce(owner: &RepositoryHttp) {
    for _ in 0..10_000 {
        if owner.active_observations() == (0, 0) {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("Original HTTP handler did not quiesce; no finish claim");
}
fn checked(owner: RepositoryHttp, label: &str) {
    assert!(owner.finish().unwrap().original_worker_checked());
    let counts = chinwag_snapshot_session_private::native_counts_for_private_probe();
    assert!(counts.opens > 0);
    assert_eq!(counts.opens, counts.checked_closes);
    eprintln!(
        "ROOT_HTTP_CHECKED {}",
        json!({"label":label,"original_worker_join_and_admission_close":true,"native_opens":counts.opens,"native_checked_closes":counts.checked_closes})
    );
}

#[test]
fn protocol_sse_current_store_and_restart() {
    let fixture = Fixture::new();
    let old = fixture.image();
    let mut owner = fixture.open();
    let rt = runtime();
    // The context error occurs before closing/cancelling the retained original.
    owner = {
        let _entered = rt.enter();
        match owner.finish() {
            Err(failure) => {
                assert!(failure.reason().contains("outside a Tokio"));
                failure.into_original()
            }
            Ok(_) => panic!("finish inside Tokio accepted"),
        }
    };
    {
        let _entered = rt.enter();
        assert!(
            RepositoryHttp::open_private_repository(
                fixture.repo.clone(),
                AccessSecret::new(*fixture.secret),
                authority()
            )
            .is_err()
        );
    }
    rt.block_on(async {
        let discovery = rpc(&mut owner, &fixture, "discovery", "server/discover", json!({})).await;
        assert_eq!(discovery["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "chinwag-context");
        assert_eq!(discovery["result"]["supportedVersions"], json!(["2026-07-28"]));
        let listed = rpc(&mut owner, &fixture, "list-three", "tools/list", json!({})).await;
        let names: Vec<_> = listed["result"]["tools"].as_array().unwrap().iter().map(|tool| tool["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["chinwag_read_thread", "chinwag_pin_context", "chinwag_handoff"]);
        assert_eq!(fixture.image(), old);
        for (label, request, expected) in negatives(&fixture) {
            let response = owner.request(request).await.unwrap();
            let (status, _) = observe(label, response).await;
            assert_eq!(status, expected, "{label}");
            assert_eq!(fixture.image(), old, "{label} changed current store");
        }
        let mut large = pin(); large["body"] = Value::String("x".repeat(65_536));
        let response = owner.request(fixture.tool("chinwag_pin_context", large)).await.unwrap();
        let (_, refused) = observe("bounded-tool-output", response).await;
        assert_eq!(refused.unwrap()["result"]["isError"], true);
        assert_eq!(fixture.image(), old);
        let first = tool(&mut owner, &fixture, "first-pin", "chinwag_pin_context", pin()).await;
        assert_eq!(first, json!({"thread":expected_thread(),"pin":expected_pin(),"replayed":false}));
        let written = fixture.image(); assert_ne!(written, old);
        let retry = tool(&mut owner, &fixture, "exact-retry", "chinwag_pin_context", pin()).await;
        assert_eq!(retry, json!({"thread":expected_thread(),"pin":expected_pin(),"replayed":true}));
        assert_eq!(fixture.image(), written);
        let handoff = tool(&mut owner, &fixture, "local-offer", "chinwag_handoff", json!({"id":"http-offer","thread_id":"http-thread","target_label":"caller-unverified-target","note":"Local offer only","created_at_ms":2})).await;
        assert_eq!(handoff["state"], "recorded_local_offer");
        assert_eq!(handoff["delivery"], "not_attempted");
        assert_eq!(handoff["replayed"], false);
        let view = tool(&mut owner, &fixture, "read-current", "chinwag_read_thread", json!({"thread_id":"http-thread"})).await;
        assert_eq!(view["thread"], expected_thread()); assert_eq!(view["pins"], json!([expected_pin()]));
        assert_eq!(view["messages"].as_array().unwrap().len(), 1);
        quiesce(&owner).await;
    });
    checked(owner, "protocol-original");
    let persisted = fixture.image();
    let mut restarted = fixture.open();
    rt.block_on(async {
        let view = tool(
            &mut restarted,
            &fixture,
            "restart-read",
            "chinwag_read_thread",
            json!({"thread_id":"http-thread"}),
        )
        .await;
        assert_eq!(view["thread"], expected_thread());
        assert_eq!(view["pins"], json!([expected_pin()]));
        assert_eq!(view["messages"].as_array().unwrap().len(), 1);
        quiesce(&restarted).await;
    });
    checked(restarted, "restart-original");
    assert_eq!(fixture.image(), persisted);
}

fn negatives(fixture: &Fixture) -> Vec<(&'static str, Request<Full<Bytes>>, u16)> {
    let fresh = || fixture.tool("chinwag_pin_context", pin());
    let mut cases = Vec::new();
    let mut request = fresh();
    request.headers_mut().remove("authorization");
    cases.push(("missing-auth", request, 401));
    let mut request = fresh();
    request
        .headers_mut()
        .insert("authorization", HeaderValue::from_static("Bearer invalid"));
    cases.push(("wrong-auth", request, 401));
    let mut request = fresh();
    request
        .headers_mut()
        .append("authorization", fixture.header.clone());
    cases.push(("duplicate-auth", request, 401));
    let mut request = fresh();
    request
        .headers_mut()
        .insert("host", HeaderValue::from_static("other.invalid:43871"));
    cases.push(("wrong-host", request, 403));
    let mut request = fresh();
    request
        .headers_mut()
        .append("host", HeaderValue::from_static("127.0.0.1:43871"));
    cases.push(("duplicate-host", request, 403));
    let mut request = fresh();
    request
        .headers_mut()
        .insert("origin", HeaderValue::from_static("http://127.0.0.1:43871"));
    cases.push(("present-origin", request, 403));
    let mut request = fresh();
    *request.uri_mut() = "http://other.invalid:43871/mcp".parse().unwrap();
    cases.push(("wrong-absolute-authority", request, 403));
    let mut request = fresh();
    *request.uri_mut() = "/other".parse().unwrap();
    cases.push(("wrong-path", request, 404));
    let mut request = fresh();
    *request.uri_mut() = "/mcp?token=not-a-secret".parse().unwrap();
    cases.push(("query-refused", request, 404));
    let mut request = fresh();
    *request.method_mut() = Method::GET;
    cases.push(("legacy-GET-refused", request, 405));
    let mut request = fresh();
    request.headers_mut().remove("mcp-protocol-version");
    cases.push(("missing-protocol", request, 400));
    let mut request = fresh();
    request.headers_mut().insert(
        "mcp-protocol-version",
        HeaderValue::from_static("2025-11-25"),
    );
    cases.push(("legacy-protocol-refused", request, 400));
    let mut request = fresh();
    request.headers_mut().append(
        "mcp-protocol-version",
        HeaderValue::from_static("2026-07-28"),
    );
    cases.push(("duplicate-protocol", request, 400));
    let mut request = fresh();
    request.headers_mut().remove("mcp-method");
    cases.push(("missing-method", request, 400));
    let mut request = fresh();
    request
        .headers_mut()
        .insert("mcp-method", HeaderValue::from_static("tools/list"));
    cases.push(("mismatched-method", request, 400));
    let mut request = fresh();
    request.headers_mut().remove("mcp-name");
    cases.push(("missing-tool-name", request, 400));
    let mut request = fresh();
    request
        .headers_mut()
        .insert("mcp-name", HeaderValue::from_static("chinwag_read_thread"));
    cases.push(("mismatched-tool-name", request, 400));
    let mut request = fresh();
    *request.body_mut() = Full::new(Bytes::from_static(b"{bad"));
    cases.push(("malformed-JSON", request, 415));
    let mut request = fresh();
    *request.body_mut() = Full::new(Bytes::from_static(b"[]"));
    cases.push(("batch-refused", request, 415));
    let mut request = fresh();
    *request.body_mut() = Full::new(Bytes::from(vec![b' '; crate::wire::MAX_INPUT_BYTES + 1]));
    cases.push(("bounded-input", request, 413));
    for (label, bad_meta) in [
        (
            "missing-client-capabilities",
            json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"fixture","version":"1"}}),
        ),
        (
            "mismatched-body-protocol",
            json!({"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientInfo":{"name":"fixture","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}),
        ),
        (
            "missing-body-protocol",
            json!({"io.modelcontextprotocol/clientInfo":{"name":"fixture","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}),
        ),
    ] {
        let mut request = fresh();
        *request.body_mut() = Full::new(Bytes::from(serde_json::to_vec(&json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"chinwag_pin_context","arguments":pin(),"_meta":bad_meta}})).unwrap()));
        cases.push((label, request, 400));
    }
    cases
}

fn cancellation(phase: Phase, label: &str) {
    let fixture = Fixture::new();
    let old = fixture.image();
    let (probe, control) = Probe::new(phase);
    let mut owner = RepositoryHttp::open_with_probe(
        fixture.repo.clone(),
        AccessSecret::new(*fixture.secret),
        authority(),
        probe,
    )
    .unwrap();
    let rt = runtime();
    rt.block_on(async {
        let mut original = Box::pin(owner.request(fixture.tool("chinwag_pin_context", pin())));
        tokio::select! {
            reached = control.reached => reached.expect("original request reached named boundary"),
            _ = &mut original => panic!("HTTP result returned before controlled boundary"),
        }
        assert_eq!(fixture.image(), old);
        drop(original); // The actual SDK disconnect guard cancels this exact handler.
        quiesce(&owner).await;
        let released = control.resume.send(());
        assert_eq!(released.is_ok(), phase == Phase::BeforeCommit);
    });
    checked(owner, label);
    assert_eq!(fixture.image(), old);
    eprintln!(
        "ROOT_HTTP_CANCEL {}",
        json!({"label":label,"actual_original_request_future_dropped":true,"no_HTTP_result_delivered":true,"original_current_store_bytes_unchanged":true})
    );
}
#[test]
fn cancel_before_queue() {
    cancellation(Phase::BeforeEnqueue, "before-enqueue");
}
#[test]
fn cancel_prepared_before_staging() {
    cancellation(Phase::BeforeCommit, "prepared-before-staging");
}

#[test]
fn committed_write_response_drop_preserves_current_database_without_ack() {
    let fixture = Fixture::new();
    let old = fixture.image();
    let mut owner = fixture.open();
    let rt = runtime();
    rt.block_on(async {
        let response = owner
            .request(fixture.tool("chinwag_pin_context", pin()))
            .await
            .unwrap();
        assert_eq!(response.status(), Some(StatusCode::OK));
        assert_ne!(fixture.image(), old);
        drop(response); // No frame read and no client tool acknowledgment.
        quiesce(&owner).await;
    });
    checked(owner, "committed-response-dropped");
    let written = fixture.image();
    let mut restarted = fixture.open();
    rt.block_on(async {
        let view = tool(
            &mut restarted,
            &fixture,
            "read-after-output-loss",
            "chinwag_read_thread",
            json!({"thread_id":"http-thread"}),
        )
        .await;
        assert_eq!(view["thread"], expected_thread());
        assert_eq!(view["pins"], json!([expected_pin()]));
        assert_eq!(view["messages"], json!([]));
        quiesce(&restarted).await;
    });
    checked(restarted, "restart-after-output-loss");
    assert_eq!(fixture.image(), written);
    eprintln!(
        "ROOT_HTTP_OUTPUT_LOSS {}",
        json!({"actual_original_SSE_body_dropped_unread":true,"current_write_retained":true,"no_inherited_tool_acknowledgment":true})
    );
}

#[test]
fn cancel_inside_second_native_prepare_callback() {
    let fixture = Fixture::new();
    let old = fixture.image();
    let (probe, control) = Probe::new(Phase::DuringPrepare);
    let observed = probe.clone();
    let mut owner = RepositoryHttp::open_with_probe(
        fixture.repo.clone(),
        AccessSecret::new(*fixture.secret),
        authority(),
        probe,
    )
    .unwrap();
    runtime().block_on(async {
        let mut original = Box::pin(owner.request(fixture.tool("chinwag_pin_context", pin())));
        tokio::select! {
            reached = control.reached => reached.expect("second callback inside original prepare"),
            _ = &mut original => panic!("request ended before actual second prepare callback"),
        }
        assert_eq!(observed.prepare_checks(), 2);
        assert_eq!(fixture.image(), old);
        drop(original);
        quiesce(&owner).await;
        control
            .resume
            .send(())
            .expect("original worker was blocked inside prepare callback");
    });
    checked(owner, "cancel-inside-second-prepare-callback");
    assert_eq!(fixture.image(), old);
    assert_eq!(observed.prepare_checks(), 2);
    eprintln!(
        "ROOT_HTTP_DURING_PREPARE {}",
        json!({"prepare_callback_count":2,"request_future_actually_dropped":true,"current_store_unchanged":true,"no_response_delivered":true,"original_worker_checked":true})
    );
}

#[test]
fn forgotten_response_retains_activity_and_refuses_finish() {
    let fixture = Fixture::new();
    let old = fixture.image();
    let mut owner = fixture.open();
    runtime().block_on(async {
        let response = owner
            .request(fixture.request("tools/list", json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), Some(StatusCode::OK));
        std::mem::forget(response); // Deliberate one-response leak in this test process only.
        for _ in 0..10_000 {
            if owner.active_observations().1 == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(owner.active_observations(), (1, 0));
    });
    let first = match owner.finish() {
        Err(failure) => failure,
        Ok(_) => panic!("forgotten response minted a checked finish receipt"),
    };
    assert!(first.reason().contains("activity still retained"));
    let original = first.into_original();
    assert_eq!(original.active_observations(), (1, 0));
    let second = match original.finish() {
        Err(failure) => failure,
        Ok(_) => panic!("second finish bypassed the same retained activity"),
    };
    assert!(second.reason().contains("activity still retained"));
    assert_eq!(fixture.image(), old);
    // There is intentionally no successful worker/HTTP finish receipt. Dropping
    // this original is not reported as a join or as release of the leaked guard.
    drop(second);
    eprintln!(
        "ROOT_HTTP_FORGOTTEN {}",
        json!({"frontend_activity_retained":1,"finish_refusals":2,"current_store_unchanged":true,"successful_HTTP_or_worker_finish_receipt":false,"intentional_test_process_response_leak":true})
    );
}

#[test]
fn second_finish_after_actual_worker_error_stays_refused() {
    let fixture = Fixture::new();
    let old = fixture.image();
    let mut owner = fixture.open();
    let admitted = fixture.repo.join(".git");
    let preserved = fixture.repo.join("shutdown-error-original.git");
    assert!(!preserved.exists());
    // Owned fresh fixture only: hide the admitted directory to make the next
    // original operation fail its held/named identity check before any DB read.
    // A missing DB alone is an ordinary pre-marker refusal, not a worker error.
    std::fs::rename(&admitted, &preserved).unwrap();
    runtime().block_on(async {
        let response = owner
            .request(fixture.tool("chinwag_read_thread", json!({"thread_id":"not-present"})))
            .await
            .unwrap();
        let (_, reply) = observe("actual-original-worker-admission-error", response).await;
        assert_eq!(reply.unwrap()["result"]["isError"], true);
        quiesce(&owner).await;
    });
    let first = match owner.finish() {
        Err(failure) => failure,
        Ok(_) => panic!("original worker error became a successful finish"),
    };
    assert!(first.reason().contains("Original HTTP worker unconfirmed"));
    let original = first.into_original();
    // The first finish consumed and joined the actual failing worker. Restoring
    // the same admitted directory does not start a worker or retry the request.
    std::fs::rename(&preserved, &admitted).unwrap();
    assert_eq!(fixture.image(), old);
    let second = match original.finish() {
        Err(failure) => failure,
        Ok(_) => panic!("second finish minted a receipt after shutdown error"),
    };
    assert!(second.reason().contains("shutdown already attempted"));
    drop(second);
    let counts = chinwag_snapshot_session_private::native_counts_for_private_probe();
    assert!(counts.opens > 0);
    assert_eq!(counts.opens, counts.checked_closes);
    eprintln!(
        "ROOT_HTTP_SHUTDOWN_ERROR {}",
        json!({"actual_worker_admission_error":true,"first_checked_shutdown_error":true,"second_finish_already_attempted":true,"no_worker_restart_or_read_retry":true,"original_admitted_directory_restored":true,"current_store_unchanged":true,"successful_HTTP_finish_receipt":false,"native_opens":counts.opens,"native_checked_closes":counts.checked_closes})
    );
}
