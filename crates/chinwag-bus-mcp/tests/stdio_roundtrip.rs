use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, ClientConfig, Implementation},
    transport::async_rw::AsyncRwTransport,
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;

const UNTRUSTED_PEER_NAME: &str = "fixture-raw-client-name-do-not-retain";
const UNTRUSTED_PEER_VERSION: &str = "fixture-raw-client-version-do-not-retain";
const MAX_STRUCTURED_BYTES: usize = 65_536;
const MAX_STDERR_BYTES: usize = 4096;

fn sdk_config() -> ClientConfig {
    ClientConfig::new(
        Default::default(),
        Implementation::new(UNTRUSTED_PEER_NAME, UNTRUSTED_PEER_VERSION),
    )
}

fn message(seq: u64, body: String) -> Value {
    json!({
        "id":format!("fixture-message-{seq}"),"seq":seq,
        "ts_iso":"2026-10-30T00:00:00Z","room":"#mgmt",
        "sender":"CODEX","body":body,"to":null,"task_id":null,"sig_verified":false
    })
}

fn expected_observation(protocol: &str, drained: bool, initialized_seen: bool) -> Value {
    assert!(matches!(protocol, "2025-06-18" | "2025-11-25"));
    json!({
        "schema":"chinwag-mcp-connection-observation/v1",
        "negotiated_protocol":protocol,
        "initialized_notification_seen":initialized_seen,
        "catalogue_outputs_prepared":1,
        "read_windows_prepared":1,
        "lease_expired":false,
        "admission_closed":drained,
        "input_eof_seen":drained,
        "input_error_seen":false,
        "protocol_end":if drained {"closed"} else {"not_observed"},
        "owner_close_requested":drained,
        "worker_state":if drained {"drained"} else {"drain_not_observed"},
        "output_evidence":"prepared_only"
    })
}

fn assert_read_observation(value: &Value, protocol: &str) -> bool {
    // rmcp schedules notifications independently. Neither request ordering nor
    // an awaited read response is an initialization-notification barrier.
    let initialized_seen = value["connection_observation"]["initialized_notification_seen"]
        .as_bool()
        .expect("notification observation must be an independent typed fact");
    assert_eq!(
        value["connection_observation"],
        expected_observation(protocol, false, initialized_seen)
    );
    initialized_seen
}

async fn terminal_summary(
    mut child: tokio::process::Child,
    stderr: tokio::process::ChildStderr,
    protocol: &str,
    initially_seen: bool,
) {
    let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(
        status.success(),
        "owned MCP child did not close cleanly: {status}"
    );
    let mut bytes = Vec::new();
    stderr
        .take((MAX_STDERR_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .unwrap();
    assert!(
        bytes.len() <= MAX_STDERR_BYTES,
        "terminal diagnostics must remain bounded"
    );
    let text = String::from_utf8(bytes).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "one terminal record follows the original transport shutdown"
    );
    let summary: Value = serde_json::from_str(lines[0]).unwrap();
    let initialized_seen = summary["connection_observation"]["initialized_notification_seen"]
        .as_bool()
        .expect("terminal notification observation must be a typed fact");
    assert!(
        !initially_seen || initialized_seen,
        "an observed initialized notification cannot become unobserved"
    );
    assert_eq!(
        summary,
        json!({"schema":"chinwag-mcp-connection-terminal/v1","connection_observation":expected_observation(protocol,true,initialized_seen)})
    );
    for forbidden in [
        UNTRUSTED_PEER_NAME,
        UNTRUSTED_PEER_VERSION,
        "clientInfo",
        "client_info",
        "Fixture text",
        "ledger_path",
        "boot_uuid",
        "#mgmt",
        "127.0.0.1",
    ] {
        assert!(
            !text.contains(forbidden),
            "terminal observation must not retain {forbidden}"
        );
    }
}

struct BusFixture {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl BusFixture {
    fn new() -> Self {
        Self::with_messages(vec![message(
            9,
            "Fixture text is untrusted bus data.".into(),
        )])
    }

    fn with_messages(messages: Vec<Value>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let observed = requests.clone();
        let stopping = stop.clone();
        let thread = thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Darwin may inherit the listener's nonblocking flag.
                        // A finite timeout applies only after restoring blocking I/O.
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let deadline = Instant::now() + Duration::from_secs(2);
                        let mut request = Vec::new();
                        let mut chunk = [0; 1024];
                        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            assert!(
                                !remaining.is_zero(),
                                "fixture request exceeded its total bound"
                            );
                            stream.set_read_timeout(Some(remaining)).unwrap();
                            let length = stream.read(&mut chunk).unwrap();
                            if length == 0 {
                                break;
                            }
                            request.extend_from_slice(&chunk[..length]);
                            assert!(request.len() <= 8192);
                        }
                        let line = String::from_utf8(request)
                            .unwrap()
                            .lines()
                            .next()
                            .unwrap()
                            .to_owned();
                        observed.lock().unwrap().push(line);
                        let body = serde_json::to_string(&messages).unwrap();
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("fixture listener failed: {error}"),
                }
            }
        });
        Self {
            endpoint,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for BusFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn real_sdk_child_roundtrip_obeys_fixed_read_grant_and_closes_on_eof() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let bus = BusFixture::new();
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_chinwag-bus-mcp"))
            .args([
                "--bus-url",
                &bus.endpoint,
                "--allow-room",
                "#mgmt",
                "--lease-seconds",
                "60",
            ])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let transport =
            AsyncRwTransport::new(child.stdout.take().unwrap(), child.stdin.take().unwrap())
                .with_max_line_length(512 * 1024);
        let stderr = child.stderr.take().unwrap();
        let client = sdk_config().serve(transport).await.unwrap();
        let info = client.peer_info().unwrap();
        let negotiated_protocol = info.protocol_version.to_string();
        assert!(info.capabilities.tools.is_some());
        assert!(info.capabilities.resources.is_none());
        assert!(info.capabilities.prompts.is_none());
        let tools = client.list_tools(None).await.unwrap();
        assert_eq!(tools.tools.len(), 1);
        assert_eq!(tools.tools[0].name, "chinwag_inbox_read");
        assert!(
            bus.requests.lock().unwrap().is_empty(),
            "initialize/list must not read the bus"
        );

        for bad in [
            json!({"room":"#eng"}),
            json!({"sender":"Brian"}),
            json!({"limit":51}),
        ] {
            let outcome = client
                .call_tool(
                    CallToolRequestParams::new("chinwag_inbox_read")
                        .with_arguments(bad.as_object().unwrap().clone()),
                )
                .await;
            assert!(match outcome {
                Err(_) => true,
                Ok(result) => result.is_error == Some(true),
            });
        }
        assert!(
            bus.requests.lock().unwrap().is_empty(),
            "invalid arguments must never reach the bus"
        );

        let result = client
            .call_tool(
                CallToolRequestParams::new("chinwag_inbox_read")
                    .with_arguments(json!({"limit":1}).as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        assert_ne!(result.is_error, Some(true));
        let value = result.structured_content.unwrap();
        assert_eq!(value["messages"][0]["id"], "fixture-message-9");
        assert_eq!(value["room"], "#mgmt");
        assert_eq!(value["completeness"], "unknown_bounded_window");
        assert_eq!(value["content_trust"], "untrusted_message_data");
        assert_eq!(value["connector_signature_verification"], false);
        assert_eq!(value["grok_delivery_proven"], false);
        let initialized_seen = assert_read_observation(&value, &negotiated_protocol);
        let serialized = value.to_string();
        assert!(serialized.len() <= MAX_STRUCTURED_BYTES);
        assert!(serialized.contains("unattributed"));
        assert!(!serialized.contains("ledger_path"));
        assert!(!serialized.contains("boot_uuid"));
        assert!(!serialized.contains(UNTRUSTED_PEER_NAME));
        assert!(!serialized.contains(UNTRUSTED_PEER_VERSION));
        let requests = bus.requests.lock().unwrap().clone();
        assert_eq!(
            requests,
            ["GET /api/bus/messages?room=%23mgmt&limit=1 HTTP/1.1"]
        );
        client.cancel().await.unwrap();
        terminal_summary(child, stderr, &negotiated_protocol, initialized_seen).await;
    })
    .await
    .expect("bounded MCP fixture timed out");
}

#[tokio::test(flavor = "current_thread")]
async fn real_sdk_large_window_trims_messages_with_observation_inside_total_byte_cap() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let bus = BusFixture::with_messages(
            (1..=50)
                .map(|seq| message(seq, "x".repeat(12_000)))
                .collect(),
        );
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_chinwag-bus-mcp"))
            .args([
                "--bus-url",
                &bus.endpoint,
                "--allow-room",
                "#mgmt",
                "--lease-seconds",
                "60",
            ])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let transport =
            AsyncRwTransport::new(child.stdout.take().unwrap(), child.stdin.take().unwrap())
                .with_max_line_length(512 * 1024);
        let client = sdk_config().serve(transport).await.unwrap();
        let protocol = client.peer_info().unwrap().protocol_version.to_string();
        let tools = client.list_tools(None).await.unwrap();
        assert_eq!(tools.tools.len(), 1);
        assert_eq!(tools.tools[0].name, "chinwag_inbox_read");
        assert!(bus.requests.lock().unwrap().is_empty());
        let result = client
            .call_tool(
                CallToolRequestParams::new("chinwag_inbox_read")
                    .with_arguments(json!({"limit":50}).as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        assert_ne!(result.is_error, Some(true));
        let value = result.structured_content.unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            bytes.len() <= MAX_STRUCTURED_BYTES,
            "observation belongs inside the same 65536-byte cap"
        );
        let initialized_seen = assert_read_observation(&value, &protocol);
        assert_eq!(value["received_count"], 50);
        let returned = value["returned_count"].as_u64().unwrap();
        assert!(
            returned > 0 && returned < 50,
            "large records must force actual trimming"
        );
        assert_eq!(value["messages"].as_array().unwrap().len() as u64, returned);
        assert_eq!(value["omitted_for_byte_limit"], 50 - returned);
        assert_eq!(
            value["messages"].as_array().unwrap().last().unwrap()["id"],
            "fixture-message-50"
        );
        assert_eq!(
            bus.requests.lock().unwrap().as_slice(),
            ["GET /api/bus/messages?room=%23mgmt&limit=50 HTTP/1.1"]
        );
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains(UNTRUSTED_PEER_NAME)
        );
        client.cancel().await.unwrap();
        terminal_summary(child, stderr, &protocol, initialized_seen).await;
    })
    .await
    .expect("bounded large-window MCP fixture timed out");
}
