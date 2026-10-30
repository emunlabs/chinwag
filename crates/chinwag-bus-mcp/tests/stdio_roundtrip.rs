use rmcp::{ServiceExt, model::CallToolRequestParams, transport::async_rw::AsyncRwTransport};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

struct BusFixture {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl BusFixture {
    fn new() -> Self {
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
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut chunk = [0; 1024];
                        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
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
                        let body = json!([{
                            "id": "fixture-message-9", "seq": 9,
                            "ts_iso": "2026-10-30T00:00:00Z", "room": "#mgmt",
                            "sender": "CODEX", "body": "Fixture text is untrusted bus data.",
                            "to": null, "task_id": null, "sig_verified": false
                        }])
                        .to_string();
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
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let transport =
            AsyncRwTransport::new(child.stdout.take().unwrap(), child.stdin.take().unwrap())
                .with_max_line_length(512 * 1024);
        let client = ().serve(transport).await.unwrap();
        let info = client.peer_info().unwrap();
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
        let serialized = value.to_string();
        assert!(serialized.contains("unattributed"));
        assert!(!serialized.contains("ledger_path"));
        assert!(!serialized.contains("boot_uuid"));
        let requests = bus.requests.lock().unwrap().clone();
        assert_eq!(
            requests,
            ["GET /api/bus/messages?room=%23mgmt&limit=1 HTTP/1.1"]
        );
        client.cancel().await.unwrap();
        let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(
            status.success(),
            "owned MCP child did not close cleanly: {status}"
        );
    })
    .await
    .expect("bounded MCP fixture timed out");
}
