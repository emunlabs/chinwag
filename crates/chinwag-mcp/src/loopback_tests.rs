//! New once-only fixtures; each request crosses an actual TCP HTTP/1 connection.
use crate::{loopback_listener::LoopbackListener, repository_http::AccessSecret};
use bytes::Bytes;
use http::{HeaderValue, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{io::Read, net::SocketAddr, path::PathBuf, thread::JoinHandle, time::Duration};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

struct Fixture {
    repo: PathBuf,
    secret: Zeroizing<[u8; 32]>,
    header: HeaderValue,
}
impl Fixture {
    fn new() -> Self {
        let repo =
            PathBuf::from(std::env::var_os("CHINWAG_HTTP_FIXTURE").expect("new private fixture"));
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
        Self {
            repo,
            secret,
            header,
        }
    }
    fn bind(&self) -> LoopbackListener {
        let owner = LoopbackListener::bind_private_repository(
            self.repo.clone(),
            AccessSecret::new(*self.secret),
        )
        .unwrap();
        assert_eq!(owner.address().ip(), std::net::Ipv4Addr::LOCALHOST);
        assert_ne!(owner.address().port(), 0);
        owner
    }
    fn start(&self) -> Running {
        let mut owner = self.bind();
        let address = owner.address();
        let stop = CancellationToken::new();
        let signal = stop.clone();
        let thread = std::thread::spawn(move || {
            let stopped = owner.serve_until(signal).expect("original socket loop");
            let observations = (stopped.connections(), stopped.transport_failures());
            assert!(
                owner.serve_until(CancellationToken::new()).is_err(),
                "no second serve"
            );
            assert!(owner.finish().unwrap().original_worker_checked());
            observations
        });
        Running {
            address,
            stop,
            thread,
        }
    }
    fn request(
        &self,
        address: SocketAddr,
        method: &str,
        mut params: Value,
    ) -> Request<Full<Bytes>> {
        params.as_object_mut().unwrap().insert("_meta".into(), json!({
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientInfo":{"name":"Root-actual-loopback-client","version":"0.0.1"},
            "io.modelcontextprotocol/clientCapabilities":{}
        }));
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("host", address.to_string())
            .header("authorization", self.header.clone())
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method);
        if let Some(name) = params.get("name").and_then(Value::as_str) {
            builder = builder.header("mcp-name", name);
        }
        builder
            .body(Full::new(Bytes::from(
                serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":19,"method":method,"params":params}),
                )
                .unwrap(),
            )))
            .unwrap()
    }
    fn tool(&self, address: SocketAddr, name: &str, args: Value) -> Request<Full<Bytes>> {
        self.request(address, "tools/call", json!({"name":name,"arguments":args}))
    }
    fn image(&self) -> Vec<u8> {
        std::fs::read(self.repo.join(".chinwag/state.crdb")).unwrap()
    }
}
struct Running {
    address: SocketAddr,
    stop: CancellationToken,
    thread: JoinHandle<(u64, u64)>,
}
impl Running {
    fn finish(self, expected: u64) {
        self.stop.cancel();
        let (connections, failures) = self
            .thread
            .join()
            .expect("actual original server thread join");
        assert_eq!(connections, expected);
        assert_eq!(failures, 0);
        assert!(
            std::net::TcpStream::connect_timeout(&self.address, Duration::from_millis(100))
                .is_err(),
            "original port still accepting"
        );
        let counts = chinwag_snapshot_session_private::native_counts_for_private_probe();
        assert!(counts.opens > 0);
        assert_eq!(counts.opens, counts.checked_closes);
        eprintln!(
            "ROOT_LOOPBACK_CHECKED {}",
            json!({"connections":connections,"transport_failures":failures,"actual_server_thread_join":true,"original_port_closed":true,"native_opens":counts.opens,"native_checked_closes":counts.checked_closes})
        );
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
async fn exchange(
    address: SocketAddr,
    request: Request<Full<Bytes>>,
    label: &str,
) -> (u16, Option<Value>) {
    tokio::time::timeout(Duration::from_secs(8), async {
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
        let task = tokio::spawn(connection);
        let response = sender.send_request(request).await.unwrap();
        let status = response.status().as_u16();
        assert!(response.headers().get("mcp-session-id").is_none());
        let is_sse = response.headers().get("content-type").is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        drop(sender);
        task.await.expect("original client connection task join").expect("original client connection EOF");
        let value = if is_sse {
            let text = std::str::from_utf8(&body).unwrap().replace("\r\n", "\n");
            assert!(text.ends_with("\n\n"));
            let data: Vec<_> = text.lines().filter_map(|line| line.strip_prefix("data:")).filter(|s| !s.trim().is_empty()).collect();
            assert_eq!(data.len(), 1);
            let value: Value = serde_json::from_str(data[0]).unwrap();
            assert_eq!(value["id"], 19);
            Some(value)
        } else { None };
        eprintln!("ROOT_LOOPBACK_WIRE {}", json!({"label":label,"status":status,"actual_TCP_client_EOF":true,"SSE":is_sse,"literal_body":String::from_utf8(body.to_vec()).unwrap()}));
        (status, value)
    }).await.expect("bounded actual TCP client")
}
async fn tool(f: &Fixture, server: &Running, label: &str, name: &str, args: Value) -> Value {
    let (status, reply) = exchange(server.address, f.tool(server.address, name, args), label).await;
    assert_eq!(status, 200);
    let reply = reply.unwrap();
    assert_eq!(reply["result"]["isError"], false);
    reply["result"]["structuredContent"].clone()
}
fn pin() -> Value {
    json!({"id":"tcp-pin","thread_id":"tcp-thread","file_path":"literal.rs","symbol_hash":"caller-symbol","source_commit":"caller-source","body":"Real loopback decision 🌱","created_at_ms":1,"create_thread":{"repo_id":"caller-repo","branch_ref":"refs/heads/main","title":"Actual TCP thread"}})
}

#[test]
fn actual_tcp_sse_write_read_retry_handoff_restart() {
    let f = Fixture::new();
    let old = f.image();
    let server = f.start();
    let rt = runtime();
    rt.block_on(async {
        let (status, discovery) = exchange(server.address, f.request(server.address,"server/discover",json!({})),"discovery").await;
        assert_eq!(status,200);
        assert_eq!(discovery.unwrap()["result"]["supportedVersions"],json!(["2026-07-28"]));
        let first = tool(&f,&server,"first-pin","chinwag_pin_context",pin()).await;
        assert_eq!(first["replayed"],false);
        assert_eq!(first["pin"]["body"],pin()["body"]);
        let written=f.image();assert_ne!(old,written);
        let retry=tool(&f,&server,"exact-retry","chinwag_pin_context",pin()).await;
        assert_eq!(retry["replayed"],true);assert_eq!(f.image(),written);
        let handoff=tool(&f,&server,"handoff-local-offer","chinwag_handoff",json!({"id":"tcp-offer","thread_id":"tcp-thread","target_label":"unverified-caller-label","note":"Local offer only","created_at_ms":2})).await;
        assert_eq!(handoff["state"],"recorded_local_offer");assert_eq!(handoff["delivery"],"not_attempted");
        let view=tool(&f,&server,"read-current","chinwag_read_thread",json!({"thread_id":"tcp-thread"})).await;
        assert_eq!(view["pins"][0]["body"],pin()["body"]);assert_eq!(view["messages"].as_array().unwrap().len(),1);
    });
    server.finish(5);
    let written = f.image();
    let restarted = f.start();
    rt.block_on(async {
        let view = tool(
            &f,
            &restarted,
            "restart-read",
            "chinwag_read_thread",
            json!({"thread_id":"tcp-thread"}),
        )
        .await;
        assert_eq!(view["pins"][0]["body"], pin()["body"]);
        assert_eq!(view["messages"].as_array().unwrap().len(), 1);
    });
    restarted.finish(1);
    assert_eq!(f.image(), written);
}

#[test]
fn actual_tcp_authority_auth_origin_protocol_and_size_refusals() {
    let f = Fixture::new();
    let old = f.image();
    let server = f.start();
    runtime().block_on(async {
        let fresh = || f.tool(server.address, "chinwag_pin_context", pin());
        let mut cases = Vec::new();
        let mut r = fresh();
        r.headers_mut().remove("authorization");
        cases.push(("no-auth", r, 401));
        let mut r = fresh();
        r.headers_mut().append("authorization", f.header.clone());
        cases.push(("duplicate-auth", r, 401));
        let mut r = fresh();
        r.headers_mut()
            .insert("host", HeaderValue::from_static("other.invalid:1234"));
        cases.push(("wrong-host", r, 403));
        let mut r = fresh();
        r.headers_mut().insert(
            "origin",
            HeaderValue::from_str(&format!("http://{}", server.address)).unwrap(),
        );
        cases.push(("origin-refused", r, 403));
        let mut r = fresh();
        *r.uri_mut() = "/mcp?secret=no".parse().unwrap();
        cases.push(("query-refused", r, 404));
        let mut r = fresh();
        *r.method_mut() = http::Method::GET;
        cases.push(("GET-refused", r, 405));
        let mut r = fresh();
        r.headers_mut().insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-11-25"),
        );
        cases.push(("legacy-protocol", r, 400));
        let mut r = fresh();
        r.headers_mut().remove("mcp-name");
        cases.push(("missing-name", r, 400));
        let mut r = fresh();
        *r.body_mut() = Full::new(Bytes::from_static(b"{bad"));
        cases.push(("bad-json", r, 415));
        let mut r = fresh();
        *r.body_mut() = Full::new(Bytes::from(vec![b' '; crate::wire::MAX_INPUT_BYTES + 1]));
        cases.push(("body-limit", r, 413));
        for (label, r, status) in cases {
            let (actual, _) = exchange(server.address, r, label).await;
            assert_eq!(actual, status, "{label}");
            assert_eq!(f.image(), old, "{label}");
        }
    });
    server.finish(10);
    assert_eq!(f.image(), old);
}

#[test]
fn actual_tcp_idle_connection_cancel_and_original_finish() {
    let f = Fixture::new();
    let old = f.image();
    let owner = f.bind();
    let failure = match owner.finish() {
        Err(e) => e,
        Ok(_) => panic!("unserved listener accepted finish"),
    };
    assert!(failure.reason().contains("not been stopped"));
    let mut owner = failure.into_original();
    let address = owner.address();
    let stop = CancellationToken::new();
    let signal = stop.clone();
    let thread = std::thread::spawn(move || {
        let stopped = owner.serve_until(signal).unwrap();
        assert!(owner.finish().unwrap().original_worker_checked());
        stopped.connections()
    });
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    // A partial request forces the original connection future to remain pending.
    use std::io::Write;
    stream.write_all(b"POST /mcp HTTP/1.1\r\nHost: ").unwrap();
    std::thread::sleep(Duration::from_millis(25));
    stop.cancel();
    let connections = thread.join().expect("original idle server joined");
    // A cancellation before accept does not satisfy this active-connection case.
    assert_eq!(connections, 1);
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut b = [0u8; 1];
    assert!(!matches!(stream.read(&mut b),Ok(n) if n>0));
    assert!(std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err());
    assert_eq!(f.image(), old);
    let counts = chinwag_snapshot_session_private::native_counts_for_private_probe();
    assert_eq!(counts.opens, counts.checked_closes);
    eprintln!(
        "ROOT_LOOPBACK_CANCEL {}",
        json!({"original_server_join":true,"original_socket_closed":true,"partial_request_no_result":true,"store_unchanged":true,"connections":connections,"native_opens":counts.opens,"native_checked_closes":counts.checked_closes})
    );
}

#[test]
fn actual_tcp_committed_status_then_unread_result_preserves_current_store() {
    use std::io::Write;
    let f = Fixture::new();
    let old = f.image();
    let server = f.start();
    let address = server.address;
    let request = f.tool(address, "chinwag_pin_context", pin());
    let (parts, body) = request.into_parts();
    let body = runtime().block_on(body.collect()).unwrap().to_bytes();
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    stream.write_all(b"POST /mcp HTTP/1.1\r\n").unwrap();
    // Write the actual authenticated request only to this original socket. Never log it.
    for (name, value) in &parts.headers {
        stream.write_all(name.as_str().as_bytes()).unwrap();
        stream.write_all(b": ").unwrap();
        stream.write_all(value.as_bytes()).unwrap();
        stream.write_all(b"\r\n").unwrap();
    }
    write!(stream, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    // One-byte reads cannot consume response headers or a tool-result frame.
    // The listener constructs this status only after its original response body
    // was buffered and the original pin operation has completed.
    let mut status_line = Vec::new();
    for _ in 0..128 {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).unwrap();
        status_line.push(byte[0]);
        if status_line.ends_with(b"\r\n") {
            break;
        }
    }
    assert_eq!(status_line, b"HTTP/1.1 200 OK\r\n");
    let written = f.image();
    assert_ne!(written, old);
    drop(stream); // No response header or SSE frame was read by the application.
    server.stop.cancel();
    let (connections, failures) = server
        .thread
        .join()
        .expect("original output-loss server joined");
    assert_eq!(connections, 1);
    // Client output loss can be observed as a transport error or a completed send;
    // neither observation is a client tool acknowledgment or a database rollback.
    assert!(failures <= 1);
    assert!(std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err());
    let counts = chinwag_snapshot_session_private::native_counts_for_private_probe();
    assert!(counts.opens > 0);
    assert_eq!(counts.opens, counts.checked_closes);
    eprintln!(
        "ROOT_LOOPBACK_OUTPUT_LOSS {}",
        json!({"status":200,"client_read_only_status_line":true,"tool_result_frames_read":0,"tool_acknowledgment_received":false,"current_write_retained":true,"connections":connections,"transport_failures":failures,"actual_original_server_join":true,"original_port_closed":true,"native_opens":counts.opens,"native_checked_closes":counts.checked_closes})
    );
    let restarted = f.start();
    runtime().block_on(async {
        let view = tool(
            &f,
            &restarted,
            "restart-after-TCP-output-loss",
            "chinwag_read_thread",
            json!({"thread_id":"tcp-thread"}),
        )
        .await;
        assert_eq!(view["pins"].as_array().unwrap().len(), 1);
        assert_eq!(view["pins"][0]["body"], pin()["body"]);
        assert_eq!(view["messages"], json!([]));
    });
    restarted.finish(1);
    assert_eq!(f.image(), written);
}
