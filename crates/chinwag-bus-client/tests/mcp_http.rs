use chinwag_bus_client::{
    BusClient, ClientError, HttpMcpSetupOffer, MAX_MCP_HTTP_STATUS_BYTES, McpWorkerState,
    RuntimeMcpStatus,
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

const NONCE: &str = "0123456789abcdef0123456789abcdef";
const PRIVATE_MARKER: &str = "fixture-private-body-do-not-display";

fn status() -> Value {
    json!({
        "ok":true,"schema":"chinwag-runtime-owned-mcp/v1",
        "binding_authority":"owner_local_http_capability_unattributed",
        "transport":{
            "schema":"chinwag-owner-http-inbox/v1",
            "session_started":false,"session_closed":false,"transport_worker_joined":false,"reader_worker_joined":false,
            "client_identity":"unattributed_owner_http_capability",
            "connection_observation":{
                "schema":"chinwag-mcp-connection-observation/v1","negotiated_protocol":null,
                "initialized_notification_seen":false,"catalogue_outputs_prepared":0,"read_windows_prepared":0,
                "lease_expired":false,"admission_closed":false,"input_eof_seen":false,"input_error_seen":false,
                "protocol_end":"not_observed","owner_close_requested":false,"worker_state":"drain_not_observed","output_evidence":"prepared_only"
            }
        }
    })
}
fn with_offer(endpoint: &str) -> Value {
    let mut value = status();
    value["setup_offer"] =
        serde_json::to_value(HttpMcpSetupOffer::new(endpoint, NONCE).unwrap()).unwrap();
    value
}

fn fixture(
    status: u16,
    body: impl FnOnce(&str) -> Option<Vec<u8>>,
    extra_declared: usize,
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let body = body(&url);
    let worker = thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(3);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(stream) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < until);
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        };
        // Darwin may preserve nonblocking mode on accept; bound a blocking read.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut captured = Vec::new();
        while !captured.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            assert!(Instant::now() < until);
            let mut bytes = [0u8; 1024];
            let count = stream.read(&mut bytes).unwrap();
            assert!(count > 0);
            captured.extend_from_slice(&bytes[..count]);
            assert!(captured.len() < 4096);
        }
        if let Some(body) = body {
            write!(stream,"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()+extra_declared).unwrap();
            let _ = stream.write_all(&body);
        }
        drop(stream);
        let mut requests = vec![String::from_utf8(captured).unwrap()];
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_millis(30)))
                    .unwrap();
                let mut bytes = [0u8; 4096];
                let count = stream.read(&mut bytes).unwrap_or(0);
                requests.push(String::from_utf8_lossy(&bytes[..count]).into_owned());
            }
            thread::sleep(Duration::from_millis(5));
        }
        requests
    });
    (url, worker)
}
fn json_fixture(value: Value) -> (String, thread::JoinHandle<Vec<String>>) {
    fixture(200, move |_| Some(serde_json::to_vec(&value).unwrap()), 0)
}

#[test]
fn one_explicit_same_endpoint_get_accepts_old_status_without_setup_offer() {
    let (url, worker) = json_fixture(status());
    let observed = BusClient::new(&url)
        .unwrap()
        .mcp_http_status()
        .unwrap()
        .unwrap();
    assert!(observed.setup_offer.is_none());
    assert_eq!(
        observed
            .transport
            .connection_observation
            .read_windows_prepared,
        0
    );
    let requests = worker.join().unwrap();
    assert_eq!(requests.len(), 1);
    let request = requests[0].to_ascii_lowercase();
    assert!(request.starts_with("get /api/onboarding/mcp-http/status http/1.1\r\n"));
    assert_eq!(
        request
            .matches("x-chinwag-onboarding-intent: 1\r\n")
            .count(),
        1
    );
    for forbidden in [
        "authorization:",
        "cookie:",
        "proxy-authorization:",
        "post ",
        "/api/bus/clients",
        "/api/bus/messages",
        "/api/mcp ",
    ] {
        assert!(!request.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn same_endpoint_offer_builds_only_fixed_vscode_http_and_password_input() {
    let (url, worker) = fixture(
        200,
        |endpoint| Some(serde_json::to_vec(&with_offer(endpoint)).unwrap()),
        0,
    );
    let observed = BusClient::new(&url)
        .unwrap()
        .mcp_http_status()
        .unwrap()
        .unwrap();
    let offer = observed.usable_setup_offer().unwrap();
    let config = offer.vscode_configuration().unwrap();
    assert_eq!(
        config,
        json!({
            "servers":{format!("chinwag-native-inbox-mgmt-http-{NONCE}"):{
                "type":"http","url":format!("{url}api/mcp"),
                "headers":{"Authorization":format!("Bearer ${{input:chinwag-http-token-{NONCE}}}")}
            }},
            "inputs":[{"type":"promptString","id":format!("chinwag-http-token-{NONCE}"),"description":"Enter the Chinwag HTTP capability supplied by the runtime owner","password":true}]
        })
    );
    let text = serde_json::to_string(&config).unwrap();
    for forbidden in [
        "command",
        "args",
        "env",
        "default",
        "gallery",
        "cookie",
        PRIVATE_MARKER,
    ] {
        assert!(!text.contains(forbidden));
    }
    assert_eq!(worker.join().unwrap().len(), 1);
}

#[test]
fn strict_schema_enums_unknown_private_fields_and_derived_join_are_rejected() {
    for (pointer, value) in [
        ("/ok", json!(false)),
        ("/schema", json!("other")),
        (
            "/binding_authority",
            json!("owner_local_stdio_unattributed"),
        ),
        ("/transport/schema", json!("other")),
        ("/transport/client_identity", json!("verified_cursor")),
        ("/transport/connection_observation/schema", json!("other")),
        (
            "/transport/connection_observation/negotiated_protocol",
            json!("2026-07-28"),
        ),
        (
            "/transport/connection_observation/protocol_end",
            json!("connected"),
        ),
        (
            "/transport/connection_observation/worker_state",
            json!("running"),
        ),
        (
            "/transport/connection_observation/output_evidence",
            json!("received"),
        ),
        ("/transport/reader_worker_joined", json!(true)),
        (
            "/transport/connection_observation/read_windows_prepared",
            json!(-1),
        ),
    ] {
        let mut body = status();
        *body.pointer_mut(pointer).unwrap() = value;
        let (url, worker) = json_fixture(body);
        assert!(
            BusClient::new(&url).unwrap().mcp_http_status().is_err(),
            "{pointer}"
        );
        assert_eq!(worker.join().unwrap().len(), 1);
    }
    for location in ["", "/transport", "/transport/connection_observation"] {
        let mut body = status();
        body.pointer_mut(location)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("private_token".into(), json!(PRIVATE_MARKER));
        let (url, worker) = json_fixture(body);
        let error = BusClient::new(&url)
            .unwrap()
            .mcp_http_status()
            .unwrap_err()
            .to_string();
        assert!(!error.contains(PRIVATE_MARKER));
        assert!(!error.contains("private_token"));
        assert_eq!(worker.join().unwrap().len(), 1);
    }
}

#[test]
fn independent_protocol_facts_and_saturated_counts_remain_valid_history() {
    let mut value = status();
    let transport = &mut value["transport"];
    transport["session_started"] = json!(true);
    transport["session_closed"] = json!(true);
    transport["transport_worker_joined"] = json!(true);
    let observation = &mut transport["connection_observation"];
    observation["negotiated_protocol"] = json!("2025-06-18");
    observation["catalogue_outputs_prepared"] = json!(0);
    observation["read_windows_prepared"] = json!(u64::MAX);
    observation["lease_expired"] = json!(true);
    observation["admission_closed"] = json!(false);
    observation["worker_state"] = json!("failed");
    let (url, worker) = json_fixture(value);
    let status = BusClient::new(&url)
        .unwrap()
        .mcp_http_status()
        .unwrap()
        .unwrap();
    assert_eq!(
        status.transport.connection_observation.worker_state,
        McpWorkerState::Failed
    );
    assert_eq!(
        status
            .transport
            .connection_observation
            .read_windows_prepared,
        u64::MAX
    );
    assert!(
        !status
            .transport
            .connection_observation
            .initialized_notification_seen
    );
    assert_eq!(worker.join().unwrap().len(), 1);
}

#[test]
fn nullable_protocol_is_required_while_only_setup_offer_is_compatible_when_absent() {
    let original = status();
    assert!(serde_json::from_value::<RuntimeMcpStatus>(original.clone()).is_ok());
    let mut missing = original;
    missing["transport"]["connection_observation"]
        .as_object_mut()
        .unwrap()
        .remove("negotiated_protocol");
    assert!(serde_json::from_value::<RuntimeMcpStatus>(missing).is_err());
}

#[test]
fn status_errors_are_fixed_bounded_and_never_echo_response_or_transport_details() {
    for http_status in [403, 500] {
        let (url, worker) = fixture(http_status, |_| Some(PRIVATE_MARKER.as_bytes().to_vec()), 0);
        let error = BusClient::new(&url).unwrap().mcp_http_status().unwrap_err();
        assert!(matches!(error,ClientError::HttpStatus{status,..} if status==http_status));
        assert!(!error.to_string().contains(PRIVATE_MARKER));
        assert!(!error.to_string().contains(&url));
        assert_eq!(worker.join().unwrap().len(), 1);
    }
    for body in [
        None,
        Some(PRIVATE_MARKER.as_bytes().to_vec()),
        Some(b"{\"private_token\":\"fixture-private-body-do-not-display\"}".to_vec()),
    ] {
        let (url, worker) = fixture(200, move |_| body, 0);
        let error = BusClient::new(&url)
            .unwrap()
            .mcp_http_status()
            .unwrap_err()
            .to_string();
        assert!(!error.contains(PRIVATE_MARKER));
        assert!(!error.contains(&url));
        assert!(!error.contains("private_token"));
        assert_eq!(worker.join().unwrap().len(), 1);
    }
    let (url, worker) = fixture(200, |_| Some(serde_json::to_vec(&status()).unwrap()), 20);
    let error = BusClient::new(&url)
        .unwrap()
        .mcp_http_status()
        .unwrap_err()
        .to_string();
    assert!(!error.contains(&url));
    assert_eq!(worker.join().unwrap().len(), 1);
}

#[test]
fn response_cap_is_four_kib_and_404_is_only_unavailable_compatibility() {
    let (url, worker) = fixture(200, |_| Some(vec![b' '; MAX_MCP_HTTP_STATUS_BYTES + 1]), 0);
    assert!(matches!(
        BusClient::new(&url).unwrap().mcp_http_status(),
        Err(ClientError::ResponseTooLarge {
            limit: MAX_MCP_HTTP_STATUS_BYTES
        })
    ));
    assert_eq!(worker.join().unwrap().len(), 1);
    let (url, worker) = fixture(404, |_| Some(PRIVATE_MARKER.as_bytes().to_vec()), 0);
    assert!(
        BusClient::new(&url)
            .unwrap()
            .mcp_http_status()
            .unwrap()
            .is_none()
    );
    assert_eq!(worker.join().unwrap().len(), 1);
}

#[test]
fn offer_constructor_requires_canonical_origin_and_exact_nonsecret_nonce() {
    for endpoint in ["http://127.0.0.1/", "http://127.0.0.1:44346/"] {
        let offer = HttpMcpSetupOffer::new(endpoint, NONCE).unwrap();
        assert_eq!(offer.url, format!("{endpoint}api/mcp"));
        offer.validate().unwrap();
    }
    for endpoint in [
        "http://localhost:44346/",
        "http://127.0.0.2:44346/",
        "http://127.0.0.1:44346",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:0/",
        "https://127.0.0.1/",
        "http://127.0.0.1/path/",
        "http://127.0.0.1/?q=1",
        "http://127.0.0.1/#x",
        "http://user@127.0.0.1/",
        "http://[::1]/",
        "http://127.0.0.1/./",
    ] {
        assert!(
            HttpMcpSetupOffer::new(endpoint, NONCE).is_err(),
            "{endpoint}"
        );
    }
    for nonce in [
        "",
        "0123",
        "0123456789ABCDEF0123456789ABCDEF",
        "../0123456789abcdef0123456789abcd",
        "0123456789abcdef0123456789abcdef0",
    ] {
        assert!(HttpMcpSetupOffer::new("http://127.0.0.1/", nonce).is_err());
    }
}

#[test]
fn mismatched_forward_port_alias_path_and_offer_ids_cannot_be_copied() {
    for url_kind in [
        "port", "alias", "query", "fragment", "path", "userinfo", "encoded",
    ] {
        let (url, worker) = fixture(
            200,
            move |endpoint| {
                let mut value = with_offer(endpoint);
                value["setup_offer"]["url"] = json!(match url_kind {
                    "port" => "http://127.0.0.1:1/api/mcp".into(),
                    "alias" => format!("{}api/mcp", endpoint.replace("127.0.0.1", "localhost")),
                    "query" => format!("{endpoint}api/mcp?q=1"),
                    "fragment" => format!("{endpoint}api/mcp#x"),
                    "path" => format!("{endpoint}api/./mcp"),
                    "userinfo" => format!("{}api/mcp", endpoint.replace("http://", "http://user@")),
                    "encoded" => format!("{endpoint}api/%6dcp"),
                    _ => unreachable!(),
                });
                Some(serde_json::to_vec(&value).unwrap())
            },
            0,
        );
        assert!(
            BusClient::new(&url).unwrap().mcp_http_status().is_err(),
            "{url_kind}"
        );
        assert_eq!(worker.join().unwrap().len(), 1);
    }
    for key in ["server_name", "input_id"] {
        let mut offer = HttpMcpSetupOffer::new("http://127.0.0.1/", NONCE).unwrap();
        if key == "server_name" {
            offer.server_name.push('a');
        } else {
            offer.input_id = offer.input_id.replace(NONCE, &"a".repeat(32));
        }
        assert!(offer.validate().is_err());
        assert!(offer.vscode_configuration().is_err());
    }
}

#[test]
fn expired_closed_or_used_offer_is_valid_history_but_never_usable_for_setup() {
    for pointer in [
        "/transport/session_started",
        "/transport/session_closed",
        "/transport/connection_observation/lease_expired",
        "/transport/connection_observation/admission_closed",
    ] {
        let mut value = with_offer("http://127.0.0.1/");
        *value.pointer_mut(pointer).unwrap() = json!(true);
        let status: RuntimeMcpStatus = serde_json::from_value(value).unwrap();
        status.validate_for("http://127.0.0.1/").unwrap();
        assert!(status.usable_setup_offer().is_none(), "{pointer}");
    }
    let mut value = with_offer("http://127.0.0.1/");
    value["setup_offer"]["token"] = json!(PRIVATE_MARKER);
    assert!(serde_json::from_value::<RuntimeMcpStatus>(value).is_err());
}
