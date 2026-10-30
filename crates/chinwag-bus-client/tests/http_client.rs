use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chinwag_bus_client::{
    BusClient, ClientError, MAX_RESPONSE_BYTES, OperationState, SendRequest, new_request_id,
};
use serde_json::{Value, json};

#[derive(Debug)]
struct Captured {
    header: String,
    body: Vec<u8>,
}

struct Fixture {
    base_url: String,
    worker: JoinHandle<Vec<Captured>>,
}

impl Fixture {
    fn http(status: &str, body: Vec<u8>) -> Self {
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        Self::raw([response.into_bytes(), body].concat())
    }

    fn raw(response: Vec<u8>) -> Self {
        Self::at_endpoint(move |_| response)
    }

    fn at_endpoint(build_response: impl FnOnce(&str) -> Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let response = build_response(&base_url);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "client did not connect");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            let first = capture(&mut stream);
            // A closed socket before the response models a POST persisted by the
            // server but no receipt reaching the client. Never replay that POST.
            let _ = stream.write_all(&response);
            drop(stream);
            let mut requests = vec![first];
            let retry_deadline = Instant::now() + Duration::from_millis(150);
            while Instant::now() < retry_deadline {
                match listener.accept() {
                    Ok((mut duplicate, _)) => {
                        duplicate.set_nonblocking(false).unwrap();
                        requests.push(capture(&mut duplicate));
                        let _ = duplicate.write_all(&response);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture retry accept failed: {error}"),
                }
            }
            requests
        });
        Self { base_url, worker }
    }

    fn requests(self) -> Vec<Captured> {
        self.worker.join().unwrap()
    }
}

fn capture(stream: &mut TcpStream) -> Captured {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0; 2048];
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "connection ended before request headers");
        bytes.extend_from_slice(&chunk[..read]);
        assert!(bytes.len() <= 65536);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let header = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
    let length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(length <= 65536);
    while bytes.len() < header_end + length {
        let mut chunk = [0; 2048];
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "connection ended before request body");
        bytes.extend_from_slice(&chunk[..read]);
    }
    Captured {
        header,
        body: bytes[header_end..header_end + length].to_vec(),
    }
}

fn request() -> SendRequest {
    SendRequest {
        sender: "Brian".into(),
        room: "#mgmt".into(),
        body: "alpha fixture message".into(),
        to: Some("PRODUCT".into()),
        task_id: Some("ALPHA-HTTP-FIXTURE".into()),
    }
}

fn message() -> Value {
    json!({
        "id": "bus-fixture-42", "seq": 42, "ts_iso": "2026-10-30T12:00:00Z",
        "room": "#mgmt", "sender": "Brian", "body": "alpha fixture message",
        "to": "PRODUCT", "task_id": "ALPHA-HTTP-FIXTURE", "sig_verified": true,
        "extra_wire_field": "ignored"
    })
}

fn receipt() -> Value {
    json!({
        "ok": true,
        "message": message(),
        "ack": {
            "ok": true, "seq": 42, "message_id": "bus-fixture-42", "room": "#mgmt",
            "transport": "local-crdb+jsonl (daemon starting)", "sig_verified": false,
            "subscribers_notified": 0, "daemon_endpoint_id": "fixture-only"
        }
    })
}

#[test]
fn explicit_attempt_identity_is_sent_once_and_status_is_get_only() {
    let id = "ui-fixture-request-0001";
    let fixture = Fixture::http("200 OK", serde_json::to_vec(&receipt()).unwrap());
    BusClient::new(&fixture.base_url)
        .unwrap()
        .send_with_id(&request(), id)
        .unwrap();
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .header
            .to_ascii_lowercase()
            .contains(&format!("x-chinwag-request-id: {id}\r\n"))
    );
    let status = json!({"ok":true,"request_id":id,"state":"delivered","receipt":{"message":message(),"ack":receipt()["ack"]}});
    let fixture = Fixture::http("200 OK", serde_json::to_vec(&status).unwrap());
    let operation = BusClient::new(&fixture.base_url)
        .unwrap()
        .operation(id)
        .unwrap();
    match operation.state {
        OperationState::Delivered(receipt) => receipt.validate_for(&request()).unwrap(),
        state => panic!("expected restored receipt, got {state:?}"),
    }
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .header
            .starts_with(&format!("GET /api/bus/sends/{id} HTTP/1.1\r\n"))
    );
    assert!(requests[0].body.is_empty());
}

#[test]
fn operation_unknown_pending_uncertain_and_invalid_identity_never_post() {
    let id = "ui-fixture-request-0002";
    let fixture = Fixture::http(
        "404 Not Found",
        br#"{"ok":false,"error":"unknown"}"#.to_vec(),
    );
    assert!(matches!(
        BusClient::new(&fixture.base_url).unwrap().operation(id),
        Err(ClientError::HttpStatus { status: 404, .. })
    ));
    assert_eq!(fixture.requests().len(), 1);
    for (state, error) in [("pending", None), ("uncertain", Some("child output lost"))] {
        let fixture = Fixture::http(
            "200 OK",
            serde_json::to_vec(&json!({"ok":true,"request_id":id,"state":state,"error":error}))
                .unwrap(),
        );
        let result = BusClient::new(&fixture.base_url)
            .unwrap()
            .operation(id)
            .unwrap();
        if state == "pending" {
            assert_eq!(result.state, OperationState::Pending);
        } else {
            assert_eq!(
                result.state,
                OperationState::Uncertain("child output lost".into())
            );
        }
        assert_eq!(fixture.requests().len(), 1);
    }
    for malformed in [
        json!({"ok":true,"request_id":"a-different-request-id","state":"pending"}),
        json!({"ok":true,"request_id":id,"state":"delivered"}),
        json!({"ok":true,"request_id":id,"state":"new-unknown-state"}),
        json!({"ok":true,"request_id":id,"state":"pending","receipt":{"message":message(),"ack":receipt()["ack"]}}),
    ] {
        let fixture = Fixture::http("200 OK", serde_json::to_vec(&malformed).unwrap());
        assert!(
            BusClient::new(&fixture.base_url)
                .unwrap()
                .operation(id)
                .is_err()
        );
        assert_eq!(fixture.requests().len(), 1);
    }
    let client = BusClient::new("http://127.0.0.1:1").unwrap();
    for invalid in [
        "short",
        "request-id-with/slash",
        "request-id-\r\ninjection",
        "request-id-non-ascii-é",
    ] {
        assert!(matches!(
            client.operation(invalid),
            Err(ClientError::InvalidRequest(_))
        ));
        assert!(matches!(
            client.send_with_id(&request(), invalid),
            Err(ClientError::InvalidRequest(_))
        ));
    }
}

#[test]
fn fresh_ids_are_unique_and_mismatched_post_receipt_is_uncertain() {
    let one = new_request_id().unwrap();
    let two = new_request_id().unwrap();
    assert_ne!(one, two);
    assert!(one.len() >= 16 && one.len() <= 100);
    let mut returned = receipt();
    returned["request_id"] = json!(two);
    returned["state"] = json!("delivered");
    let fixture = Fixture::http("200 OK", serde_json::to_vec(&returned).unwrap());
    assert!(
        BusClient::new(&fixture.base_url)
            .unwrap()
            .send_with_id(&request(), &one)
            .unwrap_err()
            .send_outcome_unknown()
    );
    assert_eq!(fixture.requests().len(), 1);
}

#[test]
fn accepts_only_http_loopback_endpoints_without_userinfo() {
    for invalid in [
        "https://127.0.0.1:8080",
        "http://example.org",
        "http://0.0.0.0:8080",
        "http://192.168.1.2",
        "http://127.0.0.1.example.org",
        "http://[::ffff:192.168.1.2]",
        "http://user:secret@localhost",
        "http://@localhost",
        "http://localhost/api",
        "http://localhost/?a=b",
        "http://localhost/#fragment",
        "file:///tmp/socket",
    ] {
        assert!(
            matches!(
                BusClient::new(invalid),
                Err(ClientError::InvalidEndpoint(_))
            ),
            "{invalid}"
        );
    }
    for valid in [
        "http://127.0.0.1:8080",
        "http://127.0.0.2",
        "http://localhost:8080/",
        "http://[::1]:8080",
    ] {
        assert!(BusClient::new(valid).is_ok(), "{valid}");
    }
}

#[test]
fn get_status_preserves_backend_status_fields() {
    let fixture = Fixture::http(
        "200 OK",
        br#"{"ok":false,"daemon":"unavailable","transport":"local"}"#.to_vec(),
    );
    let client = BusClient::new(&fixture.base_url).unwrap();
    let status = client.status().unwrap();
    assert_eq!(status["ok"], false);
    assert_eq!(status["transport"], "local");
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .header
            .starts_with("GET /api/bus/status HTTP/1.1\r\n")
    );
}

#[test]
fn messages_percent_encode_room_and_parse_existing_array_shape() {
    let room = "#room space&limit=999?é";
    let mut entry = message();
    entry["room"] = json!(room);
    let fixture = Fixture::http("200 OK", serde_json::to_vec(&vec![entry]).unwrap());
    let messages = BusClient::new(&fixture.base_url)
        .unwrap()
        .messages(room, 12)
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].room, room);
    let requests = fixture.requests();
    assert!(requests[0].header.starts_with(
        "GET /api/bus/messages?room=%23room%20space%26limit%3D999%3F%C3%A9&limit=12 HTTP/1.1\r\n"
    ));
}

#[test]
fn messages_reject_cross_room_rows() {
    let fixture = Fixture::http("200 OK", serde_json::to_vec(&vec![message()]).unwrap());
    let error = BusClient::new(&fixture.base_url)
        .unwrap()
        .messages("#qa", 10)
        .unwrap_err();
    assert!(matches!(error, ClientError::InvalidResponse(_)));
    assert_eq!(fixture.requests().len(), 1);
}

#[test]
fn successful_send_preserves_wire_identity_transport_and_signature_results() {
    let fixture = Fixture::http("200 OK", serde_json::to_vec(&receipt()).unwrap());
    let result = BusClient::new(&fixture.base_url)
        .unwrap()
        .send(&request())
        .unwrap();
    assert_eq!(result.message.id, "bus-fixture-42");
    assert_eq!(result.ack.seq, 42);
    assert_eq!(result.ack.transport, "local-crdb+jsonl (daemon starting)");
    assert!(result.message.sig_verified);
    assert!(!result.ack.sig_verified);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .header
            .starts_with("POST /api/bus/send HTTP/1.1\r\n")
    );
    let headers = requests[0].header.to_ascii_lowercase();
    assert!(headers.contains("content-type: application/json\r\n"));
    assert!(headers.contains("x-chinwag-ui-intent: 1\r\n"));
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
        json!({
            "sender": "Brian", "room": "#mgmt", "body": "alpha fixture message",
            "to": "PRODUCT", "task_id": "ALPHA-HTTP-FIXTURE", "wake": false
        })
    );
}

#[test]
fn send_normalizes_sender_once_before_writing_the_request() {
    for sender in [" CODEX ", " ■ CODEX ", "● ■ ◆ CODEX "] {
        let mut req = request();
        req.sender = sender.into();
        let mut response = receipt();
        response["message"]["sender"] = json!("CODEX");
        let fixture = Fixture::http("200 OK", serde_json::to_vec(&response).unwrap());
        let delivered = BusClient::new(&fixture.base_url)
            .unwrap()
            .send(&req)
            .unwrap();
        assert_eq!(delivered.message.sender, "CODEX");
        let requests = fixture.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap()["sender"],
            "CODEX"
        );
    }
}

#[test]
fn glyph_only_sender_and_empty_optional_metadata_are_rejected_before_post() {
    let client = BusClient::new("http://127.0.0.1:1").unwrap();
    for sender in ["●", " ■ ◆ ", "● ■ ◆"] {
        let mut req = request();
        req.sender = sender.into();
        assert!(matches!(
            client.send(&req),
            Err(ClientError::InvalidRequest(_))
        ));
    }
    for field in ["to", "task_id"] {
        for empty in ["", " \t "] {
            let mut req = request();
            if field == "to" {
                req.to = Some(empty.into());
            } else {
                req.task_id = Some(empty.into());
            }
            assert!(
                matches!(client.send(&req), Err(ClientError::InvalidRequest(_))),
                "{field}"
            );
        }
    }
}

#[test]
fn messages_reject_a_blank_returned_sender() {
    let mut entry = message();
    entry["sender"] = json!(" \t ");
    let fixture = Fixture::http("200 OK", serde_json::to_vec(&vec![entry]).unwrap());
    let error = BusClient::new(&fixture.base_url)
        .unwrap()
        .messages("#mgmt", 10)
        .unwrap_err();
    assert!(matches!(error, ClientError::InvalidResponse(_)));
    assert_eq!(fixture.requests().len(), 1);
}

#[test]
fn send_accepts_exact_alpha_echo_and_trimmed_workbench_echo() {
    for echoed_body in ["  alpha fixture message\n", "alpha fixture message"] {
        let mut req = request();
        req.body = "  alpha fixture message\n".into();
        let mut response = receipt();
        response["message"]["body"] = json!(echoed_body);
        let fixture = Fixture::http("200 OK", serde_json::to_vec(&response).unwrap());
        let delivered = BusClient::new(&fixture.base_url)
            .unwrap()
            .send(&req)
            .unwrap();
        assert_eq!(delivered.message.body, echoed_body);
        let requests = fixture.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap()["body"],
            req.body
        );
    }
}

#[test]
fn send_rejects_wrong_room_id_sequence_and_negative_ack() {
    for (field, value) in [
        ("room", json!("#qa")),
        ("message_id", json!("other-id")),
        ("seq", json!(43)),
        ("ok", json!(false)),
    ] {
        let mut body = receipt();
        body["ack"][field] = value;
        let fixture = Fixture::http("200 OK", serde_json::to_vec(&body).unwrap());
        let error = BusClient::new(&fixture.base_url)
            .unwrap()
            .send(&request())
            .unwrap_err();
        assert!(error.send_outcome_unknown(), "{field}: {error}");
        assert_eq!(fixture.requests().len(), 1, "must not replay {field}");
    }
}

#[test]
fn send_rejects_wrong_message_room_or_empty_identity_fields() {
    for (field, value) in [
        ("room", json!("#qa")),
        ("id", json!("")),
        ("seq", json!(0)),
        ("body", json!("another submission")),
        ("sender", json!("Nic")),
    ] {
        let mut body = receipt();
        body["message"][field] = value;
        let fixture = Fixture::http("200 OK", serde_json::to_vec(&body).unwrap());
        assert!(
            BusClient::new(&fixture.base_url)
                .unwrap()
                .send(&request())
                .unwrap_err()
                .send_outcome_unknown()
        );
        assert_eq!(fixture.requests().len(), 1);
    }
}

#[test]
fn http_403_preserves_operator_restriction_without_impersonation_or_retry() {
    let fixture = Fixture::http(
        "403 Forbidden",
        br#"{"ok":false,"error":"sender restricted to human/operator seats"}"#.to_vec(),
    );
    let mut req = request();
    req.sender = "CODEX".into();
    let error = BusClient::new(&fixture.base_url)
        .unwrap()
        .send(&req)
        .unwrap_err();
    assert!(!error.send_outcome_unknown());
    assert!(matches!(
        &error,
        ClientError::HttpStatus { status: 403, .. }
    ));
    assert!(error.to_string().contains("human/operator seats"));
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).unwrap()["sender"],
        "CODEX"
    );
}

#[test]
fn http_408_after_a_complete_post_remains_uncertain_without_retry() {
    let fixture = Fixture::http(
        "408 Request Timeout",
        br#"{"ok":false,"error":"request outcome unavailable after timeout"}"#.to_vec(),
    );
    let error = BusClient::new(&fixture.base_url)
        .unwrap()
        .send(&request())
        .unwrap_err();
    assert!(error.send_outcome_unknown(), "{error}");
    assert!(error.to_string().contains("HTTP 408"));
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).unwrap()["body"],
        request().body
    );
}

#[test]
fn malformed_json_does_not_confirm_send_or_retry() {
    let fixture = Fixture::http("200 OK", b"{not json}".to_vec());
    let error = BusClient::new(&fixture.base_url)
        .unwrap()
        .send(&request())
        .unwrap_err();
    assert!(error.send_outcome_unknown());
    assert!(error.to_string().contains("invalid response JSON"));
    assert_eq!(fixture.requests().len(), 1);
}

#[test]
fn bounded_response_rejects_oversized_get_and_send() {
    let fixture = Fixture::http("200 OK", vec![b' '; MAX_RESPONSE_BYTES + 1]);
    let error = BusClient::new(&fixture.base_url)
        .unwrap()
        .status()
        .unwrap_err();
    assert!(
        matches!(
            error,
            ClientError::ResponseTooLarge {
                limit: MAX_RESPONSE_BYTES
            }
        ),
        "{error:?}"
    );
    assert_eq!(fixture.requests().len(), 1);
    let fixture = Fixture::http("200 OK", vec![b' '; MAX_RESPONSE_BYTES + 1]);
    let error = BusClient::new(&fixture.base_url)
        .unwrap()
        .send(&request())
        .unwrap_err();
    assert!(error.send_outcome_unknown());
    assert!(error.to_string().contains("byte limit"));
    assert_eq!(fixture.requests().len(), 1);
}

#[test]
fn disconnected_or_truncated_receipt_leaves_send_outcome_unknown_without_retry() {
    for response in [
        Vec::new(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n{}".to_vec(),
    ] {
        let fixture = Fixture::raw(response);
        let error = BusClient::new(&fixture.base_url)
            .unwrap()
            .send(&request())
            .unwrap_err();
        assert!(error.send_outcome_unknown(), "{error}");
        assert_eq!(fixture.requests().len(), 1);
    }
}

#[test]
fn redirect_with_location_cannot_replay_a_post_to_another_route() {
    let fixture = Fixture::at_endpoint(|base_url| {
        format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {base_url}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
    });
    let error = BusClient::new(&fixture.base_url)
        .unwrap()
        .send(&request())
        .unwrap_err();
    assert!(error.send_outcome_unknown());
    assert!(error.to_string().contains("HTTP 307"));
    assert_eq!(fixture.requests().len(), 1);
}

#[test]
fn server_error_after_post_is_an_uncertain_send() {
    let fixture = Fixture::http(
        "500 Internal Server Error",
        b"persisted but receipt unavailable".to_vec(),
    );
    let error = BusClient::new(&fixture.base_url)
        .unwrap()
        .send(&request())
        .unwrap_err();
    assert!(error.send_outcome_unknown());
    assert_eq!(fixture.requests().len(), 1);
}

#[test]
fn validates_inputs_before_attempting_connection() {
    let client = BusClient::new("http://127.0.0.1:1").unwrap();
    assert!(matches!(
        client.messages("mgmt", 10),
        Err(ClientError::InvalidRequest(_))
    ));
    assert!(matches!(
        client.messages("#mgmt", 0),
        Err(ClientError::InvalidRequest(_))
    ));
    let mut req = request();
    req.body = " \n\t".into();
    assert!(matches!(
        client.send(&req),
        Err(ClientError::InvalidRequest(_))
    ));
}
