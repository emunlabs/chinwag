use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use chinwag_bus_client::{
    BusClient, ClientError, NativeOpenReceipt, NativeOpenRequest, NativeOpenState, OnboardingStatus,
};
use serde_json::{Value, json};

const REQUEST_ID: &str = "ui-explicit-human-open-0001";

fn request() -> NativeOpenRequest {
    NativeOpenRequest {
        installation_id: "a".repeat(64),
    }
}

fn receipt() -> Value {
    json!({
        "schema":"chinwag-native-open/v1", "request_id":REQUEST_ID,
        "installation_id":"a".repeat(64), "state":"opened_or_reused",
        "message":"Opened or reused; connection setup is separate."
    })
}

fn fixture(status: u16, body: Option<Value>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
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
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut captured = Vec::new();
        loop {
            let remaining = until.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "fixture request exceeded its deadline"
            );
            stream.set_read_timeout(Some(remaining)).unwrap();
            let mut buf = [0; 2048];
            let count = stream.read(&mut buf).unwrap();
            assert!(count > 0);
            captured.extend_from_slice(&buf[..count]);
            assert!(captured.len() < 4096);
            if let Some(end) = captured.windows(4).position(|v| v == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&captured[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .map_or(0, |value| value.trim().parse::<usize>().unwrap());
                if captured.len() >= end + 4 + length {
                    break;
                }
            }
        }
        if let Some(body) = body {
            let body = serde_json::to_vec(&body).unwrap();
            write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
        drop(stream);
        let mut requests = vec![String::from_utf8(captured).unwrap()];
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            if let Ok((mut duplicate, _)) = listener.accept() {
                duplicate
                    .set_read_timeout(Some(Duration::from_millis(50)))
                    .unwrap();
                let mut bytes = [0; 4096];
                let size = duplicate.read(&mut bytes).unwrap_or(0);
                requests.push(String::from_utf8_lossy(&bytes[..size]).into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        requests
    });
    (url, worker)
}

#[test]
fn explicit_open_posts_one_exact_opaque_target_without_identity_or_paths() {
    let (url, worker) = fixture(200, Some(receipt()));
    let result = BusClient::new(&url)
        .unwrap()
        .open_application(REQUEST_ID, &request())
        .unwrap();
    assert_eq!(result.state, NativeOpenState::OpenedOrReused);
    let captured = worker.join().unwrap();
    assert_eq!(captured.len(), 1);
    let wire = &captured[0];
    assert!(wire.starts_with("POST /api/onboarding/open HTTP/1.1\r\n"));
    assert!(
        wire.to_ascii_lowercase()
            .contains("x-chinwag-onboarding-intent: 1\r\n")
    );
    assert!(
        wire.to_ascii_lowercase()
            .contains(&format!("x-chinwag-request-id: {REQUEST_ID}\r\n"))
    );
    let body: Value = serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body, json!({"installation_id":"a".repeat(64)}));
    for forbidden in ["sender", "wake", "path", "session", "authorization:"] {
        assert!(!wire.contains(forbidden));
    }
}

#[test]
fn missing_or_conflicting_open_receipt_is_uncertain_and_never_replayed() {
    let mut mismatch = receipt();
    mismatch["installation_id"] = json!("b".repeat(64));
    for body in [
        None,
        Some(mismatch),
        Some(json!({"ok":true,"connected":true})),
    ] {
        let (url, worker) = fixture(200, body);
        assert!(matches!(
            BusClient::new(&url)
                .unwrap()
                .open_application(REQUEST_ID, &request()),
            Err(ClientError::NativeOpenOutcomeUnknown { .. })
        ));
        assert_eq!(worker.join().unwrap().len(), 1);
    }
}

#[test]
fn lookup_is_get_only_and_missing_receipt_does_not_authorize_replay() {
    for (status, body, expected) in [
        (200, receipt(), true),
        (404, json!({"error":"not found"}), false),
    ] {
        let (url, worker) = fixture(status, Some(body));
        let found = BusClient::new(&url)
            .unwrap()
            .application_open_receipt(REQUEST_ID)
            .unwrap();
        assert_eq!(found.is_some(), expected);
        let captured = worker.join().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].starts_with(&format!(
            "GET /api/onboarding/opens/{REQUEST_ID} HTTP/1.1\r\n"
        )));
        assert!(!captured[0].contains("POST "));
    }
}

#[test]
fn capability_lookup_is_get_only_and_does_not_inventory_apps() {
    let body = json!({"schema":"chinwag-native-onboarding/v1", "native_open_allowed":true,"openable_installation_ids":["a".repeat(64)]});
    let (url, worker) = fixture(200, Some(body));
    assert!(
        BusClient::new(&url)
            .unwrap()
            .onboarding_status()
            .unwrap()
            .native_open_allowed
    );
    let captured = worker.join().unwrap();
    assert_eq!(captured.len(), 1);
    assert!(captured[0].starts_with("GET /api/onboarding/status HTTP/1.1\r\n"));
    assert!(!captured[0].contains("/api/bus/clients"));
}

#[test]
fn capability_bounds_and_false_connection_claims_are_rejected() {
    let valid = json!({"schema":"chinwag-native-onboarding/v1","native_open_allowed":true,"openable_installation_ids":["a".repeat(64)]});
    for case in 0..6 {
        let mut value = valid.clone();
        match case {
            0 => value["native_open_allowed"] = json!(false),
            1 => value["openable_installation_ids"] = json!(["a".repeat(64), "a".repeat(64)]),
            2 => value["openable_installation_ids"] = json!(["/Applications/Cursor.app"]),
            3 => value["openable_installation_ids"] = json!(vec!["a".repeat(64); 129]),
            4 => value["schema"] = json!("other/v2"),
            _ => value["connected"] = json!(true),
        }
        let parsed = serde_json::from_value::<OnboardingStatus>(value);
        assert!(parsed.is_err() || parsed.unwrap().validate().is_err());
    }
    let mut value = receipt();
    value["state"] = json!("connected");
    assert!(serde_json::from_value::<NativeOpenReceipt>(value).is_err());
}

#[test]
fn invalid_request_is_rejected_before_network_io() {
    let client = BusClient::new("http://127.0.0.1:9").unwrap();
    for bad_id in [
        "a".repeat(63),
        "A".repeat(64),
        "/Applications/Grok Bot.app".into(),
    ] {
        assert!(matches!(
            client.open_application(
                REQUEST_ID,
                &NativeOpenRequest {
                    installation_id: bad_id
                }
            ),
            Err(ClientError::InvalidRequest(_))
        ));
    }
    assert!(matches!(
        client.application_open_receipt("bad/id"),
        Err(ClientError::InvalidRequest(_))
    ));
}
