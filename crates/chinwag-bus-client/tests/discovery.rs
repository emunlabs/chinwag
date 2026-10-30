use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use chinwag_bus_client::{
    BusClient, ClientError, ClientInventory, ClientKind, DiscoveryState, InstallationLocation,
};
use serde_json::{Value, json};

fn inventory() -> Value {
    json!({
        "schema":"chinwag-client-inventory/v1","observed_at_unix_ms":1793361786000_u64,"host_label":"Studio",
        "coverage":{"pid_capacity":4096,"candidate_capacity":128,"sampled_pid_count":100,"candidate_process_count":75,"omitted_candidate_count":0,"raced_processes":1,"permission_denied_processes":2,"unavailable_processes":3,"invalid_process_metadata":4,"unclassified_interpreters":5,"unresolved_components":0,"pid_capacity_reached":false,"candidate_capacity_reached":false},
        "clients":[{"id":"a".repeat(64),"family":"grok_bot","kind":"application","state":"detected_unverified","component_count":75}]
    })
}

fn endpoint(status: u16, body: Vec<u8>) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let mut buf = [0; 2048];
            let count = stream.read(&mut buf).unwrap();
            assert!(count > 0);
            request.extend_from_slice(&buf[..count]);
            assert!(request.len() < 16_384);
        }
        write!(stream,"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
        // An oversized response may be closed once the byte cap is reached.
        let _ = stream.write_all(&body);
        String::from_utf8(request).unwrap()
    });
    (format!("http://{address}"), worker)
}

#[test]
fn explicit_discovery_get_preserves_server_host_and_grouped_component_count() {
    let (url, worker) = endpoint(200, serde_json::to_vec(&inventory()).unwrap());
    let snapshot = BusClient::new(&url).unwrap().clients().unwrap();
    assert_eq!(snapshot.host_label, "Studio");
    assert_eq!(snapshot.observed_at_unix_ms, 1793361786000);
    assert_eq!(snapshot.clients.len(), 1);
    assert_eq!(snapshot.clients[0].component_count, 75);
    assert_eq!(snapshot.clients[0].kind, ClientKind::Application);
    assert_eq!(
        snapshot.clients[0].state,
        DiscoveryState::DetectedUnverified
    );
    let request = worker.join().unwrap();
    assert!(request.starts_with("GET /api/bus/clients HTTP/1.1\r\n"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("x-chinwag-discovery-intent: 1\r\n")
    );
    assert!(!request.contains("POST "));
    assert!(!request.to_ascii_lowercase().contains("authorization:"));
    let lower = request.to_ascii_lowercase();
    assert_eq!(
        lower
            .lines()
            .filter(|line| line.starts_with("x-chinwag-discovery-intent:"))
            .collect::<Vec<_>>(),
        vec!["x-chinwag-discovery-intent: 1"]
    );
    assert_eq!(
        lower
            .lines()
            .filter(|line| line.starts_with("x-chinwag-discovery-details:"))
            .collect::<Vec<_>>(),
        vec!["x-chinwag-discovery-details: 1"]
    );
    let value = serde_json::to_value(snapshot).unwrap();
    let fields = value["clients"][0].as_object().unwrap();
    assert_eq!(fields.len(), 5);
    for name in ["pid", "path", "uid", "boot_uuid", "session", "raw_metadata"] {
        assert!(!fields.contains_key(name));
    }
}

#[test]
fn unknown_schema_connected_state_and_private_extra_fields_are_rejected() {
    for variant in 0..5 {
        let mut value = inventory();
        match variant {
            0 => value["schema"] = json!("other/v2"),
            1 => value["clients"][0]["state"] = json!("connected"),
            2 => value["clients"][0]["pid"] = json!(123),
            3 => value["clients"][0]["kind"] = json!("agent"),
            _ => value["private_content"] = json!("must not appear"),
        }
        let (url, worker) = endpoint(200, serde_json::to_vec(&value).unwrap());
        assert!(
            BusClient::new(&url).unwrap().clients().is_err(),
            "variant {variant}"
        );
        assert!(worker.join().unwrap().starts_with("GET "));
    }
}

#[test]
fn malformed_counts_ids_labels_and_unbounded_row_sets_are_rejected() {
    let mut cases = Vec::new();
    let mut value = inventory();
    value["coverage"]["pid_capacity"] = json!(4097);
    cases.push(value);
    let mut value = inventory();
    value["coverage"]["candidate_capacity"] = json!(129);
    cases.push(value);
    let mut value = inventory();
    value["coverage"]["sampled_pid_count"] = json!(4097);
    cases.push(value);
    let mut value = inventory();
    value["coverage"]["unclassified_interpreters"] = json!(101);
    cases.push(value);
    let mut value = inventory();
    value["clients"][0]["component_count"] = json!(0);
    cases.push(value);
    let mut value = inventory();
    value["clients"][0]["id"] = json!("A".repeat(64));
    cases.push(value);
    let mut value = inventory();
    value["clients"][0]["family"] = json!("private/path");
    cases.push(value);
    let mut value = inventory();
    value["host_label"] = json!("/Users/private");
    cases.push(value);
    let mut value = inventory();
    value["coverage"]["unresolved_components"] = json!(1);
    cases.push(value);
    let mut value = inventory();
    let duplicate = value["clients"][0].clone();
    value["clients"].as_array_mut().unwrap().push(duplicate);
    cases.push(value);
    let mut value = inventory();
    value["clients"] = json!(vec![value["clients"][0].clone(); 129]);
    cases.push(value);
    for (index, value) in cases.into_iter().enumerate() {
        let parsed = serde_json::from_value::<ClientInventory>(value);
        assert!(
            parsed.is_err() || parsed.unwrap().validate().is_err(),
            "case {index}"
        );
    }
}

#[test]
fn missing_old_server_endpoint_and_oversized_snapshot_return_bounded_errors() {
    let (url, worker) = endpoint(404, b"{\"error\":\"older server\"}".to_vec());
    assert!(matches!(
        BusClient::new(&url).unwrap().clients(),
        Err(ClientError::HttpStatus { status: 404, .. })
    ));
    worker.join().unwrap();
    let (url, worker) = endpoint(200, vec![b' '; chinwag_bus_client::MAX_RESPONSE_BYTES + 1]);
    assert!(matches!(
        BusClient::new(&url).unwrap().clients(),
        Err(ClientError::ResponseTooLarge { .. })
    ));
    worker.join().unwrap();
}

fn installed_inventory() -> Value {
    let mut value = inventory();
    value["installations"] = json!({"observed_at_unix_ms":1793361786000_u64,
        "apps":[{"id":"b".repeat(64),"family":"grok_bot","kind":"application",
            "running_instances":0,"state":"installed_unverified"}],
        "coverage":{"entry_capacity":4096,"entries_examined":5,"installation_capacity":128,
            "capacity_reached":false,"unavailable_roots":0,"invalid_metadata":0}});
    value
}

#[test]
fn explicit_details_get_accepts_new_public_hints_and_old_runtime_missing_hints() {
    for details in [false, true] {
        let mut value = installed_inventory();
        if details {
            value["installations"]["apps"][0]["location"] = json!("user_applications");
            value["installations"]["apps"][0]["version"] = json!("v1.2.3 (42)");
        }
        let (url, worker) = endpoint(200, serde_json::to_vec(&value).unwrap());
        let result = BusClient::new(&url).unwrap().clients().unwrap();
        let app = &result.installations.as_ref().unwrap().apps[0];
        if details {
            assert_eq!(app.location, Some(InstallationLocation::UserApplications));
            assert_eq!(app.version.as_deref(), Some("v1.2.3 (42)"));
        } else {
            assert!(app.location.is_none());
            assert!(app.version.is_none());
        }
        let request = worker.join().unwrap().to_ascii_lowercase();
        assert_eq!(
            request
                .lines()
                .filter(|line| line.starts_with("x-chinwag-discovery-details:"))
                .collect::<Vec<_>>(),
            vec!["x-chinwag-discovery-details: 1"]
        );
        assert!(request.starts_with("get /api/bus/clients "));
        assert!(!request.contains("post "));
    }
}

#[test]
fn malformed_optional_details_are_rejected_by_the_http_client() {
    for malformed in [
        json!({"location":"private_applications"}),
        json!({"version":"1.0 PRIVATE_MARKER"}),
        json!({"version":"1/Users/private"}),
        json!({"version":format!("1{}", "a".repeat(64))}),
    ] {
        let mut value = installed_inventory();
        value["installations"]["apps"][0]
            .as_object_mut()
            .unwrap()
            .extend(malformed.as_object().unwrap().clone());
        let (url, worker) = endpoint(200, serde_json::to_vec(&value).unwrap());
        assert!(BusClient::new(&url).unwrap().clients().is_err());
        assert!(worker.join().unwrap().starts_with("GET "));
    }
}
