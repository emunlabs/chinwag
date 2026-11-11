//! Contract fixtures from iroh-relay 1.4.1 server.rs:1030-1085 and
//! iroh 1.4.1 net_report/reportgen.rs:621-644. Cloudflare dispatch still needs live QA.
use native_blind_relay::http_probe::response;

#[test]
fn latency_probe_matches_native_relay_contract() {
    let probe = response(true, "/ping", Some("ignored")).unwrap();
    assert_eq!(probe.status, 200);
    assert!(probe.allow_origin);
    assert_eq!(probe.challenge_response, None);
}

#[test]
fn captive_probe_echo_satisfies_actual_native_detector() {
    let host = "chinwag-native-blind-relay.brianspector.workers.dev";
    let challenge = format!("ts_{host}");
    let probe = response(true, "/generate_204", Some(&challenge)).unwrap();
    assert_eq!(probe.status, 204);
    assert_eq!(
        probe.challenge_response,
        Some(format!("response {challenge}"))
    );
    assert!(!probe.allow_origin);
    for value in ["a", "123az__.", "AZaz09._-", &"a".repeat(63)] {
        let probe = response(true, "/generate_204", Some(value)).unwrap();
        assert_eq!(probe.challenge_response, Some(format!("response {value}")));
    }
}

#[test]
fn invalid_challenges_are_not_echoed_but_keep_no_content_status() {
    let long = "a".repeat(64);
    for value in [
        None,
        Some(""),
        Some(long.as_str()),
        Some("a b"),
        Some("a/b"),
        Some("a:b"),
        Some("a\r\nb"),
        Some("é"),
    ] {
        let probe = response(true, "/generate_204", value).unwrap();
        assert_eq!(probe.status, 204);
        assert_eq!(probe.challenge_response, None);
    }
}

#[test]
fn discovery_cannot_accept_other_routes_or_non_get_requests() {
    for path in ["/ping", "/generate_204"] {
        assert_eq!(response(false, path, Some("abc")), None);
    }
    for path in ["/relay", "/health", "/ping/", "/generate_204/", "/"] {
        assert_eq!(response(true, path, Some("abc")), None);
    }
}
