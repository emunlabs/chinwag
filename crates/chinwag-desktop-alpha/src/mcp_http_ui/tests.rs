use super::*;
use chinwag_bus_client::HttpMcpSetupOffer;
use serde_json::{Value, json};

const ENDPOINT: &str = "http://127.0.0.1:44345";
const CANONICAL_ENDPOINT: &str = "http://127.0.0.1:44345/";
const CHECKED_AT: u64 = 1_793_361_600_000;

fn status(nonce: char) -> RuntimeMcpStatus {
    let offer = HttpMcpSetupOffer::new(CANONICAL_ENDPOINT, &nonce.to_string().repeat(32)).unwrap();
    let value = json!({
        "ok": true,
        "schema": "chinwag-runtime-owned-mcp/v1",
        "binding_authority": "owner_local_http_capability_unattributed",
        "transport": {
            "schema": "chinwag-owner-http-inbox/v1",
            "client_identity": "unattributed_owner_http_capability",
            "session_started": false,
            "session_closed": false,
            "transport_worker_joined": false,
            "reader_worker_joined": false,
            "connection_observation": {
                "schema": "chinwag-mcp-connection-observation/v1",
                "negotiated_protocol": null,
                "initialized_notification_seen": false,
                "catalogue_outputs_prepared": 0,
                "read_windows_prepared": 0,
                "lease_expired": false,
                "admission_closed": false,
                "input_eof_seen": false,
                "input_error_seen": false,
                "protocol_end": "not_observed",
                "owner_close_requested": false,
                "worker_state": "drain_not_observed",
                "output_evidence": "prepared_only"
            }
        },
        "setup_offer": offer
    });
    let status: RuntimeMcpStatus = serde_json::from_value(value).unwrap();
    status.validate_for(CANONICAL_ENDPOINT).unwrap();
    status
}

fn complete(
    panel: &mut McpHttpPanel,
    kind: McpHttpRequestKind,
    value: RuntimeMcpStatus,
) -> Option<String> {
    value.validate_for(CANONICAL_ENDPOINT).unwrap();
    let request = panel.begin(kind, ENDPOINT.into(), 4);
    panel.complete(&request, ENDPOINT, 4, CHECKED_AT, Ok(Some(value)))
}

#[test]
fn explicit_check_displays_a_dated_sample_without_copying() {
    let mut panel = McpHttpPanel::default();
    assert!(matches!(panel.state(), McpHttpState::NotRequested));
    assert!(!panel.copy_eligible());
    assert!(panel.sample_lines().is_empty());
    let request = panel.begin(McpHttpRequestKind::Check, ENDPOINT.into(), 4);
    assert_eq!(request.endpoint(), ENDPOINT);
    assert_eq!(request.connection_generation, 4);
    assert_eq!(request.kind, McpHttpRequestKind::Check);
    assert_eq!(request.generation, 1);
    assert!(matches!(
        panel.state(),
        McpHttpState::Loading {
            kind: McpHttpRequestKind::Check
        }
    ));
    assert!(!panel.copy_eligible());
    assert!(
        panel
            .complete(&request, ENDPOINT, 4, CHECKED_AT, Ok(Some(status('a'))))
            .is_none()
    );
    assert!(matches!(
        panel.state(),
        McpHttpState::Ready {
            checked_at: CHECKED_AT,
            ..
        }
    ));
    assert!(panel.copy_eligible());
    assert_eq!(
        panel.sample_lines()[0],
        "Sample checked 2026-10-30 12:00:00 UTC"
    );
    assert!(panel.message().contains("VS Code Local only"));
}

#[test]
fn copy_clears_the_old_sample_and_returns_only_its_fresh_configuration_once() {
    let mut panel = McpHttpPanel::default();
    assert!(complete(&mut panel, McpHttpRequestKind::Check, status('a')).is_none());
    let request = panel.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
    assert!(!panel.copy_eligible());
    assert!(panel.sample_lines().is_empty());
    assert_eq!(panel.message(), "Checking before copying…");
    let text = panel
        .complete(&request, ENDPOINT, 4, CHECKED_AT + 1, Ok(Some(status('b'))))
        .unwrap();
    let configuration: Value = serde_json::from_str(&text).unwrap();
    let nonce = "b".repeat(32);
    let server = format!("chinwag-native-inbox-mgmt-http-{nonce}");
    let input = format!("chinwag-http-token-{nonce}");
    assert_eq!(
        configuration["servers"][&server]["url"],
        format!("{CANONICAL_ENDPOINT}api/mcp")
    );
    assert_eq!(
        configuration["servers"][&server]["headers"]["Authorization"],
        format!("Bearer ${{input:{input}}}")
    );
    assert_eq!(configuration["inputs"][0]["id"], input);
    assert_eq!(configuration["inputs"][0]["password"], true);
    assert!(configuration["inputs"][0].get("default").is_none());
    assert!(configuration["servers"][&server].get("command").is_none());
    assert!(!text.contains(&"a".repeat(32)));
    assert!(
        panel
            .complete(&request, ENDPOINT, 4, CHECKED_AT + 2, Ok(Some(status('c'))))
            .is_none()
    );
    let McpHttpState::Ready { status, checked_at } = panel.state() else {
        panic!("expected current sample")
    };
    assert_eq!(*checked_at, CHECKED_AT + 1);
    assert!(
        status
            .setup_offer
            .as_ref()
            .unwrap()
            .server_name
            .ends_with(&nonce)
    );
}

#[test]
fn later_request_wins_without_an_old_completion_erasing_it() {
    let mut panel = McpHttpPanel::default();
    let old = panel.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
    let current = panel.begin(McpHttpRequestKind::Check, ENDPOINT.into(), 4);
    assert!(
        panel
            .complete(&old, ENDPOINT, 4, CHECKED_AT, Ok(Some(status('a'))))
            .is_none()
    );
    assert!(matches!(
        panel.state(),
        McpHttpState::Loading {
            kind: McpHttpRequestKind::Check
        }
    ));
    assert!(
        panel
            .complete(&current, ENDPOINT, 4, CHECKED_AT + 1, Ok(Some(status('b'))))
            .is_none()
    );
    let McpHttpState::Ready { status, .. } = panel.state() else {
        panic!("expected newer sample")
    };
    assert!(
        status
            .setup_offer
            .as_ref()
            .unwrap()
            .input_id
            .ends_with(&"b".repeat(32))
    );
}

#[test]
fn endpoint_and_connection_changes_clear_samples_and_block_in_flight_copy() {
    for (current_endpoint, generation) in [("http://127.0.0.1:44346", 4), (ENDPOINT, 5)] {
        let mut panel = McpHttpPanel::default();
        let request = panel.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
        assert!(
            panel
                .complete(
                    &request,
                    current_endpoint,
                    generation,
                    CHECKED_AT,
                    Ok(Some(status('a')))
                )
                .is_none()
        );
        assert!(matches!(panel.state(), McpHttpState::NotRequested));
        assert!(!panel.copy_eligible());
    }
    let mut panel = McpHttpPanel::default();
    assert!(complete(&mut panel, McpHttpRequestKind::Check, status('a')).is_none());
    panel.sync_context(ENDPOINT, 4);
    assert!(panel.copy_eligible());
    panel.sync_context(ENDPOINT, 5);
    assert!(matches!(panel.state(), McpHttpState::NotRequested));
    assert!(complete(&mut panel, McpHttpRequestKind::Check, status('a')).is_none());
    panel.sync_context("http://127.0.0.1:44346", 4);
    assert!(panel.sample_lines().is_empty());
    assert!(!panel.copy_eligible());
}

#[test]
fn cleared_foreign_and_saturated_tokens_cannot_revive_a_copy() {
    let mut panel = McpHttpPanel::default();
    let cleared = panel.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
    panel.clear();
    assert!(
        panel
            .complete(&cleared, ENDPOINT, 4, CHECKED_AT, Ok(Some(status('a'))))
            .is_none()
    );
    let mut other = McpHttpPanel::default();
    let foreign = other.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
    let current = panel.begin(McpHttpRequestKind::Check, ENDPOINT.into(), 4);
    assert!(
        panel
            .complete(&foreign, ENDPOINT, 4, CHECKED_AT, Ok(Some(status('a'))))
            .is_none()
    );
    assert!(matches!(panel.state(), McpHttpState::Loading { .. }));
    assert!(
        panel
            .complete(&current, ENDPOINT, 4, CHECKED_AT, Ok(Some(status('a'))))
            .is_none()
    );
    panel.generation = u64::MAX;
    let old = panel.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
    let new = panel.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
    assert_eq!(old.generation, new.generation);
    assert!(
        panel
            .complete(&old, ENDPOINT, 4, CHECKED_AT, Ok(Some(status('a'))))
            .is_none()
    );
    assert!(
        panel
            .complete(&new, ENDPOINT, 4, CHECKED_AT, Ok(Some(status('b'))))
            .is_some()
    );
}

#[test]
fn old_runtime_and_fixed_failure_clear_every_previous_positive_sample() {
    let mut panel = McpHttpPanel::default();
    assert!(complete(&mut panel, McpHttpRequestKind::Check, status('a')).is_none());
    let request = panel.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
    assert!(
        panel
            .complete(&request, ENDPOINT, 4, CHECKED_AT, Ok(None))
            .is_none()
    );
    assert!(matches!(panel.state(), McpHttpState::NotAvailable));
    assert!(!panel.copy_eligible());
    assert!(panel.sample_lines().is_empty());
    assert!(complete(&mut panel, McpHttpRequestKind::Check, status('b')).is_none());
    let request = panel.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
    assert!(
        panel
            .complete(
                &request,
                ENDPOINT,
                4,
                CHECKED_AT,
                Err("Bearer secret-clientInfo-private-path".into())
            )
            .is_none()
    );
    assert!(matches!(panel.state(), McpHttpState::Unavailable));
    assert_eq!(
        panel.message(),
        "Runtime inbox check failed. Check again for a new sample."
    );
    assert!(!panel.copy_eligible());
    assert!(panel.sample_lines().is_empty());
}

#[test]
fn a_new_sample_replaces_counters_protocol_and_owner_offer_whole() {
    let mut panel = McpHttpPanel::default();
    let mut previous = status('a');
    previous
        .transport
        .connection_observation
        .negotiated_protocol = Some(McpProtocolVersion::November2025);
    previous
        .transport
        .connection_observation
        .initialized_notification_seen = true;
    previous
        .transport
        .connection_observation
        .catalogue_outputs_prepared = 90;
    previous
        .transport
        .connection_observation
        .read_windows_prepared = 80;
    assert!(complete(&mut panel, McpHttpRequestKind::Check, previous).is_none());
    let next = status('b');
    let request = panel.begin(McpHttpRequestKind::Check, ENDPOINT.into(), 4);
    assert!(
        panel
            .complete(
                &request,
                ENDPOINT,
                4,
                CHECKED_AT + 1,
                Ok(Some(next.clone()))
            )
            .is_none()
    );
    let McpHttpState::Ready { status, checked_at } = panel.state() else {
        panic!("expected replacement sample")
    };
    assert_eq!(status.as_ref(), &next);
    assert_eq!(*checked_at, CHECKED_AT + 1);
    let lines = panel.sample_lines().join("\n");
    assert!(lines.contains("Protocol negotiation: not observed"));
    assert!(lines.contains("Catalogue outputs prepared: 0"));
    assert!(lines.contains("Inbox windows prepared: 0"));
}

#[test]
fn used_closed_expired_and_offerless_samples_stay_visible_without_copy() {
    for condition in 0..5 {
        let mut value = status('a');
        match condition {
            0 => value.transport.session_started = true,
            1 => value.transport.session_closed = true,
            2 => value.transport.connection_observation.lease_expired = true,
            3 => value.transport.connection_observation.admission_closed = true,
            4 => value.setup_offer = None,
            _ => unreachable!(),
        }
        let mut panel = McpHttpPanel::default();
        assert!(complete(&mut panel, McpHttpRequestKind::Copy, value.clone()).is_none());
        assert!(!panel.copy_eligible());
        let McpHttpState::Ready { status, .. } = panel.state() else {
            panic!("historical sample must remain visible")
        };
        assert_eq!(status.as_ref(), &value);
        assert!(!panel.sample_lines().is_empty());
        assert!(!panel.message().contains("merge the configuration"));
    }
}

#[test]
fn invalid_sample_time_and_defensive_copy_builder_failure_clear_positive_state() {
    for timestamp in [0, 253_402_300_800_000, u64::MAX] {
        let mut panel = McpHttpPanel::default();
        assert!(complete(&mut panel, McpHttpRequestKind::Check, status('a')).is_none());
        let request = panel.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
        assert!(
            panel
                .complete(&request, ENDPOINT, 4, timestamp, Ok(Some(status('a'))))
                .is_none()
        );
        assert!(matches!(panel.state(), McpHttpState::Unavailable));
        assert!(panel.sample_lines().is_empty());
    }
    let mut panel = McpHttpPanel::default();
    let mut invalid = status('a');
    invalid.setup_offer.as_mut().unwrap().input_id = "foreign-input".into();
    let request = panel.begin(McpHttpRequestKind::Copy, ENDPOINT.into(), 4);
    assert!(
        panel
            .complete(&request, ENDPOINT, 4, CHECKED_AT, Ok(Some(invalid)))
            .is_none()
    );
    assert!(matches!(panel.state(), McpHttpState::Unavailable));
    assert!(!panel.copy_eligible());
}

#[test]
fn projection_keeps_independent_facts_and_never_promotes_preparation_to_delivery() {
    let mut value = status('a');
    let observation = &mut value.transport.connection_observation;
    observation.negotiated_protocol = Some(McpProtocolVersion::June2025);
    observation.initialized_notification_seen = true;
    observation.catalogue_outputs_prepared = u64::MAX;
    observation.read_windows_prepared = 1;
    observation.lease_expired = true;
    observation.admission_closed = true;
    observation.protocol_end = McpProtocolEnd::Closed;
    value.transport.session_started = true;
    value.transport.session_closed = true;
    let mut panel = McpHttpPanel::default();
    assert!(complete(&mut panel, McpHttpRequestKind::Check, value).is_none());
    let lines = panel.sample_lines().join("\n");
    for fact in [
        "Sample checked 2026-10-30 12:00:00 UTC",
        "Read-only #mgmt · owner-local HTTP · peer unattributed",
        "Protocol negotiation: 2025-06-18",
        "Initialized notification observed: yes",
        "Catalogue outputs prepared: 18446744073709551615",
        "Inbox windows prepared: 1",
        "Grant expired in sample: yes · admission closed: yes",
        "Session started: yes · session closed: yes",
        "Protocol end: closed",
        "Prepared output does not verify client receipt or message delivery.",
    ] {
        assert!(lines.contains(fact), "missing safe sample fact {fact}");
    }
    for unsupported in [
        "Connected",
        "clientInfo",
        "Bearer",
        "messages read",
        "127.0.0.1",
        "chinwag-http-token-",
    ] {
        assert!(
            !lines.contains(unsupported),
            "unexpected projected field {unsupported}"
        );
    }
    assert!(!panel.copy_eligible());
}
