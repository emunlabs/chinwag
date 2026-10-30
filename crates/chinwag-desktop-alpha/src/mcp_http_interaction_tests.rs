use super::*;
use chinwag_bus_client::{HttpMcpSetupOffer, RuntimeMcpStatus};
use gpui_kit::{TestAppContext, test::TestWindowExt};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Instant,
};

fn response(endpoint: &str, index: usize) -> Vec<u8> {
    let nonce = if index == 3 { "b" } else { "a" }.repeat(32);
    let offer = HttpMcpSetupOffer::new(endpoint, &nonce).unwrap();
    let value = json!({
        "ok": true,
        "schema": "chinwag-runtime-owned-mcp/v1",
        "binding_authority": "owner_local_http_capability_unattributed",
        "setup_offer": offer,
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
                "lease_expired": index == 1,
                "admission_closed": false,
                "input_eof_seen": false,
                "input_error_seen": false,
                "protocol_end": "not_observed",
                "owner_close_requested": false,
                "worker_state": "drain_not_observed",
                "output_evidence": "prepared_only"
            }
        }
    });
    let validated: RuntimeMcpStatus = serde_json::from_value(value.clone()).unwrap();
    validated.validate_for(endpoint).unwrap();
    serde_json::to_vec(&value).unwrap()
}

#[gpui_kit::test]
fn explicit_status_and_fresh_copy_clicks_only_get_status_and_preserve_the_workbench(
    cx: &mut TestAppContext,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let canonical_endpoint = format!("{endpoint}/");
    let requests_seen = Arc::new(AtomicUsize::new(0));
    let counter = requests_seen.clone();
    let fixture_endpoint = canonical_endpoint.clone();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(12);
        let mut requests = Vec::new();
        for index in 0..4 {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing explicit status GET");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                }
            };
            // Darwin can inherit the listener's nonblocking flag on accept.
            stream.set_nonblocking(false).unwrap();
            let mut bytes = Vec::new();
            while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero(), "fixture request deadline");
                stream.set_read_timeout(Some(remaining)).unwrap();
                let mut chunk = [0; 1024];
                let count = stream.read(&mut chunk).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
                assert!(bytes.len() <= 4096, "status GET header cap");
            }
            let request = String::from_utf8(bytes).unwrap();
            let lower = request.to_ascii_lowercase();
            assert!(lower.starts_with("get /api/onboarding/mcp-http/status http/1.1\r\n"));
            assert_eq!(
                lower.matches("x-chinwag-onboarding-intent: 1\r\n").count(),
                1
            );
            for forbidden in [
                "authorization:",
                "proxy-authorization:",
                "cookie:",
                "post ",
                "/api/bus/clients",
                "/api/bus/messages",
                "/api/mcp ",
            ] {
                assert!(!lower.contains(forbidden), "unexpected request {forbidden}");
            }
            assert!(request.ends_with("\r\n\r\n"), "GET must have no body");
            requests.push(request);
            counter.fetch_add(1, Ordering::SeqCst);
            let body = response(&fixture_endpoint, index);
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "fixture response deadline");
            stream.set_write_timeout(Some(remaining)).unwrap();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
        let no_retry_until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < no_retry_until {
            match listener.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Ok(_) => panic!("unexpected automatic fifth request"),
                Err(error) => panic!("fixture no-retry check: {error}"),
            }
            thread::sleep(Duration::from_millis(5));
        }
        requests
    });

    cx.update(init);
    cx.write_to_clipboard(ClipboardItem::new_string(
        "unchanged virtual clipboard".into(),
    ));
    let (window, view) = cx.update(|cx| {
        open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: Default::default(),
                    size: size(px(1200.), px(900.)),
                })),
                ..Default::default()
            },
            cx,
            |window, cx| cx.new(|cx| Workbench::with_settings(window, cx, endpoint.clone(), None)),
        )
        .unwrap()
    });
    let message = BusMessage {
        id: "fixture-existing-message".into(),
        seq: 7,
        ts_iso: "2026-10-30T12:00:00Z".into(),
        room: "#eng".into(),
        sender: "CODEX".into(),
        body: "Keep this conversation".into(),
        to: None,
        task_id: None,
        sig_verified: false,
    };
    let draft = "Keep this unsent draft\nwith trailing spaces  ";
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.conversation.select_room("#eng");
            view.conversation.messages.push(message.clone());
            view.sender = "Nic";
            view.composer
                .update(cx, |state, cx| state.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input(draft, cx);
    })
    .unwrap();
    cx.run_until_parked();
    assert_eq!(
        requests_seen.load(Ordering::SeqCst),
        0,
        "mount must make no request"
    );
    cx.update(|cx| {
        assert!(matches!(
            view.read(cx).mcp_http_panel.state(),
            McpHttpState::NotRequested
        ));
    });

    for (index, control) in [
        "check-mcp-http",
        "copy-mcp-http-configuration",
        "check-mcp-http",
        "copy-mcp-http-configuration",
    ]
    .into_iter()
    .enumerate()
    {
        cx.update_window(window, |_, window, cx| {
            window.draw(cx).clear(cx);
            assert!(window.find(control).visible());
            window.click(control, cx);
        })
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            cx.run_until_parked();
            let loading = cx.update(|cx| {
                matches!(
                    view.read(cx).mcp_http_panel.state(),
                    McpHttpState::Loading { .. }
                )
            });
            if !loading {
                break;
            }
            assert!(Instant::now() < deadline, "status click did not settle");
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(requests_seen.load(Ordering::SeqCst), index + 1);
        cx.update(|cx| {
            let view = view.read(cx);
            let McpHttpState::Ready { status, checked_at } = view.mcp_http_panel.state() else {
                panic!("expected a validated status sample")
            };
            assert!(*checked_at > 0);
            assert_eq!(
                status.transport.connection_observation.lease_expired,
                index == 1
            );
            assert_eq!(view.mcp_http_panel.copy_eligible(), index != 1);
            assert_eq!(view.conversation.room, "#eng");
            assert_eq!(view.conversation.messages, vec![message.clone()]);
            assert_eq!(view.sender, "Nic");
            assert_eq!(view.composer.read(cx).value(), draft);
            assert_eq!(view.drafts.get("#eng").map(String::as_str), Some(draft));
            assert!(matches!(view.connection, Connection::Disconnected));
            assert!(matches!(view.conversation.send_state, SendState::Idle));
            assert!(view.load_task.is_none());
            assert!(view.send_task.is_none());
            assert!(view.inventory_task.is_none());
            assert!(view.opening_tasks.is_empty());
            assert!(view.selection_task.is_none());
            if index < 3 {
                assert!(view.mcp_http_copy_notice.is_none());
            } else {
                assert!(
                    view.mcp_http_copy_notice
                        .as_deref()
                        .unwrap()
                        .starts_with("Configuration copied.")
                );
            }
        });
        let clipboard = cx.read_from_clipboard().unwrap().text().unwrap();
        if index < 3 {
            assert_eq!(clipboard, "unchanged virtual clipboard");
        } else {
            let configuration: Value = serde_json::from_str(&clipboard).unwrap();
            let nonce = "b".repeat(32);
            let server = format!("chinwag-native-inbox-mgmt-http-{nonce}");
            let input = format!("chinwag-http-token-{nonce}");
            assert_eq!(configuration["servers"].as_object().unwrap().len(), 1);
            assert_eq!(
                configuration["servers"][&server]["url"],
                format!("{canonical_endpoint}api/mcp")
            );
            assert_eq!(
                configuration["servers"][&server]["headers"]["Authorization"],
                format!("Bearer ${{input:{input}}}")
            );
            assert_eq!(configuration["inputs"][0]["id"], input);
            assert_eq!(configuration["inputs"][0]["password"], true);
            assert!(configuration["inputs"][0].get("default").is_none());
            assert!(
                !clipboard.contains(&"a".repeat(32)),
                "copy must use its fresh offer"
            );
        }
    }
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click(("room", 0_usize), cx);
    })
    .unwrap();
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        assert_eq!(view.conversation.room, "#alpha");
        assert!(
            matches!(view.mcp_http_panel.state(), McpHttpState::NotRequested),
            "a room change invalidates the connection generation even while disconnected"
        );
        assert!(view.mcp_http_copy_notice.is_none());
    });
    assert_eq!(worker.join().unwrap().len(), 4);
    assert_eq!(requests_seen.load(Ordering::SeqCst), 4);
}
