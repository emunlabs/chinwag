// Enable as a test module in main.rs once the gpui-kit test-support dependency resolves.
// This mounts the actual Workbench with no environment-derived draft path or connection.
use super::*;
use gpui_kit::{TestAppContext, test::TestWindowExt};

#[gpui_kit::test]
fn signed_sender_requires_explicit_selection_and_uncertain_attempt_reconciles_by_get(
    cx: &mut TestAppContext,
) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let directory = std::env::temp_dir().join(chinwag_bus_client::new_request_id().unwrap());
    std::fs::create_dir(&directory).unwrap();
    let draft_path = directory.join("human-drafts.json");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_settings(window, cx, endpoint.clone(), Some(draft_path.clone()))
            })
        })
        .unwrap()
    });
    let attempt = cx
        .update_window(window, |_, window, cx| {
            view.update(cx, |view, cx| {
                view.connection = Connection::Connected {
                    endpoint: endpoint.clone(),
                    detail: "Shared signed test fixture".into(),
                    send_available: true,
                    read_only: false,
                    signed_posting: true,
                    allowed_senders: vec!["Brian".into()],
                };
                assert_eq!(view.sender, "CODEX");
                assert!(
                    !view.can_send(),
                    "connecting must not choose Brian automatically"
                );
                view.sender = "Brian";
                assert!(view.can_send());
                view.conversation.select_room("#mgmt");
                let request = SendRequest {
                    sender: "Brian".into(),
                    room: "#mgmt".into(),
                    body: "original uncertain text".into(),
                    to: None,
                    task_id: None,
                };
                view.composer.update(cx, |state, cx| {
                    state.set_value(request.body.clone(), window, cx)
                });
                let attempt = view
                    .outbox
                    .as_mut()
                    .unwrap()
                    .prepare(&endpoint, request)
                    .unwrap();
                view.update_attempt(
                    &attempt.id,
                    AttemptState::Uncertain("HTTP receipt lost".into()),
                );
                view.conversation.send_state = SendState::Uncertain {
                    body: attempt.request.body.clone(),
                    error: "HTTP receipt lost".into(),
                };
                assert!(
                    view.outbox
                        .as_ref()
                        .unwrap()
                        .blocks(&endpoint, &attempt.request)
                );
                attempt
            })
        })
        .unwrap();
    let receipt = serde_json::json!({
        "message":{"id":"bus-1793361786-8ea53586","seq":839,"ts_iso":"2026-10-30T12:00:00Z","room":"#mgmt","sender":"Brian","body":attempt.request.body,"sig_verified":true},
        "ack":{"ok":true,"seq":839,"message_id":"bus-1793361786-8ea53586","room":"#mgmt","transport":"local-crdb+jsonl (daemon starting)","sig_verified":true,"subscribers_notified":0}
    });
    let id = attempt.id.clone();
    let worker = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "native Check send receipt did not make its GET"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
            let mut chunk = [0; 2048];
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
        }
        let header = String::from_utf8(bytes).unwrap();
        assert!(
            header.starts_with(&format!("GET /api/bus/sends/{id} HTTP/1.1\r\n")),
            "{header}"
        );
        let body = serde_json::to_vec(
            &serde_json::json!({"ok":true,"request_id":id,"state":"delivered","receipt":receipt}),
        )
        .unwrap();
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
        stream.write_all(&body).unwrap();
        header
    });
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.check_send_receipt(&attempt.id, window, cx)
        })
    })
    .unwrap();
    cx.run_until_parked();
    assert!(worker.join().unwrap().starts_with("GET "));
    cx.run_until_parked();
    cx.update(|cx| {
        let view=view.read(cx);
        assert!(view.checking_id.is_none());
        assert!(view.send_task.is_none(),"reconciliation must not start the send path");
        assert!(matches!(view.outbox.as_ref().unwrap().attempts[0].state,AttemptState::Delivered(_)));
        assert!(matches!(&view.conversation.send_state,SendState::Delivered{id,..} if id=="bus-1793361786-8ea53586"));
        assert!(view.outbox.as_ref().unwrap().attempts[0].visible_in_send_history());
        let (line,needs_attention)=view.receipt_line();
        assert!(needs_attention,"native storage must not clear team-delivery attention");
        assert!(line.contains("Stored in native bus; Grok Bot receipt unconfirmed"));
        assert!(line.contains("local-crdb+jsonl (daemon starting)"));
        assert!(line.contains("native subscribers notified: 0"));
        assert_eq!(view.composer.read(cx).value(),"");
    });
    let value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(outbox::path_for_drafts(&draft_path).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(value["attempts"][0]["state"], "delivered");
    std::fs::remove_dir_all(directory).unwrap();
}

#[gpui_kit::test]
fn retained_native_composer_preserves_multiline_and_disconnected_send_guard(
    cx: &mut TestAppContext,
) {
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: Default::default(),
                    size: size(px(1120.), px(800.)),
                })),
                ..Default::default()
            },
            cx,
            |window, cx| {
                cx.new(|cx| Workbench::with_settings(window, cx, "http://127.0.0.1:1".into(), None))
            },
        )
        .expect("mount actual alpha workbench")
    });
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.composer
                .update(cx, |state, cx| state.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input("first line", cx);
    })
    .unwrap();
    cx.simulate_keystrokes(window, "enter");
    cx.update_window(window, |_, window, cx| window.input("second line  ", cx))
        .unwrap();
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        assert_eq!(view.composer.read(cx).value(), "first line\nsecond line  ");
        assert!(matches!(view.conversation.send_state, SendState::Idle));
        assert_eq!(
            view.drafts.get("#alpha").map(String::as_str),
            Some("first line\nsecond line  ")
        );
    });

    // The real Enter action must be captured before Textarea inserts a newline.
    // A disconnected shortcut is explicit but cannot publish or clear the draft.
    cx.simulate_keystrokes(
        window,
        if cfg!(target_os = "macos") {
            "cmd-enter"
        } else {
            "ctrl-enter"
        },
    );
    cx.update(|cx| {
        let view = view.read(cx);
        assert_eq!(view.composer.read(cx).value(), "first line\nsecond line  ");
        assert!(matches!(view.conversation.send_state, SendState::Idle));
        assert!(view.send_task.is_none());
    });

    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.select_room("#mgmt", window, cx);
            assert_eq!(view.composer.read(cx).value(), "");
            view.composer
                .update(cx, |state, cx| state.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input("management draft", cx);
    })
    .unwrap();
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.select_room("#alpha", window, cx);
            assert_eq!(view.composer.read(cx).value(), "first line\nsecond line  ");
            assert_eq!(
                view.drafts.get("#mgmt").map(String::as_str),
                Some("management draft")
            );
            assert!(view.draft_file.is_none());
            assert!(view.send_task.is_none());
            assert!(matches!(view.connection, Connection::Disconnected));
            view.connection = Connection::Connected {
                endpoint: "http://127.0.0.1:1".into(),
                detail: "Native coordination bus · read only; signing/delivery not invoked".into(),
                send_available: false,
                read_only: true,
                signed_posting: false,
                allowed_senders: Vec::new(),
            };
            view.composer
                .update(cx, |state, cx| state.focus(window, cx));
        });
        window.draw(cx).clear(cx);
    })
    .unwrap();
    cx.simulate_keystrokes(
        window,
        if cfg!(target_os = "macos") {
            "cmd-enter"
        } else {
            "ctrl-enter"
        },
    );
    cx.update(|cx| {
        let view = view.read(cx);
        assert_eq!(view.composer.read(cx).value(), "first line\nsecond line  ");
        assert!(!view.can_send());
        assert!(view.send_task.is_none());
        assert!(matches!(view.conversation.send_state, SendState::Idle));
    });
}

fn discovery_snapshot_fixture(host: &str) -> serde_json::Value {
    serde_json::json!({"schema":"chinwag-client-inventory/v1","observed_at_unix_ms":1793361786000_u64,"host_label":host,
        "coverage":{"pid_capacity":4096,"candidate_capacity":128,"sampled_pid_count":100,"candidate_process_count":75,"omitted_candidate_count":0,"raced_processes":0,"permission_denied_processes":0,"unavailable_processes":0,"invalid_process_metadata":0,"unclassified_interpreters":5,"unresolved_components":0,"pid_capacity_reached":false,"candidate_capacity_reached":false},
        "clients":[{"id":"a".repeat(64),"family":"grok_bot","kind":"application","state":"detected_unverified","component_count":75}]})
}

fn discovery_http_fixture(
    missing: bool,
    expected_requests: usize,
    inventory: serde_json::Value,
) -> (String, std::thread::JoinHandle<Vec<String>>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut requests = Vec::new();
        while requests.len() < expected_requests {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "explicit load did not perform its expected GETs"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("fixture accept {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut raw = Vec::new();
            while !raw.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut buf = [0; 2048];
                let count = stream.read(&mut buf).unwrap();
                assert!(count > 0);
                raw.extend_from_slice(&buf[..count]);
                assert!(raw.len() < 16_384);
            }
            let request = String::from_utf8(raw).unwrap();
            assert!(
                request.starts_with("GET "),
                "discovery/connect fixtures may never publish"
            );
            let (status, value) = if request.starts_with("GET /api/bus/status ") {
                (
                    200,
                    serde_json::json!({"ok":true,"mode":"fleet-ledger-read-only","read_only":true,"send_allowed":false}),
                )
            } else if request.starts_with("GET /api/bus/messages?room=%23alpha&limit=100 ") {
                (
                    200,
                    serde_json::json!([{"id":"fixture-history","seq":7,"ts_iso":"2026-10-30T12:00:00Z","room":"#alpha","sender":"Brian","body":"History remains usable","sig_verified":false}]),
                )
            } else if request.starts_with("GET /api/bus/clients ") {
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("x-chinwag-discovery-intent: 1\r\n")
                );
                if missing {
                    (
                        404,
                        serde_json::json!({"error":"older server has no discovery API"}),
                    )
                } else {
                    (200, inventory.clone())
                }
            } else {
                panic!("unexpected request {request}")
            };
            let body = serde_json::to_vec(&value).unwrap();
            write!(stream,"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
            stream.write_all(&body).unwrap();
            requests.push(request);
        }
        requests
    });
    (endpoint, worker)
}

#[gpui_kit::test]
fn explicit_connect_uses_server_inventory_and_old_server_404_does_not_break_history(
    cx: &mut TestAppContext,
) {
    cx.update(init);
    for missing in [false, true] {
        let (endpoint, worker) =
            discovery_http_fixture(missing, 3, discovery_snapshot_fixture("Studio"));
        let (window, view) = cx.update(|cx| {
            open_window(WindowOptions::default(), cx, |window, cx| {
                cx.new(|cx| Workbench::with_settings(window, cx, endpoint.clone(), None))
            })
            .unwrap()
        });
        cx.update_window(window, |_, _, cx| view.update(cx, |view, cx| view.load(cx)))
            .unwrap();
        cx.run_until_parked();
        let requests = worker.join().unwrap();
        cx.run_until_parked();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.starts_with("GET /api/bus/clients "))
                .count(),
            1
        );
        assert!(requests.iter().all(|r| r.starts_with("GET ")));
        cx.update(|cx| {
            let view = view.read(cx);
            assert!(
                matches!(view.connection, Connection::Connected { .. }),
                "inventory failure must not disconnect chat"
            );
            assert_eq!(view.conversation.messages.len(), 1);
            assert_eq!(view.conversation.messages[0].body, "History remains usable");
            assert!(view.send_task.is_none());
            assert_eq!(
                view.client_inventory.endpoint.as_deref(),
                Some(endpoint.as_str())
            );
            if missing {
                assert!(matches!(
                    view.client_inventory.state,
                    InventoryState::Unavailable(_)
                ));
                assert!(view.client_inventory.summary().contains("Unavailable"));
            } else {
                assert!(matches!(
                    view.client_inventory.state,
                    InventoryState::Ready(_)
                ));
                assert!(
                    view.client_inventory
                        .summary()
                        .contains("Studio · 1 app family · 1 running instance")
                );
                assert!(
                    view.client_inventory
                        .coverage_lines()
                        .iter()
                        .any(|line| line.contains("2026-10-30 12:03:06 UTC"))
                );
                assert!(!view.client_inventory.summary().contains("Unix ms"));
                assert_eq!(view.client_inventory.rows().len(), 1);
                assert!(
                    view.client_inventory.rows()[0]
                        .contains("75 components · Detected · not connected")
                );
            }
            assert_eq!(
                posting_hint(&view.connection, view.sender),
                "Sending disabled for this read-only connection"
            );
        });
    }
}

#[gpui_kit::test]
fn find_apps_is_one_explicit_read_with_family_rows_and_collapsible_details(
    cx: &mut TestAppContext,
) {
    cx.update(init);
    let mut inventory = discovery_snapshot_fixture("Studio");
    inventory["clients"][0]["component_count"] = serde_json::json!(40);
    let mut second = inventory["clients"][0].clone();
    second["id"] = serde_json::json!("b".repeat(64));
    second["component_count"] = serde_json::json!(35);
    inventory["clients"].as_array_mut().unwrap().push(second);
    inventory["installations"] = serde_json::json!({
        "observed_at_unix_ms":1793361786000_u64,
        "apps":[
            {"id":"c".repeat(64),"family":"grok_bot","kind":"application","running_instances":2,"state":"installed_unverified"},
            {"id":"d".repeat(64),"family":"chatgpt_desktop","kind":"application","running_instances":0,"state":"installed_unverified"},
            {"id":"e".repeat(64),"family":"claude_code","kind":"command_line","running_instances":0,"state":"installed_unverified"}
        ],
        "coverage":{"entry_capacity":512,"entries_examined":12,"installation_capacity":128,
            "capacity_reached":false,"unavailable_roots":0,"invalid_metadata":0}
    });
    let (endpoint, worker) = discovery_http_fixture(false, 1, inventory);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| Workbench::with_settings(window, cx, endpoint.clone(), None))
        })
        .unwrap()
    });
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("find-client-apps", cx);
    })
    .unwrap();
    cx.run_until_parked();
    let requests = worker.join().unwrap();
    cx.run_until_parked();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/bus/clients "));
    cx.update(|cx| {
        let view = view.read(cx);
        assert!(matches!(view.connection, Connection::Disconnected));
        assert!(view.send_task.is_none());
        assert!(!view.client_inventory.details_expanded);
        assert_eq!(
            view.client_inventory.summary(),
            "Studio · 3 app families · 2 running instances"
        );
        let rows = view.client_inventory.rows();
        assert_eq!(rows.len(), 3);
        assert!(rows[1].starts_with("ChatGPT · application · Installed · running not observed"));
        assert!(
            rows[2].starts_with("Claude Code · command line · Installed · running not observed")
        );
        assert!(
            rows[0].contains(
                "Grok Bot · application · Installed · 2 running instances · 75 components"
            )
        );
        assert!(rows.iter().all(|row| row.contains("not connected")));
    });
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("toggle-client-discovery-details", cx);
    })
    .unwrap();
    cx.update(|cx| assert!(view.read(cx).client_inventory.details_expanded));
}

#[gpui_kit::test]
fn stale_inventory_completion_cannot_reappear_after_endpoint_edit_or_room_change(
    cx: &mut TestAppContext,
) {
    cx.update(init);
    let original = "http://127.0.0.1:41111";
    let edited = "http://127.0.0.1:42222";
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| Workbench::with_settings(window, cx, original.into(), None))
        })
        .unwrap()
    });
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            let connection_generation = view.connection_generation;
            let generation = view.client_inventory.begin(original.into());
            view.endpoint
                .update(cx, |endpoint, cx| endpoint.set_value(edited, window, cx));
            let snapshot =
                serde_json::from_value(discovery_snapshot_fixture("Old server")).unwrap();
            assert!(
                !view.apply_client_inventory(
                    connection_generation,
                    generation,
                    original,
                    Ok(snapshot),
                    cx
                ),
                "endpoint input changes invalidate even before subscription delivery"
            );
            view.client_inventory.clear();
            let generation = view.client_inventory.begin(edited.into());
            let connection_generation = view.connection_generation;
            view.select_room("#mgmt", window, cx);
            let snapshot =
                serde_json::from_value(discovery_snapshot_fixture("Old room completion")).unwrap();
            assert!(!view.apply_client_inventory(
                connection_generation,
                generation,
                edited,
                Ok(snapshot),
                cx
            ));
            assert!(matches!(
                view.client_inventory.state,
                InventoryState::NotRequested
            ));
            assert!(view.inventory_task.is_none());
            assert!(view.send_task.is_none());
        })
    })
    .unwrap();
    cx.run_until_parked();
}
