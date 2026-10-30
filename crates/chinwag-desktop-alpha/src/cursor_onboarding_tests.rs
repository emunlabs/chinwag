use super::*;

fn cursor_copies_inventory(two: bool) -> Value {
    let mut value = cursor_inventory();
    value["installations"]["apps"][0]["location"] = json!("shared_applications");
    value["installations"]["apps"][0]["version"] = json!("1.2.3");
    if two {
        value["installations"]["apps"][1]["family"] = json!("cursor");
        value["installations"]["apps"][1]["location"] = json!("user_applications");
        value["installations"]["apps"][1]["version"] = json!("1.2.4");
    }
    value
}

#[test]
fn focused_mode_requires_exact_opt_in_and_has_a_distinct_window_title() {
    assert!(AppMode::from_setting(None) == AppMode::Workbench);
    assert!(AppMode::from_setting(Some("Cursor")) == AppMode::Workbench);
    assert!(AppMode::from_setting(Some("cursor ")) == AppMode::Workbench);
    let mode = AppMode::from_setting(Some("cursor"));
    assert!(mode == AppMode::CursorOnboarding);
    assert_eq!(mode.window_title(), "Connect Cursor to Chinwag");
}

#[gpui_kit::test]
fn cursor_window_finds_once_without_chat_or_automatic_setup(cx: &mut TestAppContext) {
    let directory = Directory::new();
    let (endpoint, worker) = fixture(2, |request, index| {
        assert!(request.starts_with("GET "), "launch must not submit setup");
        if index == 0 {
            assert!(request.starts_with("GET /api/bus/clients "));
            (200, cursor_copies_inventory(false))
        } else {
            assert!(request.starts_with("GET /api/onboarding/cursor-mcp/status "));
            (200, status(true))
        }
    });
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_mode_settings(
                    window,
                    cx,
                    endpoint.clone(),
                    Some(directory.drafts()),
                    AppMode::CursorOnboarding,
                    Some("Configured host hint".into()),
                )
            })
        })
        .unwrap()
    });
    cx.run_until_parked();
    assert_eq!(worker.join().unwrap().len(), 2);
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        assert!(
            window
                .within("cursor-onboarding")
                .find("find-cursor")
                .visible()
        );
        let copy = window.find(("cursor-copy", 0_usize));
        assert!(copy.visible());
        assert_eq!(copy.label(), Some("Cursor · Applications · Version 1.2.3"));
        assert_eq!(
            window.find("cursor-onboarding-setup").label(),
            Some("Set up Cursor")
        );
        assert!(window.try_find("send").is_none());
        assert!(window.try_find(("room", 0_usize)).is_none());
        assert!(window.try_find("find-client-apps").is_none());
        view.update(cx, |view, cx| {
            assert_eq!(view.cursor_target_host(), "Studio");
            assert_eq!(
                view.selected_cursor_copy.as_deref(),
                Some("a".repeat(64).as_str())
            );
            assert_eq!(
                view.client_inventory.cursor_copies()[0].1,
                "Cursor · Applications · Version 1.2.3"
            );
            assert!(
                view._refresh_task.is_none(),
                "onboarding has no polling loop"
            );
            assert!(
                view.load_task.is_none(),
                "onboarding does not load chat history"
            );
            assert!(view.openings.as_ref().unwrap().attempts.is_empty());
            assert!(view.can_act_on_installation(
                OpeningAction::CursorMcpSetup,
                &"a".repeat(64),
                cx
            ));
            assert!(!view.can_send());
            assert!(view.send_task.is_none());
            assert!(matches!(view.connection, Connection::Disconnected));
        });
    })
    .unwrap();
}

#[gpui_kit::test]
fn cursor_copy_choice_and_primary_action_use_existing_durable_preflight(cx: &mut TestAppContext) {
    let directory = Directory::new();
    let drafts = directory.drafts();
    let history = openings::path_for_drafts(&drafts).unwrap();
    let (endpoint, worker) = fixture(5, move |request, index| match index {
        0 | 2 => {
            assert!(request.starts_with("GET /api/bus/clients "));
            assert!(!history.exists(), "metadata cannot create an attempt");
            (200, cursor_copies_inventory(true))
        }
        1 | 3 => {
            assert!(request.starts_with("GET /api/onboarding/cursor-mcp/status "));
            assert!(!history.exists());
            (200, status(true))
        }
        _ => {
            assert!(request.starts_with("POST /api/onboarding/cursor-mcp/setup "));
            let body: Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(body, json!({"installation_id":"b".repeat(64)}));
            let saved: Value = serde_json::from_slice(&std::fs::read(&history).unwrap()).unwrap();
            assert_eq!(saved["attempts"][0]["state"], "pending");
            assert_eq!(saved["attempts"][0]["action"], "cursor_mcp_setup");
            assert_eq!(
                saved["attempts"][0]["id"],
                header(request, "X-Chinwag-Request-Id")
            );
            (200, reply(request, "b".repeat(64), "opened_or_reused"))
        }
    });
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_mode_settings(
                    window,
                    cx,
                    endpoint.clone(),
                    Some(drafts.clone()),
                    AppMode::CursorOnboarding,
                    None,
                )
            })
        })
        .unwrap()
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("cursor-onboarding-setup", cx);
        view.update(cx, |view, _| {
            assert!(view.selected_cursor_copy.is_none());
            assert!(
                view.selection_task.is_none(),
                "an unselected click starts no metadata request"
            );
            assert!(view.opening_tasks.is_empty());
            assert!(view.openings.as_ref().unwrap().attempts.is_empty());
        });
        window.click(("cursor-copy", 1_usize), cx);
        window.click("cursor-onboarding-setup", cx);
        window.click("cursor-onboarding-setup", cx);
        view.update(cx, |view, _| {
            assert_eq!(
                view.opening_selection.as_ref().unwrap().app.id,
                "b".repeat(64)
            );
            assert!(view.openings.as_ref().unwrap().attempts.is_empty());
        });
    })
    .unwrap();
    cx.run_until_parked();
    let requests = worker.join().unwrap();
    cx.run_until_parked();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with("POST "))
            .count(),
        1
    );
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("cursor-onboarding-setup").label(),
            Some("Set up Cursor again")
        );
        view.update(cx, |view, _| {
            let attempts = &view.openings.as_ref().unwrap().attempts;
            assert_eq!(attempts.len(), 1);
            assert_eq!(attempts[0].installation_id, "b".repeat(64));
            assert!(attempts[0].summary().contains("connection unconfirmed"));
            assert!(matches!(view.connection, Connection::Disconnected));
            assert!(view.send_task.is_none());
        });
    })
    .unwrap();
}

#[gpui_kit::test]
fn cursor_metadata_failure_keeps_setup_disabled_and_exposes_manual_recovery(
    cx: &mut TestAppContext,
) {
    let directory = Directory::new();
    let (endpoint, worker) = fixture(3, |request, index| {
        assert!(
            request.starts_with("GET "),
            "failed setup and manual Find must never POST"
        );
        match index {
            0 => {
                assert!(request.starts_with("GET /api/bus/clients "));
                (503, json!({"error":"Synthetic unreachable metadata"}))
            }
            1 => {
                assert!(request.starts_with("GET /api/bus/clients "));
                (200, cursor_copies_inventory(false))
            }
            _ => {
                assert!(request.starts_with("GET /api/onboarding/cursor-mcp/status "));
                (200, status(true))
            }
        }
    });
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_mode_settings(
                    window,
                    cx,
                    endpoint.clone(),
                    Some(directory.drafts()),
                    AppMode::CursorOnboarding,
                    Some("Studio".into()),
                )
            })
        })
        .unwrap()
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("cursor-onboarding-setup").disabled(),
            Some(true)
        );
        window.click("cursor-onboarding-setup", cx);
        window.click("cursor-onboarding-details", cx);
        assert_eq!(
            window.find("cursor-onboarding-details").label(),
            Some("Hide details")
        );
        view.update(cx, |view, _| {
            assert!(matches!(
                view.client_inventory.state,
                InventoryState::Unavailable(_)
            ));
            assert_eq!(view.cursor_target_host(), "Studio");
            assert!(view.openings.as_ref().unwrap().attempts.is_empty());
            assert!(view.selection_task.is_none());
            assert!(view.opening_tasks.is_empty());
            assert!(view.client_inventory.details_expanded);
        });
        window.click("find-cursor", cx);
    })
    .unwrap();
    cx.run_until_parked();
    let requests = worker.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        assert!(matches!(
            view.client_inventory.state,
            InventoryState::Ready(_)
        ));
        assert!(view.can_act_on_installation(OpeningAction::CursorMcpSetup, &"a".repeat(64), cx));
        assert!(view.openings.as_ref().unwrap().attempts.is_empty());
        assert!(view.opening_tasks.is_empty());
    });
}

#[gpui_kit::test]
fn older_cross_action_pending_cursor_request_remains_recoverable(cx: &mut TestAppContext) {
    let directory = Directory::new();
    let drafts = directory.drafts();
    let (endpoint, worker) = fixture(3, |request, index| match index {
        0 => {
            assert!(request.starts_with("GET /api/bus/clients "));
            (200, cursor_copies_inventory(false))
        }
        1 => {
            assert!(request.starts_with("GET /api/onboarding/cursor-mcp/status "));
            (200, status(true))
        }
        _ => {
            assert!(
                request.starts_with("GET /api/onboarding/opens/"),
                "saved action chooses its original GET route"
            );
            let id = request
                .split_whitespace()
                .nth(1)
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap();
            (
                200,
                json!({"schema":"chinwag-native-open/v1","request_id":id,"installation_id":"a".repeat(64),
                "state":"opened_or_reused","message":"Synthetic OS acknowledgement"}),
            )
        }
    });
    {
        let mut store = OpeningStore::open(openings::path_for_drafts(&drafts).unwrap()).unwrap();
        store
            .prepare(OpeningAction::OrdinaryOpen, &endpoint, &"a".repeat(64))
            .unwrap();
        for _ in 0..5 {
            let attempt = store
                .prepare(OpeningAction::CursorMcpSetup, &endpoint, &"b".repeat(64))
                .unwrap();
            store
                .apply_receipt(
                    &attempt.id,
                    NativeOpenReceipt {
                        schema: "chinwag-native-open/v1".into(),
                        request_id: attempt.id.clone(),
                        installation_id: "b".repeat(64),
                        state: chinwag_bus_client::NativeOpenState::OpenedOrReused,
                        message: "Synthetic acknowledgement".into(),
                    },
                )
                .unwrap();
        }
    }
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_mode_settings(
                    window,
                    cx,
                    endpoint.clone(),
                    Some(drafts.clone()),
                    AppMode::CursorOnboarding,
                    None,
                )
            })
        })
        .unwrap()
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("cursor-onboarding-setup").disabled(),
            Some(true)
        );
        assert_eq!(
            window.find(("cursor-setup-status", 0_usize)).label(),
            Some("Check opening status")
        );
        // Unresolved requests lead the history, so the older blocked copy
        // retains a visible native recovery control above recent successes.
        window.click(("cursor-setup-status", 0_usize), cx);
    })
    .unwrap();
    cx.run_until_parked();
    let requests = worker.join().unwrap();
    cx.run_until_parked();
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    cx.update(|cx| {
        assert!(!view.read(cx).openings.as_ref().unwrap().attempts[0].unresolved());
    });
}
