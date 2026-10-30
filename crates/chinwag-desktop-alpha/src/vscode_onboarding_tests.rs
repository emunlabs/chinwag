use super::*;

fn vscode_inventory() -> Value {
    let mut value = inventory();
    value["installations"]["apps"][0]["family"] = json!("visual_studio_code");
    value["installations"]["apps"][0]["location"] = json!("shared_applications");
    value["installations"]["apps"][0]["version"] = json!("1.108.0");
    value
}

#[gpui_kit::test]
fn vscode_human_click_refreshes_then_persists_before_one_post_and_blocks_ack_repeat(
    cx: &mut TestAppContext,
) {
    let directory = Directory::new();
    let drafts = directory.drafts();
    let history = openings::path_for_drafts(&drafts).unwrap();
    let (endpoint, worker) = fixture(6, move |request, index| match index {
        0 | 3 => {
            assert!(request.starts_with("GET /api/bus/clients "));
            assert!(!history.exists(), "metadata creates no attempt");
            (200, vscode_inventory())
        }
        1 => {
            assert!(request.starts_with("GET /api/onboarding/status "));
            (200, status(true))
        }
        2 | 4 => {
            assert!(request.starts_with("GET /api/onboarding/vscode-mcp/status "));
            assert!(!history.exists());
            (200, status(true))
        }
        _ => {
            assert!(request.starts_with("POST /api/onboarding/vscode-mcp/setup "));
            let saved: Value = serde_json::from_slice(&std::fs::read(&history).unwrap()).unwrap();
            assert_eq!(saved["attempts"][0]["action"], "vscode_mcp_setup");
            assert_eq!(saved["attempts"][0]["state"], "pending");
            assert_eq!(
                saved["attempts"][0]["id"],
                header(request, "X-Chinwag-Request-Id")
            );
            assert_eq!(
                serde_json::from_str::<Value>(request.split_once("\r\n\r\n").unwrap().1).unwrap(),
                json!({"installation_id":"a".repeat(64)})
            );
            (200, reply(request, "a".repeat(64), "opened_or_reused"))
        }
    });
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_settings(window, cx, endpoint.clone(), Some(drafts.clone()))
            })
        })
        .unwrap()
    });
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("find-client-apps", cx);
    })
    .unwrap();
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find(("setup-vscode-mcp", 0_usize)).label(),
            Some("Set up VS Code")
        );
        assert!(
            window.try_find(("setup-vscode-mcp", 1_usize)).is_none(),
            "Grok is not a VS Code copy"
        );
        window.click(("setup-vscode-mcp", 0_usize), cx);
        window.click(("setup-vscode-mcp", 0_usize), cx);
        view.update(cx, |view, _| {
            assert!(view.openings.as_ref().unwrap().attempts.is_empty());
            assert_eq!(
                view.opening_selection.as_ref().unwrap().action,
                OpeningAction::VsCodeMcpSetup
            );
        });
    })
    .unwrap();
    cx.run_until_parked();
    let requests = worker.join().unwrap();
    assert_eq!(requests.len(), 6);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with("POST "))
            .count(),
        1
    );
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, _| {
            let store = view.openings.as_mut().unwrap();
            assert_eq!(store.attempts.len(), 1);
            assert_eq!(store.attempts[0].action, OpeningAction::VsCodeMcpSetup);
            assert!(
                store.attempts[0]
                    .summary()
                    .contains("inbox read are unverified")
            );
            // Push the selected acknowledgement beyond the recent-four boundary.
            for _ in 0..5 {
                let other = store
                    .prepare(OpeningAction::OrdinaryOpen, &endpoint, &"b".repeat(64))
                    .unwrap();
                store
                    .apply_receipt(
                        &other.id,
                        NativeOpenReceipt {
                            schema: "chinwag-native-open/v1".into(),
                            request_id: other.id.clone(),
                            installation_id: other.installation_id.clone(),
                            state: chinwag_bus_client::NativeOpenState::OpenedOrReused,
                            message: "Synthetic unrelated OS acknowledgement".into(),
                        },
                    )
                    .unwrap();
            }
        });
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find(("setup-vscode-mcp", 0_usize)).label(),
            Some("VS Code setup request sent")
        );
        assert_eq!(
            window.find(("setup-vscode-mcp", 0_usize)).disabled(),
            Some(true)
        );
        window.click(("setup-vscode-mcp", 0_usize), cx);
        view.update(cx, |view, cx| {
            view.act_on_installation(OpeningAction::VsCodeMcpSetup, &"a".repeat(64), cx);
            assert!(view.selection_task.is_none());
            assert!(view.opening_tasks.is_empty());
            assert_eq!(view.openings.as_ref().unwrap().attempts.len(), 6);
            assert!(matches!(view.connection, Connection::Disconnected));
        });
    })
    .unwrap();
}

#[gpui_kit::test]
fn saved_unknown_vscode_setup_recovers_via_original_get_only_after_restart(
    cx: &mut TestAppContext,
) {
    let directory = Directory::new();
    let drafts = directory.drafts();
    let history = openings::path_for_drafts(&drafts).unwrap();
    let (endpoint, worker) = fixture(4, |request, index| match index {
        0 => {
            assert!(request.starts_with("GET /api/bus/clients "));
            (200, vscode_inventory())
        }
        1 => {
            assert!(request.starts_with("GET /api/onboarding/status "));
            (200, status(true))
        }
        2 => {
            assert!(request.starts_with("GET /api/onboarding/vscode-mcp/status "));
            (200, status(true))
        }
        _ => {
            assert!(request.starts_with("GET /api/onboarding/vscode-mcp/setups/"));
            let id = request
                .split_whitespace()
                .nth(1)
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap();
            (
                200,
                json!({"schema":"chinwag-native-open/v1","request_id":id,
                "installation_id":"a".repeat(64),"state":"opened_or_reused","message":"Synthetic OS setup acknowledgement"}),
            )
        }
    });
    let original = {
        let mut store = OpeningStore::open(history.clone()).unwrap();
        let original = store
            .prepare(OpeningAction::VsCodeMcpSetup, &endpoint, &"a".repeat(64))
            .unwrap();
        store
            .mark_uncertain(&original.id, "Synthetic missing POST response")
            .unwrap();
        original
    };
    {
        let store = OpeningStore::open(history.clone()).unwrap();
        assert_eq!(store.attempts[0].action, OpeningAction::VsCodeMcpSetup);
        assert_eq!(store.attempts[0].id, original.id);
        assert!(store.attempts[0].unresolved());
    }
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_settings(window, cx, endpoint.clone(), Some(drafts.clone()))
            })
        })
        .unwrap()
    });
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("find-client-apps", cx);
    })
    .unwrap();
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find(("setup-vscode-mcp", 0_usize)).disabled(),
            Some(true)
        );
        window.click(("setup-vscode-mcp", 0_usize), cx);
        view.update(cx, |view, cx| {
            for action in [
                OpeningAction::OrdinaryOpen,
                OpeningAction::CursorMcpSetup,
                OpeningAction::VsCodeMcpSetup,
            ] {
                assert!(!view.can_act_on_installation(action, &"a".repeat(64), cx));
                view.act_on_installation(action, &"a".repeat(64), cx);
            }
            assert!(view.selection_task.is_none());
            assert_eq!(view.openings.as_ref().unwrap().attempts.len(), 1);
        });
        assert_eq!(
            window.find(("check-opening-status", 0_usize)).label(),
            Some("Check VS Code setup status")
        );
        window.click(("check-opening-status", 0_usize), cx);
    })
    .unwrap();
    cx.run_until_parked();
    assert!(
        worker
            .join()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("GET "))
    );
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        let store = view.openings.as_ref().unwrap();
        assert_eq!(store.attempts.len(), 1);
        assert_eq!(store.attempts[0].id, original.id);
        assert_eq!(store.attempts[0].action, OpeningAction::VsCodeMcpSetup);
        assert!(!store.attempts[0].unresolved());
    });
}

#[gpui_kit::test]
fn older_runtime_vscode_404_preserves_inventory_and_ordinary_opening(cx: &mut TestAppContext) {
    let directory = Directory::new();
    let (endpoint, worker) = fixture(3, |request, index| match index {
        0 => {
            assert!(request.starts_with("GET /api/bus/clients "));
            (200, vscode_inventory())
        }
        1 => {
            assert!(request.starts_with("GET /api/onboarding/status "));
            (200, status(true))
        }
        _ => {
            assert!(request.starts_with("GET /api/onboarding/vscode-mcp/status "));
            (404, json!({"error":"old runtime"}))
        }
    });
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_settings(window, cx, endpoint.clone(), Some(directory.drafts()))
            })
        })
        .unwrap()
    });
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("find-client-apps", cx);
    })
    .unwrap();
    cx.run_until_parked();
    assert_eq!(worker.join().unwrap().len(), 3);
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        assert!(window.try_find(("setup-vscode-mcp", 0_usize)).is_none());
        view.update(cx, |view, cx| {
            assert!(matches!(
                view.client_inventory.state,
                InventoryState::Ready(_)
            ));
            assert!(view.can_open_installation(&"a".repeat(64), cx));
            assert!(!view.can_act_on_installation(
                OpeningAction::VsCodeMcpSetup,
                &"a".repeat(64),
                cx
            ));
            assert!(
                view.client_inventory
                    .vscode_mcp_notice
                    .as_deref()
                    .unwrap()
                    .contains("unavailable")
            );
            assert!(view.openings.as_ref().unwrap().attempts.is_empty());
            assert!(matches!(view.connection, Connection::Disconnected));
        });
    })
    .unwrap();
}

#[gpui_kit::test]
fn stale_vscode_selection_or_endpoint_generation_never_creates_pending(cx: &mut TestAppContext) {
    let directory = Directory::new();
    let endpoint = "http://127.0.0.1:9";
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_settings(window, cx, endpoint.into(), Some(directory.drafts()))
            })
        })
        .unwrap()
    });
    cx.update_window(window, |_, _, cx| {
        view.update(cx, |view, cx| {
            for mutation in 0..4 {
                let inventory: ClientInventory =
                    serde_json::from_value(vscode_inventory()).unwrap();
                let generation = view.client_inventory.begin(endpoint.into());
                view.client_inventory
                    .complete(generation, endpoint, Ok(inventory.clone()));
                view.client_inventory.complete_vscode_mcp_status(
                    generation,
                    endpoint,
                    Ok(serde_json::from_value(status(true)).unwrap()),
                );
                let selection = OpeningSelection {
                    app: inventory.installations.as_ref().unwrap().apps[0].clone(),
                    endpoint: endpoint.into(),
                    epoch: view.opening_epoch,
                    inventory_generation: generation,
                    connection_generation: view.connection_generation,
                    generation: mutation + 1,
                    action: OpeningAction::VsCodeMcpSetup,
                };
                view.opening_selection = Some(selection.clone());
                let mut fresh = inventory;
                match mutation {
                    0 => fresh.installations.as_mut().unwrap().apps[0].id = "c".repeat(64),
                    1 => fresh.installations.as_mut().unwrap().apps[0].version = Some("2.0".into()),
                    2 => view.connection_generation = view.connection_generation.wrapping_add(1),
                    _ => {
                        view.client_inventory.begin("http://127.0.0.1:8".into());
                    }
                }
                view.apply_selection_refresh(
                    &selection,
                    AppInventoryRead {
                        inventory: Ok(fresh),
                        opening_status: None,
                        cursor_mcp_status: None,
                        vscode_mcp_status: Some(Ok(serde_json::from_value(status(true)).unwrap())),
                    },
                    cx,
                );
                assert!(view.openings.as_ref().unwrap().attempts.is_empty());
                assert!(view.opening_tasks.is_empty());
                assert!(view.selection_task.is_none());
            }
            assert!(
                !openings::path_for_drafts(&directory.drafts())
                    .unwrap()
                    .exists()
            );
        });
    })
    .unwrap();
}
