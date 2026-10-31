use super::*;
use chinwag_gemini_control::{Receipt, SavedOperation, StartupRecord, test_support};
use gpui_kit::{
    Bounds, TestAppContext, WindowBounds, WindowOptions, init, open_window, px, size,
    test::TestWindowExt,
};
use std::{sync::Mutex, time::Duration};
use tokio::sync::watch;

#[derive(Clone)]
enum Call {
    Start(String, String),
    Prompt(ObservedSession, String, String),
    Cancel(ObservedActivePrompt, String),
    Lookup(String),
    EndInput,
}
struct FakePort {
    sender: watch::Sender<WorkSnapshot>,
    calls: Mutex<Vec<Call>>,
    prompt_error: Mutex<Option<GeminiError>>,
}
impl FakePort {
    fn new() -> Arc<Self> {
        let (sender, _) = watch::channel(WorkSnapshot::ready("Owned Gemini fixture".into()));
        Arc::new(Self {
            sender,
            calls: Mutex::new(Vec::new()),
            prompt_error: Mutex::new(None),
        })
    }
    fn publish(&self, update: impl FnOnce(&mut WorkSnapshot)) {
        self.sender.send_modify(|snapshot| {
            update(snapshot);
            snapshot.revision += 1;
        });
    }
}
impl HumanWorkPort for FakePort {
    fn subscribe(&self) -> watch::Receiver<WorkSnapshot> {
        self.sender.subscribe()
    }
    fn start(&self, id: &str, text: &str) -> chinwag_gemini_control::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Start(id.into(), text.into()));
        Ok(())
    }
    fn prompt(
        &self,
        target: &ObservedSession,
        id: &str,
        text: &str,
    ) -> chinwag_gemini_control::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Prompt(target.clone(), id.into(), text.into()));
        self.prompt_error.lock().unwrap().take().map_or(Ok(()), Err)
    }
    fn cancel(
        &self,
        target: &ObservedActivePrompt,
        id: &str,
    ) -> chinwag_gemini_control::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Cancel(target.clone(), id.into()));
        Ok(())
    }
    fn lookup(&self, id: &str) -> chinwag_gemini_control::Result<()> {
        self.calls.lock().unwrap().push(Call::Lookup(id.into()));
        Ok(())
    }
    fn end_input(&self) -> chinwag_gemini_control::Result<()> {
        self.calls.lock().unwrap().push(Call::EndInput);
        Ok(())
    }
}
fn receipt(
    id: &str,
    text: &str,
    kind: ActionKind,
    session: &ObservedSession,
    active: Option<&ObservedActivePrompt>,
    evidence: Evidence,
) -> Receipt {
    Receipt {
        operation: SavedOperation {
            schema: "chinwag-gemini-operation/v1".into(),
            id: id.into(),
            kind,
            text: text.into(),
            session_epoch: session.session_epoch().into(),
            session_id: (kind != ActionKind::Start).then(|| session.session_id().into()),
            prompt_rpc_id: active
                .map_or_else(|| format!("prompt-{id}"), |active| active.rpc_id().into()),
            prompt_generation: active.map_or(1, ObservedActivePrompt::generation),
            startup: (kind == ActionKind::Start).then(|| StartupRecord {
                binary: "/fixture/bin/gemini".into(),
                sha256: "a".repeat(64),
                workdir: "/fixture/work".into(),
                policy: "configured_runtime_effects_manual_mode_extensions_disabled".into(),
            }),
        },
        evidence,
        recovered_after_restart: false,
        persistence_failed: false,
    }
}
fn mount(
    cx: &mut TestAppContext,
    port: Arc<dyn HumanWorkPort>,
) -> (gpui_kit::AnyWindowHandle, Entity<GeminiWorkView>) {
    cx.update(init);
    cx.update(|cx| {
        open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: Default::default(),
                    size: size(px(1150.), px(1100.)),
                })),
                ..WindowOptions::default()
            },
            cx,
            |window, cx| cx.new(|cx| GeminiWorkView::new(port, window, cx)),
        )
        .unwrap()
    })
}
fn active_port() -> (Arc<FakePort>, ObservedSession, ObservedActivePrompt) {
    let (session, active) = test_support::observed_targets().unwrap();
    let port = FakePort::new();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Prompting;
        snapshot.session = Some(session.clone());
        snapshot.active_prompt = Some(active.clone());
        snapshot.start = Some(receipt(
            active.operation_id(),
            "Original task",
            ActionKind::Start,
            &session,
            None,
            Evidence {
                frame_written: true,
                ..Evidence::default()
            },
        ));
    });
    (port, session, active)
}

#[gpui_kit::test]
fn mount_is_inert_start_click_is_once_and_saved_exact_draft_clears(cx: &mut TestAppContext) {
    let port = FakePort::new();
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    assert!(port.calls.lock().unwrap().is_empty());
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor
                .update(cx, |editor, cx| editor.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        assert!(window.try_find("submit-claude-work").is_none());
        assert!(window.try_find("send").is_none());
        window.input("Write a clear explanation", cx);
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("submit-gemini-work").label(),
            Some("Start Gemini task")
        );
        window.click("submit-gemini-work", cx);
        window.click("submit-gemini-work", cx);
    })
    .unwrap();
    cx.run_until_parked();
    let (id, text) = match &port.calls.lock().unwrap()[0] {
        Call::Start(id, text) => (id.clone(), text.clone()),
        _ => panic!("Start"),
    };
    assert_eq!(port.calls.lock().unwrap().len(), 1);
    let session = test_support::observed_session().unwrap();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Starting;
        snapshot.start = Some(receipt(
            &id,
            &text,
            ActionKind::Start,
            &session,
            None,
            Evidence::default(),
        ));
    });
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        assert!(view.flight.is_none());
        assert_eq!(view.editor.read(cx).value(), "");
    });
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("submit-gemini-work", cx);
    })
    .unwrap();
    assert_eq!(
        port.calls.lock().unwrap().len(),
        1,
        "watch and disabled action cannot start again"
    );
}

#[gpui_kit::test]
fn busy_cancel_keeps_draft_and_requires_terminal_plus_retired_cancel_then_manual_send(
    cx: &mut TestAppContext,
) {
    let (port, session, active) = active_port();
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor
                .update(cx, |editor, cx| editor.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("My next direction", cx);
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("submit-gemini-work").label(),
            Some("Response pending · keep drafting")
        );
        window.click("submit-gemini-work", cx);
        window.click("cancel-gemini-response", cx);
        window.click("cancel-gemini-response", cx);
    })
    .unwrap();
    let cancel_id = match &port.calls.lock().unwrap()[0] {
        Call::Cancel(captured, id) => {
            assert!(same_active(captured, &active));
            id.clone()
        }
        _ => panic!("Cancel"),
    };
    assert_eq!(port.calls.lock().unwrap().len(), 1);
    port.publish(|snapshot| {
        snapshot.operations.push(receipt(
            &cancel_id,
            "",
            ActionKind::Cancel,
            &session,
            Some(&active),
            Evidence {
                frame_written: true,
                ..Evidence::default()
            },
        ));
        snapshot.cancel_pending = true;
        snapshot.active_prompt = None;
        snapshot.can_prompt = true;
        snapshot.phase = WorkPhase::Idle;
        snapshot.start.as_mut().unwrap().evidence.terminal = Some(StopReason::Cancelled);
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("submit-gemini-work").label(),
            Some("Waiting for cancellation to retire")
        );
        window.click("submit-gemini-work", cx);
        view.update(cx, |view, cx| {
            assert_eq!(view.editor.read(cx).value(), "My next direction")
        });
    })
    .unwrap();
    assert_eq!(
        port.calls.lock().unwrap().len(),
        1,
        "terminal alone cannot dispatch queued text"
    );
    port.publish(|snapshot| {
        snapshot.cancel_pending = false;
        snapshot.can_prompt = true;
    });
    cx.run_until_parked();
    assert_eq!(
        port.calls.lock().unwrap().len(),
        1,
        "retiring Cancel never auto sends"
    );
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("submit-gemini-work", cx);
        window.click("submit-gemini-work", cx);
    })
    .unwrap();
    let calls = port.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    match &calls[1] {
        Call::Prompt(captured, _, text) => {
            assert_eq!(captured.session_epoch(), session.session_epoch());
            assert_eq!(text, "My next direction");
        }
        _ => panic!("separate human Prompt"),
    }
}

#[gpui_kit::test]
fn late_foreign_receipt_and_same_text_restoration_do_not_clear_a_new_draft(
    cx: &mut TestAppContext,
) {
    let (port, session, _) = active_port();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Idle;
        snapshot.active_prompt = None;
        snapshot.can_prompt = true;
    });
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor
                .update(cx, |editor, cx| editor.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("Keep this text", cx);
        window.draw(cx).clear(cx);
        window.click("submit-gemini-work", cx);
    })
    .unwrap();
    cx.run_until_parked();
    let (id, text) = match &port.calls.lock().unwrap()[0] {
        Call::Prompt(_, id, text) => (id.clone(), text.clone()),
        _ => panic!("Prompt"),
    };
    port.publish(|snapshot| {
        snapshot.operations = vec![receipt(
            &id,
            "different payload",
            ActionKind::Prompt,
            &session,
            None,
            Evidence::default(),
        )];
    });
    cx.run_until_parked();
    cx.update(|cx| {
        assert!(view.read(cx).flight.is_some());
        assert_eq!(view.read(cx).editor.read(cx).value(), text);
    });
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor
                .update(cx, |editor, cx| editor.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        let select_all = if cfg!(target_os = "macos") {
            "cmd-a"
        } else {
            "ctrl-a"
        };
        // set_value intentionally emits no Change event. Exercise actual
        // human edits so the FIFO draft identity must notice restoration.
        window.press(select_all, cx);
        window.input("different edit", cx);
        window.press(select_all, cx);
        window.input(&text, cx);
    })
    .unwrap();
    cx.run_until_parked();
    cx.update(|cx| {
        let current = view.read(cx);
        let captured = current
            .flight
            .as_ref()
            .unwrap()
            .draft_identity
            .as_ref()
            .unwrap();
        assert!(
            !Arc::ptr_eq(captured, &current.draft_identity),
            "actual edit/restore changes the draft identity"
        );
        assert_eq!(current.editor.read(cx).value(), text);
    });
    port.publish(|snapshot| {
        snapshot.operations = vec![receipt(
            &id,
            &text,
            ActionKind::Prompt,
            &session,
            None,
            Evidence {
                frame_written: true,
                ..Evidence::default()
            },
        )];
    });
    cx.run_until_parked();
    cx.update(|cx| {
        assert!(view.read(cx).flight.is_none());
        assert_eq!(view.read(cx).editor.read(cx).value(), text);
    });
    assert_eq!(port.calls.lock().unwrap().len(), 1);
}

#[gpui_kit::test]
fn stale_cancel_is_not_retargeted_and_permission_intervention_keeps_exact_cancel(
    cx: &mut TestAppContext,
) {
    let (port, _, active) = active_port();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::OwnerActionRequired;
        snapshot.pending_permissions = 1;
    });
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    let (_, foreign) = test_support::observed_targets().unwrap();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.cancel(&foreign, cx);
            assert!(view.flight.is_none());
        });
        window.draw(cx).clear(cx);
        window.click("cancel-gemini-response", cx);
    })
    .unwrap();
    let calls = port.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(matches!(&calls[0],Call::Cancel(captured,_)if same_active(captured,&active)));
}

#[gpui_kit::test]
fn unknown_receipt_lookup_expired_control_and_end_input_never_resend(cx: &mut TestAppContext) {
    let (port, session, _) = active_port();
    port.publish(|snapshot| {
        snapshot.control_expired = true;
    });
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor
                .update(cx, |editor, cx| editor.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("Keep drafting after control expiry", cx);
        window.draw(cx).clear(cx);
        window.click("submit-gemini-work", cx);
        window.click("cancel-gemini-response", cx);
        window.click(("lookup-gemini-operation", 0_usize), cx);
        window.click("end-gemini-input", cx);
        window.click("end-gemini-input", cx);
    })
    .unwrap();
    let calls = port.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(
        matches!(&calls[0],Call::Lookup(id)if id==port.sender.borrow().start.as_ref().unwrap().operation.id.as_str())
    );
    assert!(matches!(&calls[1], Call::EndInput));
    drop(calls);
    port.publish(|snapshot| {
        snapshot.operations.push(receipt(
            "11111111-1111-4111-8111-111111111111",
            "historical",
            ActionKind::Prompt,
            &session,
            None,
            Evidence {
                write_uncertain: true,
                ..Evidence::default()
            },
        ));
    });
    cx.run_until_parked();
    cx.update(|cx| {
        assert_eq!(
            view.read(cx).editor.read(cx).value(),
            "Keep drafting after control expiry"
        )
    });
    assert_eq!(port.calls.lock().unwrap().len(), 2);
}

#[gpui_kit::test]
fn command_prefixes_are_not_dispatched_and_plain_enter_keeps_a_draft(cx: &mut TestAppContext) {
    let port = FakePort::new();
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    for text in ["/help", "  $command", "\u{feff}/command"] {
        cx.update_window(window, |_, window, cx| {
            view.update(cx, |view, cx| {
                view.editor
                    .update(cx, |editor, cx| editor.set_value(text, window, cx))
            });
            window.draw(cx).clear(cx);
            window.click("submit-gemini-work", cx);
        })
        .unwrap();
    }
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |editor, cx| {
                editor.set_value("Ordinary prose", window, cx);
                editor.focus(window, cx);
            })
        });
        window.draw(cx).clear(cx);
        window.press("end", cx);
        window.press("enter", cx);
    })
    .unwrap();
    cx.run_until_parked();
    assert!(port.calls.lock().unwrap().is_empty());
    cx.update(|cx| {
        assert!(
            view.read(cx)
                .editor
                .read(cx)
                .value()
                .contains("Ordinary prose")
        )
    });
}

#[test]
fn evidence_never_fabricates_cancel_ack_or_model_seen_and_preserves_stop_reason() {
    let lost = Evidence {
        terminal_unknown: true,
        ..Evidence::default()
    };
    assert!(
        evidence_lines(ActionKind::Prompt, &lost, false)
            .join(" ")
            .contains("after owned transport loss")
    );
    for resolved in [
        Evidence {
            terminal: Some(StopReason::EndTurn),
            ..lost.clone()
        },
        Evidence {
            rpc_error: true,
            ..lost.clone()
        },
    ] {
        assert!(
            !evidence_lines(ActionKind::Prompt, &resolved, false)
                .join(" ")
                .contains("terminal response is unavailable"),
            "later actual response supersedes unknown projection"
        );
    }
    let cancel = evidence_lines(
        ActionKind::Cancel,
        &Evidence {
            frame_written: true,
            permission_cancel_responses_written: 1,
            ..Evidence::default()
        },
        false,
    )
    .join(" ");
    assert!(cancel.contains("not a cancellation acknowledgement"));
    assert!(cancel.contains("No permission was approved"));
    for reason in [
        StopReason::EndTurn,
        StopReason::MaxTokens,
        StopReason::MaxTurnRequests,
        StopReason::Refusal,
        StopReason::Cancelled,
    ] {
        let text = evidence_lines(
            ActionKind::Prompt,
            &Evidence {
                terminal: Some(reason),
                ..Evidence::default()
            },
            false,
        )
        .join(" ");
        assert!(text.contains(stop_label(reason)));
        assert!(!text.contains("Model seen"));
    }
    assert!(
        evidence_lines(
            ActionKind::Start,
            &Evidence {
                not_dispatched: true,
                ..Evidence::default()
            },
            false
        )[0]
        .contains("startup may already have run")
    );
}

async fn read_peer_frame(peer: &mut tokio::io::DuplexStream) -> serde_json::Value {
    use tokio::io::AsyncReadExt as _;
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        loop {
            let byte = peer.read_u8().await.expect("synthetic peer open");
            if byte == b'\n' {
                break;
            }
            bytes.push(byte);
            assert!(bytes.len() <= 65536);
        }
        serde_json::from_slice(&bytes).unwrap()
    })
    .await
    .expect("bounded protocol request")
}
async fn send_peer_frame(peer: &mut tokio::io::DuplexStream, value: serde_json::Value) {
    use tokio::io::AsyncWriteExt as _;
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(3), peer.write_all(&bytes))
        .await
        .unwrap()
        .unwrap();
}
fn wait_snapshot(
    runtime: &tokio::runtime::Runtime,
    port: &Arc<dyn HumanWorkPort>,
    predicate: impl Fn(&WorkSnapshot) -> bool,
) -> WorkSnapshot {
    let mut receiver = port.subscribe();
    runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let snapshot = receiver.borrow_and_update().clone();
                    if predicate(&snapshot) {
                        return snapshot;
                    }
                    receiver.changed().await.expect("owner update");
                }
            })
            .await
        })
        .expect("bounded actual owner update")
}

/// Actual retained actor, journal and ACP wire; only the child spawn factory is
/// replaced by a synthetic duplex peer. No Gemini executable or model runs.
#[gpui_kit::test]
fn real_owner_clicks_start_cancel_late_permission_terminal_then_manual_send(
    cx: &mut TestAppContext,
) {
    cx.executor().allow_parking();
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt as _;
    use tokio::io::AsyncReadExt as _;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let journal = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("gemini-operations");
    let (port, mut peer) = test_support::open_fixture_service(&journal).unwrap();
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    assert!(port.subscribe().borrow().start.is_none());
    runtime.block_on(async {
        assert!(
            tokio::time::timeout(Duration::from_millis(20), peer.io.read_u8())
                .await
                .is_err(),
            "mount emits no requests"
        );
    });
    let mut submitted_id = String::new();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor
                .update(cx, |editor, cx| editor.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("Explain a small native interface", cx);
        window.draw(cx).clear(cx);
        window.click("submit-gemini-work", cx);
        submitted_id = view
            .read(cx)
            .flight
            .as_ref()
            .expect("human Start flight")
            .id
            .clone();
        window.click("submit-gemini-work", cx);
    })
    .unwrap();
    let initialize = runtime.block_on(read_peer_frame(&mut peer.io));
    assert_eq!(initialize["method"], "initialize");
    assert_eq!(initialize["params"]["clientCapabilities"], json!({}));
    // The wire and coalesced watch use different threads. Check the exact
    // original Saved bytes at the first observed effect, before waiting for
    // any snapshot publication; watch delivery is not the durability proof.
    let bytes = std::fs::read(journal.join(format!("{submitted_id}.jsonl")))
        .expect("original Saved record exists when initialize is observed");
    let first = bytes.split(|byte| *byte == b'\n').next().unwrap();
    let saved_line: serde_json::Value = serde_json::from_slice(first).unwrap();
    assert_eq!(saved_line["type"], "saved");
    assert_eq!(saved_line["operation"]["id"], submitted_id);
    assert_eq!(
        saved_line["operation"]["text"],
        "Explain a small native interface"
    );
    assert_eq!(
        saved_line["operation"]["startup"]["policy"],
        "configured_runtime_effects_manual_mode_extensions_disabled"
    );
    let published = wait_snapshot(&runtime, &port, |snapshot| {
        snapshot
            .start
            .as_ref()
            .is_some_and(|receipt| receipt.operation.id == submitted_id)
    });
    let saved = published.start.unwrap();
    assert_eq!(
        saved_line["operation"],
        serde_json::to_value(&saved.operation).unwrap()
    );
    assert_eq!(
        initialize["id"],
        format!("init-{}", saved.operation.session_epoch)
    );
    runtime.block_on(send_peer_frame(&mut peer.io,json!({"jsonrpc":"2.0","id":initialize["id"],"result":{"protocolVersion":1,"agentInfo":{"name":"gemini-cli","version":"0.66.0"},"agentCapabilities":{}}})));
    let new = runtime.block_on(read_peer_frame(&mut peer.io));
    assert_eq!(new["method"], "session/new");
    assert_eq!(new["params"]["cwd"], peer.workdir.to_str().unwrap());
    assert_eq!(new["params"]["mcpServers"], json!([]));
    let session = "aaaaaaaa-1111-4111-8111-111111111111";
    runtime.block_on(send_peer_frame(&mut peer.io,json!({"jsonrpc":"2.0","id":new["id"],"result":{"sessionId":session,"modes":{"currentModeId":"default"}}})));
    let initial = runtime.block_on(read_peer_frame(&mut peer.io));
    assert_eq!(initial["method"], "session/prompt");
    assert_eq!(initial["params"]["sessionId"], session);
    assert_eq!(
        initial["params"]["prompt"],
        json!([{"type":"text","text":"Explain a small native interface"}])
    );
    wait_snapshot(&runtime, &port, |snapshot| {
        snapshot.active_prompt.is_some()
            && snapshot
                .start
                .as_ref()
                .is_some_and(|r| r.evidence.frame_written)
            && snapshot.last_submission.as_ref().is_some_and(|s| {
                s.id == saved.operation.id && s.kind == ActionKind::Start && s.saved
            })
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            assert!(view.flight.is_none());
            assert!(
                view.snapshot
                    .start
                    .as_ref()
                    .unwrap()
                    .evidence
                    .terminal
                    .is_none()
            );
            assert_eq!(view.editor.read(cx).value(), "");
            view.editor
                .update(cx, |editor, cx| editor.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input("Keep this separate follow-up", cx);
        window.draw(cx).clear(cx);
        window.click("submit-gemini-work", cx);
        window.click("cancel-gemini-response", cx);
        window.click("cancel-gemini-response", cx);
    })
    .unwrap();
    let cancel = runtime.block_on(read_peer_frame(&mut peer.io));
    assert_eq!(
        cancel,
        json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":session}})
    );
    let permission = json!({"jsonrpc":"2.0","id":"late-permission","method":"session/request_permission","params":{"sessionId":session,"toolCall":{},"options":[{"optionId":"allow-once","name":"Allow","kind":"allow_once"}]}});
    runtime.block_on(send_peer_frame(&mut peer.io,json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":session,"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Late session-only output"}}}})));
    runtime.block_on(send_peer_frame(&mut peer.io, permission));
    let denied = runtime.block_on(read_peer_frame(&mut peer.io));
    assert_eq!(
        denied,
        json!({"jsonrpc":"2.0","id":"late-permission","result":{"outcome":{"outcome":"cancelled"}}})
    );
    let cancelling = wait_snapshot(&runtime, &port, |snapshot| {
        snapshot.operations.iter().any(|r| {
            r.operation.kind == ActionKind::Cancel
                && r.evidence.permission_cancel_responses_written == 1
        })
    });
    assert!(!cancelling.can_prompt);
    assert!(cancelling.start.unwrap().evidence.terminal.is_none());
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("submit-gemini-work", cx);
        view.update(cx, |view, cx| {
            assert_eq!(view.editor.read(cx).value(), "Keep this separate follow-up")
        });
    })
    .unwrap();
    runtime.block_on(send_peer_frame(
        &mut peer.io,
        json!({"jsonrpc":"2.0","id":initial["id"],"result":{"stopReason":"cancelled"}}),
    ));
    let ended = wait_snapshot(&runtime, &port, |snapshot| {
        snapshot.can_prompt
            && !snapshot.cancel_pending
            && snapshot
                .start
                .as_ref()
                .is_some_and(|r| r.evidence.terminal == Some(StopReason::Cancelled))
    });
    assert!(ended.active_prompt.is_none());
    runtime.block_on(async {
        assert!(
            tokio::time::timeout(Duration::from_millis(20), peer.io.read_u8())
                .await
                .is_err(),
            "terminal never auto sends draft"
        );
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("submit-gemini-work").label(),
            Some("Send next input")
        );
        window.click("submit-gemini-work", cx);
        window.click("submit-gemini-work", cx);
    })
    .unwrap();
    let next = runtime.block_on(read_peer_frame(&mut peer.io));
    assert_eq!(next["method"], "session/prompt");
    assert_ne!(next["id"], initial["id"]);
    assert_eq!(
        next["params"]["prompt"],
        json!([{"type":"text","text":"Keep this separate follow-up"}])
    );
    runtime.block_on(send_peer_frame(
        &mut peer.io,
        json!({"jsonrpc":"2.0","id":next["id"],"result":{"stopReason":"end_turn"}}),
    ));
    wait_snapshot(&runtime, &port, |snapshot| {
        snapshot.can_prompt
            && snapshot.operations.iter().any(|r| {
                r.operation.kind == ActionKind::Prompt
                    && r.evidence.terminal == Some(StopReason::EndTurn)
            })
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click(("lookup-gemini-operation", 0_usize), cx);
        window.click("end-gemini-input", cx);
        window.click("end-gemini-input", cx);
    })
    .unwrap();
    runtime.block_on(async {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), peer.io.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof,
            "lookup no frame; explicit EndInput closes stdin"
        );
    });
    peer.finish(0);
    wait_snapshot(&runtime, &port, |snapshot| snapshot.lifecycle.child_exited);
    cx.run_until_parked();
    cx.update_window(window, |_, window, _| window.remove_window())
        .unwrap();
    drop(view);
    drop(port);
}
