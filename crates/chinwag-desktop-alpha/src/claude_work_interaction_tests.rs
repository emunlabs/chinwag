use super::*;
use chinwag_claude_control::{
    ObservedSession, Receipt, SavedInput, StartupRecord, WorkSubmission, test_support,
};
use gpui_kit::{
    Bounds, TestAppContext, WindowBounds, WindowOptions, init, open_window, px, size,
    test::TestWindowExt,
};
use std::{path::PathBuf, sync::Mutex};
use tokio::sync::watch;

async fn read_peer_frame(peer: &mut tokio::io::DuplexStream) -> serde_json::Value {
    use tokio::io::AsyncReadExt as _;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        loop {
            let byte = peer.read_u8().await.expect("fixture peer remains open");
            if byte == b'\n' {
                break;
            }
            bytes.push(byte);
            assert!(bytes.len() <= 65536, "bounded native frame");
        }
        serde_json::from_slice(&bytes).expect("one JSON frame")
    })
    .await
    .expect("bounded fixture request")
}

async fn send_peer_frame(peer: &mut tokio::io::DuplexStream, value: serde_json::Value) {
    use tokio::io::AsyncWriteExt as _;
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    tokio::time::timeout(std::time::Duration::from_secs(3), peer.write_all(&bytes))
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
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    let snapshot = receiver.borrow_and_update().clone();
                    if predicate(&snapshot) {
                        return snapshot;
                    }
                    receiver.changed().await.expect("retained owner updates");
                }
            })
            .await
        })
        .expect("bounded actual owner update")
}

#[derive(Clone)]
enum Call {
    Start {
        id: String,
        text: String,
    },
    Direction {
        id: String,
        text: String,
        session: ObservedSession,
        timing: InputTiming,
    },
    Lookup(String),
    EndInput,
}

struct FakePort {
    sender: watch::Sender<WorkSnapshot>,
    calls: Mutex<Vec<Call>>,
    direction_error: Mutex<Option<ClaudeError>>,
}

impl FakePort {
    fn new() -> Arc<Self> {
        let (sender, _) = watch::channel(WorkSnapshot::ready("Owned Claude fixture".into()));
        Arc::new(Self {
            sender,
            calls: Mutex::new(Vec::new()),
            direction_error: Mutex::new(None),
        })
    }

    fn publish(&self, update: impl FnOnce(&mut WorkSnapshot)) {
        self.sender.send_modify(|snapshot| {
            update(snapshot);
            snapshot.revision += 1;
        });
    }

    fn start_call(&self) -> (String, String) {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .find_map(|call| match call {
                Call::Start { id, text } => Some((id.clone(), text.clone())),
                _ => None,
            })
            .expect("one explicit Start")
    }

    fn direction_call(&self) -> (String, String, ObservedSession, InputTiming) {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find_map(|call| match call {
                Call::Direction {
                    id,
                    text,
                    session,
                    timing,
                } => Some((id.clone(), text.clone(), session.clone(), *timing)),
                _ => None,
            })
            .expect("one explicit direction")
    }
}

impl HumanWorkPort for FakePort {
    fn subscribe(&self) -> watch::Receiver<WorkSnapshot> {
        self.sender.subscribe()
    }
    fn start(&self, id: &str, text: &str) -> chinwag_claude_control::Result<()> {
        self.calls.lock().unwrap().push(Call::Start {
            id: id.into(),
            text: text.into(),
        });
        Ok(())
    }
    fn direction(
        &self,
        session: &ObservedSession,
        id: &str,
        text: &str,
        timing: InputTiming,
    ) -> chinwag_claude_control::Result<()> {
        self.calls.lock().unwrap().push(Call::Direction {
            id: id.into(),
            text: text.into(),
            session: session.clone(),
            timing,
        });
        match self.direction_error.lock().unwrap().take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn lookup(&self, id: &str) -> chinwag_claude_control::Result<()> {
        self.calls.lock().unwrap().push(Call::Lookup(id.into()));
        Ok(())
    }
    fn end_input(&self) -> chinwag_claude_control::Result<()> {
        self.calls.lock().unwrap().push(Call::EndInput);
        Ok(())
    }
}

fn receipt(
    id: String,
    text: String,
    kind: ActionKind,
    timing: InputTiming,
    session: &ObservedSession,
    evidence: InputEvidence,
) -> Receipt {
    Receipt {
        operation: SavedInput {
            schema: "chinwag-claude-input/v1".into(),
            id,
            session_epoch: session.session_epoch().into(),
            session_id: session.session_id().into(),
            kind,
            timing,
            text,
            startup: (kind == ActionKind::Start).then(|| StartupRecord {
                binary: PathBuf::from("/fixture/bin/claude"),
                sha256: "a".repeat(64),
                workdir: PathBuf::from("/fixture/work"),
                policy: "managed_policy_prose_only".into(),
            }),
        },
        evidence,
        recovered_after_restart: false,
        persistence_failed: false,
    }
}

fn working_port(session: &ObservedSession) -> Arc<FakePort> {
    let port = FakePort::new();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Working;
        snapshot.session = Some(session.clone());
        snapshot.start = Some(receipt(
            "11111111-1111-4111-8111-111111111111".into(),
            "Existing owned work".into(),
            ActionKind::Start,
            InputTiming::Now,
            session,
            InputEvidence {
                frame_written: true,
                ..InputEvidence::default()
            },
        ));
    });
    port
}

fn mount(
    cx: &mut TestAppContext,
    port: Arc<FakePort>,
) -> (gpui_kit::AnyWindowHandle, Entity<ClaudeWorkView>) {
    cx.update(init);
    cx.update(|cx| {
        open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: Default::default(),
                    size: size(px(1100.), px(1000.)),
                })),
                ..WindowOptions::default()
            },
            cx,
            |window, cx| cx.new(|cx| ClaudeWorkView::new(port, window, cx)),
        )
        .unwrap()
    })
}

#[gpui_kit::test]
fn mount_is_inert_start_is_once_and_busy_direction_retains_a_revised_draft(
    cx: &mut TestAppContext,
) {
    let session = test_support::observed_session().unwrap();
    let port = FakePort::new();
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    assert!(port.calls.lock().unwrap().is_empty());
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        assert!(window.try_find("submit-codex-work").is_none());
        assert!(window.try_find("send").is_none());
        assert!(window.try_find("check-mcp-http").is_none());
        window.input("Write the original prose task", cx);
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("submit-claude-work").label(),
            Some("Start Claude task")
        );
        window.click("submit-claude-work", cx);
        window.click("submit-claude-work", cx);
    })
    .unwrap();
    let (start_id, start_text) = port.start_call();
    assert_eq!(port.calls.lock().unwrap().len(), 1);
    assert_eq!(start_id.len(), 36);
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Working;
        snapshot.session = Some(session.clone());
        snapshot.start = Some(receipt(
            start_id,
            start_text,
            ActionKind::Start,
            InputTiming::Now,
            &session,
            InputEvidence::default(),
        ));
        // Saved Start settles UI flight before echo, reply, result or completion.
        snapshot.last_submission = None;
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            assert!(view.flight.is_none());
            assert_eq!(view.editor.read(cx).value(), "");
            view.editor.update(cx, |state, cx| state.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input("Use a shorter ending", cx);
        window.click("claude-timing-tools", cx);
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("submit-claude-work").label(),
            Some("Send after running tools")
        );
        window.click("submit-claude-work", cx);
        window.click("submit-claude-work", cx);
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.press("end", cx);
        window.input("; keep this new draft", cx);
    })
    .unwrap();
    let (id, text, captured, timing) = port.direction_call();
    assert_eq!(timing, InputTiming::AfterTools);
    assert_eq!(captured.session_epoch(), session.session_epoch());
    assert_eq!(captured.session_id(), session.session_id());
    assert_eq!(port.calls.lock().unwrap().len(), 2);
    port.publish(|snapshot| {
        snapshot.inputs = vec![receipt(
            id,
            text,
            ActionKind::Direction,
            timing,
            &session,
            InputEvidence {
                user_replayed: true,
                ..InputEvidence::default()
            },
        )];
        snapshot.last_submission = Some(WorkSubmission {
            id: "unrelated".into(),
            kind: ActionKind::Lookup,
            saved: false,
            error: None,
        });
    });
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        assert!(view.flight.is_none());
        assert_eq!(
            view.editor.read(cx).value(),
            "Use a shorter ending; keep this new draft"
        );
        assert_eq!(view.snapshot.phase, WorkPhase::Working);
        assert!(!view.snapshot.inputs[0].evidence.reply_correlated);
        assert!(!view.snapshot.inputs[0].evidence.result_correlated);
    });
    port.publish(|snapshot| {
        snapshot.inputs[0].evidence.reply_correlated = true;
        snapshot.inputs[0].evidence.result_correlated = true;
    });
    cx.run_until_parked();
    assert_eq!(
        port.calls.lock().unwrap().len(),
        2,
        "late evidence never dispatches a draft"
    );
}

#[gpui_kit::test]
fn timing_is_captured_by_the_human_click_and_never_automatically_queued(cx: &mut TestAppContext) {
    let session = test_support::observed_session().unwrap();
    let port = working_port(&session);
    let (window, view) = mount(cx, port.clone());
    for (timing, button, label) in [
        (
            InputTiming::Now,
            "claude-timing-now",
            "Send direction now — may interrupt",
        ),
        (
            InputTiming::AfterTurn,
            "claude-timing-turn",
            "Send after this turn",
        ),
    ] {
        cx.update_window(window, |_, window, cx| {
            view.update(cx, |view, cx| {
                view.editor.update(cx, |state, cx| {
                    state.set_value("Explicit human direction", window, cx);
                    state.focus(window, cx);
                })
            });
            window.draw(cx).clear(cx);
            window.click(button, cx);
            window.draw(cx).clear(cx);
            assert_eq!(window.find("submit-claude-work").label(), Some(label));
            window.click("submit-claude-work", cx);
            window.click("claude-timing-tools", cx);
            window.click("submit-claude-work", cx);
        })
        .unwrap();
        let (id, text, _, captured) = port.direction_call();
        assert_eq!(captured, timing);
        port.publish(|snapshot| {
            snapshot.inputs.push(receipt(
                id,
                text,
                ActionKind::Direction,
                timing,
                &session,
                InputEvidence {
                    frame_written: true,
                    ..InputEvidence::default()
                },
            ))
        });
        cx.run_until_parked();
    }
    assert_eq!(port.calls.lock().unwrap().len(), 2);
}

#[gpui_kit::test]
fn receipt_must_match_text_timing_and_exact_owned_session_before_clearing(cx: &mut TestAppContext) {
    let session = test_support::observed_session().unwrap();
    let foreign = test_support::observed_session().unwrap();
    let port = working_port(&session);
    let (window, view) = mount(cx, port.clone());
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("The exact submitted direction", cx);
        window.draw(cx).clear(cx);
        window.click("submit-claude-work", cx);
    })
    .unwrap();
    let (id, text, _, timing) = port.direction_call();
    let valid = receipt(
        id.clone(),
        text.clone(),
        ActionKind::Direction,
        timing,
        &session,
        InputEvidence::default(),
    );
    for fault in 0..3 {
        let mut wrong = valid.clone();
        match fault {
            0 => wrong.operation.text = "A foreign payload".into(),
            1 => wrong.operation.timing = InputTiming::AfterTurn,
            _ => {
                wrong.operation.session_epoch = foreign.session_epoch().into();
                wrong.operation.session_id = foreign.session_id().into();
            }
        }
        port.publish(|snapshot| {
            snapshot.inputs = vec![wrong];
            snapshot.last_submission = Some(WorkSubmission {
                id: id.clone(),
                kind: ActionKind::Direction,
                saved: true,
                error: None,
            });
        });
        cx.run_until_parked();
        cx.update(|cx| {
            assert!(view.read(cx).flight.is_some());
            assert_eq!(view.read(cx).editor.read(cx).value(), text);
        });
    }
    port.publish(|snapshot| snapshot.inputs = vec![valid]);
    cx.run_until_parked();
    cx.update(|cx| {
        assert!(view.read(cx).flight.is_none());
        assert_eq!(view.read(cx).editor.read(cx).value(), "");
    });
    assert_eq!(port.calls.lock().unwrap().len(), 1);
}

#[gpui_kit::test]
fn editing_and_restoring_the_submitted_text_retains_the_new_draft(cx: &mut TestAppContext) {
    let session = test_support::observed_session().unwrap();
    let port = FakePort::new();
    let (window, view) = mount(cx, port.clone());
    let original = "Keep this exact text as a new draft";
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input(original, cx);
        window.draw(cx).clear(cx);
        window.click("submit-claude-work", cx);
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        let select_all = if cfg!(target_os = "macos") {
            "cmd-a"
        } else {
            "ctrl-a"
        };
        window.press(select_all, cx);
        window.input("A newly edited draft", cx);
        window.press(select_all, cx);
        window.input(original, cx);
    })
    .unwrap();
    cx.run_until_parked();
    let (id, text) = port.start_call();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Starting;
        snapshot.start = Some(receipt(
            id,
            text,
            ActionKind::Start,
            InputTiming::Now,
            &session,
            InputEvidence::default(),
        ));
    });
    cx.run_until_parked();
    cx.update(|cx| {
        assert!(view.read(cx).flight.is_none());
        assert_eq!(view.read(cx).editor.read(cx).value(), original);
    });
    assert_eq!(port.calls.lock().unwrap().len(), 1);
}

#[gpui_kit::test]
fn unknown_start_has_only_original_receipt_lookup_and_no_second_start(cx: &mut TestAppContext) {
    let session = test_support::observed_session().unwrap();
    let port = FakePort::new();
    let (window, view) = mount(cx, port.clone());
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("One original task", cx);
        window.draw(cx).clear(cx);
        window.click("submit-claude-work", cx);
    })
    .unwrap();
    let (id, text) = port.start_call();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::OutcomeUnknown;
        snapshot.start = Some(receipt(
            id.clone(),
            text,
            ActionKind::Start,
            InputTiming::Now,
            &session,
            InputEvidence {
                write_uncertain: true,
                ..InputEvidence::default()
            },
        ));
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            assert!(view.flight.is_none());
            assert_eq!(view.notice, Some(error_message(ClaudeError::Uncertain)));
            view.editor.update(cx, |state, cx| state.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input("Retain this next draft", cx);
        window.draw(cx).clear(cx);
        window.click("submit-claude-work", cx);
        window.click(("lookup-claude-input", 0_usize), cx);
    })
    .unwrap();
    let calls = port.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(matches!(&calls[1], Call::Lookup(original) if original == &id));
    drop(calls);
    port.publish(|snapshot| {
        snapshot.last_submission = Some(WorkSubmission {
            id,
            kind: ActionKind::Lookup,
            saved: false,
            error: None,
        })
    });
    cx.run_until_parked();
    assert_eq!(port.calls.lock().unwrap().len(), 2);
    cx.update(|cx| {
        assert_eq!(
            view.read(cx).editor.read(cx).value(),
            "Retain this next draft"
        )
    });
}

#[gpui_kit::test]
fn stale_or_busy_direction_keeps_text_and_end_input_is_explicit_once(cx: &mut TestAppContext) {
    let session = test_support::observed_session().unwrap();
    let port = working_port(&session);
    let (window, view) = mount(cx, port.clone());
    for error in [ClaudeError::StaleSession, ClaudeError::Busy] {
        *port.direction_error.lock().unwrap() = Some(error);
        cx.update_window(window, |_, window, cx| {
            view.update(cx, |view, cx| {
                view.editor.update(cx, |state, cx| {
                    state.set_value("Retain direction", window, cx);
                    state.focus(window, cx);
                })
            });
            window.draw(cx).clear(cx);
            window.click("submit-claude-work", cx);
            view.update(cx, |view, cx| {
                assert!(view.flight.is_none());
                assert_eq!(view.notice, Some(error_message(error)));
                view.editor.update(cx, |state, cx| state.focus(window, cx));
            });
            window.draw(cx).clear(cx);
            window.press("end", cx);
            window.input(" edited", cx);
        })
        .unwrap();
        cx.run_until_parked();
        cx.update(|cx| {
            assert_eq!(
                view.read(cx).editor.read(cx).value(),
                "Retain direction edited"
            )
        });
    }
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("end-claude-input", cx);
        window.click("end-claude-input", cx);
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.press("end", cx);
        window.input(" after input ended", cx);
        window.click("submit-claude-work", cx);
    })
    .unwrap();
    assert_eq!(port.calls.lock().unwrap().len(), 3);
    assert!(matches!(port.calls.lock().unwrap()[2], Call::EndInput));
    cx.update(|cx| {
        assert_eq!(
            view.read(cx).editor.read(cx).value(),
            "Retain direction edited after input ended"
        );
        assert!(view.read(cx).notice.unwrap().contains("does not guarantee"));
        assert!(!view.read(cx).snapshot.lifecycle.child_exited);
    });
}

#[gpui_kit::test]
fn dropping_the_window_does_not_start_a_child_or_end_input(cx: &mut TestAppContext) {
    let port = FakePort::new();
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    cx.update_window(window, |_, window, _| window.remove_window())
        .unwrap();
    drop(view);
    cx.run_until_parked();
    assert!(port.calls.lock().unwrap().is_empty());
}

#[test]
fn echo_reply_and_result_copy_never_claims_model_awareness_or_application() {
    let lines = evidence_lines(
        &InputEvidence {
            user_replayed: true,
            reply_correlated: true,
            result_correlated: true,
            ..InputEvidence::default()
        },
        false,
    );
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("harness") && lines[0].contains("unverified"));
    assert!(lines[1].contains("attributed") && lines[1].contains("unverified"));
    assert!(lines[2].contains("does not prove"));
    assert!(
        evidence_lines(
            &InputEvidence {
                not_dispatched: true,
                ..InputEvidence::default()
            },
            false
        )[0]
        .contains("startup may already have run")
    );
}

/// Actual production owner, wire observer and durable journal, with only the
/// child factory replaced by a synthetic duplex peer. No Claude binary runs.
#[gpui_kit::test]
fn native_clicks_cross_the_real_owner_wire_and_journal_before_the_turn_ends(
    cx: &mut TestAppContext,
) {
    // This fixture intentionally crosses the real owner thread and duplex IO.
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
        .join("claude-inputs");
    let (port, mut peer) = test_support::open_fixture_service(&journal).unwrap();
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: Default::default(),
                    size: size(px(1100.), px(1000.)),
                })),
                ..WindowOptions::default()
            },
            cx,
            |window, cx| cx.new(|cx| ClaudeWorkView::new(port.clone(), window, cx)),
        )
        .unwrap()
    });
    cx.run_until_parked();
    assert!(port.subscribe().borrow().start.is_none());
    runtime.block_on(async {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), peer.io.read_u8())
                .await
                .is_err(),
            "mount emits no protocol request"
        );
    });
    let original = "Write prose literally: /not-a-command @not-a-file";
    let mut submitted_id = String::new();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input(original, cx);
        window.draw(cx).clear(cx);
        window.click("submit-claude-work", cx);
        submitted_id = view
            .read(cx)
            .flight
            .as_ref()
            .expect("human Start flight")
            .id
            .clone();
        window.click("submit-claude-work", cx);
    })
    .unwrap();
    let initialize = runtime.block_on(read_peer_frame(&mut peer.io));
    assert_eq!(initialize["type"], "control_request");
    assert_eq!(initialize["request"]["subtype"], "initialize");
    // The actual first wire effect and coalesced watch publication can race.
    // Check the exact original Saved bytes now, before waiting for any watch
    // update; publication delivery is not the consume-before-effect proof.
    let bytes = std::fs::read(journal.join(format!("{submitted_id}.jsonl")))
        .expect("original Saved record exists when initialize is observed");
    let first = bytes.split(|byte| *byte == b'\n').next().unwrap();
    let saved_line: serde_json::Value = serde_json::from_slice(first).unwrap();
    assert_eq!(saved_line["type"], "saved");
    assert_eq!(saved_line["operation"]["id"], submitted_id);
    assert_eq!(saved_line["operation"]["text"], original);
    assert_eq!(
        saved_line["operation"]["startup"]["policy"],
        "managed_policy_prose_only"
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
    runtime.block_on(send_peer_frame(&mut peer.io, json!({"type":"control_response","response":{
        "subtype":"success","request_id":initialize["request_id"],"response":{"claude_code_version":"2.1.314"}
    }})));
    let initial = runtime.block_on(read_peer_frame(&mut peer.io));
    assert_eq!(initial["type"], "user");
    assert_eq!(
        initial["message"]["content"],
        json!([{ "type": "text", "text": original }])
    );
    assert_eq!(initial["client_composed"], true);
    assert_eq!(initial["origin"]["kind"], "human");
    assert_eq!(initial["uuid"], saved.operation.id);
    let session_id = initial["session_id"].as_str().unwrap().to_owned();
    let cwd = peer.workdir.to_str().unwrap().to_owned();
    runtime.block_on(send_peer_frame(&mut peer.io, json!({"type":"system","subtype":"init",
        "session_id":session_id,"claude_code_version":"2.1.314","cwd":cwd,"tools":[],"permissionMode":"default"
    })));
    runtime.block_on(send_peer_frame(&mut peer.io, json!({"type":"assistant","uuid":new_operation_id().unwrap(),"session_id":session_id,
        "parent_tool_use_id":null,"user_message_uuid":initial["uuid"],
        "message":{"id":"msg-initial-fixture","type":"message","role":"assistant","content":[{"type":"text","text":"Original prose is still being written."}]}
    })));
    wait_snapshot(&runtime, &port, |snapshot| {
        snapshot.phase == WorkPhase::Working
            && snapshot.session.is_some()
            && snapshot.start.as_ref().is_some_and(|start| {
                start.operation.id == saved.operation.id && start.evidence.frame_written
            })
            && snapshot.last_submission.as_ref().is_some_and(|submission| {
                submission.id == saved.operation.id
                    && submission.kind == ActionKind::Start
                    && submission.saved
                    && submission.error.is_none()
            })
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            assert!(view.flight.is_none());
            assert_eq!(view.editor.read(cx).value(), "");
            assert!(
                !view
                    .snapshot
                    .start
                    .as_ref()
                    .unwrap()
                    .evidence
                    .result_correlated
            );
            view.editor.update(cx, |state, cx| state.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input("Change the ending while this response is busy", cx);
        window.click("claude-timing-now", cx);
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("submit-claude-work").label(),
            Some("Send direction now — may interrupt")
        );
        window.click("submit-claude-work", cx);
        window.click("submit-claude-work", cx);
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.press("end", cx);
        window.input("; retain this edited draft", cx);
    })
    .unwrap();
    let direction = runtime.block_on(read_peer_frame(&mut peer.io));
    assert_eq!(direction["type"], "user");
    assert_eq!(direction["session_id"], session_id);
    assert_eq!(direction["priority"], "now");
    assert_eq!(direction["origin"]["kind"], "human");
    assert_eq!(direction["client_composed"], true);
    assert_ne!(direction["uuid"], initial["uuid"]);
    assert_eq!(
        direction["message"]["content"],
        json!([{ "type": "text", "text": "Change the ending while this response is busy" }])
    );
    let direction_id = direction["uuid"].as_str().unwrap().to_owned();
    assert_eq!(direction_id.len(), 36);
    assert!(journal.join(format!("{direction_id}.jsonl")).is_file());
    runtime.block_on(send_peer_frame(
        &mut peer.io,
        json!({"type":"user","isReplay":true,
            "uuid":direction["uuid"],"session_id":session_id,"parent_tool_use_id":null,
            "message":{"role":"user","content":direction["message"]["content"]}
        }),
    ));
    let echoed = wait_snapshot(&runtime, &port, |snapshot| {
        snapshot
            .inputs
            .iter()
            .any(|input| input.operation.id == direction_id && input.evidence.user_replayed)
    });
    let input = echoed
        .inputs
        .iter()
        .find(|input| input.operation.id == direction_id)
        .unwrap();
    assert!(!input.evidence.reply_correlated);
    assert!(!input.evidence.result_correlated);
    cx.run_until_parked();
    cx.update(|cx| {
        assert_eq!(
            view.read(cx).editor.read(cx).value(),
            "Change the ending while this response is busy; retain this edited draft"
        )
    });
    runtime.block_on(send_peer_frame(&mut peer.io, json!({"type":"assistant","uuid":new_operation_id().unwrap(),"session_id":session_id,
        "parent_tool_use_id":null,"user_message_uuid":direction["uuid"],
        "message":{"id":"msg-direction-fixture","type":"message","role":"assistant","content":[{"type":"text","text":"The new ending is now in this synthetic reply."}]}
    })));
    wait_snapshot(&runtime, &port, |snapshot| {
        snapshot
            .inputs
            .iter()
            .any(|input| input.operation.id == direction_id && input.evidence.reply_correlated)
    });
    runtime.block_on(send_peer_frame(
        &mut peer.io,
        json!({"type":"result","uuid":new_operation_id().unwrap(),"subtype":"success","session_id":session_id,
            "user_message_uuids":[initial["uuid"],direction["uuid"]],"is_error":false,"result":"Synthetic final prose"
        }),
    ));
    let finished = wait_snapshot(&runtime, &port, |snapshot| {
        snapshot
            .inputs
            .iter()
            .any(|input| input.operation.id == direction_id && input.evidence.result_correlated)
    });
    assert_eq!(
        finished.inputs.len(),
        1,
        "double clicks emitted one direction only"
    );
    assert!(finished.start.as_ref().unwrap().evidence.result_correlated);
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click(("lookup-claude-input", 1_usize), cx);
        window.click("end-claude-input", cx);
        window.click("end-claude-input", cx);
    })
    .unwrap();
    runtime.block_on(async {
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(3), peer.io.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof,
            "lookup emits no frame and EndInput closes stdin"
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
