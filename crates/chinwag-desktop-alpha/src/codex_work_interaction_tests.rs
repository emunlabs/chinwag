use super::*;
use chinwag_codex_steer::{
    CodexSteerConnection, ConnectionOwner, ObservedActiveTurn, OwnerControlScope, Receipt,
    WorkStartReceipt, WorkSubmission,
};
use gpui_kit::{
    Bounds, TestAppContext, WindowBounds, WindowOptions, init, open_window, px, size,
    test::TestWindowExt,
};
use serde_json::json;
use std::{sync::Mutex, time::Duration};
use tokio::{io::AsyncWriteExt, sync::watch};

enum Call {
    Start {
        id: String,
        text: String,
    },
    Steer {
        id: String,
        text: String,
        target: ObservedActiveTurn,
    },
    Lookup(String),
    Close,
}

struct FakePort {
    sender: watch::Sender<WorkSnapshot>,
    calls: Mutex<Vec<Call>>,
    steer_error: Mutex<Option<SteerError>>,
}

impl FakePort {
    fn new() -> Arc<Self> {
        let (sender, _) = watch::channel(WorkSnapshot::ready("Owned fixture folder".into()));
        Arc::new(Self {
            sender,
            calls: Mutex::new(Vec::new()),
            steer_error: Mutex::new(None),
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
            .expect("explicit Start call")
    }

    fn steer_call(&self) -> (String, String, ObservedActiveTurn) {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .find_map(|call| match call {
                Call::Steer { id, text, target } => {
                    Some((id.clone(), text.clone(), target.clone()))
                }
                _ => None,
            })
            .expect("explicit Steer call")
    }
}

impl HumanWorkPort for FakePort {
    fn subscribe(&self) -> watch::Receiver<WorkSnapshot> {
        self.sender.subscribe()
    }
    fn start(&self, id: &str, text: &str) -> chinwag_codex_steer::Result<()> {
        self.calls.lock().unwrap().push(Call::Start {
            id: id.into(),
            text: text.into(),
        });
        Ok(())
    }
    fn steer(
        &self,
        target: &ObservedActiveTurn,
        id: &str,
        text: &str,
    ) -> chinwag_codex_steer::Result<()> {
        self.calls.lock().unwrap().push(Call::Steer {
            id: id.into(),
            text: text.into(),
            target: target.clone(),
        });
        match self.steer_error.lock().unwrap().take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn lookup(&self, id: &str) -> chinwag_codex_steer::Result<()> {
        self.calls.lock().unwrap().push(Call::Lookup(id.into()));
        Ok(())
    }
    fn close(&self) -> chinwag_codex_steer::Result<()> {
        self.calls.lock().unwrap().push(Call::Close);
        Ok(())
    }
}

/// A real opaque handle is minted by the public core from a synthetic stream.
/// No child process, server, model, journal or private-field constructor is used.
struct TargetFixture {
    runtime: tokio::runtime::Runtime,
    connection: CodexSteerConnection,
    owner: ConnectionOwner,
    _peer: tokio::io::DuplexStream,
    target: ObservedActiveTurn,
}

impl TargetFixture {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_time()
            .build()
            .unwrap();
        let (connection, owner, peer, target) = runtime.block_on(async {
            let (bridge, mut peer) = tokio::io::duplex(8192);
            let (reader, writer) = tokio::io::split(bridge);
            let scope = OwnerControlScope::new("human-owned UI fixture".into(), "ui-owned-thread".into(), Duration::from_secs(60)).unwrap();
            let (connection, owner) = CodexSteerConnection::from_established_io(scope, reader, writer).unwrap();
            let mut bytes = serde_json::to_vec(&json!({"method":"turn/started","params":{
                "threadId":"ui-owned-thread","turn":{"id":"ui-active-turn","items":[],"status":"inProgress"}
            }})).unwrap();
            bytes.push(b'\n');
            peer.write_all(&bytes).await.unwrap();
            let target = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Some(target) = connection.active_turn() { break target; }
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            (connection, owner, peer, target)
        });
        Self {
            runtime,
            connection,
            owner,
            _peer: peer,
            target,
        }
    }

    fn receipt(
        &self,
        id: &str,
        text: &str,
        target: &ObservedActiveTurn,
        evidence: Evidence,
    ) -> Receipt {
        let grant = self.owner.human_grant().unwrap();
        let prepared = self.connection.prepare(&grant, target, id, text).unwrap();
        Receipt {
            operation: prepared.record().clone(),
            evidence,
            recovered_after_restart: false,
            persistence_failed: false,
        }
    }
}

impl Drop for TargetFixture {
    fn drop(&mut self) {
        self.runtime.block_on(self.connection.shutdown()).unwrap();
    }
}

fn start_receipt(id: String, text: String) -> WorkStartReceipt {
    WorkStartReceipt {
        id,
        text,
        connected: true,
        initialized: true,
        bootstrap_uncertain: true,
        thread_id: Some("ui-owned-thread".into()),
        accepted_turn_id: None,
        evidence: Evidence {
            frame_written: true,
            ..Evidence::default()
        },
        recovered_after_restart: false,
        persistence_failed: false,
    }
}

fn mount(
    cx: &mut TestAppContext,
    port: Arc<FakePort>,
) -> (gpui_kit::AnyWindowHandle, Entity<CodexWorkView>) {
    cx.update(init);
    cx.update(|cx| {
        open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: Default::default(),
                    size: size(px(1050.), px(850.)),
                })),
                ..WindowOptions::default()
            },
            cx,
            |window, cx| cx.new(|cx| CodexWorkView::new(port, window, cx)),
        )
        .unwrap()
    })
}

#[gpui_kit::test]
fn start_once_then_steer_before_initial_ack_or_completion_preserves_a_revised_draft(
    cx: &mut TestAppContext,
) {
    let fixture = TargetFixture::new();
    let port = FakePort::new();
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    assert!(port.calls.lock().unwrap().is_empty(), "mount must be inert");
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        assert!(
            window.try_find("send").is_none(),
            "dedicated view has no bus composer"
        );
        assert!(window.try_find("check-mcp-http").is_none());
        window.input("Build the requested artifact", cx);
        window.draw(cx).clear(cx);
        assert_eq!(window.find("submit-codex-work").label(), Some("Start task"));
        window.click("submit-codex-work", cx);
        window.click("submit-codex-work", cx);
    })
    .unwrap();
    let (start_id, start_text) = port.start_call();
    assert_eq!(port.calls.lock().unwrap().len(), 1);
    assert_eq!(start_text, "Build the requested artifact");
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::StartUnknown;
        snapshot.target = Some(fixture.target.clone());
        snapshot.start = Some(start_receipt(start_id, start_text));
        // No turn/start acknowledgment or last_submission completion is supplied.
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            assert!(view.flight.is_none());
            assert_eq!(view.editor.read(cx).value(), "");
            assert!(
                view.snapshot
                    .start
                    .as_ref()
                    .unwrap()
                    .accepted_turn_id
                    .is_none()
            );
            view.editor.update(cx, |state, cx| state.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input("Use the existing Rust module", cx);
        window.draw(cx).clear(cx);
        assert_eq!(
            window.find("submit-codex-work").label(),
            Some("Steer current turn")
        );
        window.click("submit-codex-work", cx);
        window.click("submit-codex-work", cx);
        view.update(cx, |view, cx| {
            assert!(view.flight.is_some());
            view.editor.update(cx, |state, cx| state.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input("; keep this next draft", cx);
    })
    .unwrap();
    let (id, text, captured) = port.steer_call();
    assert_eq!(text, "Use the existing Rust module");
    assert_eq!(captured.thread_id(), fixture.target.thread_id());
    assert_eq!(captured.turn_id(), fixture.target.turn_id());
    let receipt = fixture.receipt(
        &id,
        &text,
        &captured,
        Evidence {
            harness_recorded: true,
            ..Evidence::default()
        },
    );
    assert_eq!(
        port.calls.lock().unwrap().len(),
        2,
        "no duplicate or queued action"
    );
    port.publish(|snapshot| {
        snapshot.steers = vec![receipt];
        // A watch sample can coalesce the original report with unrelated
        // progress. The retained matching receipt must still release flight.
        snapshot.last_submission = Some(WorkSubmission {
            id: "unrelated-lookup-0001".into(),
            kind: WorkActionKind::Lookup,
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
            "Use the existing Rust module; keep this next draft"
        );
        assert!(view.snapshot.target.is_some(), "turn has not completed");
        assert!(view.snapshot.steers[0].evidence.harness_recorded);
        assert!(!view.snapshot.steers[0].evidence.core_accepted);
        assert!(
            evidence_lines(view.snapshot.steers[0].evidence, false, EvidenceLane::Steer)
                .iter()
                .any(|line| line.contains("Model awareness") && line.contains("unverified"))
        );
    });
    port.publish(|snapshot| {
        snapshot.steers[0].evidence.core_accepted = true;
    });
    cx.run_until_parked();
    assert_eq!(
        port.calls.lock().unwrap().len(),
        2,
        "late evidence must not dispatch draft"
    );
}

#[gpui_kit::test]
fn stale_or_busy_steer_keeps_editable_text_without_automatic_retarget_or_queue(
    cx: &mut TestAppContext,
) {
    let fixture = TargetFixture::new();
    let port = FakePort::new();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Working;
        snapshot.target = Some(fixture.target.clone());
        snapshot.start = Some(start_receipt(
            "work-existing-0001".into(),
            "Existing owned work".into(),
        ));
    });
    let (window, view) = mount(cx, port.clone());
    for error in [SteerError::StaleTarget, SteerError::Busy] {
        *port.steer_error.lock().unwrap() = Some(error);
        cx.update_window(window, |_, window, cx| {
            view.update(cx, |view, cx| {
                view.editor.update(cx, |state, cx| {
                    state.set_value("Keep my revised direction", window, cx);
                    state.focus(window, cx);
                });
            });
            window.draw(cx).clear(cx);
            window.click("submit-codex-work", cx);
            view.update(cx, |view, cx| {
                assert!(view.flight.is_none());
                assert_eq!(view.editor.read(cx).value(), "Keep my revised direction");
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
                "Keep my revised direction edited"
            )
        });
    }
    assert_eq!(
        port.calls.lock().unwrap().len(),
        2,
        "only the two explicit clicks reached the port"
    );
}

#[gpui_kit::test]
fn unknown_original_steer_uses_lookup_only_and_no_active_turn_cannot_dispatch(
    cx: &mut TestAppContext,
) {
    let fixture = TargetFixture::new();
    let port = FakePort::new();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Working;
        snapshot.target = Some(fixture.target.clone());
        snapshot.start = Some(start_receipt(
            "work-existing-0002".into(),
            "Existing owned work".into(),
        ));
    });
    let (window, view) = mount(cx, port.clone());
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("The explicitly submitted direction", cx);
        window.draw(cx).clear(cx);
        window.click("submit-codex-work", cx);
    })
    .unwrap();
    let (id, text, target) = port.steer_call();
    let receipt = fixture.receipt(
        &id,
        &text,
        &target,
        Evidence {
            write_uncertain: true,
            ..Evidence::default()
        },
    );
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::StartUnknown;
        snapshot.target = None;
        snapshot.steers = vec![receipt];
        snapshot.last_submission = Some(WorkSubmission {
            id: id.clone(),
            kind: WorkActionKind::Steer,
            saved: true,
            error: Some(SteerError::Uncertain),
        });
    });
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            assert!(view.flight.is_none());
            assert!(view.notice.unwrap().contains("Check its receipt"));
            view.editor.update(cx, |state, cx| state.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input("New draft without an active turn", cx);
        window.draw(cx).clear(cx);
        window.click("submit-codex-work", cx);
        window.click(("lookup-codex-steer", 0_usize), cx);
    })
    .unwrap();
    let calls = port.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(matches!(&calls[0], Call::Steer { .. }));
    assert!(matches!(&calls[1], Call::Lookup(original) if original == &id));
    drop(calls);
    port.publish(|snapshot| {
        snapshot.last_submission = Some(WorkSubmission {
            id,
            kind: WorkActionKind::Lookup,
            saved: false,
            error: None,
        });
    });
    cx.run_until_parked();
    assert_eq!(port.calls.lock().unwrap().len(), 2);
    cx.update(|cx| {
        assert_eq!(
            view.read(cx).editor.read(cx).value(),
            "New draft without an active turn"
        )
    });
}

#[gpui_kit::test]
fn finished_work_and_explicit_close_keep_the_editor_available_without_starting_again(
    cx: &mut TestAppContext,
) {
    let port = FakePort::new();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Finished;
        snapshot.start = Some(start_receipt(
            "work-existing-0003".into(),
            "Finished work".into(),
        ));
    });
    let (window, view) = mount(cx, port.clone());
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("Retain this draft after the turn ends", cx);
        window.draw(cx).clear(cx);
        assert_eq!(window.find("submit-codex-work").label(), Some("Turn ended"));
        window.click("submit-codex-work", cx);
        window.click("close-codex-control", cx);
        window.click("close-codex-control", cx);
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("; still editable", cx);
    })
    .unwrap();
    assert_eq!(port.calls.lock().unwrap().len(), 1);
    assert!(matches!(port.calls.lock().unwrap()[0], Call::Close));
    cx.update(|cx| {
        let view = view.read(cx);
        assert!(view.close_requested);
        assert_eq!(
            view.notice,
            Some("Control connection closing. Work may continue.")
        );
        assert_eq!(
            view.editor.read(cx).value(),
            "Retain this draft after the turn ends; still editable"
        );
    });
}

#[gpui_kit::test]
fn dropping_the_window_does_not_issue_a_close_or_start_command(cx: &mut TestAppContext) {
    let port = FakePort::new();
    let (window, view) = mount(cx, port.clone());
    cx.run_until_parked();
    cx.update_window(window, |_, window, _| window.remove_window())
        .unwrap();
    drop(view);
    cx.run_until_parked();
    assert!(port.calls.lock().unwrap().is_empty());
}

#[gpui_kit::test]
fn same_id_different_start_text_does_not_settle_or_clear_the_original_draft(
    cx: &mut TestAppContext,
) {
    let port = FakePort::new();
    let (window, view) = mount(cx, port.clone());
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("The exact task I submitted", cx);
        window.draw(cx).clear(cx);
        window.click("submit-codex-work", cx);
    })
    .unwrap();
    let (id, text) = port.start_call();
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Starting;
        snapshot.start = Some(start_receipt(
            id.clone(),
            "Different task under the same ID".into(),
        ));
        snapshot.last_submission = None;
    });
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        assert!(
            view.flight.is_some(),
            "foreign payload cannot settle this submission"
        );
        assert_eq!(view.editor.read(cx).value(), text);
    });
    port.publish(|snapshot| {
        snapshot.start = Some(start_receipt(id, text));
    });
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        assert!(view.flight.is_none());
        assert_eq!(view.editor.read(cx).value(), "");
    });
    assert_eq!(
        port.calls.lock().unwrap().len(),
        1,
        "receipt changes never dispatch again"
    );
}

#[gpui_kit::test]
fn edits_after_click_remain_a_new_draft_even_when_restored_to_submitted_text(
    cx: &mut TestAppContext,
) {
    let port = FakePort::new();
    let (window, view) = mount(cx, port.clone());
    let original = "The original task text";
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor.update(cx, |state, cx| state.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input(original, cx);
        window.draw(cx).clear(cx);
        window.click("submit-codex-work", cx);
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
        window.input("A different new draft", cx);
        window.press(select_all, cx);
        window.input(original, cx);
    })
    .unwrap();
    cx.run_until_parked();
    let (id, text) = port.start_call();
    assert_eq!(text, original, "click captures the original text only");
    port.publish(|snapshot| {
        snapshot.phase = WorkPhase::Starting;
        snapshot.start = Some(start_receipt(id, text));
    });
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        assert!(view.flight.is_none());
        assert_eq!(
            view.editor.read(cx).value(),
            original,
            "newly re-entered matching text must not be cleared"
        );
    });
    assert_eq!(port.calls.lock().unwrap().len(), 1);
}

#[test]
fn initial_turn_not_dispatched_copy_preserves_possible_bootstrap_effects() {
    let evidence = Evidence {
        not_dispatched: true,
        ..Evidence::default()
    };
    let initial = evidence_lines(evidence, false, EvidenceLane::InitialTurn);
    assert_eq!(
        initial,
        vec!["Initial turn request not dispatched; bootstrap may already have run."]
    );
    let steer = evidence_lines(evidence, false, EvidenceLane::Steer);
    assert_eq!(steer, vec!["Steer request not dispatched."]);
    for lines in [initial, steer] {
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("No request frame began"))
        );
    }
}
