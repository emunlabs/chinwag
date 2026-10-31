use super::*;
use chinwag_team_direction::{Member, ReportKind, SubmissionReport};
use gpui_kit::{
    Bounds, MouseButton, TestAppContext, WindowBounds, WindowOptions, init, open_window, px, size,
    test::{TestEventExt, TestQueryExt, TestWindowExt},
};
use std::os::unix::fs::PermissionsExt as _;
use tokio::io::DuplexStream;

struct ActualTeam {
    _directory: tempfile::TempDir,
    host: Arc<DesktopTeamHost>,
    claude: Arc<dyn chinwag_claude_control::HumanWorkPort>,
    gemini: Arc<dyn chinwag_gemini_control::HumanWorkPort>,
    claude_peer: chinwag_claude_control::test_support::FixturePeer,
    gemini_peer: chinwag_gemini_control::test_support::FixturePeer,
}
fn actual_team() -> ActualTeam {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.path().canonicalize().unwrap();
    let (claude, claude_peer) =
        chinwag_claude_control::test_support::open_fixture_service(&root.join("claude-native"))
            .unwrap();
    let (gemini, gemini_peer) =
        chinwag_gemini_control::test_support::open_fixture_service(&root.join("gemini-native"))
            .unwrap();
    let core = TeamHost::from_ports(
        &root.join("team-state"),
        vec![
            Member {
                id: "claude-review".into(),
                label: "Owned work".into(),
                port: HeldWorkPort::Claude(claude.clone()),
            },
            Member {
                id: "gemini-research".into(),
                label: "Owned work".into(),
                port: HeldWorkPort::Gemini(gemini.clone()),
            },
        ],
    )
    .unwrap();
    ActualTeam {
        _directory: directory,
        host: DesktopTeamHost::new(core),
        claude,
        gemini,
        claude_peer,
        gemini_peer,
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()
        .unwrap()
}
fn wait_team(
    runtime: &tokio::runtime::Runtime,
    host: &Arc<DesktopTeamHost>,
    predicate: impl Fn(&TeamSnapshot) -> bool,
) -> TeamSnapshot {
    let mut receiver = host.core.subscribe();
    runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let snapshot = receiver.borrow_and_update().clone();
                    if predicate(&snapshot) {
                        return snapshot;
                    }
                    receiver
                        .changed()
                        .await
                        .expect("retained team owner updates");
                }
            })
            .await
        })
        .expect("bounded actual team update")
}
fn mount(
    cx: &mut TestAppContext,
    host: Arc<DesktopTeamHost>,
) -> (gpui_kit::AnyWindowHandle, Entity<TeamWorkView>) {
    cx.update(init);
    cx.update(|cx| {
        open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds {
                    origin: Default::default(),
                    size: size(px(1280.), px(1100.)),
                })),
                ..WindowOptions::default()
            },
            cx,
            |window, cx| cx.new(|cx| TeamWorkView::new(host, window, cx)),
        )
        .unwrap()
    })
}
async fn read_frame(peer: &mut DuplexStream) -> serde_json::Value {
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
    .expect("bounded actual native request")
}
async fn send_frame(peer: &mut DuplexStream, value: serde_json::Value) {
    use tokio::io::AsyncWriteExt as _;
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(3), peer.write_all(&bytes))
        .await
        .unwrap()
        .unwrap();
}
fn no_frame(runtime: &tokio::runtime::Runtime, peer: &mut DuplexStream) {
    use tokio::io::AsyncReadExt as _;
    runtime.block_on(async {
        assert!(
            tokio::time::timeout(Duration::from_millis(20), peer.read_u8())
                .await
                .is_err(),
            "no hidden native action"
        );
    });
}
fn type_native(
    cx: &mut TestAppContext,
    window: gpui_kit::AnyWindowHandle,
    label: &str,
    text: &str,
    button: &'static str,
) {
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        let position = window.find_by_label(label).bounds().center();
        window.pointer_move(position, None, cx);
        window.pointer_down(position, MouseButton::Left, cx);
        window.pointer_up(position, MouseButton::Left, cx);
        window.input(text, cx);
        window.draw(cx).clear(cx);
        window.click(button, cx);
        window.click(button, cx);
    })
    .unwrap();
    cx.run_until_parked();
}
fn open_member(
    cx: &mut TestAppContext,
    window: gpui_kit::AnyWindowHandle,
    index: usize,
) -> gpui_kit::AnyWindowHandle {
    let before = cx.update(|cx| {
        cx.windows()
            .iter()
            .map(|handle| handle.window_id())
            .collect::<Vec<_>>()
    });
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click(("open-team-member", index), cx);
    })
    .unwrap();
    cx.run_until_parked();
    cx.update(|cx| {
        cx.windows()
            .into_iter()
            .find(|handle| !before.contains(&handle.window_id()))
            .expect("native work window opens")
    })
}

#[test]
fn restoring_equal_human_values_is_still_a_new_revision() {
    let mut state = Presentation::default();
    state.draft = "Keep this direction".into();
    state.consumed_revision = Some(state.revision);
    assert!(state.consumed());
    state.selected.insert("codex".into());
    state.edit();
    state.selected.remove("codex");
    state.edit();
    assert!(
        !state.consumed(),
        "restoring the selected set is still an explicit new human revision"
    );
    state.consumed_revision = Some(state.revision);
    state.draft = "Different direction".into();
    state.edit();
    state.draft = "Keep this direction".into();
    state.edit();
    assert!(
        !state.consumed(),
        "same-text restoration must preserve the new draft"
    );
}

#[test]
fn flight_retirement_never_rearms_an_unchanged_consumed_revision() {
    let mut state = Presentation::default();
    state.draft = "One explicit direction".into();
    state.consumed_revision = Some(state.revision);
    state.flight = Some(Flight::Submitted("parent-original".into()));
    state.flight = None;
    assert!(state.consumed());
    state.edit();
    assert!(
        !state.consumed(),
        "only a new explicit human revision rearms it"
    );
}

#[gpui_kit::test]
fn show_team_raises_the_exact_owned_window_without_opening_another_owner(cx: &mut TestAppContext) {
    cx.executor().allow_parking();
    let mut actual = actual_team();
    let rt = runtime();
    wait_team(&rt, &actual.host, |snapshot| snapshot.members.len() == 2);
    let (team_window, team_view) = mount(cx, actual.host.clone());
    cx.run_until_parked();
    let member_window = open_member(cx, team_window, 0);
    cx.update_window(member_window, |_, window, _| window.activate_window())
        .unwrap();
    cx.run_until_parked();
    assert_eq!(
        cx.update(|cx| cx.active_window().map(|handle| handle.window_id())),
        Some(member_window.window_id())
    );
    let count = cx.update(|cx| cx.windows().len());
    cx.update(|cx| crate::open_team_work_window(actual.host.clone(), cx));
    cx.run_until_parked();
    assert_eq!(
        cx.update(|cx| cx.active_window().map(|handle| handle.window_id())),
        Some(team_window.window_id())
    );
    assert_eq!(
        cx.update(|cx| cx.windows().len()),
        count,
        "Show focuses the existing exact Team window"
    );
    // A stale retained handle is checked against the app's owned window table,
    // not treated as proof the old window still exists.
    cx.update_window(team_window, |_, window, _| window.remove_window())
        .unwrap();
    cx.update(|cx| crate::open_team_work_window(actual.host.clone(), cx));
    cx.run_until_parked();
    let reopened = actual
        .host
        .window
        .lock()
        .unwrap()
        .expect("owned Team window reopened");
    assert_ne!(reopened.window_id(), team_window.window_id());
    drop(team_view);
    assert_eq!(
        *actual.host.window.lock().unwrap(),
        Some(reopened),
        "dropping the old view cannot clear a newer owned handle"
    );
    no_frame(&rt, &mut actual.claude_peer.io);
    no_frame(&rt, &mut actual.gemini_peer.io);
    assert!(actual.host.core.subscribe().borrow().directions.is_empty());
    actual.host.close_controls();
    actual.claude_peer.finish(0);
    actual.gemini_peer.finish(0);
    for window in [reopened, member_window] {
        cx.update_window(window, |_, window, _| window.remove_window())
            .unwrap();
    }
}

#[gpui_kit::test]
fn retained_presentation_survives_window_close_without_start_or_control(cx: &mut TestAppContext) {
    cx.executor().allow_parking();
    let mut actual = actual_team();
    let rt = runtime();
    wait_team(&rt, &actual.host, |snapshot| snapshot.members.len() == 2);
    let (window, view) = mount(cx, actual.host.clone());
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor
                .update(cx, |editor, cx| editor.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input("Keep this team draft", cx);
        window.click(("team-member", 0_usize), cx);
    })
    .unwrap();
    cx.run_until_parked();
    no_frame(&rt, &mut actual.claude_peer.io);
    no_frame(&rt, &mut actual.gemini_peer.io);
    assert!(actual.host.core.subscribe().borrow().directions.is_empty());
    cx.update_window(window, |_, window, _| window.remove_window())
        .unwrap();
    drop(view);
    cx.run_until_parked();
    let (reopened, reopened_view) = mount(cx, actual.host.clone());
    cx.run_until_parked();
    cx.update(|cx| {
        let view = reopened_view.read(cx);
        assert_eq!(view.editor.read(cx).value(), "Keep this team draft");
        assert_eq!(view.selection().0.len(), 1);
    });
    no_frame(&rt, &mut actual.claude_peer.io);
    no_frame(&rt, &mut actual.gemini_peer.io);
    actual.host.close_controls();
    actual.claude_peer.finish(0);
    actual.gemini_peer.finish(0);
    cx.update_window(reopened, |_, window, _| window.remove_window())
        .unwrap();
    drop(reopened_view);
}

#[gpui_kit::test]
fn lookup_completion_requires_same_parent_kind_and_at_least_requested_serial(
    cx: &mut TestAppContext,
) {
    cx.executor().allow_parking();
    let actual = actual_team();
    let rt = runtime();
    wait_team(&rt, &actual.host, |snapshot| snapshot.members.len() == 2);
    let (window, view) = mount(cx, actual.host.clone());
    cx.run_until_parked();
    actual.host.presentation.lock().unwrap().lookup_pending = Some(("parent-original".into(), 7));
    for (reported_id, kind, serial, retired, settled) in [
        ("other-parent", ReportKind::Lookup, Some(7), true, false),
        ("parent-original", ReportKind::Submit, None, true, false),
        ("parent-original", ReportKind::Lookup, Some(6), true, false),
        ("parent-original", ReportKind::Lookup, Some(7), false, false),
        ("parent-original", ReportKind::Lookup, Some(7), true, true),
    ] {
        cx.update_window(window, |_, window, cx| {
            view.update(cx, |view, cx| {
                let mut snapshot = view.snapshot.clone();
                snapshot.revision = snapshot.revision.saturating_add(100);
                snapshot.lookups.insert(
                    "parent-original".into(),
                    SubmissionReport {
                        id: reported_id.into(),
                        kind,
                        lookup_serial: serial,
                        admitted: true,
                        stage_retired: retired,
                        error: None,
                    },
                );
                view.apply_snapshot(snapshot, window, cx);
            })
        })
        .unwrap();
        assert_eq!(
            actual
                .host
                .presentation
                .lock()
                .unwrap()
                .lookup_pending
                .is_none(),
            settled
        );
    }
    assert!(
        actual
            .host
            .presentation
            .lock()
            .unwrap()
            .notice
            .as_ref()
            .unwrap()
            .contains("native receipt lookups requested")
    );
    assert!(actual.host.core.subscribe().borrow().directions.is_empty());
    actual.host.close_controls();
    actual.claude_peer.finish(0);
    actual.gemini_peer.finish(0);
    cx.update_window(window, |_, window, _| window.remove_window())
        .unwrap();
    drop(view);
}

#[gpui_kit::test]
fn coalesced_failed_submit_and_unrelated_lookup_both_settle_without_losing_draft(
    cx: &mut TestAppContext,
) {
    cx.executor().allow_parking();
    let mut actual = actual_team();
    let rt = runtime();
    wait_team(&rt, &actual.host, |snapshot| snapshot.members.len() == 2);
    let (window, view) = mount(cx, actual.host.clone());
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.editor
                .update(cx, |editor, cx| editor.focus(window, cx));
        });
        window.draw(cx).clear(cx);
        window.input("Keep the failed submission draft", cx);
    })
    .unwrap();
    cx.run_until_parked();
    {
        let mut state = actual.host.presentation.lock().unwrap();
        state.flight = Some(Flight::Submitted("parent-submit-a".into()));
        state.consumed_revision = Some(state.revision);
        state.lookup_pending = Some(("parent-lookup-b".into(), 7));
    }
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            let mut snapshot = view.snapshot.clone();
            snapshot.revision = snapshot.revision.saturating_add(100);
            assert!(
                snapshot.directions.is_empty(),
                "failed-before-save has no durable parent receipt"
            );
            snapshot.submissions.insert(
                "parent-submit-a".into(),
                SubmissionReport {
                    id: "parent-submit-a".into(),
                    kind: ReportKind::Submit,
                    lookup_serial: None,
                    admitted: true,
                    stage_retired: true,
                    error: Some(TeamError::Storage),
                },
            );
            snapshot.lookups.insert(
                "parent-lookup-b".into(),
                SubmissionReport {
                    id: "parent-lookup-b".into(),
                    kind: ReportKind::Lookup,
                    lookup_serial: Some(7),
                    admitted: true,
                    stage_retired: true,
                    error: None,
                },
            );
            view.apply_snapshot(snapshot, window, cx);
            assert_eq!(
                view.editor.read(cx).value(),
                "Keep the failed submission draft"
            );
        })
    })
    .unwrap();
    {
        let state = actual.host.presentation.lock().unwrap();
        assert!(
            state.flight.is_none(),
            "retained failed SubmitA settles without any DirectionReceipt"
        );
        assert!(
            state.lookup_pending.is_none(),
            "unrelated retained LookupB also settles"
        );
        assert!(
            state.consumed(),
            "coalescing cannot rearm an unchanged human revision"
        );
        let notice = state.notice.as_ref().unwrap();
        assert!(notice.contains(error_message(TeamError::Storage)));
        assert!(
            notice.contains("native receipt lookups requested"),
            "lookup success must not hide the submit error"
        );
    }
    // Retained reports recur in later snapshots; they must not overwrite a
    // newer human notice after their matching pending actions were settled.
    actual.host.presentation.lock().unwrap().notice = Some("A newer human notice".into());
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            let mut snapshot = view.snapshot.clone();
            snapshot.revision = snapshot.revision.saturating_add(1);
            view.apply_snapshot(snapshot, window, cx);
        })
    })
    .unwrap();
    assert_eq!(
        actual.host.presentation.lock().unwrap().notice.as_deref(),
        Some("A newer human notice")
    );
    assert!(actual.host.core.subscribe().borrow().directions.is_empty());
    no_frame(&rt, &mut actual.claude_peer.io);
    no_frame(&rt, &mut actual.gemini_peer.io);
    actual.host.close_controls();
    actual.claude_peer.finish(0);
    actual.gemini_peer.finish(0);
    cx.update_window(window, |_, window, _| window.remove_window())
        .unwrap();
}

#[gpui_kit::test]
fn newer_same_parent_lookup_uses_its_actual_outcome_and_never_retires_submit_flight(
    cx: &mut TestAppContext,
) {
    cx.executor().allow_parking();
    let mut actual = actual_team();
    let rt = runtime();
    wait_team(&rt, &actual.host, |snapshot| snapshot.members.len() == 2);
    let (window, view) = mount(cx, actual.host.clone());
    cx.run_until_parked();
    {
        let mut state = actual.host.presentation.lock().unwrap();
        state.flight = Some(Flight::Submitted("parent-submit-original".into()));
        state.lookup_pending = Some(("parent-check-original".into(), 7));
    }
    for (requested, observed, error, settled) in [
        (7, 8, Some(TeamError::Unavailable), true),
        (9, 8, None, false),
        (9, 10, None, true),
    ] {
        actual.host.presentation.lock().unwrap().lookup_pending =
            Some(("parent-check-original".into(), requested));
        cx.update_window(window, |_, window, cx| {
            view.update(cx, |view, cx| {
                let mut snapshot = view.snapshot.clone();
                snapshot.revision = snapshot.revision.saturating_add(100);
                snapshot.lookups.insert(
                    "parent-check-original".into(),
                    SubmissionReport {
                        id: "parent-check-original".into(),
                        kind: ReportKind::Lookup,
                        lookup_serial: Some(observed),
                        admitted: true,
                        stage_retired: true,
                        error,
                    },
                );
                view.apply_snapshot(snapshot, window, cx);
            })
        })
        .unwrap();
        let state = actual.host.presentation.lock().unwrap();
        assert_eq!(state.lookup_pending.is_none(), settled);
        assert!(
            matches!(&state.flight, Some(Flight::Submitted(id)) if id == "parent-submit-original"),
            "a lookup result never retires an unrelated submission"
        );
        if settled {
            let notice = state.notice.as_ref().unwrap();
            if let Some(error) = error {
                assert!(
                    notice.contains(error_message(error)),
                    "newer actual error must not become a successful check"
                );
                assert!(!notice.contains("native receipt lookups requested"));
            } else {
                assert!(
                    notice.contains(
                        "Original parent record checked; native receipt lookups requested"
                    )
                );
            }
        }
    }
    assert!(actual.host.core.subscribe().borrow().directions.is_empty());
    no_frame(&rt, &mut actual.claude_peer.io);
    no_frame(&rt, &mut actual.gemini_peer.io);
    actual.host.close_controls();
    actual.claude_peer.finish(0);
    actual.gemini_peer.finish(0);
    cx.update_window(window, |_, window, _| window.remove_window())
        .unwrap();
}

/// Crosses the real team coordinator, parent journal, two real native actors,
/// their child journals and existing native Start/Cancel views. Only external
/// CLI child IO is synthetic; no model or installed runtime is invoked.
#[gpui_kit::test]
fn native_team_subset_then_separate_gemini_cancel_and_human_send(cx: &mut TestAppContext) {
    cx.executor().allow_parking();
    use serde_json::json;
    let mut actual = actual_team();
    let rt = runtime();
    wait_team(&rt, &actual.host, |snapshot| snapshot.members.len() == 2);
    let (team_window, team_view) = mount(cx, actual.host.clone());
    cx.run_until_parked();
    let (claude_index, gemini_index) = cx.update(|cx| {
        let members = &team_view.read(cx).snapshot.members;
        (
            members
                .iter()
                .position(|m| m.id == "claude-review")
                .unwrap(),
            members
                .iter()
                .position(|m| m.id == "gemini-research")
                .unwrap(),
        )
    });
    cx.update_window(team_window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click(("team-member", claude_index), cx);
        window.click(("team-member", gemini_index), cx);
        assert!(
            window
                .find(("team-member", claude_index))
                .label()
                .unwrap()
                .contains("claude-review")
        );
        assert!(
            window
                .find(("team-member", gemini_index))
                .label()
                .unwrap()
                .contains("gemini-research")
        );
    })
    .unwrap();
    cx.run_until_parked();
    no_frame(&rt, &mut actual.claude_peer.io);
    no_frame(&rt, &mut actual.gemini_peer.io);
    let claude_window = open_member(cx, team_window, claude_index);
    let gemini_window = open_member(cx, team_window, gemini_index);
    no_frame(&rt, &mut actual.claude_peer.io);
    no_frame(&rt, &mut actual.gemini_peer.io);
    assert!(actual.host.core.subscribe().borrow().directions.is_empty());
    assert!(actual.claude.subscribe().borrow().start.is_none());
    assert!(actual.gemini.subscribe().borrow().start.is_none());

    type_native(
        cx,
        claude_window,
        "Claude task or direction draft",
        "Write the original review",
        "submit-claude-work",
    );
    let init = rt.block_on(read_frame(&mut actual.claude_peer.io));
    assert_eq!(init["type"], "control_request");
    rt.block_on(send_frame(&mut actual.claude_peer.io,json!({"type":"control_response","response":{"subtype":"success","request_id":init["request_id"],"response":{"claude_code_version":"2.1.314"}}})));
    let initial_claude = rt.block_on(read_frame(&mut actual.claude_peer.io));
    let claude_session = initial_claude["session_id"].as_str().unwrap().to_owned();
    rt.block_on(send_frame(&mut actual.claude_peer.io,json!({"type":"system","subtype":"init","session_id":claude_session,"claude_code_version":"2.1.314","cwd":actual.claude_peer.workdir,"tools":[],"permissionMode":"default"})));
    rt.block_on(send_frame(&mut actual.claude_peer.io,json!({"type":"assistant","uuid":chinwag_claude_control::new_operation_id().unwrap(),"session_id":claude_session,"parent_tool_use_id":null,"user_message_uuid":initial_claude["uuid"],"message":{"id":"msg-team-fixture","type":"message","role":"assistant","content":[{"type":"text","text":"Original review remains in progress."}]}})));

    type_native(
        cx,
        gemini_window,
        "Gemini task or next input draft",
        "Research the original task",
        "submit-gemini-work",
    );
    let init = rt.block_on(read_frame(&mut actual.gemini_peer.io));
    assert_eq!(init["method"], "initialize");
    rt.block_on(send_frame(&mut actual.gemini_peer.io,json!({"jsonrpc":"2.0","id":init["id"],"result":{"protocolVersion":1,"agentInfo":{"name":"gemini-cli","version":"0.66.0"}}})));
    let new = rt.block_on(read_frame(&mut actual.gemini_peer.io));
    assert_eq!(new["method"], "session/new");
    let gemini_session = "aaaaaaaa-1111-4111-8111-111111111111";
    rt.block_on(send_frame(&mut actual.gemini_peer.io,json!({"jsonrpc":"2.0","id":new["id"],"result":{"sessionId":gemini_session,"modes":{"currentModeId":"default"}}})));
    let initial_gemini = rt.block_on(read_frame(&mut actual.gemini_peer.io));
    assert_eq!(initial_gemini["method"], "session/prompt");
    wait_team(&rt, &actual.host, |snapshot| {
        snapshot.members.iter().all(|member| match &member.native {
            NativeSnapshot::Claude(native) => {
                native.session.is_some()
                    && native.last_submission.as_ref().is_some_and(|s| {
                        s.kind == chinwag_claude_control::ActionKind::Start && s.saved
                    })
            }
            NativeSnapshot::Gemini(native) => {
                native.active_prompt.is_some()
                    && native.last_submission.as_ref().is_some_and(|s| {
                        s.kind == chinwag_gemini_control::ActionKind::Start && s.saved
                    })
            }
            _ => false,
        })
    });
    cx.run_until_parked();
    let direction = "Focus on the simplest native working path";
    cx.update_window(team_window, |_, window, cx| {
        team_view.update(cx, |view, cx| {
            view.editor
                .update(cx, |editor, cx| editor.focus(window, cx))
        });
        window.draw(cx).clear(cx);
        window.input(direction, cx);
        window.draw(cx).clear(cx);
        window.click("send-team-direction", cx);
    })
    .unwrap();
    cx.run_until_parked();
    assert!(
        actual.host.core.subscribe().borrow().directions.is_empty(),
        "blocked whole selection has zero effects"
    );
    no_frame(&rt, &mut actual.claude_peer.io);
    no_frame(&rt, &mut actual.gemini_peer.io);
    cx.update_window(team_window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("send-team-ready-subset", cx);
        window.click("send-team-ready-subset", cx);
    })
    .unwrap();
    cx.run_until_parked();
    let steered = rt.block_on(read_frame(&mut actual.claude_peer.io));
    assert_eq!(steered["type"], "user");
    assert_eq!(steered["priority"], "now");
    assert_eq!(
        steered["message"]["content"],
        json!([{"type":"text","text":direction}])
    );
    assert_ne!(steered["uuid"], initial_claude["uuid"]);
    no_frame(&rt, &mut actual.gemini_peer.io);
    let partial = wait_team(&rt, &actual.host, |snapshot| {
        snapshot.directions.len() == 1
            && snapshot.directions[0].stage_retired
            && snapshot.directions[0]
                .members
                .iter()
                .any(|m| m.id == "claude-review" && m.child_saved)
    });
    let original = &partial.directions[0];
    assert_eq!(original.intent.selected.len(), 2);
    assert_eq!(original.intent.effective, vec!["claude-review"]);
    assert_eq!(
        original
            .intent
            .members
            .iter()
            .find(|m| m.id == "claude-review")
            .unwrap()
            .child_id
            .as_deref(),
        steered["uuid"].as_str()
    );
    assert!(
        original
            .intent
            .members
            .iter()
            .find(|m| m.id == "gemini-research")
            .unwrap()
            .excluded
            .is_some()
    );
    cx.run_until_parked();
    cx.update(|cx| {
        assert_eq!(team_view.read(cx).editor.read(cx).value(), direction);
        let p = actual.host.presentation.lock().unwrap();
        assert!(p.flight.is_none());
        assert!(p.consumed());
    });
    cx.update_window(team_window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("send-team-ready-subset", cx);
    })
    .unwrap();
    cx.run_until_parked();
    assert_eq!(
        actual.host.core.subscribe().borrow().directions.len(),
        1,
        "retired flight cannot rearm the same human revision"
    );
    no_frame(&rt, &mut actual.claude_peer.io);
    no_frame(&rt, &mut actual.gemini_peer.io);

    cx.update_window(gemini_window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("cancel-gemini-response", cx);
        window.click("cancel-gemini-response", cx);
    })
    .unwrap();
    cx.run_until_parked();
    let cancel = rt.block_on(read_frame(&mut actual.gemini_peer.io));
    assert_eq!(
        cancel,
        json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":gemini_session}})
    );
    rt.block_on(send_frame(
        &mut actual.gemini_peer.io,
        json!({"jsonrpc":"2.0","id":initial_gemini["id"],"result":{"stopReason":"cancelled"}}),
    ));
    wait_team(&rt, &actual.host, |snapshot| {
        snapshot.members.iter().any(|member|matches!(&member.native,NativeSnapshot::Gemini(native)if native.can_prompt&&!native.cancel_pending))
    });
    cx.run_until_parked();
    no_frame(&rt, &mut actual.gemini_peer.io);
    assert_eq!(
        actual.host.core.subscribe().borrow().directions.len(),
        1,
        "new eligibility never automatically sends"
    );
    cx.update_window(team_window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("new-team-direction", cx);
        window.click(("team-member", claude_index), cx);
        window.draw(cx).clear(cx);
        window.click("send-team-direction", cx);
        window.click("send-team-direction", cx);
    })
    .unwrap();
    cx.run_until_parked();
    let next = rt.block_on(read_frame(&mut actual.gemini_peer.io));
    assert_eq!(next["method"], "session/prompt");
    assert_ne!(next["id"], initial_gemini["id"]);
    assert_eq!(
        next["params"]["prompt"],
        json!([{"type":"text","text":direction}])
    );
    no_frame(&rt, &mut actual.claude_peer.io);
    let full = wait_team(&rt, &actual.host, |snapshot| {
        snapshot.directions.len() == 2
            && snapshot.directions.iter().any(|receipt| {
                receipt.intent.effective == vec!["gemini-research"]
                    && receipt.stage_retired
                    && receipt
                        .members
                        .iter()
                        .all(|member| member.child_saved && member.clear_safe)
            })
    });
    cx.run_until_parked();
    cx.update(|cx| assert_eq!(team_view.read(cx).editor.read(cx).value(), ""));
    let complete = full
        .directions
        .iter()
        .find(|receipt| receipt.intent.effective == vec!["gemini-research"])
        .unwrap();
    let round = SentRound {
        id: complete.intent.id.clone(),
        text: complete.intent.text.clone(),
        revision: complete.intent.human_revision,
        selection_revision: 1,
        options_revision: 1,
        selected: complete.intent.selected.clone(),
        effective: complete.intent.effective.clone(),
    };
    assert!(may_clear(complete, &round));
    let mut uncertain = complete.clone();
    uncertain.members[0].clear_safe = false;
    assert!(uncertain.members[0].child_saved);
    assert!(
        !may_clear(&uncertain, &round),
        "Saved alone cannot clear an uncertain or rejected native outcome"
    );
    // Reuse this actual saved parent/native receipt as a controlled late
    // projection. Native input below edits and restores all human choices;
    // delivering the old success again must not clear that newer draft.
    let mut restored_round = round.clone();
    cx.update_window(team_window, |_, window, cx| {
        {
            let mut state = actual.host.presentation.lock().unwrap();
            state.revision = round.revision;
            state.draft = direction.into();
            restored_round.selection_revision = state.selection_revision;
            restored_round.options_revision = state.options_revision;
            state.pending_clear = Some(restored_round.clone());
        }
        team_view.update(cx, |view, cx| {
            view.editor.update(cx, |editor, cx| {
                editor.set_value(direction, window, cx);
                editor.focus(window, cx);
            })
        });
        window.draw(cx).clear(cx);
        let select_all = if cfg!(target_os = "macos") {
            "cmd-a"
        } else {
            "ctrl-a"
        };
        window.press(select_all, cx);
        window.input("A new edited draft", cx);
        window.press(select_all, cx);
        window.input(direction, cx);
        window.click(("team-member", gemini_index), cx);
        window.click(("team-member", gemini_index), cx);
        window.click(("team-member", claude_index), cx);
        window.draw(cx).clear(cx);
        window.click(("team-claude-timing", claude_index * 3 + 1), cx);
        window.click(("team-claude-timing", claude_index * 3), cx);
        window.click(("team-member", claude_index), cx);
    })
    .unwrap();
    cx.run_until_parked();
    cx.update_window(team_window, |_, window, cx| {
        team_view.update(cx, |view, cx| {
            {
                let mut state = actual.host.presentation.lock().unwrap();
                assert!(state.revision > restored_round.revision);
                assert!(state.selection_revision > restored_round.selection_revision);
                assert!(state.options_revision > restored_round.options_revision);
                assert_eq!(
                    state.selected.iter().cloned().collect::<Vec<_>>(),
                    restored_round.selected
                );
                assert_eq!(state.timings.get("claude-review"), Some(&ClaudeTiming::Now));
                state.pending_clear = Some(restored_round.clone());
            }
            let mut late = full.clone();
            late.revision = view.snapshot.revision.saturating_add(100);
            view.apply_snapshot(late, window, cx);
            assert_eq!(
                view.editor.read(cx).value(),
                direction,
                "restored text/selection/options are a new draft despite an old success"
            );
        })
    })
    .unwrap();
    assert_eq!(
        actual.host.core.subscribe().borrow().directions.len(),
        2,
        "editing, selection and timing never send automatically"
    );
    no_frame(&rt, &mut actual.claude_peer.io);
    no_frame(&rt, &mut actual.gemini_peer.io);
    actual.host.close_controls();
    actual.claude_peer.finish(0);
    actual.gemini_peer.finish(0);
    for window in [team_window, claude_window, gemini_window] {
        cx.update_window(window, |_, window, _| window.remove_window())
            .unwrap();
    }
    drop(team_view);
}
