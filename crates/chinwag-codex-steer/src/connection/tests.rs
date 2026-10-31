use super::*;
use serde_json::{Value, json};
use tokio::io::{DuplexStream, ReadHalf, WriteHalf};

const THREAD: &str = "thread-owned-1";
const TEXT: &str = "Human explicit mid-run steer";
struct Fixture {
    connection: CodexSteerConnection,
    owner: ConnectionOwner,
    peer: BufReader<DuplexStream>,
}
fn fixture(capacity: usize) -> Fixture {
    let (bridge, peer) = tokio::io::duplex(capacity);
    let (reader, writer) = tokio::io::split(bridge);
    let scope = OwnerControlScope::new(
        "explicit-human-fixture".into(),
        THREAD.into(),
        Duration::from_secs(60),
    )
    .unwrap();
    let (connection, owner) =
        CodexSteerConnection::from_established_io(scope, reader, writer).unwrap();
    Fixture {
        connection,
        owner,
        peer: BufReader::new(peer),
    }
}
async fn send(peer: &mut BufReader<DuplexStream>, value: Value) {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    peer.get_mut().write_all(&bytes).await.unwrap();
    peer.get_mut().flush().await.unwrap();
}
async fn frame(peer: &mut BufReader<DuplexStream>) -> Value {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), peer.read_until(b'\n', &mut bytes))
        .await
        .unwrap()
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn started(thread: &str, turn: &str) -> Value {
    json!({"method":"turn/started","params":{"threadId":thread,"turn":{"id":turn,"items":[],"status":"inProgress"}}})
}
fn completed(turn: &str) -> Value {
    json!({"method":"turn/completed","params":{"threadId":THREAD,"turn":{"id":turn,"items":[],"status":"completed"}}})
}
async fn active(fixture: &mut Fixture, turn: &str) -> ObservedActiveTurn {
    send(&mut fixture.peer, started(THREAD, turn)).await;
    until(|| {
        fixture
            .connection
            .active_turn()
            .is_some_and(|target| target.turn_id() == turn)
    })
    .await;
    fixture.connection.active_turn().unwrap()
}
async fn until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn dispatch(fixture: &Fixture, target: &ObservedActiveTurn, id: &str) -> Evidence {
    let grant = fixture.owner.human_grant().unwrap();
    let prepared = fixture
        .connection
        .prepare(&grant, target, id, TEXT)
        .unwrap();
    fixture
        .connection
        .dispatch_committed(CommittedSteerAttempt::new(prepared))
        .await
}
fn recorded(id: &str, turn: &str, text: &str) -> Value {
    json!({"method":"item/completed","params":{"threadId":THREAD,"turnId":turn,"item":{"type":"userMessage","id":"item-harness-1","clientId":id,"content":[{"type":"text","text":text,"text_elements":[]}]},"completedAtMs":17}})
}

#[tokio::test]
async fn exact_observed_active_target_accepts_without_waiting_for_turn_completion() {
    let mut f = fixture(65536);
    assert!(f.connection.active_turn().is_none());
    send(&mut f.peer, started("foreign-thread", "foreign-turn")).await;
    tokio::task::yield_now().await;
    assert!(f.connection.active_turn().is_none());
    let target = active(&mut f, "turn-1").await;
    let written = dispatch(&f, &target, "steer-explicit-0001").await;
    assert!(written.frame_written && !written.core_accepted);
    let request = frame(&mut f.peer).await;
    assert_eq!(request["method"], "turn/steer");
    assert_eq!(request["params"]["threadId"], THREAD);
    assert_eq!(request["params"]["expectedTurnId"], "turn-1");
    send(
        &mut f.peer,
        json!({"id":request["id"],"result":{"turnId":"turn-1"}}),
    )
    .await;
    until(|| {
        f.connection
            .evidence("steer-explicit-0001")
            .is_some_and(|e| e.core_accepted)
    })
    .await;
    assert!(
        f.connection.active_turn().is_some(),
        "peer has not completed the running turn"
    );
    send(&mut f.peer, completed("turn-1")).await;
    until(|| f.connection.active_turn().is_none()).await;
    assert!(f.connection.owns_target(&target));
    assert!(target.matches_record(&SavedSteer {
        schema: OPERATION_SCHEMA.into(),
        id: "steer-explicit-0001".into(),
        transport_epoch: f.connection.transport_epoch().into(),
        thread_id: THREAD.into(),
        expected_turn_id: "turn-1".into(),
        text: TEXT.into()
    }));
    f.connection.shutdown().await.unwrap();
}

#[tokio::test]
async fn core_and_harness_facts_arrive_in_either_order_and_wrong_correlations_do_not_promote() {
    for harness_first in [true, false] {
        let mut f = fixture(65536);
        let target = active(&mut f, "turn-1").await;
        dispatch(&f, &target, "steer-correlate-001").await;
        let request = frame(&mut f.peer).await;
        send(&mut f.peer, json!({"id":123,"result":{"turnId":"turn-1"}})).await;
        send(
            &mut f.peer,
            json!({"id":"unrelated-rpc","result":{"turnId":"turn-1"}}),
        )
        .await;
        send(
            &mut f.peer,
            recorded("steer-correlate-001", "wrong-turn", TEXT),
        )
        .await;
        send(
            &mut f.peer,
            recorded("steer-correlate-001", "turn-1", "different text"),
        )
        .await;
        tokio::task::yield_now().await;
        assert!(
            !f.connection
                .evidence("steer-correlate-001")
                .unwrap()
                .core_accepted
        );
        assert!(
            !f.connection
                .evidence("steer-correlate-001")
                .unwrap()
                .harness_recorded
        );
        let success = json!({"id":request["id"],"result":{"turnId":"turn-1"}});
        let harness = recorded("steer-correlate-001", "turn-1", TEXT);
        if harness_first {
            send(&mut f.peer, harness).await;
            send(&mut f.peer, success).await;
        } else {
            send(&mut f.peer, success).await;
            send(&mut f.peer, harness).await;
        }
        until(|| {
            f.connection
                .evidence("steer-correlate-001")
                .is_some_and(|e| e.core_accepted && e.harness_recorded)
        })
        .await;
        f.connection.shutdown().await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn ordinary_rpc_timeout_keeps_late_evidence_and_allows_another_explicit_steer() {
    let mut f = fixture(65536);
    let target = active(&mut f, "turn-1").await;
    dispatch(&f, &target, "steer-timeout-0001").await;
    let first = frame(&mut f.peer).await;
    tokio::task::yield_now().await;
    tokio::time::advance(ACK_TIMEOUT + Duration::from_millis(1)).await;
    until(|| {
        f.connection
            .evidence("steer-timeout-0001")
            .is_some_and(|e| e.write_uncertain)
    })
    .await;
    assert!(
        dispatch(&f, &target, "steer-distinct-0002")
            .await
            .frame_written
    );
    let second = frame(&mut f.peer).await;
    send(
        &mut f.peer,
        json!({"id":second["id"],"result":{"turnId":"turn-1"}}),
    )
    .await;
    send(&mut f.peer, recorded("steer-timeout-0001", "turn-1", TEXT)).await;
    send(
        &mut f.peer,
        json!({"id":first["id"],"result":{"turnId":"turn-1"}}),
    )
    .await;
    until(|| {
        f.connection
            .evidence("steer-timeout-0001")
            .is_some_and(|e| e.core_accepted && e.harness_recorded)
    })
    .await;
    let evidence = f.connection.evidence("steer-timeout-0001").unwrap();
    assert!(evidence.write_uncertain && evidence.core_accepted);
    f.connection.shutdown().await.unwrap();
}

#[tokio::test]
async fn revoked_or_changed_target_before_final_write_dispatches_no_frame() {
    for revoke in [true, false] {
        let mut f = fixture(65536);
        let target = active(&mut f, "turn-1").await;
        let grant = f.owner.human_grant().unwrap();
        let prepared = f
            .connection
            .prepare(&grant, &target, "steer-prewrite-001", TEXT)
            .unwrap();
        if revoke {
            f.owner.revoke();
        } else {
            send(&mut f.peer, completed("turn-1")).await;
            until(|| f.connection.active_turn().is_none()).await;
        }
        assert!(
            f.connection
                .dispatch_committed(CommittedSteerAttempt::new(prepared))
                .await
                .not_dispatched
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), f.peer.read_u8())
                .await
                .is_err()
        );
        f.connection.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn slow_frame_writer_does_not_stop_turn_notifications_or_survive_caller_drop() {
    let mut f = fixture(32);
    let target = active(&mut f, "turn-1").await;
    let grant = f.owner.human_grant().unwrap();
    let prepared = f
        .connection
        .prepare(&grant, &target, "steer-slow-write-01", TEXT)
        .unwrap();
    let connection = f.connection.clone();
    let caller = tokio::spawn(async move {
        connection
            .dispatch_committed(CommittedSteerAttempt::new(prepared))
            .await
    });
    let first = f.peer.read_u8().await.unwrap();
    assert_eq!(first, b'{');
    caller.abort();
    let _ = caller.await;
    send(&mut f.peer, completed("turn-1")).await;
    until(|| f.connection.active_turn().is_none()).await;
    let mut bytes = vec![first];
    f.peer.read_until(b'\n', &mut bytes).await.unwrap();
    let request: Value = serde_json::from_slice(&bytes).unwrap();
    send(
        &mut f.peer,
        json!({"id":request["id"],"result":{"turnId":"turn-1"}}),
    )
    .await;
    until(|| {
        f.connection
            .evidence("steer-slow-write-01")
            .is_some_and(|e| e.core_accepted)
    })
    .await;
    f.connection.shutdown().await.unwrap();
}

#[tokio::test]
async fn unsupported_server_request_surfaces_owner_intervention_without_auto_reply_or_peer_kill() {
    let mut f = fixture(65536);
    let target = active(&mut f, "turn-1").await;
    dispatch(&f, &target, "steer-intervention01").await;
    let request = frame(&mut f.peer).await;
    send(&mut f.peer,json!({"id":"approval-1","method":"item/commandExecution/requestApproval","params":{"threadId":THREAD}})).await;
    until(|| f.owner.intervention_required()).await;
    assert!(matches!(
        f.owner.human_grant(),
        Err(SteerError::OwnerInterventionRequired)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), f.peer.read_u8())
            .await
            .is_err()
    );
    send(
        &mut f.peer,
        json!({"id":request["id"],"result":{"turnId":"turn-1"}}),
    )
    .await;
    until(|| {
        f.connection
            .evidence("steer-intervention01")
            .is_some_and(|e| e.core_accepted)
    })
    .await;
    f.connection.shutdown().await.unwrap();
}

struct FlushFault(WriteHalf<DuplexStream>);
impl AsyncWrite for FlushFault {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, bytes)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("fixture flush fault")))
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn flush_uncertainty_fences_new_frames_but_keeps_original_late_acceptance() {
    let (bridge, peer) = tokio::io::duplex(65536);
    let (reader, writer): (ReadHalf<_>, WriteHalf<_>) = tokio::io::split(bridge);
    let scope = OwnerControlScope::new(
        "explicit flush fixture".into(),
        THREAD.into(),
        Duration::from_secs(60),
    )
    .unwrap();
    let (connection, owner) =
        CodexSteerConnection::from_established_io(scope, reader, FlushFault(writer)).unwrap();
    let mut f = Fixture {
        connection,
        owner,
        peer: BufReader::new(peer),
    };
    let target = active(&mut f, "turn-1").await;
    let evidence = dispatch(&f, &target, "steer-flush-fault01").await;
    assert!(evidence.write_uncertain && !evidence.core_accepted);
    let request = frame(&mut f.peer).await;
    assert!(matches!(
        f.owner.human_grant(),
        Err(SteerError::Unavailable)
    ));
    send(
        &mut f.peer,
        json!({"id":request["id"],"result":{"turnId":"turn-1"}}),
    )
    .await;
    until(|| {
        f.connection
            .evidence("steer-flush-fault01")
            .is_some_and(|e| e.core_accepted)
    })
    .await;
    assert!(
        f.connection
            .evidence("steer-flush-fault01")
            .unwrap()
            .write_uncertain
    );
    f.connection.shutdown().await.unwrap();
}

#[tokio::test]
async fn explicit_owner_close_ends_events_even_when_connection_clones_are_retained() {
    let f = fixture(65536);
    let clone = f.connection.clone();
    let mut events = f.connection.take_events().unwrap();
    assert!(f.connection.take_events().is_none());
    f.owner.request_close();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), events.recv())
            .await
            .unwrap()
            .is_none()
    );
    clone.shutdown().await.unwrap();
}

#[test]
fn constructing_without_serviced_runtime_returns_fixed_error_instead_of_panicking() {
    let (bridge, _peer) = tokio::io::duplex(128);
    let (read, write) = tokio::io::split(bridge);
    let scope = OwnerControlScope::new(
        "owner fixture".into(),
        THREAD.into(),
        Duration::from_secs(60),
    )
    .unwrap();
    assert!(matches!(
        CodexSteerConnection::from_established_io(scope, read, write),
        Err(SteerError::Unavailable)
    ));
}

#[tokio::test]
async fn queued_close_emits_definitive_no_dispatch_before_event_end_and_writer_result() {
    let mut f = fixture(65536);
    let target = active(&mut f, "turn-1").await;
    let grant = f.owner.human_grant().unwrap();
    let prepared = f
        .connection
        .prepare(&grant, &target, "steer-queued-close1", TEXT)
        .unwrap();
    let writer = f.connection.writer.lock().await;
    let mut events = f.connection.take_events().unwrap();
    let connection = f.connection.clone();
    let caller = tokio::spawn(async move {
        connection
            .dispatch_committed(CommittedSteerAttempt::new(prepared))
            .await
    });
    until(|| f.connection.evidence("steer-queued-close1").is_some()).await;
    f.owner.request_close();
    let event = events.recv().await.unwrap();
    assert_eq!(event.id, "steer-queued-close1");
    assert!(event.evidence.not_dispatched && !event.evidence.write_uncertain);
    assert!(
        events.recv().await.is_none(),
        "owner close ends events even with retained connection"
    );
    drop(writer);
    let evidence = caller.await.unwrap();
    assert!(evidence.not_dispatched && !evidence.write_uncertain);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), f.peer.read_u8())
            .await
            .is_err()
    );
    f.connection.shutdown().await.unwrap();
}

#[tokio::test]
async fn expired_grant_before_prepare_or_final_write_cannot_dispatch() {
    use std::future::Future;
    let mut f = fixture(65536);
    let target = active(&mut f, "turn-1").await;
    let grant = f.owner.human_grant().unwrap();
    let mut expired = grant.clone();
    expired.deadline = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    assert!(matches!(
        f.connection
            .prepare(&expired, &target, "steer-expired-before", TEXT),
        Err(SteerError::PermissionDenied)
    ));
    let mut prepared = f
        .connection
        .prepare(&grant, &target, "steer-expired-after", TEXT)
        .unwrap();
    prepared.grant.deadline = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    let evidence = f
        .connection
        .dispatch_committed(CommittedSteerAttempt::new(prepared))
        .await;
    assert!(evidence.not_dispatched && !evidence.frame_written && !evidence.write_uncertain);
    // No timers: a direct poll proves the peer has no frame available.
    let mut reading = Box::pin(f.peer.read_u8());
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(reading.as_mut().poll(cx).is_pending()))
            .await
    );
    drop(reading);
    f.connection.shutdown().await.unwrap();
}

const INITIAL_ID: &str = "work-initial-human-01";
fn fresh_fixture() -> Fixture {
    let (bridge, peer) = tokio::io::duplex(65536);
    let (reader, writer) = tokio::io::split(bridge);
    let mut scope = OwnerControlScope::new(
        "dedicated consenting owner".into(),
        THREAD.into(),
        Duration::from_secs(30),
    )
    .unwrap();
    scope.fresh = Some((INITIAL_ID.into(), "Initial explicit work".into()));
    let (connection, owner) =
        CodexSteerConnection::from_established_io(scope, reader, writer).unwrap();
    Fixture {
        connection,
        owner,
        peer: BufReader::new(peer),
    }
}
async fn initial(f: &mut Fixture) -> Value {
    let capsule = CommittedInitialTurn::new(
        INITIAL_ID.into(),
        "Initial explicit work".into(),
        f.connection.shared.epoch.clone(),
        THREAD.into(),
        f.connection.shared.scope.deadline,
    )
    .unwrap();
    let written = f.connection.dispatch_initial(capsule).await;
    assert!(written.frame_written && !written.core_accepted);
    let request = frame(&mut f.peer).await;
    assert_eq!(request["method"], "turn/start");
    request
}
#[tokio::test]
async fn owned_start_allows_midrun_steer_before_initial_reply_and_never_reopens_after_completion() {
    let mut f = fresh_fixture();
    let mut events = f.connection.take_events().unwrap();
    assert!(matches!(
        f.owner.human_grant(),
        Err(SteerError::PermissionDenied)
    ));
    let start = initial(&mut f).await;
    let target = active(&mut f, "turn-owned").await;
    let action = f
        .connection
        .capture_human_action(&target, "steer-human-owned01", TEXT)
        .unwrap();
    let grant = f.owner.authorize_action(&action).unwrap();
    let prepared = f
        .connection
        .prepare(&grant, &target, action.id(), action.text())
        .unwrap();
    assert!(
        f.connection
            .dispatch_committed(CommittedSteerAttempt::new(prepared))
            .await
            .frame_written
    );
    let steer = frame(&mut f.peer).await;
    assert_eq!(steer["method"], "turn/steer");
    send(
        &mut f.peer,
        json!({"id":steer["id"],"result":{"turnId":"turn-owned"}}),
    )
    .await;
    until(|| f.connection.evidence(action.id()).unwrap().core_accepted).await;
    assert!(
        !f.connection
            .subscribe_activity()
            .borrow()
            .initial
            .as_ref()
            .unwrap()
            .evidence
            .core_accepted
    );
    send(&mut f.peer, completed("turn-owned")).await;
    until(|| f.connection.subscribe_activity().borrow().completed).await;
    send(&mut f.peer,json!({"id":start["id"],"result":{"turn":{"id":"turn-owned","items":[],"status":"inProgress"}}})).await;
    send(&mut f.peer, started(THREAD, "turn-owned")).await;
    send(&mut f.peer, started(THREAD, "another-turn")).await;
    until(|| {
        f.connection
            .subscribe_activity()
            .borrow()
            .initial
            .as_ref()
            .unwrap()
            .evidence
            .core_accepted
    })
    .await;
    assert!(f.connection.active_turn().is_none());
    assert!(f.owner.authorize_action(&action).is_err());
    while let Ok(event) = events.try_recv() {
        assert_ne!(
            event.id, INITIAL_ID,
            "Initial facts never enter Steer journal channel"
        );
    }
    f.connection.shutdown().await.unwrap();
}
#[tokio::test]
async fn exact_work_action_rejects_substitution_and_expiry_without_writing() {
    use std::future::Future;
    let mut f = fresh_fixture();
    initial(&mut f).await;
    let target = active(&mut f, "turn-owned").await;
    let action = f
        .connection
        .capture_human_action(&target, "steer-human-exact01", TEXT)
        .unwrap();
    let grant = f.owner.authorize_action(&action).unwrap();
    assert!(matches!(
        f.connection
            .prepare(&grant, &target, "steer-human-other01", TEXT),
        Err(SteerError::PermissionDenied)
    ));
    assert!(matches!(
        f.connection
            .prepare(&grant, &target, action.id(), "different human text"),
        Err(SteerError::PermissionDenied)
    ));
    let mut expired = action.clone();
    expired.deadline = Instant::now() - Duration::from_secs(1);
    assert!(f.owner.authorize_action(&expired).is_err());
    let mut prepared = f
        .connection
        .prepare(&grant, &target, action.id(), TEXT)
        .unwrap();
    prepared.grant.deadline = Instant::now() - Duration::from_secs(1);
    let evidence = f
        .connection
        .dispatch_committed(CommittedSteerAttempt::new(prepared))
        .await;
    assert!(evidence.not_dispatched && !evidence.write_uncertain);
    let mut reading = Box::pin(f.peer.read_u8());
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(reading.as_mut().poll(cx).is_pending()))
            .await
    );
    drop(reading);
    f.connection.shutdown().await.unwrap();
}
#[tokio::test]
async fn first_work_uses_a_fresh_exact_action_instead_of_a_generic_legacy_grant() {
    let mut f = fresh_fixture();
    initial(&mut f).await;
    let target = active(&mut f, "turn-owned").await;
    // Each explicit action captures an immutable 30s deadline. Generic legacy
    // grants remain unavailable for the fresh-work scope.
    let action = f
        .connection
        .capture_human_action(&target, "steer-later-action1", TEXT)
        .unwrap();
    assert!(action.deadline <= Instant::now() + Duration::from_secs(30));
    let grant = f.owner.authorize_action(&action).unwrap();
    assert!(
        f.connection
            .prepare(&grant, &target, action.id(), TEXT)
            .is_ok()
    );
    f.connection.shutdown().await.unwrap();
}
#[tokio::test]
async fn completed_agent_text_is_bounded_same_owned_turn_and_not_a_model_awareness_receipt() {
    let mut f = fresh_fixture();
    initial(&mut f).await;
    active(&mut f, "turn-owned").await;
    send(&mut f.peer,json!({"method":"item/completed","params":{"threadId":THREAD,"turnId":"turn-owned","item":{"type":"agentMessage","text":"é".repeat(crate::MAX_TEXT_BYTES)}}})).await;
    until(|| {
        f.connection
            .subscribe_activity()
            .borrow()
            .agent_text
            .is_some()
    })
    .await;
    let activity = f.connection.subscribe_activity().borrow().clone();
    assert_eq!(activity.agent_text.unwrap().len(), crate::MAX_TEXT_BYTES);
    assert!(!activity.initial.unwrap().evidence.core_accepted);
    send(&mut f.peer,json!({"id":"approval-request","method":"item/commandExecution/requestApproval","params":{}})).await;
    until(|| f.connection.subscribe_activity().borrow().intervention).await;
    assert!(f.connection.active_turn().is_none());
    f.connection.shutdown().await.unwrap();
}

#[tokio::test]
async fn terminal_initial_response_ends_work_even_without_completion_notification() {
    for status in ["completed", "failed", "interrupted"] {
        let mut f = fresh_fixture();
        let request = initial(&mut f).await;
        send(&mut f.peer,json!({"id":request["id"],"result":{"turn":{"id":"turn-terminal","items":[],"status":status}}})).await;
        until(|| f.connection.subscribe_activity().borrow().completed).await;
        send(&mut f.peer, started(THREAD, "turn-terminal")).await;
        send(&mut f.peer, started(THREAD, "later-turn")).await;
        tokio::task::yield_now().await;
        assert!(f.connection.active_turn().is_none());
        let observation = f.connection.subscribe_activity().borrow().clone();
        assert!(
            observation.completed && observation.initial.as_ref().unwrap().evidence.core_accepted
        );
        assert_eq!(
            observation.initial.unwrap().accepted_turn_id.as_deref(),
            Some("turn-terminal")
        );
        f.connection.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn early_owned_thread_activity_fences_initial_start_instead_of_steering_existing_work() {
    use std::future::Future;
    for event in [
        started(THREAD, "already-active"),
        completed("already-completed"),
    ] {
        let mut f = fresh_fixture();
        send(&mut f.peer, event).await;
        until(|| f.connection.subscribe_activity().borrow().intervention).await;
        assert!(f.connection.active_turn().is_none());
        let capsule = CommittedInitialTurn::new(
            INITIAL_ID.into(),
            "Initial explicit work".into(),
            f.connection.shared.epoch.clone(),
            THREAD.into(),
            f.connection.shared.scope.deadline,
        )
        .unwrap();
        let result = f.connection.dispatch_initial(capsule).await;
        assert!(result.not_dispatched && !result.frame_written && !result.write_uncertain);
        let mut reading = Box::pin(f.peer.read_u8());
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                reading.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        drop(reading);
        f.connection.shutdown().await.unwrap();
    }
}

struct PartialWriteFault {
    writer: WriteHalf<DuplexStream>,
    remaining: usize,
}
impl AsyncWrite for PartialWriteFault {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.remaining == 0 {
            return std::task::Poll::Ready(Err(std::io::Error::other(
                "fixture partial write fault",
            )));
        }
        let length = bytes.len().min(self.remaining);
        let result = std::pin::Pin::new(&mut self.writer).poll_write(cx, &bytes[..length]);
        if let std::task::Poll::Ready(Ok(n)) = &result {
            self.remaining -= *n;
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn partial_steer_write_exposes_fenced_open_connection_with_no_active_control_target() {
    let (bridge, peer) = tokio::io::duplex(65536);
    let (reader, writer) = tokio::io::split(bridge);
    let scope = OwnerControlScope::new(
        "explicit partial-fault fixture".into(),
        THREAD.into(),
        Duration::from_secs(60),
    )
    .unwrap();
    let (connection, owner) = CodexSteerConnection::from_established_io(
        scope,
        reader,
        PartialWriteFault {
            writer,
            remaining: 8,
        },
    )
    .unwrap();
    let mut f = Fixture {
        connection,
        owner,
        peer: BufReader::new(peer),
    };
    let target = active(&mut f, "turn-running").await;
    let evidence = dispatch(&f, &target, "steer-partial-fault1").await;
    assert!(evidence.write_uncertain && !evidence.frame_written);
    let activity = f.connection.subscribe_activity().borrow().clone();
    assert!(activity.write_fenced);
    assert!(activity.target.is_none());
    assert!(!activity.closed && !activity.completed && !activity.intervention);
    let mut prefix = [0u8; 8];
    f.peer.read_exact(&mut prefix).await.unwrap();
    assert_eq!(prefix[0], b'{');
    assert!(!prefix.contains(&b'\n'));
    f.connection.shutdown().await.unwrap();
}

#[tokio::test]
async fn contradictory_initial_success_preserves_first_turn_and_fences_delayed_started() {
    use std::future::Future;
    let mut f = fresh_fixture();
    let request = initial(&mut f).await;
    send(&mut f.peer,json!({"id":request["id"],"result":{"turn":{"id":"turn-first-accepted","items":[],"status":"inProgress"}}})).await;
    until(|| {
        f.connection
            .subscribe_activity()
            .borrow()
            .initial
            .as_ref()
            .unwrap()
            .evidence
            .core_accepted
    })
    .await;
    send(&mut f.peer,json!({"id":request["id"],"result":{"turn":{"id":"turn-contradiction","items":[],"status":"inProgress"}}})).await;
    send(&mut f.peer, started(THREAD, "turn-contradiction")).await;
    until(|| f.connection.subscribe_activity().borrow().intervention).await;
    let activity = f.connection.subscribe_activity().borrow().clone();
    let initial = activity.initial.unwrap();
    assert_eq!(
        initial.accepted_turn_id.as_deref(),
        Some("turn-first-accepted")
    );
    assert!(initial.evidence.core_accepted && initial.evidence.write_uncertain);
    assert!(activity.write_fenced && activity.target.is_none() && !activity.completed);
    assert!(f.connection.active_turn().is_none());
    let mut reading = Box::pin(f.peer.read_u8());
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(reading.as_mut().poll(cx).is_pending()))
            .await
    );
    drop(reading);
    f.connection.shutdown().await.unwrap();
}

#[tokio::test]
async fn known_full_native_history_rejects_read_only_human_capture_without_frame() {
    let mut f = fresh_fixture();
    let _initial = initial(&mut f).await;
    let target = active(&mut f, "turn-owned").await;
    {
        let mut state = f.connection.shared.state.lock().unwrap();
        for index in 0..MAX_OPERATIONS {
            let id = format!("retained-native-steer-{index:04}");
            state.records.insert(
                id.clone(),
                Pending {
                    record: SavedSteer {
                        schema: OPERATION_SCHEMA.into(),
                        id,
                        transport_epoch: f.connection.shared.epoch.clone(),
                        thread_id: THREAD.into(),
                        expected_turn_id: target.turn_id().into(),
                        text: TEXT.into(),
                    },
                    rpc_id: format!("native-rpc-{index}"),
                    evidence: Evidence::default(),
                    may_have_written: false,
                },
            );
        }
    }
    assert_eq!(
        f.connection
            .capture_human_action_before(
                &target,
                "new-team-full-0001",
                TEXT,
                Instant::now() + Duration::from_secs(30)
            )
            .err(),
        Some(SteerError::Capacity)
    );
    assert!(f.connection.active_turn().is_some());
    assert_eq!(
        f.connection.shared.state.lock().unwrap().records.len(),
        MAX_OPERATIONS
    );
    let mut reading = Box::pin(f.peer.read_u8());
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(reading.as_mut().poll(cx).is_pending()))
            .await
    );
    drop(reading);
    f.connection.shutdown().await.unwrap();
}
