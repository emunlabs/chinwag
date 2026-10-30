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
