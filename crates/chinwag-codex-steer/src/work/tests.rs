use super::*;
use crate::RuntimePolicyDeclaration;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};
use tokio::net::{UnixListener, UnixStream};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

const WAIT: Duration = Duration::from_secs(3);
const START_ID: &str = "human-work-start-0001";
const START_TEXT: &str = "Create the requested Rust artifact\nwith a quoted \"name\".";
const STEER_ID: &str = "human-work-steer-0001";
const STEER_TEXT: &str = "Use the existing module\nand keep its public API.";
const THREAD: &str = "fresh-owned-thread";
const TURN: &str = "initial-owned-turn";
type Peer = WebSocketStream<UnixStream>;

struct Fixture {
    _temp: tempfile::TempDir,
    config: WorkConfig,
    listener: UnixListener,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("cw-port-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let cwd = root.join("work");
        fs::create_dir(&cwd).unwrap();
        fs::set_permissions(&cwd, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("declared.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let config = WorkConfig::new(
            &path,
            &cwd,
            &root.join("journal"),
            RuntimePolicyDeclaration::DedicatedRuntimeWithExplicitLogin,
        )
        .unwrap();
        Self {
            _temp: temp,
            config,
            listener,
        }
    }

    fn assert_intent(&self) {
        let path = self.config.journal.join("work.jsonl");
        let bytes =
            fs::read(&path).expect("Start must be consumed before accepting its connection");
        assert!(bytes.ends_with(b"\n"));
        let first = bytes.split(|byte| *byte == b'\n').next().unwrap();
        let value: Value = serde_json::from_slice(first).unwrap();
        assert_eq!(value["kind"], "intent");
        assert_eq!(value["intent"]["id"], START_ID);
        assert_eq!(value["intent"]["text"], START_TEXT);
        assert_eq!(
            value["intent"]["cwd"],
            self.config.workdir.to_str().unwrap()
        );
        assert_eq!(
            value["intent"]["socket"],
            self.config.socket.to_str().unwrap()
        );
        assert_eq!(value["intent"]["dedicated_explicit_login_consent"], true);
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o600);
    }

    async fn accept(&self) -> Peer {
        let (stream, _) = tokio::time::timeout(WAIT, self.listener.accept())
            .await
            .unwrap()
            .unwrap();
        self.assert_intent();
        tokio::time::timeout(WAIT, tokio_tungstenite::accept_async(stream))
            .await
            .unwrap()
            .unwrap()
    }

    async fn no_second_connection(&self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(30), self.listener.accept())
                .await
                .is_err(),
            "an explicit duplicate or recovery must not reconnect"
        );
    }
}

async fn snapshot(
    receiver: &mut watch::Receiver<WorkSnapshot>,
    predicate: impl Fn(&WorkSnapshot) -> bool,
) -> WorkSnapshot {
    tokio::time::timeout(WAIT, async {
        loop {
            let value = receiver.borrow_and_update().clone();
            if predicate(&value) {
                return value;
            }
            receiver.changed().await.expect("retained owner snapshot");
        }
    })
    .await
    .expect("bounded owner snapshot transition")
}

async fn frame(peer: &mut Peer) -> Value {
    tokio::time::timeout(WAIT, async {
        loop {
            match peer
                .next()
                .await
                .expect("peer stream before expected request")
                .unwrap()
            {
                Message::Text(text) => {
                    let value = crate::wire::unique_value(text.as_bytes()).unwrap();
                    assert!(value.get("jsonrpc").is_none());
                    assert!(value.get("trace").is_none());
                    return value;
                }
                Message::Ping(bytes) => {
                    peer.send(Message::Pong(bytes)).await.unwrap();
                }
                Message::Pong(_) => {}
                _ => panic!("unexpected peer message before application request"),
            }
        }
    })
    .await
    .expect("bounded application request")
}

async fn send(peer: &mut Peer, value: Value) {
    tokio::time::timeout(
        WAIT,
        peer.send(Message::Text(serde_json::to_string(&value).unwrap().into())),
    )
    .await
    .unwrap()
    .unwrap();
}

async fn no_frame(peer: &mut Peer) {
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.next())
            .await
            .is_err(),
        "no automatic application or close frame was expected"
    );
}

async fn bootstrap(fixture: &Fixture, peer: &mut Peer) -> Value {
    fixture.assert_intent();
    let initialize = frame(peer).await;
    assert_eq!(initialize["method"], "initialize");
    assert_eq!(
        initialize["params"]["clientInfo"]["name"],
        "chinwag-owned-work"
    );
    assert_eq!(
        initialize["params"]["capabilities"],
        json!({
            "explicitGatewayOauth":true,"experimentalApi":false,"requestAttestation":false
        })
    );
    assert_eq!(initialize["params"].as_object().unwrap().len(), 2);
    send(
        peer,
        json!({"id":initialize["id"],"result":{
            "userAgent":"synthetic-peer-only","codexHome":"/fixture-private-not-projected",
            "platformFamily":"unix","platformOs":"macos"
        }}),
    )
    .await;
    assert_eq!(frame(peer).await, json!({"method":"initialized"}));
    let thread = frame(peer).await;
    assert_eq!(thread["method"], "thread/start");
    assert_eq!(thread["params"], json!({"cwd":fixture.config.workdir}));
    // Preserve a real notification encountered before the bootstrap response.
    send(
        peer,
        json!({"method":"thread/started","params":{"thread":{"id":THREAD}}}),
    )
    .await;
    send(
        peer,
        json!({"id":thread["id"],"result":{"thread":{"id":THREAD,"turns":[],"cwd":fixture.config.workdir}}}),
    )
    .await;
    let initial = frame(peer).await;
    assert_eq!(initial["method"], "turn/start");
    assert_eq!(
        initial["params"],
        json!({
            "threadId":THREAD,"clientUserMessageId":START_ID,
            "input":[{"type":"text","text":START_TEXT,"text_elements":[]}]
        })
    );
    initial
}

fn turn(status: &str) -> Value {
    json!({"id":TURN,"status":status,"items":[]})
}

async fn peer_closed_without_control_rpc(peer: &mut Peer) {
    tokio::time::timeout(WAIT, async {
        loop {
            match peer.next().await {
                Some(Ok(Message::Text(text))) => panic!("Close sent an application RPC: {text}"),
                Some(Ok(Message::Ping(bytes))) => {
                    let _ = peer.send(Message::Pong(bytes)).await;
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                _ => panic!("unexpected binary data during Close"),
            }
        }
    })
    .await
    .expect("bounded explicit connection Close")
}

async fn released(config: WorkConfig) {
    tokio::time::timeout(WAIT, async {
        loop {
            let config = config.clone();
            match tokio::task::spawn_blocking(move || WorkJournal::open(config))
                .await
                .unwrap()
            {
                Ok(journal) => {
                    drop(journal);
                    return;
                }
                Err(SteerError::Unavailable) => tokio::time::sleep(Duration::from_millis(5)).await,
                Err(_) => panic!("closed fixture journal must remain recoverable"),
            }
        }
    })
    .await
    .expect("closed owner's journal lock released");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_port_starts_only_on_human_action_and_steers_before_initial_ack_or_completion() {
    let fixture = Fixture::new();
    let port = open_work_service(fixture.config.clone()).unwrap();
    let mut observations = port.subscribe();
    snapshot(&mut observations, |value| {
        fixture.config.journal.join("work-domain.json").exists() && value.phase == WorkPhase::Ready
    })
    .await;
    assert!(observations.borrow().start.is_none());
    assert!(!fixture.config.journal.join("work.jsonl").exists());
    fixture.no_second_connection().await;

    port.start(START_ID, START_TEXT).unwrap();
    let mut peer = fixture.accept().await;
    let initial = bootstrap(&fixture, &mut peer).await;
    send(
        &mut peer,
        json!({"method":"turn/started","params":{"threadId":THREAD,"turn":turn("inProgress")}}),
    )
    .await;
    let active = snapshot(&mut observations, |value| value.target.is_some()).await;
    let target = active.target.unwrap();
    assert_eq!(target.thread_id(), THREAD);
    assert_eq!(target.turn_id(), TURN);
    let start = active.start.unwrap();
    assert!(start.connected && start.initialized && !start.evidence.core_accepted);
    assert!(
        start.accepted_turn_id.is_none(),
        "initial acknowledgment deliberately withheld"
    );

    // Removing UI waiters does not own the underlying connection lifetime.
    drop(observations);
    drop(port.subscribe());
    drop(port.clone());
    no_frame(&mut peer).await;
    let mut observations = port.subscribe();
    assert!(observations.borrow().target.is_some());
    let deadline = Instant::now() + Duration::from_secs(30);
    assert_eq!(
        port.prepare_steer(
            &target,
            "expired-team-steer-0001",
            STEER_TEXT,
            Instant::now() - Duration::from_secs(1)
        )
        .err(),
        Some(SteerError::PermissionDenied)
    );
    let dropped = port
        .prepare_steer(&target, "dropped-team-steer-0001", STEER_TEXT, deadline)
        .unwrap();
    let stale = port
        .prepare_steer(&target, "stale-team-steer-0001", STEER_TEXT, deadline)
        .unwrap();
    let prepared = port
        .prepare_steer(&target, STEER_ID, STEER_TEXT, deadline)
        .unwrap();
    assert_eq!(prepared.operation().thread_id, THREAD);
    assert_eq!(prepared.operation().expected_turn_id, TURN);
    assert_eq!(prepared.deadline(), deadline);
    assert_eq!(dropped.captured_sequence(), prepared.captured_sequence());
    drop(dropped);
    assert!(
        !fixture
            .config
            .journal
            .join("steers")
            .join(format!("{STEER_ID}.jsonl"))
            .exists()
    );
    no_frame(&mut peer).await;
    port.submit_prepared_steer(prepared).unwrap();
    let steer = frame(&mut peer).await;
    assert_eq!(steer["method"], "turn/steer");
    assert_eq!(
        steer["params"],
        json!({
            "threadId":THREAD,"expectedTurnId":TURN,"clientUserMessageId":STEER_ID,
            "input":[{"type":"text","text":STEER_TEXT,"text_elements":[]}]
        })
    );
    send(
        &mut peer,
        json!({"id":steer["id"],"result":{"turnId":TURN}}),
    )
    .await;
    send(
        &mut peer,
        json!({"method":"item/completed","params":{"threadId":THREAD,"turnId":TURN,
        "item":{"type":"userMessage","id":"recorded-steer-item","clientId":STEER_ID,
            "content":[{"type":"text","text":STEER_TEXT,"text_elements":[]}]},"completedAtMs":17}}),
    )
    .await;
    let observed = snapshot(&mut observations, |value| {
        value.steers.iter().any(|receipt| {
            receipt.operation.id == STEER_ID
                && receipt.evidence.core_accepted
                && receipt.evidence.harness_recorded
        })
    })
    .await;
    assert!(
        observed.target.is_some(),
        "Steer finished before any completion notification"
    );
    assert!(
        !observed.start.as_ref().unwrap().evidence.core_accepted,
        "Steer acceptance must not fabricate initial acceptance"
    );

    assert_eq!(
        port.submit_prepared_steer(stale),
        Err(SteerError::StaleTarget)
    );
    assert!(
        !fixture
            .config
            .journal
            .join("steers/stale-team-steer-0001.jsonl")
            .exists()
    );
    no_frame(&mut peer).await;
    let revision = observations.borrow().revision;
    port.start(START_ID, START_TEXT).unwrap();
    snapshot(&mut observations, |value| {
        value.revision > revision
            && value.last_submission.as_ref().is_some_and(|report| {
                report.id == START_ID
                    && report.kind == WorkActionKind::Start
                    && report.saved
                    && report.error.is_none()
            })
    })
    .await;
    no_frame(&mut peer).await;
    port.start("human-work-conflict-0002", "A second task must not start")
        .unwrap();
    snapshot(&mut observations, |value| {
        value.last_submission.as_ref().is_some_and(|report| {
            report.id == "human-work-conflict-0002" && report.error == Some(SteerError::Conflict)
        })
    })
    .await;
    fixture.no_second_connection().await;
    no_frame(&mut peer).await;

    send(
        &mut peer,
        json!({"id":initial["id"],"result":{"turn":turn("inProgress")}}),
    )
    .await;
    let late = snapshot(&mut observations, |value| {
        value.start.as_ref().is_some_and(|receipt| {
            receipt.evidence.core_accepted && receipt.accepted_turn_id.as_deref() == Some(TURN)
        })
    })
    .await;
    assert!(late.steers[0].evidence.core_accepted && late.steers[0].evidence.harness_recorded);
    let serialized = serde_json::to_string(late.start.as_ref().unwrap()).unwrap();
    assert!(!serialized.contains("fixture-private-not-projected"));
    send(
        &mut peer,
        json!({"method":"turn/completed","params":{"threadId":THREAD,"turn":turn("completed")}}),
    )
    .await;
    snapshot(&mut observations, |value| {
        value.phase == WorkPhase::Finished && value.target.is_none()
    })
    .await;
    no_frame(&mut peer).await;
    assert!(
        port.steer(
            &target,
            "human-steer-after-end-0002",
            "Do not start a new turn"
        )
        .is_err()
    );
    for id in [START_ID, STEER_ID] {
        let revision = observations.borrow().revision;
        port.lookup(id).unwrap();
        snapshot(&mut observations, |value| {
            value.revision > revision
                && value.last_submission.as_ref().is_some_and(|report| {
                    report.id == id
                        && report.kind == WorkActionKind::Lookup
                        && report.error.is_none()
                })
        })
        .await;
        no_frame(&mut peer).await;
    }

    port.close().unwrap();
    peer_closed_without_control_rpc(&mut peer).await;
    snapshot(&mut observations, |value| {
        value.phase == WorkPhase::Closed
            && value
                .last_submission
                .as_ref()
                .is_some_and(|report| report.kind == WorkActionKind::Close)
    })
    .await;
    released(fixture.config.clone()).await;

    let recovered = open_work_service(fixture.config.clone()).unwrap();
    let mut recovery = recovered.subscribe();
    let historical = snapshot(&mut recovery, |value| {
        value
            .start
            .as_ref()
            .is_some_and(|receipt| receipt.recovered_after_restart)
    })
    .await;
    assert!(historical.target.is_none());
    assert!(
        historical
            .steers
            .iter()
            .any(|receipt| receipt.operation.id == STEER_ID
                && receipt.evidence.core_accepted
                && receipt.evidence.harness_recorded),
        "recovery must expose original IDs before any manually keyed lookup"
    );
    assert!(historical.start.unwrap().evidence.core_accepted);
    recovered.start(START_ID, START_TEXT).unwrap();
    snapshot(&mut recovery, |value| {
        value.last_submission.as_ref().is_some_and(|report| {
            report.id == START_ID && report.kind == WorkActionKind::Start && report.saved
        })
    })
    .await;
    fixture.no_second_connection().await;
    recovered.lookup(STEER_ID).unwrap();
    let archived = snapshot(&mut recovery, |value| {
        value.last_submission.as_ref().is_some_and(|report| {
            report.id == STEER_ID && report.kind == WorkActionKind::Lookup && report.error.is_none()
        }) && value
            .steers
            .iter()
            .any(|receipt| receipt.operation.id == STEER_ID)
    })
    .await;
    let original = archived
        .steers
        .iter()
        .find(|receipt| receipt.operation.id == STEER_ID)
        .unwrap();
    assert_eq!(original.operation.text, STEER_TEXT);
    assert_eq!(original.operation.thread_id, THREAD);
    assert_eq!(original.operation.expected_turn_id, TURN);
    assert!(original.recovered_after_restart);
    assert!(original.evidence.core_accepted && original.evidence.harness_recorded);
    assert!(
        archived.target.is_none(),
        "historical receipt must not adopt a live target"
    );
    fixture.no_second_connection().await;
    recovered.close().unwrap();
    snapshot(&mut recovery, |value| value.phase == WorkPhase::Closed).await;
    released(fixture.config.clone()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_close_during_unanswered_initialize_never_starts_a_thread_or_reconnects() {
    let fixture = Fixture::new();
    let port = open_work_service(fixture.config.clone()).unwrap();
    let mut observations = port.subscribe();
    snapshot(&mut observations, |value| {
        fixture.config.journal.join("work-domain.json").exists() && value.phase == WorkPhase::Ready
    })
    .await;
    port.start(START_ID, START_TEXT).unwrap();
    let mut peer = fixture.accept().await;
    let initialize = frame(&mut peer).await;
    assert_eq!(initialize["method"], "initialize");
    port.close().unwrap();
    peer_closed_without_control_rpc(&mut peer).await;
    let closed = snapshot(&mut observations, |value| {
        value.phase == WorkPhase::Closed
            && value
                .last_submission
                .as_ref()
                .is_some_and(|report| report.kind == WorkActionKind::Close)
    })
    .await;
    assert!(closed.target.is_none());
    let receipt = closed.start.unwrap();
    assert!(
        !receipt.initialized && receipt.thread_id.is_none() && receipt.accepted_turn_id.is_none()
    );
    assert!(!receipt.evidence.core_accepted && !receipt.evidence.harness_recorded);
    fixture.no_second_connection().await;
    released(fixture.config.clone()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_fences_a_captured_steer_blocked_on_original_receipt_lookup() {
    let fixture = Fixture::new();
    let port = open_client(fixture.config.clone()).unwrap();
    struct CloseOnDrop(Arc<Client>);
    impl Drop for CloseOnDrop {
        fn drop(&mut self) {
            let _ = self.0.close();
        }
    }
    let _cleanup = CloseOnDrop(port.clone());
    let mut observations = port.subscribe();
    snapshot(&mut observations, |value| {
        fixture.config.journal.join("work-domain.json").exists() && value.phase == WorkPhase::Ready
    })
    .await;
    port.start(START_ID, START_TEXT).unwrap();
    let mut peer = fixture.accept().await;
    let initial = bootstrap(&fixture, &mut peer).await;
    send(
        &mut peer,
        json!({"method":"turn/started","params":{"threadId":THREAD,"turn":turn("inProgress")}}),
    )
    .await;
    send(
        &mut peer,
        json!({"id":initial["id"],"result":{"turn":turn("inProgress")}}),
    )
    .await;
    let active = snapshot(&mut observations, |value| {
        value.target.is_some()
            && value
                .start
                .as_ref()
                .is_some_and(|receipt| receipt.evidence.core_accepted)
    })
    .await;
    let target = active.target.unwrap();
    let controller = port.controller.lock().unwrap().as_ref().unwrap().clone();
    let journal = controller.journal_for_fixture();
    let (locked, acquired) = tokio::sync::oneshot::channel();
    let (release, released_guard) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let _guard = journal.lock().unwrap();
        locked.send(()).unwrap();
        released_guard
            .recv_timeout(WAIT * 2)
            .expect("bounded fixture release");
    });
    tokio::time::timeout(WAIT, acquired).await.unwrap().unwrap();
    let command_seen = port.command_seen.notified();
    port.steer(&target, STEER_ID, STEER_TEXT).unwrap();
    tokio::time::timeout(WAIT, command_seen)
        .await
        .expect("actor consumed the queued steer before Close");
    assert!(port.flight.load(Ordering::Acquire));
    port.close().unwrap();
    assert!(
        controller.active_turn().is_none(),
        "human Close must fence the controller synchronously"
    );
    release.send(()).unwrap();
    tokio::time::timeout(
        WAIT,
        tokio::task::spawn_blocking(move || holder.join().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    peer_closed_without_control_rpc(&mut peer).await;
    let closed = snapshot(&mut observations, |value| {
        value.phase == WorkPhase::Closed
            && value
                .last_submission
                .as_ref()
                .is_some_and(|report| report.kind == WorkActionKind::Close)
    })
    .await;
    assert!(!closed.start.as_ref().unwrap().persistence_failed);
    assert!(
        closed
            .steers
            .iter()
            .all(|receipt| !receipt.persistence_failed)
    );
    assert!(
        closed
            .steers
            .iter()
            .filter(|receipt| receipt.operation.id == STEER_ID)
            .all(|receipt| !receipt.evidence.frame_written
                && !receipt.evidence.core_accepted
                && !receipt.evidence.harness_recorded)
    );
    fixture.no_second_connection().await;
    released(fixture.config.clone()).await;
}

#[tokio::test]
async fn malformed_archive_reports_storage_failure_without_reconnecting_or_adopting_it() {
    let fixture = Fixture::new();
    {
        let mut journal = WorkJournal::open(fixture.config.clone()).unwrap();
        assert!(matches!(
            journal
                .consume(START_ID, START_TEXT, Instant::now() + WAIT)
                .unwrap(),
            ConsumedWork::Created(_)
        ));
    }
    let archive = fixture.config.journal.join("steers");
    fs::write(&archive, b"preserve malformed archive").unwrap();
    let port = open_work_service(fixture.config.clone()).unwrap();
    let mut updates = port.subscribe();
    snapshot(&mut updates, |s| s.start.is_some()).await;
    port.lookup(STEER_ID).unwrap();
    let result = snapshot(&mut updates, |s| {
        s.last_submission.as_ref().is_some_and(|r| r.id == STEER_ID)
    })
    .await;
    assert_eq!(
        result.last_submission.unwrap().error,
        Some(SteerError::Storage)
    );
    assert_eq!(fs::read(archive).unwrap(), b"preserve malformed archive");
    fixture.no_second_connection().await;
    port.close().unwrap();
    snapshot(&mut updates, |s| s.phase == WorkPhase::Closed).await;
}

#[tokio::test]
async fn prepare_steer_detects_lookup_saturated_queue_without_reservation() {
    let (commands, mut queued) = mpsc::channel(1);
    let (snapshots, _) = watch::channel(WorkSnapshot::ready("fixture".into()));
    let (close, _) = watch::channel(false);
    let admission = Arc::new(Mutex::new(Admission::default()));
    let port = Client {
        commands,
        snapshots: snapshots.subscribe(),
        close,
        flight: Arc::new(AtomicBool::new(false)),
        admission: admission.clone(),
        controller: Arc::new(Mutex::new(None)),
        command_seen: Arc::new(tokio::sync::Notify::new()),
    };
    port.lookup(STEER_ID).unwrap();
    assert_eq!(port.commands.capacity(), 0);
    // Capacity is checked before controller access. A target must still be genuinely observed;
    // this fixture obtains one from the existing synthetic observer factory.
    use tokio::io::AsyncWriteExt;
    let (io, mut peer) = tokio::io::duplex(16384);
    let (reader, writer) = tokio::io::split(io);
    let scope = crate::OwnerControlScope::new(
        "synthetic-human-owner".into(),
        THREAD.into(),
        Duration::from_secs(60),
    )
    .unwrap();
    let (connection, _owner) =
        crate::CodexSteerConnection::from_established_io(scope, reader, writer).unwrap();
    let mut activity = connection.subscribe_activity();
    tokio::time::timeout(WAIT,peer.write_all(format!("{}\n",json!({"method":"turn/started","params":{"threadId":THREAD,"turn":turn("inProgress")}})).as_bytes())).await.unwrap().unwrap();
    let target = tokio::time::timeout(WAIT, async {
        loop {
            if let Some(target) = connection.active_turn() {
                break target;
            }
            activity.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(
        port.prepare_steer(
            &target,
            STEER_ID,
            STEER_TEXT,
            Instant::now() + Duration::from_secs(30)
        )
        .err(),
        Some(SteerError::Busy)
    );
    assert_eq!(admission.lock().unwrap().prepare_sequence().unwrap(), 0);
    assert!(!port.flight.load(Ordering::Acquire));
    assert!(queued.try_recv().is_ok());
    connection.shutdown().await.unwrap();
}
