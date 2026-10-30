use super::*;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

const THREAD: &str = "thread-owned-controller";
const ID: &str = "steer-controller-0001";
const TEXT: &str = "Use the revised human direction while this turn is running.";

struct Fixture {
    controller: SteerController,
    owner: ConnectionOwner,
    peer: BufReader<DuplexStream>,
    directory: tempfile::TempDir,
}

async fn fixture(capacity: usize) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let (io, peer) = tokio::io::duplex(capacity);
    let (reader, writer) = tokio::io::split(io);
    let scope = OwnerControlScope::new(
        "explicit-human-controller-fixture".into(),
        THREAD.into(),
        Duration::from_secs(60),
    )
    .unwrap();
    let (controller, owner) = SteerController::from_established_io(
        scope,
        &directory.path().canonicalize().unwrap().join("journal"),
        reader,
        writer,
    )
    .await
    .unwrap();
    Fixture {
        controller,
        owner,
        peer: BufReader::new(peer),
        directory,
    }
}

async fn send(peer: &mut BufReader<DuplexStream>, value: Value) {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    peer.get_mut().write_all(&bytes).await.unwrap();
}

async fn frame(peer: &mut BufReader<DuplexStream>) -> Value {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), peer.read_until(b'\n', &mut bytes))
        .await
        .unwrap()
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn target(f: &mut Fixture) -> ObservedActiveTurn {
    send(
        &mut f.peer,
        json!({"method":"turn/started","params":{
            "threadId":THREAD,"turn":{"id":"turn-active","status":"inProgress","items":[]}
        }}),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(target) = f.controller.active_turn() {
                break target;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

async fn receipt_matching(
    controller: &SteerController,
    predicate: impl Fn(&Receipt) -> bool,
) -> Receipt {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(receipt) = controller.receipt(ID).await.unwrap()
                && predicate(&receipt)
            {
                break receipt;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn durable_before_wire_and_independent_acceptance_while_turn_is_running() {
    let mut f = fixture(65536).await;
    let target = target(&mut f).await;
    let grant = f.owner.human_grant().unwrap();
    let saved = f
        .controller
        .submit_human_text(&grant, &target, ID, TEXT)
        .await
        .unwrap();
    assert!(saved.evidence.frame_written && !saved.evidence.core_accepted);
    let request = frame(&mut f.peer).await;
    let disk = std::fs::read_to_string(
        f.directory
            .path()
            .canonicalize()
            .unwrap()
            .join("journal")
            .join(format!("{ID}.jsonl")),
    )
    .unwrap();
    let first: Value = serde_json::from_str(disk.lines().next().unwrap()).unwrap();
    assert_eq!(first["type"], "saved");
    assert_eq!(first["operation"]["text"], TEXT);
    assert_eq!(request["params"]["expectedTurnId"], "turn-active");
    assert_eq!(request["params"]["clientUserMessageId"], ID);
    assert!(request.get("jsonrpc").is_none());
    send(
        &mut f.peer,
        json!({"method":"item/completed","params":{
            "threadId":THREAD,"turnId":"turn-active","item":{"type":"userMessage",
            "id":"item-1","clientId":ID,"content":[{"type":"text","text":TEXT,"text_elements":[]}]}
        }}),
    )
    .await;
    let recorded = receipt_matching(&f.controller, |r| r.evidence.harness_recorded).await;
    assert!(!recorded.evidence.core_accepted);
    send(
        &mut f.peer,
        json!({"id":request["id"],"result":{"turnId":"turn-active"}}),
    )
    .await;
    let accepted = receipt_matching(&f.controller, |r| r.evidence.core_accepted).await;
    assert!(accepted.evidence.harness_recorded);
    assert!(
        f.controller.active_turn().is_some(),
        "the running turn was never completed"
    );
    assert_eq!(
        f.controller
            .submit_human_text(&grant, &target, ID, TEXT)
            .await
            .unwrap(),
        accepted
    );
    assert_eq!(
        f.controller
            .submit_human_text(&grant, &target, ID, "changed input")
            .await,
        Err(SteerError::Conflict)
    );
    let mut bytes = Vec::new();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            f.peer.read_until(b'\n', &mut bytes)
        )
        .await
        .is_err()
    );
    send(
        &mut f.peer,
        json!({"method":"turn/completed","params":{
            "threadId":THREAD,"turn":{"id":"turn-active","status":"completed","items":[]}
        }}),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while f.controller.active_turn().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        f.controller
            .submit_human_text(&grant, &target, ID, TEXT)
            .await
            .unwrap(),
        accepted
    );
    assert_eq!(
        f.controller
            .submit_human_text(&grant, &target, "steer-controller-new1", TEXT)
            .await,
        Err(SteerError::StaleTarget)
    );
    f.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn consume_before_registration_then_owner_close_is_definitively_not_dispatched() {
    let mut f = fixture(65536).await;
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    Arc::get_mut(&mut f.controller.inner)
        .unwrap()
        .before_dispatch = Some((reached.clone(), resume.clone()));
    let target = target(&mut f).await;
    let grant = f.owner.human_grant().unwrap();
    let controller = f.controller.clone();
    let submit = tokio::spawn(async move {
        controller
            .submit_human_text(&grant, &target, ID, TEXT)
            .await
    });
    reached.notified().await;
    assert!(f.controller.receipt(ID).await.unwrap().is_some());
    f.owner.request_close();
    // Complete event-channel cleanup while Saved exists and no actor registration does.
    {
        let mut worker = f.controller.inner.evidence_worker.lock().await;
        worker.as_mut().unwrap().await.unwrap().unwrap();
        worker.take();
    }
    resume.notify_one();
    let receipt = submit.await.unwrap().unwrap();
    assert!(receipt.evidence.not_dispatched);
    assert!(!receipt.evidence.write_uncertain && !receipt.persistence_failed);
    f.controller.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    assert_eq!(f.peer.read_until(b'\n', &mut bytes).await.unwrap(), 0);
}

#[tokio::test]
async fn caller_cancellation_keeps_original_writer_and_late_core_evidence() {
    let mut f = fixture(1).await;
    let target = target(&mut f).await;
    let grant = f.owner.human_grant().unwrap();
    let controller = f.controller.clone();
    let task = tokio::spawn(async move {
        controller
            .submit_human_text(&grant, &target, ID, TEXT)
            .await
    });
    // Consumed record plus first peer byte makes a partial write possible.
    let first = {
        use tokio::io::AsyncReadExt;
        let mut first = [0u8; 1];
        f.peer.read_exact(&mut first).await.unwrap();
        first[0]
    };
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let mut rest = Vec::new();
    f.peer.read_until(b'\n', &mut rest).await.unwrap();
    rest.insert(0, first);
    let request: Value = serde_json::from_slice(&rest).unwrap();
    send(
        &mut f.peer,
        json!({"id":request["id"],"result":{"turnId":"turn-active"}}),
    )
    .await;
    let receipt = receipt_matching(&f.controller, |r| r.evidence.core_accepted).await;
    assert!(!receipt.persistence_failed);
    f.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_persistence_dispatches_no_frame_and_restart_does_not_replay() {
    let mut f = fixture(65536).await;
    let target = target(&mut f).await;
    let grant = f.owner.human_grant().unwrap();
    let file = f
        .directory
        .path()
        .canonicalize()
        .unwrap()
        .join("journal")
        .join(format!("{ID}.jsonl"));
    std::fs::write(&file, b"preserve foreign partial bytes").unwrap();
    assert_eq!(
        f.controller
            .submit_human_text(&grant, &target, ID, TEXT)
            .await,
        Err(SteerError::Storage)
    );
    assert_eq!(
        std::fs::read(file).unwrap(),
        b"preserve foreign partial bytes"
    );
    f.controller.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    assert_eq!(f.peer.read_until(b'\n', &mut bytes).await.unwrap(), 0);
    let path = f.directory.path().canonicalize().unwrap().join("journal");
    drop(f.controller);
    let (io, mut peer) = tokio::io::duplex(65536);
    let (r, w) = tokio::io::split(io);
    let scope = OwnerControlScope::new(
        "new-owner-human-fixture".into(),
        THREAD.into(),
        Duration::from_secs(60),
    )
    .unwrap();
    let (controller, _owner) = SteerController::from_established_io(scope, &path, r, w)
        .await
        .unwrap();
    assert_eq!(controller.receipt(ID).await, Err(SteerError::Storage));
    controller.shutdown().await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    assert_eq!(peer.read_to_end(&mut bytes).await.unwrap(), 0);
}

#[test]
fn constructor_without_runtime_returns_fixed_error_before_creating_journal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().canonicalize().unwrap().join("journal");
    let scope = OwnerControlScope::new(
        "explicit-test".into(),
        THREAD.into(),
        Duration::from_secs(60),
    )
    .unwrap();
    let mut future = Box::pin(SteerController::from_established_io(
        scope,
        &path,
        tokio::io::empty(),
        tokio::io::sink(),
    ));
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    assert!(matches!(
        future.as_mut().poll(&mut cx),
        std::task::Poll::Ready(Err(SteerError::Unavailable))
    ));
    assert!(!path.exists());
}

#[tokio::test]
async fn consumed_fresh_bootstrap_then_live_steer_does_not_wait_for_initial_ack() {
    use crate::work_journal::{ConsumedWork, WorkJournal};
    use std::time::Instant;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let config = crate::WorkConfig::new(
        &root.join("human-declared.sock"),
        &root.join("selected-folder"),
        &root.join("work"),
        crate::RuntimePolicyDeclaration::DedicatedRuntimeWithExplicitLogin,
    )
    .unwrap();
    let mut work_journal = WorkJournal::open(config).unwrap();
    let ConsumedWork::Created(work) = work_journal
        .consume(
            "initial-controller01",
            "Initial human task",
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap()
    else {
        panic!("new consumed work");
    };
    let (io, peer) = tokio::io::duplex(65536);
    let (reader, mut writer) = tokio::io::split(io);
    let mut reader = BufReader::new(reader);
    let mut peer = BufReader::new(peer);
    let (allow_initial, wait_initial) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let init = frame(&mut peer).await;
        assert_eq!(init["method"], "initialize");
        send(&mut peer,json!({"id":init["id"],"result":{"userAgent":"synthetic","codexHome":"/private/not-retained","platformFamily":"unix","platformOs":"macos"}})).await;
        assert_eq!(frame(&mut peer).await, json!({"method":"initialized"}));
        let new_thread = frame(&mut peer).await;
        assert_eq!(new_thread["method"], "thread/start");
        // Both frames fit one read; the bootstrap must retain read-ahead.
        send(
            &mut peer,
            json!({"id":new_thread["id"],"result":{"thread":{"id":THREAD,"turns":[],"cwd":new_thread["params"]["cwd"]}}}),
        )
        .await;
        send(
            &mut peer,
            json!({"method":"thread/started","params":{"thread":{"id":THREAD}}}),
        )
        .await;
        let initial = frame(&mut peer).await;
        assert_eq!(initial["method"], "turn/start");
        assert_eq!(
            initial["params"]["clientUserMessageId"],
            "initial-controller01"
        );
        send(&mut peer,json!({"method":"turn/started","params":{"threadId":THREAD,"turn":{"id":"turn-first-owned","status":"inProgress","items":[]}}})).await;
        let steer = frame(&mut peer).await;
        assert_eq!(steer["method"], "turn/steer");
        assert_eq!(steer["params"]["expectedTurnId"], "turn-first-owned");
        send(
            &mut peer,
            json!({"id":steer["id"],"result":{"turnId":"turn-first-owned"}}),
        )
        .await;
        wait_initial.await.unwrap();
        send(&mut peer,json!({"id":initial["id"],"result":{"turn":{"id":"turn-first-owned","status":"inProgress","items":[]}}})).await;
        send(&mut peer,json!({"method":"turn/completed","params":{"threadId":THREAD,"turn":{"id":"turn-first-owned","status":"completed","items":[]}}})).await;
        peer
    });
    let proof = crate::work_bootstrap::bootstrap(&work, &mut reader, &mut writer)
        .await
        .unwrap();
    let thread = proof.thread_id().to_owned();
    let (controller, owner) =
        SteerController::from_fresh_thread(proof, &root.join("steers"), reader, writer)
            .await
            .unwrap();
    let capsule = work_journal
        .commit_initial(&work, &thread, controller.transport_epoch())
        .unwrap();
    assert!(controller.dispatch_initial(capsule).await.frame_written);
    let mut activity = controller.subscribe_activity();
    let target = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(target) = activity.borrow().target.clone() {
                break target;
            }
            activity.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let action = controller
        .capture_human_action(&target, "steer-controller-live1", TEXT)
        .unwrap();
    let grant = owner.authorize_action(&action).unwrap();
    let receipt = controller
        .submit_human_text(&grant, action.target(), action.id(), action.text())
        .await
        .unwrap();
    assert!(receipt.evidence.frame_written);
    let mut updates = controller.subscribe_receipts();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if controller
                .receipt(action.id())
                .await
                .unwrap()
                .unwrap()
                .evidence
                .core_accepted
            {
                break;
            }
            updates.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(
        !activity
            .borrow()
            .initial
            .as_ref()
            .unwrap()
            .evidence
            .core_accepted,
        "Steer was accepted while initial Start reply remained unconfirmed"
    );
    allow_initial.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if activity.borrow().completed
                && activity
                    .borrow()
                    .initial
                    .as_ref()
                    .unwrap()
                    .evidence
                    .core_accepted
            {
                break;
            }
            activity.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(controller.active_turn().is_none());
    let _peer = server.await.unwrap();
    controller.shutdown().await.unwrap();
    assert!(
        !controller
            .receipt(action.id())
            .await
            .unwrap()
            .unwrap()
            .persistence_failed,
        "Initial operation never went to the separate Steer journal"
    );
}
