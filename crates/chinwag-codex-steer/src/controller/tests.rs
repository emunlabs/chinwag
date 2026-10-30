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
