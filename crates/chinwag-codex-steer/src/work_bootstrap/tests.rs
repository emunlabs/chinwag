use super::*;
use tokio::io::{DuplexStream, duplex};

async fn request(peer: &mut BufReader<DuplexStream>) -> Value {
    let mut bytes = Vec::new();
    peer.read_until(b'\n', &mut bytes).await.unwrap();
    wire::unique_value(&bytes).unwrap()
}
async fn send(peer: &mut BufReader<DuplexStream>, value: Value) {
    let mut b = serde_json::to_vec(&value).unwrap();
    b.push(b'\n');
    peer.get_mut().write_all(&b).await.unwrap();
}

#[tokio::test]
async fn bounded_response_preserves_original_order_and_read_ahead() {
    let (left, right) = duplex(4096);
    let mut reader = BufReader::new(left);
    let mut peer = BufReader::new(right);
    let mut queue = VecDeque::new();
    send(
        &mut peer,
        json!({"method":"thread/started","params":{"thread":{"id":"thread-new"}}}),
    )
    .await;
    send(
        &mut peer,
        json!({"id":"matched","result":{"thread":{"id":"thread-new","turns":[],"cwd":"/fixture/selected"}}}),
    )
    .await;
    send(&mut peer,json!({"method":"turn/started","params":{"threadId":"thread-new","turn":{"id":"turn-new","status":"inProgress","items":[]}}})).await;
    let value = response(
        &mut reader,
        "matched",
        &mut queue,
        Instant::now() + std::time::Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(value["thread"]["id"], "thread-new");
    assert_eq!(queue.len(), 1);
    assert_eq!(
        wire::unique_value(&queue.pop_front().unwrap()).unwrap()["method"],
        "thread/started"
    );
    assert_eq!(request(&mut reader).await["method"], "turn/started");
}
#[tokio::test]
async fn foreign_response_duplicate_fields_and_server_request_do_not_mint_proof() {
    for value in [
        json!({"id":"foreign","result":{}}),
        json!({"id":"server-q","method":"item/commandExecution/requestApproval","params":{}}),
    ] {
        let (left, right) = duplex(4096);
        let mut reader = BufReader::new(left);
        let mut peer = BufReader::new(right);
        send(&mut peer, value).await;
        assert!(
            response(
                &mut reader,
                "matched",
                &mut VecDeque::new(),
                Instant::now() + std::time::Duration::from_secs(1)
            )
            .await
            .is_err()
        );
    }
    let (left, mut right) = duplex(4096);
    right
        .write_all(b"{\"id\":\"matched\",\"id\":\"foreign\",\"result\":{}}\n")
        .await
        .unwrap();
    assert!(
        response(
            &mut BufReader::new(left),
            "matched",
            &mut VecDeque::new(),
            Instant::now() + std::time::Duration::from_secs(1)
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn absolute_bootstrap_deadline_and_prefix_capacity_do_not_retry() {
    let (left, _right) = duplex(4096);
    assert!(
        response(
            &mut BufReader::new(left),
            "matched",
            &mut VecDeque::new(),
            Instant::now() - std::time::Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    let (left, right) = duplex(65536);
    let mut reader = BufReader::new(left);
    let mut peer = BufReader::new(right);
    for _ in 0..65 {
        send(
            &mut peer,
            json!({"method":"thread/status/changed","params":{}}),
        )
        .await;
    }
    assert_eq!(
        response(
            &mut reader,
            "matched",
            &mut VecDeque::new(),
            Instant::now() + std::time::Duration::from_secs(1)
        )
        .await
        .unwrap_err(),
        SteerError::Capacity
    );
}

fn committed(temp: &tempfile::TempDir) -> (crate::work_journal::WorkJournal, CommittedWork) {
    let root = temp.path().canonicalize().unwrap();
    let config = crate::WorkConfig::new(
        &root.join("declared.sock"),
        &root.join("selected-folder"),
        &root.join("work-journal"),
        crate::RuntimePolicyDeclaration::DedicatedRuntimeWithExplicitLogin,
    )
    .unwrap();
    let mut journal = crate::work_journal::WorkJournal::open(config).unwrap();
    let crate::work_journal::ConsumedWork::Created(work) = journal
        .consume(
            "human-initial-work01",
            "Initial requested task",
            Instant::now() + std::time::Duration::from_secs(30),
        )
        .unwrap()
    else {
        panic!("fresh consumed fixture");
    };
    (journal, work)
}
#[tokio::test]
async fn actual_consumed_bootstrap_emits_only_fixed_minimal_methods_and_keeps_buffered_notifications()
 {
    let temp = tempfile::tempdir().unwrap();
    let (_journal, work) = committed(&temp);
    let (left, right) = duplex(65536);
    let (r, mut w) = tokio::io::split(left);
    let mut r = BufReader::new(r);
    let mut peer = BufReader::new(right);
    let server = tokio::spawn(async move {
        let init = request(&mut peer).await;
        assert_eq!(init["method"], "initialize");
        assert_eq!(
            init["params"]["capabilities"],
            json!({"explicitGatewayOauth":true,"experimentalApi":false,"requestAttestation":false})
        );
        assert!(
            !init["params"]
                .as_object()
                .unwrap()
                .contains_key("extensions")
        );
        send(&mut peer,json!({"id":init["id"],"result":{"userAgent":"fixture-only","codexHome":"/private/not-projected","platformFamily":"unix","platformOs":"macos"}})).await;
        assert_eq!(request(&mut peer).await, json!({"method":"initialized"}));
        let thread = request(&mut peer).await;
        assert_eq!(thread["method"], "thread/start");
        assert_eq!(thread["params"].as_object().unwrap().len(), 1);
        assert!(
            thread["params"]["cwd"]
                .as_str()
                .unwrap()
                .ends_with("selected-folder")
        );
        send(
            &mut peer,
            json!({"method":"thread/status/changed","params":{"threadId":"thread-new"}}),
        )
        .await;
        send(
            &mut peer,
            json!({"id":thread["id"],"result":{"thread":{"id":"thread-new","turns":[],"cwd":thread["params"]["cwd"]}}}),
        )
        .await;
        send(
            &mut peer,
            json!({"method":"thread/started","params":{"thread":{"id":"thread-new"}}}),
        )
        .await;
        peer
    });
    let proof = bootstrap(&work, &mut r, &mut w).await.unwrap();
    assert_eq!(proof.thread_id(), "thread-new");
    assert_eq!(proof.deadline, work.deadline());
    assert_eq!(proof.id, work.id());
    assert!(String::from_utf8_lossy(&proof.prefix).contains("thread/status/changed"));
    let mut after = Vec::new();
    r.read_until(b'\n', &mut after).await.unwrap();
    assert_eq!(
        wire::unique_value(&after).unwrap()["method"],
        "thread/started"
    );
    let _peer = server.await.unwrap();
}
#[tokio::test]
async fn nonempty_new_thread_is_rejected_and_original_io_stays_with_owner() {
    let temp = tempfile::tempdir().unwrap();
    let (_journal, work) = committed(&temp);
    let (left, right) = duplex(65536);
    let (r, mut w) = tokio::io::split(left);
    let mut r = BufReader::new(r);
    let mut peer = BufReader::new(right);
    let server = tokio::spawn(async move {
        let init = request(&mut peer).await;
        send(&mut peer,json!({"id":init["id"],"result":{"userAgent":"fixture","codexHome":"/private/not-retained","platformFamily":"unix","platformOs":"macos"}})).await;
        request(&mut peer).await;
        let thread = request(&mut peer).await;
        send(&mut peer,json!({"id":thread["id"],"result":{"thread":{"id":"unexpected-existing","cwd":thread["params"]["cwd"],"turns":[{"id":"prior-turn"}]}}})).await;
        send(&mut peer, json!({"method":"owner/retained","params":{}})).await;
        peer
    });
    assert!(matches!(
        bootstrap(&work, &mut r, &mut w).await,
        Err(SteerError::Unavailable)
    ));
    let mut after = Vec::new();
    r.read_until(b'\n', &mut after).await.unwrap();
    assert_eq!(
        wire::unique_value(&after).unwrap()["method"],
        "owner/retained"
    );
    let _peer = server.await.unwrap();
}

#[tokio::test]
async fn response_must_echo_the_exact_committed_work_directory_before_proof() {
    for returned_cwd in [Some("/unexpected/other-project"), None] {
        let temp = tempfile::tempdir().unwrap();
        let (_journal, work) = committed(&temp);
        let (left, right) = duplex(65536);
        let (r, mut w) = tokio::io::split(left);
        let mut r = BufReader::new(r);
        let mut peer = BufReader::new(right);
        let server = tokio::spawn(async move {
            let init = request(&mut peer).await;
            send(&mut peer,json!({"id":init["id"],"result":{"userAgent":"fixture","codexHome":"/private/not-retained","platformFamily":"unix","platformOs":"macos"}})).await;
            request(&mut peer).await;
            let thread = request(&mut peer).await;
            let mut value = json!({"id":thread["id"],"result":{"thread":{"id":"fresh-wrong-directory","turns":[]}}});
            if let Some(cwd) = returned_cwd {
                value["result"]["thread"]["cwd"] = json!(cwd);
            }
            send(&mut peer, value).await;
            peer
        });
        assert!(matches!(
            bootstrap(&work, &mut r, &mut w).await,
            Err(SteerError::Unavailable)
        ));
        let _peer = server.await.unwrap();
    }
}
