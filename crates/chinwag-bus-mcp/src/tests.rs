use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn message(seq: u64, body: &str) -> BusMessage {
    BusMessage {
        id: format!("native-{seq}"),
        seq,
        ts_iso: "2026-10-30T00:00:00Z".into(),
        room: "#mgmt".into(),
        sender: "source-label".into(),
        body: body.into(),
        to: None,
        task_id: Some("task-label".into()),
        sig_verified: true,
    }
}

struct FixtureSource {
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<(NativeRoom, usize)>>>,
    result: Result<Vec<BusMessage>, InboxError>,
    entered: Option<oneshot::Sender<()>>,
    release: Option<Receiver<()>>,
}

impl InboxReadSource for FixtureSource {
    fn read(&mut self, room: NativeRoom, limit: usize) -> Result<Vec<BusMessage>, InboxError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().expect("fixture lock").push((room, limit));
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
        }
        if let Some(release) = self.release.take() {
            release
                .recv_timeout(Duration::from_secs(3))
                .expect("fixture release");
        }
        self.result.clone()
    }
}

type Fixture = (
    InboxServer,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<(NativeRoom, usize)>>>,
);

async fn fixture(lease: Duration) -> Fixture {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let source = FixtureSource {
        calls: calls.clone(),
        seen: seen.clone(),
        result: Ok(vec![message(7, "Untrusted message text")]),
        entered: None,
        release: None,
    };
    let server = InboxServer::start(NativeRoom::Mgmt, lease, move || {
        Ok((Box::new(source), "http://127.0.0.1:44342/".into()))
    })
    .await
    .expect("fixture launch");
    (server, calls, seen)
}

async fn gated_fixture(lease: Duration) -> (Fixture, oneshot::Receiver<()>, SyncSender<()>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (entered, event) = oneshot::channel();
    let (release, gate) = mpsc::sync_channel(1);
    let source = FixtureSource {
        calls: calls.clone(),
        seen: seen.clone(),
        result: Ok(vec![message(7, "only after the original read")]),
        entered: Some(entered),
        release: Some(gate),
    };
    let server = InboxServer::start(NativeRoom::Mgmt, lease, move || {
        Ok((Box::new(source), "http://127.0.0.1:44342/".into()))
    })
    .await
    .expect("fixture launch");
    ((server, calls, seen), event, release)
}

fn args(value: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(TOOL_NAME)
        .with_arguments(value.as_object().expect("fixture args object").clone())
}

#[test]
fn tool_only_accepts_the_bounded_count_and_no_authority_fields() {
    assert_eq!(parse_read_args(args(json!({}))).unwrap().limit, 20);
    assert_eq!(
        parse_read_args(args(json!({"limit":50}))).unwrap().limit,
        50
    );
    for value in [
        json!({"limit":0}),
        json!({"limit":51}),
        json!({"limit":-1}),
        json!({"limit":1.5}),
        json!({"limit":null}),
        json!({"room":"#eng"}),
        json!({"endpoint":"http://127.0.0.1:1/"}),
        json!({"sender":"Brian"}),
        json!({"grant":"grant-1"}),
        json!({"identity":"CODEX"}),
    ] {
        assert!(parse_read_args(args(value)).is_err());
    }
    assert!(parse_read_args(CallToolRequestParams::new("chinwag_send")).is_err());
}

#[test]
fn byte_cap_drops_whole_records_and_does_not_invent_completeness_or_verification() {
    let oversized = "\u{0001}".repeat(70_000);
    let result = bounded_window(
        vec![
            message(1, "older small record"),
            message(2, &oversized),
            message(3, "newest"),
        ],
        NativeRoom::Mgmt,
        20,
    )
    .unwrap();
    assert!(serde_json::to_vec(&result).unwrap().len() <= wire::MAX_TOOL_DATA_BYTES);
    assert_eq!(result["received_count"], 3);
    assert_eq!(result["returned_count"], 2);
    assert_eq!(result["omitted_for_byte_limit"], 1);
    assert_eq!(result["messages"][0]["seq"], 1);
    assert_eq!(result["messages"][1]["seq"], 3);
    assert_eq!(result["messages"][1]["body"], "newest");
    assert_eq!(result["completeness"], "unknown_bounded_window");
    assert_eq!(result["connector_signature_verification"], false);
    assert_eq!(result["grok_delivery_proven"], false);
    assert_eq!(result["content_trust"], "untrusted_message_data");
    assert!(result["messages"][0].get("sig_verified").is_none());
    let mut wrong_room = message(4, "not granted");
    wrong_room.room = "#eng".into();
    assert_eq!(
        bounded_window(vec![wrong_room], NativeRoom::Mgmt, 1),
        Err(InboxError::InvalidSource)
    );
    assert_eq!(
        bounded_window(vec![message(1, "a"), message(2, "b")], NativeRoom::Mgmt, 1),
        Err(InboxError::InvalidSource)
    );
}

#[tokio::test]
async fn launch_and_capability_listing_are_inert_and_read_scope_is_fixed() {
    let (server, calls, seen) = fixture(Duration::from_secs(10)).await;
    let info = serde_json::to_value(server.get_info()).unwrap();
    assert!(info["capabilities"].get("tools").is_some());
    assert!(info["capabilities"].get("resources").is_none());
    assert!(info["capabilities"].get("prompts").is_none());
    assert_eq!(server.supported_protocol_versions().len(), 2);
    assert!(server.get_tool(TOOL_NAME).is_some());
    assert!(server.get_tool("chinwag_send").is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let result = server
        .start_read(3, Box::new(|| false))
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result["room"], "#mgmt");
    assert_eq!(result["authority"], "owner_local_stdio_unattributed");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(*seen.lock().unwrap(), vec![(NativeRoom::Mgmt, 3)]);
    server.shutdown().await.unwrap();
    assert!(matches!(
        server.start_read(1, Box::new(|| false)),
        Err(InboxError::AdmissionClosed)
    ));
    let mut admission = server.shared.admission.lock().unwrap();
    let id = admission.binding.id;
    assert_eq!(
        admission
            .host
            .inspect_binding(id, Instant::now())
            .unwrap()
            .state,
        chinwag_connector_registry::BindingState::Disconnected
    );
}

#[tokio::test]
async fn expired_grant_prevents_actual_read() {
    let (server, calls, _) = fixture(Duration::from_millis(1)).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let result = server
        .start_read(1, Box::new(|| false))
        .unwrap()
        .await
        .unwrap();
    assert_eq!(result, Err(InboxError::AdmissionClosed));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn grant_expiry_during_original_read_discards_completion() {
    let ((server, calls, _), entered, release) = gated_fixture(Duration::from_millis(50)).await;
    let result = server.start_read(1, Box::new(|| false)).unwrap();
    entered.await.unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    release.send(()).unwrap();
    assert_eq!(result.await.unwrap(), Err(InboxError::AdmissionClosed));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancellation_does_not_free_the_single_reader_or_trigger_another_read() {
    let ((server, calls, _), entered, release) = gated_fixture(Duration::from_secs(10)).await;
    let result = server.start_read(1, Box::new(|| false)).unwrap();
    entered.await.unwrap();
    drop(result);
    assert!(matches!(
        server.start_read(1, Box::new(|| false)),
        Err(InboxError::Busy)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.send(()).unwrap();
    server.shutdown().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelled_at_dispatch_never_invokes_source() {
    let (server, calls, _) = fixture(Duration::from_secs(10)).await;
    assert!(matches!(
        server.start_read(1, Box::new(|| true)),
        Err(InboxError::Cancelled)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // First check is at submission; the second is on the worker at actual dispatch.
    let checks = Arc::new(AtomicUsize::new(0));
    let control = checks.clone();
    let result = server
        .start_read(
            1,
            Box::new(move || control.fetch_add(1, Ordering::SeqCst) > 0),
        )
        .unwrap();
    assert_eq!(result.await.unwrap(), Err(InboxError::Cancelled));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn eof_closes_admission_and_waits_for_original_reader() {
    let ((server, calls, _), entered, release) = gated_fixture(Duration::from_secs(10)).await;
    let result = server.start_read(1, Box::new(|| false)).unwrap();
    entered.await.unwrap();
    let owner = server.clone();
    let stopped = tokio::spawn(async move { owner.shutdown().await });
    tokio::task::yield_now().await;
    assert!(!stopped.is_finished());
    assert!(matches!(
        server.start_read(1, Box::new(|| false)),
        Err(InboxError::AdmissionClosed)
    ));
    release.send(()).unwrap();
    assert_eq!(result.await.unwrap(), Err(InboxError::AdmissionClosed));
    stopped.await.unwrap().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn revoked_generation_rejects_dispatch_without_restoring_authority() {
    let (server, calls, _) = fixture(Duration::from_secs(10)).await;
    {
        let mut admission = server.shared.admission.lock().unwrap();
        let grant = admission.binding.grant;
        admission.host.revoke(grant).unwrap();
    }
    let result = server.start_read(1, Box::new(|| false)).unwrap();
    assert_eq!(result.await.unwrap(), Err(InboxError::AdmissionClosed));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn disabling_builtin_inbox_blocks_source_and_reenable_does_not_restore_grant() {
    let (server, calls, _) = fixture(Duration::from_secs(10)).await;
    {
        let mut admission = server.shared.admission.lock().unwrap();
        admission
            .host
            .set_enabled(BuiltinConnector::NativeInbox, false)
            .unwrap();
    }
    assert_eq!(
        server
            .start_read(1, Box::new(|| false))
            .unwrap()
            .await
            .unwrap(),
        Err(InboxError::AdmissionClosed)
    );
    {
        let mut admission = server.shared.admission.lock().unwrap();
        admission
            .host
            .set_enabled(BuiltinConnector::NativeInbox, true)
            .unwrap();
    }
    assert_eq!(
        server
            .start_read(1, Box::new(|| false))
            .unwrap()
            .await
            .unwrap(),
        Err(InboxError::AdmissionClosed)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_launch_and_backend_errors_are_safe_and_not_empty_successes() {
    for lease in [Duration::ZERO, Duration::from_secs(3601)] {
        let result = InboxServer::start(NativeRoom::Mgmt, lease, || {
            panic!("must reject before factory")
        })
        .await;
        assert!(matches!(result, Err(InboxError::InvalidLaunch)));
    }
    let server = InboxServer::start(NativeRoom::Mgmt, Duration::from_secs(10), || {
        Ok((
            Box::new(FixtureSource {
                calls: Arc::new(AtomicUsize::new(0)),
                seen: Arc::new(Mutex::new(Vec::new())),
                result: Err(InboxError::Unavailable),
                entered: None,
                release: None,
            }),
            "http://127.0.0.1:44342/".into(),
        ))
    })
    .await
    .unwrap();
    let result = server
        .start_read(1, Box::new(|| false))
        .unwrap()
        .await
        .unwrap();
    assert_eq!(result, Err(InboxError::Unavailable));
    let error = serde_json::to_value(error_result(result.unwrap_err())).unwrap();
    assert_eq!(error["isError"], true);
    assert!(
        error["structuredContent"]["error"]
            .as_str()
            .unwrap()
            .contains("unavailable")
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn transport_writer_enforces_line_cap_and_resets_after_newline() {
    let mut writer = wire::BoundedWriter::new(tokio::io::sink());
    writer
        .write_all(&vec![b'x'; wire::MAX_OUTPUT_BYTES])
        .await
        .unwrap();
    assert!(writer.write_all(b"x").await.is_err());
    writer.write_all(b"\n").await.unwrap();
    writer.write_all(b"ok\n").await.unwrap();
}

#[tokio::test]
async fn last_owner_drop_stops_the_idle_blocking_worker() {
    let (server, calls, _) = fixture(Duration::from_secs(10)).await;
    let worker = server.lifetime.worker.lock().await.take().unwrap();
    drop(server);
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn aborting_the_owner_signals_cleanup_and_drains_the_original_read() {
    let ((server, calls, _), entered, release) = gated_fixture(Duration::from_secs(10)).await;
    let result = server.start_read(1, Box::new(|| false)).unwrap();
    entered.await.unwrap();
    let worker = server.lifetime.worker.lock().await.take().unwrap();
    let owner_task = tokio::spawn(async move {
        let _owner = server;
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    owner_task.abort();
    let _ = owner_task.await;
    assert!(!worker.is_finished());
    release.send(()).unwrap();
    assert_eq!(result.await.unwrap(), Err(InboxError::AdmissionClosed));
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelled_shutdown_keeps_the_original_join_handle_for_the_next_owner() {
    let ((server, calls, _), entered, release) = gated_fixture(Duration::from_secs(10)).await;
    let result = server.start_read(1, Box::new(|| false)).unwrap();
    entered.await.unwrap();
    let owner = server.clone();
    let shutdown = tokio::spawn(async move { owner.shutdown().await });
    tokio::task::yield_now().await;
    shutdown.abort();
    let _ = shutdown.await;
    {
        let stored = server.lifetime.worker.lock().await;
        assert!(stored.as_ref().is_some_and(|worker| !worker.is_finished()));
    }
    release.send(()).unwrap();
    assert_eq!(result.await.unwrap(), Err(InboxError::AdmissionClosed));
    server.shutdown().await.unwrap();
    assert!(server.lifetime.worker.lock().await.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn observed_input_eof_closes_admission_before_sdk_handler_drain() {
    let ((server, calls, _), entered, release) = gated_fixture(Duration::from_secs(10)).await;
    let result = server.start_read(1, Box::new(|| false)).unwrap();
    entered.await.unwrap();
    let admission = server.shared.clone();
    let mut input =
        wire::ClosingReader::new(tokio::io::empty(), move || admission.close_admission());
    assert_eq!(input.read(&mut [0_u8; 1]).await.unwrap(), 0);
    assert!(server.shared.closed.load(Ordering::Acquire));
    release.send(()).unwrap();
    assert_eq!(result.await.unwrap(), Err(InboxError::AdmissionClosed));
    server.shutdown().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
