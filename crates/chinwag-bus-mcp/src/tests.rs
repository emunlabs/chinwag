use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

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
    let mut input = wire::ClosingReader::new(tokio::io::empty(), move |end| {
        admission.observation.input_ended(end);
        admission.close_admission();
    });
    assert_eq!(input.read(&mut [0_u8; 1]).await.unwrap(), 0);
    assert!(server.shared.closed.load(Ordering::Acquire));
    let snapshot = server.lifecycle_snapshot();
    assert!(snapshot.input_eof_seen);
    assert!(!snapshot.input_error_seen);
    assert!(!snapshot.owner_close_requested);
    assert_eq!(snapshot.worker_state, WorkerState::DrainNotObserved);
    release.send(()).unwrap();
    assert_eq!(result.await.unwrap(), Err(InboxError::AdmissionClosed));
    server.shutdown().await.unwrap();
    assert_eq!(
        server.lifecycle_snapshot().worker_state,
        WorkerState::Drained
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn actual_sdk_hooks_allow_catalogue_before_initialized_without_reading_bus() {
    for (protocol, expected) in [
        ("2025-06-18", NegotiatedProtocol::June2025),
        ("2025-11-25", NegotiatedProtocol::November2025),
    ] {
        let (server, calls, _) = fixture(Duration::from_secs(10)).await;
        let owner = server.clone();
        let admission = server.shared.clone();
        let (peer, transport) = tokio::io::duplex(16_384);
        let (input, output) = tokio::io::split(transport);
        let transport = AsyncRwTransport::new(
            wire::ClosingReader::new(input, move |end| {
                admission.observation.input_ended(end);
                admission.close_admission();
            }),
            output,
        );
        let task = tokio::spawn(async move {
            server
                .serve(transport)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap()
        });
        let (input, mut output) = tokio::io::split(peer);
        let mut input = BufReader::new(input);
        let mut line = String::new();
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":protocol,"capabilities":{},
            "clientInfo":{"name":"DO-NOT-RETAIN-PEER","version":"PRIVATE-VERSION"}
        }});
        output
            .write_all(format!("{init}\n").as_bytes())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), input.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap()["result"]["protocolVersion"],
            protocol
        );
        assert_eq!(
            owner.lifecycle_snapshot().negotiated_protocol,
            Some(expected)
        );
        assert!(!owner.lifecycle_snapshot().initialized_notification_seen);
        output
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n")
            .await
            .unwrap();
        line.clear();
        tokio::time::timeout(Duration::from_secs(1), input.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap()["result"]["tools"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let snapshot = owner.lifecycle_snapshot();
        assert_eq!(snapshot.catalogue_outputs_prepared, 1);
        assert_eq!(snapshot.read_windows_prepared, 0);
        assert!(!snapshot.initialized_notification_seen);
        assert_eq!(snapshot.protocol_end, ProtocolEnd::NotObserved);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        output
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !owner.lifecycle_snapshot().initialized_notification_seen {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let snapshot_json = serde_json::to_string(&owner.lifecycle_snapshot()).unwrap();
        assert!(!snapshot_json.contains("DO-NOT-RETAIN-PEER"));
        assert!(!snapshot_json.contains("PRIVATE-VERSION"));
        output.shutdown().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap(),
            QuitReason::Closed
        ));
        owner.shutdown().await.unwrap();
        let snapshot = owner.lifecycle_snapshot();
        assert!(snapshot.input_eof_seen);
        assert!(snapshot.owner_close_requested);
        assert_eq!(snapshot.worker_state, WorkerState::Drained);
    }
}

#[tokio::test]
async fn snapshots_do_not_wait_for_read_mutex_or_renew_the_projected_lease() {
    let ((server, calls, _), entered, release) = gated_fixture(Duration::from_millis(20)).await;
    let result = server.start_read(1, Box::new(|| false)).unwrap();
    entered.await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    let owner = server.clone();
    let snapshot = tokio::task::spawn_blocking(move || owner.lifecycle_snapshot());
    let observed = tokio::time::timeout(Duration::from_millis(100), snapshot).await;
    release.send(()).unwrap();
    server.shutdown().await.unwrap();
    let snapshot = observed
        .expect("snapshot must not wait for the admission mutex")
        .unwrap();
    assert!(snapshot.lease_expired);
    assert!(!snapshot.admission_closed);
    assert_eq!(snapshot.read_windows_prepared, 0);
    assert!(server.lifecycle_snapshot().lease_expired);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(result.await.unwrap().is_err());
}

#[tokio::test]
async fn prepared_outputs_reserve_total_byte_budget_and_counters_saturate() {
    let (server, calls, _) = fixture(Duration::from_secs(10)).await;
    assert!(
        server
            .prepare_read_output(json!({"bad":"x".repeat(wire::MAX_TOOL_DATA_BYTES)}))
            .is_err()
    );
    assert_eq!(server.lifecycle_snapshot().read_windows_prepared, 0);
    let large = "x".repeat(12_000);
    let value = bounded_window(
        (1..=50).map(|seq| message(seq, &large)).collect(),
        NativeRoom::Mgmt,
        50,
    )
    .unwrap();
    server.shared.observation.saturate_counters_for_test();
    server.shared.observation.catalogue_prepared();
    let result = server.prepare_read_output(value).unwrap();
    let bytes = serde_json::to_vec(&result).unwrap();
    assert!(bytes.len() <= wire::MAX_TOOL_DATA_BYTES);
    assert!(result["omitted_for_byte_limit"].as_u64().unwrap() > 0);
    assert_eq!(
        result["connection_observation"]["read_windows_prepared"],
        u64::MAX
    );
    assert_eq!(
        server.lifecycle_snapshot().catalogue_outputs_prepared,
        u64::MAX
    );
    assert_eq!(
        result["connection_observation"]["output_evidence"],
        "prepared_only"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.shutdown().await.unwrap();
    let summary = terminal_summary(server.lifecycle_snapshot()).unwrap();
    assert!(summary.len() <= wire::OBSERVATION_BYTES + 1);
    assert_eq!(summary.iter().filter(|byte| **byte == b'\n').count(), 1);
    let summary: Value = serde_json::from_slice(&summary).unwrap();
    assert_eq!(summary["schema"], "chinwag-mcp-connection-terminal/v1");
    assert_eq!(summary["connection_observation"]["worker_state"], "drained");
}

#[tokio::test]
async fn owner_abort_is_observed_separately_from_transport_end_and_awaited_drain() {
    let ((server, calls, _), entered, release) = gated_fixture(Duration::from_secs(10)).await;
    let result = server.start_read(1, Box::new(|| false)).unwrap();
    entered.await.unwrap();
    let observed = server.shared.clone();
    let worker = server.lifetime.worker.lock().await.take().unwrap();
    let owner = tokio::spawn(async move {
        let _owner = server;
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    owner.abort();
    let _ = owner.await;
    let snapshot = observed.observation.snapshot(Instant::now());
    assert!(snapshot.admission_closed && snapshot.owner_close_requested);
    assert!(!snapshot.input_eof_seen && !snapshot.input_error_seen);
    assert_eq!(snapshot.protocol_end, ProtocolEnd::NotObserved);
    assert_eq!(snapshot.worker_state, WorkerState::DrainNotObserved);
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
async fn actual_input_error_closes_admission_without_claiming_eof_or_raw_error() {
    struct FailedInput;
    impl tokio::io::AsyncRead for FailedInput {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("PRIVATE-ERROR-NOT-OBSERVABLE")))
        }
    }
    let (server, calls, _) = fixture(Duration::from_secs(10)).await;
    let admission = server.shared.clone();
    let mut input = wire::ClosingReader::new(FailedInput, move |end| {
        admission.observation.input_ended(end);
        admission.close_admission();
    });
    assert!(input.read(&mut [0u8; 1]).await.is_err());
    let snapshot = server.lifecycle_snapshot();
    assert!(snapshot.input_error_seen && snapshot.admission_closed);
    assert!(!snapshot.input_eof_seen);
    assert_eq!(snapshot.protocol_end, ProtocolEnd::NotObserved);
    server.shutdown().await.unwrap();
    let terminal = terminal_summary(server.lifecycle_snapshot()).unwrap();
    assert!(
        !String::from_utf8(terminal)
            .unwrap()
            .contains("PRIVATE-ERROR")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
