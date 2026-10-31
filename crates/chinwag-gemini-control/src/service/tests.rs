use super::*;
use serde_json::{Value, json};
use std::{
    path::Path,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf};
const ID: &str = "11111111-1111-4111-8111-111111111111";
const SID: &str = "22222222-2222-4222-8222-222222222222";
const EPOCH: &str = "33333333-3333-4333-8333-333333333333";
fn config(path: &Path) -> WorkConfig {
    WorkConfig::new(
        &path.join("gemini"),
        &"0".repeat(64),
        path,
        &path.join("journal"),
        StartupPolicyDeclaration::ConfiguredRuntimeEffectsManualModeExtensionsDisabled,
    )
    .unwrap()
}
fn start_saved(config: &WorkConfig) -> SavedOperation {
    SavedOperation {
        schema: "chinwag-gemini-operation/v1".into(),
        id: ID.into(),
        kind: ActionKind::Start,
        text: "initial prose".into(),
        session_epoch: EPOCH.into(),
        session_id: None,
        prompt_rpc_id: format!("prompt-{ID}"),
        prompt_generation: 1,
        startup: Some(StartupRecord {
            binary: config.binary.clone(),
            sha256: config.sha256.clone(),
            workdir: config.workdir.clone(),
            policy: "configured_runtime_effects_manual_mode_extensions_disabled".into(),
        }),
    }
}
fn ready() -> (Arc<Shared>, SavedOperation, EvidenceChannel) {
    let conf = config(Path::new("/fixture/work"));
    let saved = start_saved(&conf);
    let (shared, events) = new_shared(conf);
    {
        let mut s = shared.state.lock().unwrap();
        s.epoch = EPOCH.into();
        s.session = Some(SID.into());
        s.initialized = true;
        s.owner_deadline = Some(Instant::now() + Duration::from_secs(900));
        s.records.insert(
            ID.into(),
            Pending {
                saved: saved.clone(),
                evidence: Evidence {
                    frame_written: true,
                    ..Default::default()
                },
                may_written: true,
            },
        );
        s.active = Some(Active {
            operation_id: ID.into(),
            rpc_id: saved.prompt_rpc_id.clone(),
            generation: 1,
            may_written: true,
        });
    }
    shared.publish_now();
    (shared, saved, events)
}
fn now(shared: &Arc<Shared>) -> WorkSnapshot {
    shared.publish_now();
    shared.snapshots.borrow().clone()
}
fn no_bytes(peer: &mut DuplexStream) {
    let mut bytes = [0u8; 1];
    let mut read = ReadBuf::new(&mut bytes);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(peer).poll_read(&mut cx, &mut read),
        Poll::Pending
    ));
}
async fn wait_notify(notify: &tokio::sync::Notify) {
    tokio::time::timeout(Duration::from_secs(3), notify.notified())
        .await
        .unwrap();
}
async fn json_read(peer: &mut DuplexStream) -> Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        loop {
            let byte = peer.read_u8().await.unwrap();
            bytes.push(byte);
            assert!(bytes.len() <= wire::MAX_OUTBOUND);
            if byte == b'\n' {
                break;
            }
        }
        serde_json::from_slice(&bytes).unwrap()
    })
    .await
    .unwrap()
}
async fn send(peer: &mut DuplexStream, v: Value) {
    tokio::time::timeout(
        Duration::from_secs(3),
        peer.write_all(&wire::encode(v).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
}
async fn until(rx: &mut watch::Receiver<WorkSnapshot>, f: impl Fn(&WorkSnapshot) -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if f(&rx.borrow()) {
                return;
            }
            rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}
async fn begin(
    peer: &mut crate::test_support::FixturePeer,
    port: &Arc<dyn HumanWorkPort>,
) -> watch::Receiver<WorkSnapshot> {
    let mut rx = port.subscribe();
    port.start(ID, "initial prose").unwrap();
    let init = json_read(&mut peer.io).await;
    assert_eq!(init["method"], "initialize");
    assert_eq!(init["params"]["clientCapabilities"], json!({}));
    send(&mut peer.io,json!({"jsonrpc":"2.0","id":init["id"],"result":{"protocolVersion":1,"agentInfo":{"name":"gemini-cli","version":CLI_VERSION}}})).await;
    let new = json_read(&mut peer.io).await;
    assert_eq!(new["method"], "session/new");
    assert_eq!(new["params"], json!({"cwd":peer.workdir,"mcpServers":[]}));
    send(&mut peer.io,json!({"jsonrpc":"2.0","id":new["id"],"result":{"sessionId":SID,"modes":{"currentModeId":"default"}}})).await;
    let first = json_read(&mut peer.io).await;
    assert_eq!(first["method"], "session/prompt");
    until(&mut rx, |s| {
        s.start.as_ref().is_some_and(|r| r.evidence.frame_written)
            && s.last_submission
                .as_ref()
                .is_some_and(|r| r.kind == ActionKind::Start && r.saved && r.error.is_none())
            && s.active_prompt.is_some()
    })
    .await;
    rx
}
#[test]
fn fixed_argv_is_configured_manual_mode_without_claiming_isolation() {
    assert_eq!(
        io::argv(),
        vec![
            "--acp",
            "--approval-mode",
            "default",
            "--extensions",
            "none"
        ]
    );
}
#[tokio::test(start_paused = true)]
async fn prompt_has_no_artificial_ack_timeout() {
    let (shared, saved, _events) = ready();
    {
        let mut s = shared.state.lock().unwrap();
        s.active = None;
        s.records.get_mut(ID).unwrap().may_written = false;
    }
    let (host, mut peer) = tokio::io::duplex(65536);
    *shared.writer.lock().await = Some(Box::new(host));
    let e = io::write_prompt(&shared, &saved, Instant::now() + Duration::from_secs(30)).await;
    assert!(e.frame_written);
    let frame = json_read(&mut peer).await;
    assert_eq!(frame["method"], "session/prompt");
    tokio::time::advance(Duration::from_secs(120)).await;
    let s = shared.state.lock().unwrap();
    assert!(s.active.is_some());
    assert!(!s.records[ID].evidence.terminal_unknown);
    assert!(!s.records[ID].evidence.write_uncertain);
}
#[tokio::test]
async fn final_input_admission_and_end_input_share_one_fence() {
    let (shared, saved, _events) = ready();
    {
        let mut s = shared.state.lock().unwrap();
        s.active = None;
        s.records.get_mut(ID).unwrap().may_written = false;
    }
    let (host, mut peer) = tokio::io::duplex(4096);
    *shared.writer.lock().await = Some(Box::new(host));
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    *shared.before_write.lock().unwrap() = Some((entered.clone(), resume.clone()));
    let owner = shared.clone();
    let task = tokio::spawn(async move {
        io::write_prompt(&owner, &saved, Instant::now() + Duration::from_secs(30)).await
    });
    wait_notify(&entered).await;
    shared.end_input();
    resume.notify_one();
    let e = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    assert!(e.not_dispatched && !e.write_uncertain);
    assert!(!shared.state.lock().unwrap().records[ID].may_written);
    no_bytes(&mut peer);
}
#[test]
fn mode_or_permission_intervention_keeps_cancel_target_without_enabling_new_prompt() {
    let (shared, _saved, _events) = ready();
    let (tx, mut rx) = mpsc::channel(8);
    let client = Client {
        shared: shared.clone(),
        commands: tx,
    };
    let target = now(&shared).session.clone().unwrap();
    observe(
        &shared,
        Event::Update {
            session: SID.into(),
            update: Update::Mode("yolo".into()),
        },
    );
    assert!(!now(&shared).can_prompt);
    assert!(now(&shared).active_prompt.is_some());
    assert_eq!(
        client.prompt(&target, &new_operation_id().unwrap(), "no new prompt"),
        Err(GeminiError::Busy)
    );
    let active = now(&shared).active_prompt.clone().unwrap();
    client
        .cancel(&active, &new_operation_id().unwrap())
        .unwrap();
    assert!(matches!(rx.try_recv(), Ok(Command::Cancel(_))));
}
#[test]
fn scope_expiry_does_not_invent_terminal_or_loss() {
    let (shared, _saved, _events) = ready();
    shared.state.lock().unwrap().owner_deadline = Some(Instant::now() - Duration::from_secs(1));
    shared.publish();
    let s = now(&shared);
    assert!(s.control_expired);
    assert!(s.active_prompt.is_none());
    assert_eq!(s.phase, WorkPhase::Prompting);
    drop(s);
    assert!(
        shared.state.lock().unwrap().records[ID]
            .evidence
            .terminal
            .is_none()
    );
    assert!(
        !shared.state.lock().unwrap().records[ID]
            .evidence
            .terminal_unknown
    );
}
#[test]
fn rpc_error_never_becomes_cancel_ack_or_reopens_prompt_control() {
    let (shared, saved, _events) = ready();
    observe(
        &shared,
        Event::Response {
            id: RpcId::String(saved.prompt_rpc_id),
            result: None,
            error: true,
        },
    );
    let s = now(&shared);
    assert_eq!(s.phase, WorkPhase::OwnerActionRequired);
    assert!(!s.can_prompt);
    drop(s);
    let state = shared.state.lock().unwrap();
    assert!(state.active.is_none());
    assert!(state.records[ID].evidence.rpc_error);
    assert!(state.records[ID].evidence.terminal.is_none());
}
#[tokio::test]
async fn permission_response_can_precede_terminal_and_notification_nondispatch_without_storage_failure()
 {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (shared, saved, mut events) = ready();
    let cancel_id = new_operation_id().unwrap();
    let cancel = SavedOperation {
        schema: "chinwag-gemini-operation/v1".into(),
        id: cancel_id.clone(),
        kind: ActionKind::Cancel,
        text: String::new(),
        session_epoch: EPOCH.into(),
        session_id: Some(SID.into()),
        prompt_rpc_id: saved.prompt_rpc_id.clone(),
        prompt_generation: 1,
        startup: None,
    };
    let journal = Arc::new(Mutex::new(
        OperationJournal::open(&root.join("journal")).unwrap(),
    ));
    let copy = cancel.clone();
    assert!(matches!(
        store(&journal, move |j| j.consume(copy)).await.unwrap(),
        Consume::Created(_)
    ));
    let request = RpcId::String("permission-1".into());
    {
        let mut s = shared.state.lock().unwrap();
        s.records.insert(
            cancel_id.clone(),
            Pending {
                saved: cancel.clone(),
                evidence: Evidence::default(),
                may_written: false,
            },
        );
        s.permissions.insert(
            request.clone(),
            Permission {
                rpc_id: saved.prompt_rpc_id.clone(),
                generation: 1,
            },
        );
        s.cancel = Some(CancelWindow {
            saved: cancel.clone(),
            deadline: Instant::now() + Duration::from_secs(30),
            committed: true,
            writer_retired: false,
            terminal_seen: false,
            jobs: 0,
            written: 0,
            scheduled: BTreeSet::new(),
        });
    }
    let (host, mut peer) = tokio::io::duplex(65536);
    *shared.writer.lock().await = Some(Box::new(host));
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    *shared.before_write.lock().unwrap() = Some((entered.clone(), resume.clone()));
    schedule_permission(&shared, request);
    wait_notify(&entered).await;
    let owner = shared.clone();
    let c = cancel.clone();
    let notification = tokio::spawn(async move {
        io::write_cancel(&owner, &c, Instant::now() + Duration::from_secs(30)).await
    });
    resume.notify_one();
    let response = json_read(&mut peer).await;
    assert_eq!(
        response["result"],
        json!({"outcome":{"outcome":"cancelled"}})
    );
    wait_notify(&entered).await;
    observe(
        &shared,
        Event::Response {
            id: RpcId::String(saved.prompt_rpc_id),
            result: Some(json!({"stopReason":"cancelled"})),
            error: false,
        },
    );
    assert!(now(&shared).cancel_pending);
    assert!(!now(&shared).can_prompt);
    resume.notify_one();
    let nd = tokio::time::timeout(Duration::from_secs(3), notification)
        .await
        .unwrap()
        .unwrap();
    assert!(nd.not_dispatched);
    let written = shared
        .state
        .lock()
        .unwrap()
        .cancel
        .as_ref()
        .unwrap()
        .written;
    assert_eq!(written, 1);
    let mut count = 0;
    while let Ok((id, e)) = events.try_recv() {
        if id == cancel_id {
            persist(&shared, &journal, &id, e).await.unwrap();
            count += 1;
        }
    }
    assert!(count >= 1);
    let r = persist(&shared, &journal, &cancel_id, nd).await.unwrap();
    assert!(!r.persistence_failed);
    assert!(r.evidence.not_dispatched);
    assert_eq!(r.evidence.permission_cancel_responses_written, 1);
    finish_cancel_writer(&shared, &cancel);
    assert!(!now(&shared).cancel_pending);
    no_bytes(&mut peer);
}
#[tokio::test]
async fn actual_port_version_mismatch_prevents_session_and_model_prompt() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (port, mut peer) =
        crate::test_support::open_fixture_service(&root.join("journal")).unwrap();
    let mut rx = port.subscribe();
    port.start(ID, "initial prose").unwrap();
    let init = json_read(&mut peer.io).await;
    send(&mut peer.io,json!({"jsonrpc":"2.0","id":init["id"],"result":{"protocolVersion":1,"agentInfo":{"name":"gemini-cli","version":"0.65.0"}}})).await;
    until(&mut rx, |s| {
        s.start.as_ref().is_some_and(|r| r.evidence.not_dispatched)
    })
    .await;
    no_bytes(&mut peer.io);
    assert!(rx.borrow().session.is_none());
    port.end_input().unwrap();
    peer.finish(0);
}
#[tokio::test]
async fn actual_port_busy_cancel_terminal_then_distinct_human_prompt_without_replay() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (port, mut peer) =
        crate::test_support::open_fixture_service(&root.join("journal")).unwrap();
    let mut rx = begin(&mut peer, &port).await;
    let target = rx.borrow().active_prompt.clone().unwrap();
    let session = rx.borrow().session.clone().unwrap();
    assert_eq!(
        port.prompt(&session, &new_operation_id().unwrap(), "must not overlap"),
        Err(GeminiError::Busy)
    );
    let cancel_id = new_operation_id().unwrap();
    port.cancel(&target, &cancel_id).unwrap();
    let cancel = json_read(&mut peer.io).await;
    assert_eq!(
        cancel,
        json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":SID}})
    );
    until(&mut rx, |s| {
        s.operations
            .iter()
            .any(|r| r.operation.id == cancel_id && r.evidence.frame_written)
    })
    .await;
    assert!(rx.borrow().cancel_pending);
    assert!(rx.borrow().active_prompt.is_some());
    send(
        &mut peer.io,
        json!({"jsonrpc":"2.0","id":target.rpc_id(),"result":{"stopReason":"cancelled"}}),
    )
    .await;
    until(&mut rx, |s| {
        s.can_prompt
            && !s.cancel_pending
            && s.start
                .as_ref()
                .is_some_and(|r| r.evidence.terminal == Some(StopReason::Cancelled))
    })
    .await;
    let next = new_operation_id().unwrap();
    let next_session = rx.borrow().session.clone().unwrap();
    port.prompt(&next_session, &next, "a separate human prompt")
        .unwrap();
    let prompt = json_read(&mut peer.io).await;
    assert_eq!(prompt["method"], "session/prompt");
    assert_eq!(prompt["id"], format!("prompt-{next}"));
    assert_ne!(prompt["id"], target.rpc_id());
    assert!(
        rx.borrow()
            .operations
            .iter()
            .find(|r| r.operation.id == cancel_id)
            .unwrap()
            .evidence
            .terminal
            .is_none()
    );
    port.end_input().unwrap();
    peer.finish(0);
}
#[tokio::test]
async fn actual_full_write_then_eof_marks_terminal_unknown_only_for_registered_effects() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (port, mut peer) =
        crate::test_support::open_fixture_service(&root.join("journal")).unwrap();
    let mut rx = begin(&mut peer, &port).await;
    peer.io.shutdown().await.unwrap();
    until(&mut rx, |s| {
        s.lifecycle.stdout_eof
            && s.start
                .as_ref()
                .is_some_and(|r| r.evidence.terminal_unknown)
    })
    .await;
    assert!(rx.borrow().start.as_ref().unwrap().evidence.frame_written);
    assert!(rx.borrow().active_prompt.is_none());
    assert!(!rx.borrow().can_prompt);
    port.end_input().unwrap();
    peer.finish(0);
}

struct NeverSpawn(Arc<AtomicBool>);
impl Spawner for NeverSpawn {
    fn spawn(
        &self,
        _: WorkConfig,
        _: Instant,
        _: Arc<AtomicBool>,
        _: Arc<Mutex<()>>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ChildIo>> + Send>> {
        self.0.store(true, Ordering::Release);
        Box::pin(async { Err(GeminiError::Unavailable) })
    }
}
#[tokio::test]
async fn actual_port_failed_start_consume_projects_original_nondispatch_without_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (shared, events) = new_shared(config(&root));
    shared.fail_consume.store(true, Ordering::Release);
    let spawned = Arc::new(AtomicBool::new(false));
    let port = launch_owner(shared, events, Arc::new(NeverSpawn(spawned.clone()))).unwrap();
    let mut rx = port.subscribe();
    port.start(ID, "retained original draft").unwrap();
    until(&mut rx, |s| {
        s.phase == WorkPhase::OwnerActionRequired
            && s.start
                .as_ref()
                .is_some_and(|r| r.persistence_failed && r.evidence.not_dispatched)
            && s.last_submission.as_ref().is_some_and(|r| {
                r.kind == ActionKind::Start && r.error == Some(GeminiError::Storage)
            })
    })
    .await;
    let original = rx.borrow().start.clone().unwrap();
    assert_eq!(original.operation.id, ID);
    assert_eq!(original.operation.text, "retained original draft");
    assert!(
        !original.evidence.frame_written
            && !original.evidence.write_uncertain
            && !original.evidence.terminal_unknown
    );
    assert!(!rx.borrow().last_submission.as_ref().unwrap().saved);
    assert!(!spawned.load(Ordering::Acquire));
    assert!(!rx.borrow().can_prompt);
    port.lookup(ID).unwrap();
    until(&mut rx, |s| {
        s.last_submission
            .as_ref()
            .is_some_and(|r| r.kind == ActionKind::Lookup)
    })
    .await;
    assert!(rx.borrow().start.as_ref().unwrap().persistence_failed);
    assert!(!spawned.load(Ordering::Acquire));
    port.end_input().unwrap();
}

#[tokio::test]
async fn synchronous_port_call_returns_while_subscriber_holds_read_guard() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (port, peer) = crate::test_support::open_fixture_service(&root.join("journal")).unwrap();
    let mut snapshots = port.subscribe();
    let held = snapshots.borrow();
    let (published, completed) = std::sync::mpsc::sync_channel(1);
    let handle = std::thread::spawn(move || {
        let result = port.end_input();
        let _ = published.send(result);
    });
    let result = completed
        .recv_timeout(Duration::from_secs(3))
        .expect("public API must not acquire its own subscriber write-lock");
    assert_eq!(result, Ok(()));
    drop(held);
    tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(move || handle.join()),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    until(&mut snapshots, |s| s.phase == WorkPhase::InputEnded).await;
    peer.finish(0);
}

#[test]
fn foreign_session_update_is_a_hard_fault_with_honest_terminal_uncertainty() {
    let (shared, saved, _events) = ready();
    observe(
        &shared,
        Event::Update {
            session: "44444444-4444-4444-8444-444444444444".into(),
            update: Update::Text("foreign text".into()),
        },
    );
    assert!(
        shared.state.lock().unwrap().records[ID]
            .evidence
            .terminal_unknown
    );
    assert!(now(&shared).active_prompt.is_none());
    assert!(now(&shared).agent_text.is_none());
    observe(
        &shared,
        Event::Response {
            id: RpcId::String(saved.prompt_rpc_id),
            result: Some(json!({"stopReason":"end_turn"})),
            error: false,
        },
    );
    let s = shared.state.lock().unwrap();
    assert_eq!(s.records[ID].evidence.terminal, Some(StopReason::EndTurn));
    assert!(s.records[ID].evidence.terminal_unknown);
}
#[test]
fn duplicate_permission_is_hard_loss_but_first_intervention_is_not() {
    let (shared, _saved, _events) = ready();
    let request = RpcId::String("permission-once".into());
    observe(
        &shared,
        Event::Permission {
            id: request.clone(),
            session: SID.into(),
        },
    );
    assert!(
        !shared.state.lock().unwrap().records[ID]
            .evidence
            .terminal_unknown
    );
    assert!(now(&shared).active_prompt.is_some());
    observe(
        &shared,
        Event::Permission {
            id: request,
            session: SID.into(),
        },
    );
    assert!(
        shared.state.lock().unwrap().records[ID]
            .evidence
            .terminal_unknown
    );
    assert!(now(&shared).active_prompt.is_none());
}
