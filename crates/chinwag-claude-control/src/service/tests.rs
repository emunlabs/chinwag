use super::*;
use serde_json::{Value, json};
use std::{
    path::Path,
    task::{Context, Poll, Waker},
};
use tokio::io::{DuplexStream, ReadBuf};
const ID: &str = "11111111-1111-4111-8111-111111111111";
const SESSION: &str = "22222222-2222-4222-8222-222222222222";
const EPOCH: &str = "33333333-3333-4333-8333-333333333333";
fn config(path: &Path) -> WorkConfig {
    WorkConfig::new(
        &path.join("claude"),
        &"0".repeat(64),
        path,
        &path.join("journal"),
        StartupPolicyDeclaration::ManagedPolicyProseOnly,
    )
    .unwrap()
}
fn ready() -> (
    Arc<Shared>,
    SavedInput,
    mpsc::Receiver<(String, InputEvidence)>,
) {
    let (shared, events) = new_shared(config(Path::new("/fixture/work")));
    let saved = SavedInput {
        schema: "chinwag-claude-input/v1".into(),
        id: ID.into(),
        session_epoch: EPOCH.into(),
        session_id: SESSION.into(),
        kind: ActionKind::Direction,
        timing: InputTiming::Now,
        text: "a literal direction".into(),
        startup: None,
    };
    {
        let mut s = shared.state.lock().unwrap();
        s.epoch = EPOCH.into();
        s.session_id = SESSION.into();
        s.initialized = true;
        s.corroborated = true;
        s.owner_deadline = Some(Instant::now() + Duration::from_secs(900));
        s.records.insert(
            ID.into(),
            Pending {
                ticket: Admission::default().admit(None, &saved.id).unwrap(),
                saved: saved.clone(),
                evidence: InputEvidence::default(),
                may_written: false,
            },
        );
        let mut initial = saved.clone();
        initial.id = "44444444-4444-4444-8444-444444444444".into();
        initial.kind = ActionKind::Start;
        s.records.insert(
            initial.id.clone(),
            Pending {
                ticket: Admission::default().admit(None, &initial.id).unwrap(),
                saved: initial,
                evidence: InputEvidence::default(),
                may_written: true,
            },
        );
    }
    // This pure observer fixture has no owner publication task.
    shared.publish_now();
    (shared, saved, events)
}
fn assert_no_bytes(peer: &mut DuplexStream) {
    let mut bytes = [0u8; 1];
    let mut b = ReadBuf::new(&mut bytes);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(peer).poll_read(&mut cx, &mut b),
        Poll::Pending
    ));
}
#[test]
fn fixed_shell_free_arguments_have_no_resume_model_or_approval_override() {
    let args = argv(SESSION);
    assert_eq!(
        args,
        vec![
            "--print",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--verbose",
            "--replay-user-messages",
            "--include-partial-messages",
            "--session-id",
            SESSION,
            "--safe-mode",
            "--restricted",
            "--tools",
            "",
            "--disallowedTools",
            "mcp__*",
            "--permission-mode",
            "default",
            "--permission-prompts",
            "none"
        ]
    );
}
#[tokio::test]
async fn end_input_before_final_admission_is_definitively_not_dispatched() {
    let (shared, saved, _events) = ready();
    let (host, mut peer) = tokio::io::duplex(4096);
    *shared.writer.lock().await = Some(Box::new(host));
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    *shared.before_write.lock().unwrap() = Some((entered.clone(), resume.clone()));
    let owner = shared.clone();
    let task = tokio::spawn(async move {
        write_input(&owner, &saved, Instant::now() + Duration::from_secs(30)).await
    });
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    shared.end_input();
    resume.notify_one();
    let evidence = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    assert!(evidence.not_dispatched);
    assert!(!evidence.write_uncertain);
    assert!(!shared.state.lock().unwrap().records[ID].may_written);
    assert_no_bytes(&mut peer);
}
#[tokio::test]
async fn final_action_and_original_owner_deadlines_do_not_renew() {
    let (shared, saved, _events) = ready();
    let (host, mut peer) = tokio::io::duplex(4096);
    *shared.writer.lock().await = Some(Box::new(host));
    assert_eq!(
        shared.valid(&saved, Instant::now() - Duration::from_secs(1)),
        Err(ClaudeError::PermissionDenied)
    );
    assert!(
        write_input(&shared, &saved, Instant::now() - Duration::from_secs(1))
            .await
            .not_dispatched
    );
    shared.state.lock().unwrap().owner_deadline = Some(Instant::now() - Duration::from_secs(1));
    assert_eq!(
        shared.valid(&saved, Instant::now() + Duration::from_secs(30)),
        Err(ClaudeError::PermissionDenied)
    );
    assert!(
        write_input(&shared, &saved, Instant::now() + Duration::from_secs(30))
            .await
            .not_dispatched
    );
    assert_no_bytes(&mut peer);
}
struct PartialFault(bool);
impl AsyncWrite for PartialFault {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.0 {
            self.0 = true;
            Poll::Ready(Ok(b.len().min(1)))
        } else {
            Poll::Ready(Err(std::io::Error::other("fixture")))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn partial_input_fault_fences_new_writes_but_keeps_late_evidence() {
    let (shared, saved, _events) = ready();
    *shared.writer.lock().await = Some(Box::new(PartialFault(false)));
    let e = write_input(&shared, &saved, Instant::now() + Duration::from_secs(30)).await;
    assert!(e.write_uncertain);
    shared.publish_now();
    assert!(shared.snapshots.borrow().session.is_none());
    observe(
        &shared,
        Event::Replay {
            session: SESSION.into(),
            id: ID.into(),
            text: saved.text.clone(),
        },
    );
    let p = &shared.state.lock().unwrap().records[ID].evidence;
    assert!(p.write_uncertain && p.user_replayed);
}
#[test]
fn wrong_startup_policy_or_foreign_session_cannot_mint_target() {
    let (shared, _, _events) = ready();
    {
        let mut s = shared.state.lock().unwrap();
        s.corroborated = false;
    }
    observe(
        &shared,
        Event::Init {
            session: SESSION.into(),
            version: CLI_VERSION.into(),
            cwd: "/fixture/work".into(),
            manual_empty: false,
        },
    );
    shared.publish_now();
    assert!(shared.snapshots.borrow().session.is_none());
    assert!(shared.state.lock().unwrap().fenced);
}
struct FixtureSpawner {
    io: Mutex<Option<ChildIo>>,
    journal: PathBuf,
    spawned: Arc<AtomicBool>,
}
impl Spawner for FixtureSpawner {
    fn spawn(
        &self,
        _: WorkConfig,
        _: String,
        _: Instant,
        _: Arc<AtomicBool>,
        _: Arc<Mutex<()>>,
    ) -> Pin<Box<dyn Future<Output = Result<ChildIo>> + Send>> {
        assert!(
            std::fs::read_dir(&self.journal).unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".jsonl"))
        );
        self.spawned.store(true, Ordering::Release);
        let io = self.io.lock().unwrap().take();
        Box::pin(async move { io.ok_or(ClaudeError::Unavailable) })
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    port: Arc<dyn HumanWorkPort>,
    peer: DuplexStream,
    _stderr: DuplexStream,
    exit: Option<oneshot::Sender<Option<i32>>>,
    workdir: PathBuf,
    spawned: Arc<AtomicBool>,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    let conf = config(&path);
    let (host, peer) = tokio::io::duplex(65536);
    let (r, w) = tokio::io::split(host);
    let (er, ew) = tokio::io::duplex(4096);
    let (exit, wait) = oneshot::channel();
    let io = ChildIo {
        reader: Box::new(r),
        writer: Box::new(w),
        stderr: Box::new(er),
        wait: Box::pin(async move { wait.await.map_err(|_| ClaudeError::Unavailable) }),
        valid: true,
        verify: Arc::new(|| Ok(())),
    };
    let spawned = Arc::new(AtomicBool::new(false));
    let port = open_with(
        conf.clone(),
        Arc::new(FixtureSpawner {
            io: Mutex::new(Some(io)),
            journal: conf.journal,
            spawned: spawned.clone(),
        }),
    )
    .unwrap();
    Fixture {
        _temp: temp,
        port,
        peer,
        _stderr: ew,
        exit: Some(exit),
        workdir: path,
        spawned,
    }
}

#[test]
fn public_end_input_returns_while_watch_snapshot_is_borrowed() {
    let fixture = fixture();
    let updates = fixture.port.subscribe();
    let borrowed = updates.borrow();
    let port = fixture.port.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (returned_tx, returned_rx) = std::sync::mpsc::channel();
    let caller = std::thread::spawn(move || {
        let _ = entered_tx.send(());
        let result = port.end_input();
        let _ = returned_tx.send(result);
    });

    let entered = entered_rx.recv_timeout(Duration::from_secs(3));
    let returned_while_borrowed = if entered.is_ok() {
        returned_rx.recv_timeout(Duration::from_secs(3))
    } else {
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    };
    let write_admission_while_borrowed =
        matches!(&returned_while_borrowed, Ok(Ok(()))).then(|| {
            fixture.port.start(
                "55555555-5555-4555-8555-555555555555",
                "This must not start after EndInput",
            )
        });

    // The original synchronous publication blocks on this borrow. Release it
    // and join before asserting, so its intended red result cannot strand a
    // caller thread or make Cargo hang.
    drop(borrowed);
    if returned_while_borrowed.is_err() && returned_rx.recv_timeout(Duration::from_secs(3)).is_err()
    {
        // A future API fault beyond the original watch-lock bug must fail
        // within a bound instead of hanging the test runner in join().
        drop(caller);
        panic!("EndInput caller remained blocked after the watch borrow was released");
    }
    let joined = caller.join();
    assert!(
        joined.is_ok(),
        "EndInput caller joins after releasing the borrow"
    );
    assert!(
        entered.is_ok(),
        "the caller reached its public API invocation"
    );
    assert!(
        matches!(returned_while_borrowed, Ok(Ok(()))),
        "synchronous EndInput must return while the watch borrow remains held"
    );
    assert_eq!(
        write_admission_while_borrowed,
        Some(Err(ClaudeError::Unavailable)),
        "EndInput must close write admission before returning, even while publication is blocked"
    );
    assert!(
        !fixture.spawned.load(Ordering::Acquire),
        "no child is started by mounting or EndInput"
    );
}

async fn read_json(peer: &mut DuplexStream) -> Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut b = Vec::new();
        loop {
            let c = peer.read_u8().await.unwrap();
            b.push(c);
            assert!(b.len() <= wire::MAX_OUTBOUND);
            if c == b'\n' {
                break;
            }
        }
        serde_json::from_slice(&b).unwrap()
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
async fn changed_until(
    rx: &mut watch::Receiver<WorkSnapshot>,
    predicate: impl Fn(&WorkSnapshot) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if predicate(&rx.borrow()) {
                break;
            }
            rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}
async fn begin(f: &mut Fixture) -> (Value, watch::Receiver<WorkSnapshot>) {
    assert!(!f.spawned.load(Ordering::Acquire));
    let mut snapshots = f.port.subscribe();
    f.port.start(ID, "initial literal prose").unwrap();
    let init = read_json(&mut f.peer).await;
    assert_eq!(init["type"], "control_request");
    send(&mut f.peer,json!({"type":"control_response","response":{"subtype":"success","request_id":init["request_id"],"response":{"claude_code_version":CLI_VERSION}}})).await;
    let user = read_json(&mut f.peer).await;
    send(&mut f.peer,json!({"type":"system","subtype":"init","session_id":user["session_id"],"claude_code_version":CLI_VERSION,"cwd":f.workdir,"tools":[],"permissionMode":"default"})).await;
    changed_until(&mut snapshots, |s| {
        s.session.is_some()
            && s.last_submission
                .as_ref()
                .is_some_and(|s| s.kind == ActionKind::Start)
    })
    .await;
    (user, snapshots)
}
#[tokio::test]
async fn known_child_exit_clears_target_and_rejects_captured_direction_before_consume() {
    let mut f = fixture();
    let (_, mut snapshots) = begin(&mut f).await;
    let target = snapshots.borrow().session.clone().unwrap();
    f.exit.take().unwrap().send(Some(0)).unwrap();
    changed_until(&mut snapshots, |s| {
        s.lifecycle.child_exited && s.lifecycle.child_wait_joined
    })
    .await;
    assert!(snapshots.borrow().session.is_none());
    assert!(!snapshots.borrow().lifecycle.stdout_eof);
    let id = new_operation_id().unwrap();
    assert_eq!(
        f.port
            .direction(&target, &id, "late human direction", InputTiming::Now),
        Err(ClaudeError::Unavailable)
    );
    assert!(
        !f.workdir
            .join("journal")
            .join(format!("{id}.jsonl"))
            .exists()
    );
    assert_no_bytes(&mut f.peer);
    f.port.end_input().unwrap();
}
#[tokio::test]
async fn incompatible_control_version_writes_no_human_input() {
    let mut f = fixture();
    let mut snapshots = f.port.subscribe();
    f.port.start(ID, "initial").unwrap();
    let init = read_json(&mut f.peer).await;
    send(&mut f.peer,json!({"type":"control_response","response":{"subtype":"success","request_id":init["request_id"],"response":{"claude_code_version":"2.1.313"}}})).await;
    changed_until(&mut snapshots, |s| {
        s.start.as_ref().is_some_and(|r| r.evidence.not_dispatched)
    })
    .await;
    assert_no_bytes(&mut f.peer);
    assert!(snapshots.borrow().session.is_none());
    f.port.end_input().unwrap();
}
#[tokio::test]
async fn busy_session_accepts_distinct_human_direction_before_initial_result() {
    let mut f = fixture();
    let (first, mut snapshots) = begin(&mut f).await;
    let target = snapshots.borrow().session.clone().unwrap();
    let id = new_operation_id().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let prepared = f
        .port
        .prepare_direction(
            &target,
            &id,
            "a human steer",
            InputTiming::AfterTools,
            deadline,
        )
        .unwrap();
    assert_eq!(prepared.deadline(), deadline);
    assert_eq!(prepared.operation().session_id, target.session_id());
    assert_no_bytes(&mut f.peer);
    f.port.submit_prepared_direction(prepared).unwrap();
    let frame = read_json(&mut f.peer).await;
    assert_eq!(frame["uuid"], id);
    assert_eq!(frame["priority"], "next");
    assert_eq!(frame["origin"]["kind"], "human");
    assert_eq!(frame["client_composed"], true);
    send(&mut f.peer,json!({"type":"user","isReplay":true,"uuid":id,"session_id":first["session_id"],"message":{"role":"user","content":[{"type":"text","text":"a human steer"}]},"parent_tool_use_id":null})).await;
    changed_until(&mut snapshots, |s| {
        s.inputs
            .iter()
            .any(|r| r.operation.id == id && r.evidence.user_replayed)
    })
    .await;
    let r = snapshots
        .borrow()
        .inputs
        .iter()
        .find(|r| r.operation.id == id)
        .unwrap()
        .clone();
    assert!(!r.evidence.reply_correlated && !r.evidence.result_correlated);
    f.port.end_input().unwrap();
}

#[test]
fn unsolicited_activity_before_initial_write_is_not_legitimized_by_later_init() {
    for event in [
        Event::Reply {
            session: SESSION.into(),
            ids: vec![ID.into()],
            text: Some("not owned generation".into()),
        },
        Event::Result {
            session: SESSION.into(),
            ids: vec![ID.into()],
            error: false,
        },
        Event::Replay {
            session: SESSION.into(),
            id: ID.into(),
            text: "a literal direction".into(),
        },
    ] {
        let (shared, _saved, _events) = ready();
        {
            let mut s = shared.state.lock().unwrap();
            s.records.values_mut().for_each(|p| p.may_written = false);
            s.corroborated = false;
            s.snapshot.phase = WorkPhase::Starting;
        }
        observe(&shared, event);
        {
            let s = shared.state.lock().unwrap();
            assert!(s.fenced);
            assert!(s.deferred.is_empty());
            assert!(s.snapshot.agent_text.is_none());
            assert!(
                s.records
                    .values()
                    .all(|p| p.evidence == InputEvidence::default())
            );
            assert_ne!(s.snapshot.phase, WorkPhase::Working);
        }
        observe(
            &shared,
            Event::Init {
                session: SESSION.into(),
                version: CLI_VERSION.into(),
                cwd: "/fixture/work".into(),
                manual_empty: true,
            },
        );
        shared.publish_now();
        assert!(shared.snapshots.borrow().session.is_none());
        assert!(shared.state.lock().unwrap().fenced);
    }
    let (shared, _saved, _events) = ready();
    {
        let mut s = shared.state.lock().unwrap();
        s.records.values_mut().for_each(|p| p.may_written = false);
        s.corroborated = false;
    }
    observe(
        &shared,
        Event::Init {
            session: SESSION.into(),
            version: CLI_VERSION.into(),
            cwd: "/fixture/work".into(),
            manual_empty: true,
        },
    );
    shared.publish_now();
    assert!(shared.state.lock().unwrap().corroborated);
    assert!(!shared.state.lock().unwrap().fenced);
    assert!(shared.snapshots.borrow().session.is_none());
}

#[tokio::test]
async fn conversation_reset_invalidates_exact_observed_target_without_adoption_or_input() {
    let (shared, _saved, _events) = ready();
    let target = shared.snapshots.borrow().session.clone().unwrap();
    let (host, mut peer) = tokio::io::duplex(4096);
    *shared.writer.lock().await = Some(Box::new(host));
    let (tx, mut commands) = mpsc::channel(8);
    let port = Client {
        shared: shared.clone(),
        commands: tx,
    };
    observe(&shared,wire::parse(&wire::encode(json!({"type":"conversation_reset","session_id":SESSION,"new_conversation_id":"55555555-5555-4555-8555-555555555555","uuid":new_operation_id().unwrap()})).unwrap()).unwrap());
    shared.publish_now();
    assert!(shared.snapshots.borrow().session.is_none());
    assert_eq!(
        shared.snapshots.borrow().phase,
        WorkPhase::OwnerActionRequired
    );
    let id = new_operation_id().unwrap();
    assert_eq!(
        port.direction(
            &target,
            &id,
            "do not write to replacement context",
            InputTiming::Now
        ),
        Err(ClaudeError::OwnerInterventionRequired)
    );
    assert!(matches!(
        commands.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(!shared.state.lock().unwrap().records.contains_key(&id));
    assert_no_bytes(&mut peer);
    assert_eq!(shared.state.lock().unwrap().session_id, SESSION);
}

#[test]
fn retained_assistant_text_cap_includes_separators_and_utf8() {
    for first in ["x".repeat(MAX_TEXT_BYTES), "x".repeat(MAX_TEXT_BYTES - 1)] {
        let event=wire::parse(&wire::encode(json!({"type":"assistant","uuid":ID,"session_id":SESSION,"message":{"id":"fixture-message","type":"message","role":"assistant","content":[{"type":"text","text":first},{"type":"text","text":"second block"},{"type":"text","text":"😀 third block"}]}})).unwrap()).unwrap();
        let Event::Reply {
            text: Some(text), ..
        } = event
        else {
            panic!("literal assistant text")
        };
        assert_eq!(text.len(), MAX_TEXT_BYTES);
        assert!(text.is_char_boundary(text.len()));
    }
}

#[test]
fn prepared_direction_is_read_only_and_lookup_cannot_release_its_later_ticket() {
    let (shared, _, _events) = ready();
    let (commands, mut queue) = mpsc::channel(8);
    let client = Client {
        shared: shared.clone(),
        commands,
    };
    let target = shared.snapshots.borrow().session.clone().unwrap();
    let id = new_operation_id().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let prepared = client
        .prepare_direction(
            &target,
            &id,
            "shared human direction",
            InputTiming::AfterTools,
            deadline,
        )
        .unwrap();
    assert_eq!(prepared.deadline(), deadline);
    assert_eq!(prepared.operation().id, id);
    assert_eq!(prepared.operation().timing, InputTiming::AfterTools);
    let older = client
        .prepare_direction(
            &target,
            &new_operation_id().unwrap(),
            "older unsubmitted",
            InputTiming::Now,
            deadline,
        )
        .unwrap();
    assert_eq!(prepared.captured_sequence(), older.captured_sequence());
    assert!(queue.try_recv().is_err());
    assert!(!shared.flight.load(Ordering::Acquire));
    assert_eq!(shared.state.lock().unwrap().records.len(), 2);
    client.lookup(ID).unwrap();
    client.submit_prepared_direction(prepared).unwrap();
    let lookup = queue.try_recv().unwrap();
    assert!(matches!(lookup.command, Command::Lookup(_)));
    shared.completed(ID.into(), ActionKind::Lookup, true, None);
    shared.release(lookup.ticket.as_ref());
    assert!(
        shared.flight.load(Ordering::Acquire),
        "Lookup cannot release an admitted Direction"
    );
    assert_eq!(
        client
            .prepare_direction(
                &target,
                &new_operation_id().unwrap(),
                "must remain busy",
                InputTiming::Now,
                deadline
            )
            .err(),
        Some(ClaudeError::Busy)
    );
    let input = queue.try_recv().unwrap();
    shared.release(input.ticket.as_ref());
    assert_eq!(
        client.submit_prepared_direction(older),
        Err(ClaudeError::StaleSession)
    );
    assert!(!shared.flight.load(Ordering::Acquire));
    assert!(queue.try_recv().is_err());
}

#[test]
fn prepared_direction_rejects_foreign_owner_expired_deadline_and_queue_failure_without_admission() {
    let (shared, _, _events) = ready();
    let (commands, mut queue) = mpsc::channel(1);
    let client = Client {
        shared: shared.clone(),
        commands,
    };
    let target = shared.snapshots.borrow().session.clone().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut expired = client
        .prepare_direction(
            &target,
            &new_operation_id().unwrap(),
            "original budget",
            InputTiming::Now,
            deadline,
        )
        .unwrap();
    expired.deadline = Instant::now() - Duration::from_secs(1);
    assert_eq!(
        client.submit_prepared_direction(expired),
        Err(ClaudeError::PermissionDenied)
    );
    let prepared = client
        .prepare_direction(
            &target,
            &new_operation_id().unwrap(),
            "queue bounded",
            InputTiming::Now,
            deadline,
        )
        .unwrap();
    let sequence = prepared.captured_sequence();
    client.lookup(ID).unwrap();
    assert_eq!(
        client
            .prepare_direction(
                &target,
                &new_operation_id().unwrap(),
                "queue already full",
                InputTiming::Now,
                deadline
            )
            .err(),
        Some(ClaudeError::Busy)
    );
    assert_eq!(
        client.submit_prepared_direction(prepared),
        Err(ClaudeError::Busy)
    );
    assert_eq!(
        shared
            .input_admission
            .lock()
            .unwrap()
            .prepare_sequence()
            .unwrap(),
        sequence
    );
    assert!(!shared.flight.load(Ordering::Acquire));
    queue.try_recv().unwrap();
    let (other, _, _events) = ready();
    let (commands, _queue) = mpsc::channel(1);
    let foreign = Client {
        shared: other,
        commands,
    };
    let prepared = client
        .prepare_direction(
            &target,
            &new_operation_id().unwrap(),
            "exact owner",
            InputTiming::Now,
            deadline,
        )
        .unwrap();
    assert_eq!(
        foreign.submit_prepared_direction(prepared),
        Err(ClaudeError::StaleSession)
    );
}

#[tokio::test]
async fn admitted_direction_final_write_uses_ticket_and_original_deadline_not_latest_sequence() {
    let (shared, saved, _events) = ready();
    let (writer, mut peer) = tokio::io::duplex(16384);
    *shared.writer.lock().await = Some(Box::new(writer));
    let ticket = shared
        .input_admission
        .lock()
        .unwrap()
        .admit(None, &saved.id)
        .unwrap();
    shared
        .state
        .lock()
        .unwrap()
        .records
        .get_mut(&saved.id)
        .unwrap()
        .ticket = ticket.clone();
    shared.input_admission.lock().unwrap().invalidate();
    let e = write_input(&shared, &saved, Instant::now() + Duration::from_secs(30)).await;
    assert!(
        e.frame_written && !e.not_dispatched,
        "newer sequence cannot revoke an admitted ticket"
    );
    let mut bytes = vec![0; wire::input(&saved).unwrap().len()];
    tokio::time::timeout(Duration::from_secs(3), peer.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    shared.release(Some(&ticket));
    let e = write_input(&shared, &saved, Instant::now() + Duration::from_secs(30)).await;
    assert!(e.not_dispatched && !e.write_uncertain);
    assert_no_bytes(&mut peer);
}

#[test]
fn known_full_native_history_rejects_prepare_without_sequence_or_reservation() {
    let (shared, saved, _events) = ready();
    {
        let mut s = shared.state.lock().unwrap();
        for index in 0..MAX_OPERATIONS - 2 {
            let mut operation = saved.clone();
            operation.id = format!("00000000-0000-4000-8000-{index:012x}");
            let ticket = Admission::default().admit(None, &operation.id).unwrap();
            s.records.insert(
                operation.id.clone(),
                Pending {
                    ticket,
                    saved: operation,
                    evidence: InputEvidence::default(),
                    may_written: false,
                },
            );
        }
        assert_eq!(s.records.len(), MAX_OPERATIONS);
    }
    let (commands, mut queued) = mpsc::channel(8);
    let client = Client {
        shared: shared.clone(),
        commands,
    };
    let target = shared.snapshots.borrow().session.clone().unwrap();
    assert_eq!(
        client
            .prepare_direction(
                &target,
                &new_operation_id().unwrap(),
                "no capacity",
                InputTiming::Now,
                Instant::now() + Duration::from_secs(30)
            )
            .err(),
        Some(ClaudeError::Capacity)
    );
    assert_eq!(
        shared
            .input_admission
            .lock()
            .unwrap()
            .prepare_sequence()
            .unwrap(),
        0
    );
    assert!(!shared.flight.load(Ordering::Acquire));
    assert!(queued.try_recv().is_err());
    assert_eq!(shared.state.lock().unwrap().records.len(), MAX_OPERATIONS);
}
