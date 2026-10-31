use super::*;
use chinwag_claude_control as claude;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
async fn frame(io: &mut DuplexStream) -> Value {
    tokio::time::timeout(Duration::from_secs(4), async {
        let mut bytes = Vec::new();
        loop {
            let b = io.read_u8().await.unwrap();
            if b == b'\n' {
                break;
            }
            bytes.push(b);
            assert!(bytes.len() <= 65536);
        }
        serde_json::from_slice(&bytes).unwrap()
    })
    .await
    .unwrap()
}
async fn send(io: &mut DuplexStream, value: Value) {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    io.write_all(&bytes).await.unwrap();
}
async fn wait_team(
    rx: &mut watch::Receiver<TeamSnapshot>,
    f: impl Fn(&TeamSnapshot) -> bool,
) -> TeamSnapshot {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let s = rx.borrow().clone();
            if f(&s) {
                return s;
            }
            rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_append_failure_keeps_committed_claim_after_actual_native_input() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (port, mut peer) =
        claude::test_support::open_fixture_service(&root.join("native")).unwrap();
    let start = claude::new_operation_id().unwrap();
    port.start(&start, "original task").unwrap();
    let init = frame(&mut peer.io).await;
    send(&mut peer.io,json!({"type":"control_response","response":{"subtype":"success","request_id":init["request_id"],"response":{"claude_code_version":"2.1.314"}}})).await;
    let initial = frame(&mut peer.io).await;
    let session = initial["session_id"].as_str().unwrap().to_owned();
    send(&mut peer.io,json!({"type":"system","subtype":"init","session_id":session,"claude_code_version":"2.1.314","cwd":peer.workdir,"tools":[],"permissionMode":"default"})).await;
    native_ready(&port, &start).await;
    let host = TeamHost::from_ports(
        &root.join("team"),
        vec![Member {
            id: "review".into(),
            label: "Review".into(),
            port: HeldWorkPort::Claude(port.clone()),
        }],
    )
    .unwrap();
    let mut changes = host.subscribe();
    wait_team(&mut changes, |s| {
        s.members
            .iter()
            .any(|m| matches!(&m.native,NativeSnapshot::Claude(n) if n.session.is_some()))
    })
    .await;
    let plan = host
        .plan(
            &["review".into()],
            "make this mobile-first",
            &BTreeMap::new(),
        )
        .unwrap();
    let captured = host
        .capture(
            &plan,
            plan.ready(),
            1,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let parent = captured.id().to_owned();
    host.shared
        .fail_admission_append
        .store(true, Ordering::Release);
    host.submit(captured).unwrap();
    let direction = frame(&mut peer.io).await;
    assert_eq!(
        direction["message"]["content"][0]["text"],
        "make this mobile-first"
    );
    let snapshot = wait_team(&mut changes, |s| {
        s.directions
            .iter()
            .any(|d| d.intent.id == parent && d.persistence_failed && d.members[0].child_saved)
    })
    .await;
    let receipt = snapshot
        .directions
        .iter()
        .find(|d| d.intent.id == parent)
        .unwrap();
    let member = &receipt.members[0];
    assert!(
        member.claimed,
        "the committed claim remains cached before native invocation"
    );
    assert_eq!(
        member.admission, None,
        "the append failed, not fabricated admission"
    );
    assert!(member.child_saved);
    assert!(!member.clear_safe);
    assert!(member.native.is_some());
    let bytes = std::fs::read(root.join("team/actions").join(format!("{parent}.jsonl"))).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"type\":\"claim\""));
    assert!(!text.contains("\"type\":\"admission\""));
    assert!(
        host.plan(&["review".into()], "new text", &BTreeMap::new())
            .is_ok(),
        "native history remains independent of parent storage failure"
    );
    host.close_admission();
    let _ = port.end_input();
    peer.finish(0);
}
struct Blocker {
    blocked: Mutex<bool>,
    released: std::sync::Condvar,
    entered: std::sync::mpsc::Sender<()>,
}
struct BlockingPort {
    snapshots: watch::Sender<chinwag_codex_steer::WorkSnapshot>,
    blocker: Arc<Blocker>,
}
impl chinwag_codex_steer::HumanWorkPort for BlockingPort {
    fn subscribe(&self) -> watch::Receiver<chinwag_codex_steer::WorkSnapshot> {
        let mut b = self.blocker.blocked.lock().unwrap();
        if *b {
            let _ = self.blocker.entered.send(());
            while *b {
                b = self.blocker.released.wait(b).unwrap();
            }
        }
        self.snapshots.subscribe()
    }
    fn start(&self, _: &str, _: &str) -> chinwag_codex_steer::Result<()> {
        Err(chinwag_codex_steer::SteerError::Unavailable)
    }
    fn steer(
        &self,
        _: &chinwag_codex_steer::ObservedActiveTurn,
        _: &str,
        _: &str,
    ) -> chinwag_codex_steer::Result<()> {
        Err(chinwag_codex_steer::SteerError::Unavailable)
    }
    fn lookup(&self, _: &str) -> chinwag_codex_steer::Result<()> {
        Ok(())
    }
    fn close(&self) -> chinwag_codex_steer::Result<()> {
        Ok(())
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_and_plan_do_not_sample_blocked_native_watch_on_caller() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (tx, entered) = std::sync::mpsc::channel();
    let blocker = Arc::new(Blocker {
        blocked: Mutex::new(false),
        released: std::sync::Condvar::new(),
        entered: tx,
    });
    let (snapshots, _) = watch::channel(chinwag_codex_steer::WorkSnapshot::ready("fixture".into()));
    let port = Arc::new(BlockingPort {
        snapshots,
        blocker: blocker.clone(),
    });
    let host = TeamHost::from_ports(
        &root.join("team"),
        vec![Member {
            id: "code".into(),
            label: "Code".into(),
            port: HeldWorkPort::Codex(port),
        }],
    )
    .unwrap();
    let mut changes = host.subscribe();
    wait_team(&mut changes, |s| s.members.len() == 1).await;
    *blocker.blocked.lock().unwrap() = true;
    host.shared.refresh();
    entered.recv_timeout(Duration::from_secs(3)).unwrap();
    let copy = host.clone();
    let (done_tx, done) = std::sync::mpsc::channel();
    let caller = std::thread::spawn(move || {
        copy.close_admission();
        let result = copy
            .plan(&["code".into()], "direction", &BTreeMap::new())
            .err();
        let _ = done_tx.send(result);
    });
    let returned = done.recv_timeout(Duration::from_secs(3));
    *blocker.blocked.lock().unwrap() = false;
    blocker.released.notify_all();
    let after = if returned.is_ok() {
        None
    } else {
        Some(done.recv_timeout(Duration::from_secs(3)))
    };
    let joined = caller.join();
    assert!(joined.is_ok());
    assert!(
        matches!(returned, Ok(Some(TeamError::Closed))),
        "Quit fence returns without native-watch sampling"
    );
    if let Some(after) = after {
        assert!(after.is_ok())
    }
}
async fn active_claude(
    root: &Path,
) -> (
    Arc<dyn claude::HumanWorkPort>,
    claude::test_support::FixturePeer,
) {
    let (port, mut peer) =
        claude::test_support::open_fixture_service(&root.join("native")).unwrap();
    let id = claude::new_operation_id().unwrap();
    port.start(&id, "initial task").unwrap();
    let init = frame(&mut peer.io).await;
    send(&mut peer.io,json!({"type":"control_response","response":{"subtype":"success","request_id":init["request_id"],"response":{"claude_code_version":"2.1.314"}}})).await;
    let first = frame(&mut peer.io).await;
    send(&mut peer.io,json!({"type":"system","subtype":"init","session_id":first["session_id"],"claude_code_version":"2.1.314","cwd":peer.workdir,"tools":[],"permissionMode":"default"})).await;
    native_ready(&port, &id).await;
    (port, peer)
}
async fn cutoff_after_claim(expire: bool) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (port, mut peer) = active_claude(&root).await;
    let host = TeamHost::from_ports(
        &root.join("team"),
        vec![Member {
            id: "review".into(),
            label: "Review".into(),
            port: HeldWorkPort::Claude(port.clone()),
        }],
    )
    .unwrap();
    let mut changes = host.subscribe();
    wait_team(&mut changes, |s| {
        s.members
            .iter()
            .any(|m| matches!(&m.native,NativeSnapshot::Claude(n) if n.session.is_some()))
    })
    .await;
    let reached = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    *host.shared.before_invoke.lock().unwrap() = Some((reached.clone(), release.clone()));
    let plan = host
        .plan(
            &["review".into()],
            "captured before parent storage",
            &BTreeMap::new(),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let action = host.capture(&plan, plan.ready(), 1, deadline).unwrap();
    let id = host.submit(action).unwrap();
    tokio::time::timeout(Duration::from_secs(3), reached.notified())
        .await
        .unwrap();
    let original = std::fs::read(root.join("team/actions").join(format!("{id}.jsonl"))).unwrap();
    assert!(String::from_utf8_lossy(&original).contains("\"type\":\"claim\""));
    if expire {
        tokio::time::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
        )
        .await;
    } else {
        host.close_admission();
    }
    release.notify_one();
    let snapshot = wait_team(&mut changes, |s| {
        s.directions
            .iter()
            .any(|d| d.intent.id == id && d.stage_retired)
    })
    .await;
    let record = snapshot
        .directions
        .iter()
        .find(|d| d.intent.id == id)
        .unwrap();
    assert!(record.members[0].claimed);
    assert!(record.members[0].admission.is_none());
    assert!(!record.members[0].child_saved);
    assert!(!record.members[0].clear_safe);
    assert_eq!(record.intent.text, "captured before parent storage");
    let seq = match record.intent.members[0].audit.as_ref().unwrap() {
        NativeAudit::Claude {
            captured_sequence, ..
        } => *captured_sequence,
        _ => panic!("Claude audit"),
    };
    let target = match plan.targets.get("review").unwrap() {
        Target::Claude(target, _) => target,
        _ => panic!("Claude target"),
    };
    let probe = port
        .prepare_direction(
            target,
            &claude::new_operation_id().unwrap(),
            "read-only probe",
            ClaudeTiming::Now,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(
        probe.captured_sequence(),
        seq,
        "no native input was admitted across cutoff"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(40), peer.io.read_u8())
            .await
            .is_err(),
        "no native direction frame after cutoff"
    );
    host.close_admission();
    let _ = port.end_input();
    peer.finish(0);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_deadline_expires_during_parent_dispatch_without_native_renewal() {
    cutoff_after_claim(true).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quit_after_durable_claim_fences_the_final_native_invocation() {
    cutoff_after_claim(false).await
}

async fn native_ready(port: &Arc<dyn claude::HumanWorkPort>, id: &str) {
    let mut rx = port.subscribe();
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let sample = rx.borrow().clone();
            if sample.session.is_some()
                && sample.last_submission.as_ref().is_some_and(|r| {
                    r.id == id
                        && r.kind == claude::ActionKind::Start
                        && r.saved
                        && r.error.is_none()
                })
            {
                break;
            }
            rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}

async fn wait_local_report(host: &TeamHost, predicate: impl Fn(&TeamSnapshot) -> bool) {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let matched = host
                .shared
                .state
                .lock()
                .is_ok_and(|s| predicate(&s.snapshot));
            if matched {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn coalesced_publication_retains_failed_submit_and_independent_parent_checks() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (port, mut peer) = active_claude(&root).await;
    let host = TeamHost::from_ports(
        &root.join("team"),
        vec![Member {
            id: "review".into(),
            label: "Review".into(),
            port: HeldWorkPort::Claude(port.clone()),
        }],
    )
    .unwrap();
    let mut changes = host.subscribe();
    wait_team(&mut changes, |s| {
        s.members
            .iter()
            .any(|m| matches!(&m.native, NativeSnapshot::Claude(n) if n.session.is_some()))
    })
    .await;
    let plan = host
        .plan(
            &["review".into()],
            "first valid direction",
            &BTreeMap::new(),
        )
        .unwrap();
    let capture = host
        .capture(
            &plan,
            plan.ready(),
            1,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let original = host.submit(capture).unwrap();
    let written = frame(&mut peer.io).await;
    assert_eq!(
        written["message"]["content"][0]["text"],
        "first valid direction"
    );
    wait_team(&mut changes, |s| {
        s.directions
            .iter()
            .any(|d| d.intent.id == original && d.stage_retired && d.members[0].clear_safe)
            && s.members.iter().any(|m| {
                matches!(&m.native, NativeSnapshot::Claude(n)
                if n.last_submission.as_ref().is_some_and(|r|
                    r.id == written["uuid"].as_str().unwrap()
                    && r.kind == claude::ActionKind::Direction && r.saved && r.error.is_none()))
            })
    })
    .await;

    // A legal watcher can hold publication while the retained actor continues.
    // Local stage completions must survive that coalescing, including a failure
    // which never created a durable parent row.
    let held = changes.borrow();
    host.shared.fail_before_save.store(true, Ordering::Release);
    let plan = host
        .plan(
            &["review".into()],
            "fails before parent save",
            &BTreeMap::new(),
        )
        .unwrap();
    let capture = host
        .capture(
            &plan,
            plan.ready(),
            2,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let failed = host.submit(capture).unwrap();
    wait_local_report(&host, |s| {
        s.submissions
            .get(&failed)
            .is_some_and(|r| r.stage_retired && r.error == Some(TeamError::Storage))
    })
    .await;
    let first_check = host.lookup(&original).unwrap();
    wait_local_report(&host, |s| {
        s.lookups
            .get(&original)
            .is_some_and(|r| r.lookup_serial == Some(first_check) && r.stage_retired)
    })
    .await;
    let missing_check = host.lookup(&failed).unwrap();
    wait_local_report(&host, |s| {
        s.lookups.get(&failed).is_some_and(|r| {
            r.lookup_serial == Some(missing_check) && r.error == Some(TeamError::InvalidInput)
        })
    })
    .await;
    let newer_check = host.lookup(&original).unwrap();
    assert!(newer_check > first_check);
    wait_local_report(&host, |s| {
        s.lookups
            .get(&original)
            .is_some_and(|r| r.lookup_serial == Some(newer_check))
    })
    .await;
    assert_eq!(
        host.lookup(&new_id("team-").unwrap()),
        Err(TeamError::InvalidInput)
    );
    assert_eq!(
        host.shared.admission.lock().unwrap().lookup_serial,
        newer_check,
        "unknown IDs consume no lookup sequence or queue slot"
    );
    drop(held);
    let snapshot = wait_team(&mut changes, |s| {
        s.submissions.get(&failed).is_some_and(|r| r.stage_retired)
            && s.lookups
                .get(&original)
                .is_some_and(|r| r.lookup_serial == Some(newer_check))
    })
    .await;
    assert_eq!(
        snapshot.submissions[&failed].error,
        Some(TeamError::Storage)
    );
    assert_eq!(snapshot.lookups[&original].error, None);
    assert_eq!(
        snapshot.lookups[&failed].error,
        Some(TeamError::InvalidInput)
    );
    assert!(!snapshot.directions.iter().any(|d| d.intent.id == failed));
    assert!(
        !root
            .join("team/actions")
            .join(format!("{failed}.jsonl"))
            .exists()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(40), peer.io.read_u8())
            .await
            .is_err(),
        "checks and failed save send no further native direction"
    );
    host.close_admission();
    let _ = port.end_input();
    peer.finish(0);
}
