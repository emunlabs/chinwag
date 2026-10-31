//! Controlled Unix WebSocket peers exercise the actual native ports and parent
//! journal. These fixtures do not start a Codex executable or a model request.
use crate::*;
use chinwag_codex_steer as codex;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::watch,
};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

const WAIT: Duration = Duration::from_secs(3);
const SHARED_TEXT: &str =
    "Keep the original work, but use the existing Rust module.\nPreserve the \"public API\".";
type Peer = WebSocketStream<UnixStream>;

struct Seat {
    id: String,
    thread: String,
    turn: String,
    workdir: PathBuf,
    journal: PathBuf,
    port: Arc<dyn codex::HumanWorkPort>,
    peer: Option<Peer>,
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    listener: UnixListener,
    seats: Vec<Seat>,
    team: Arc<TeamHost>,
}
fn private_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("cw-team-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("owner.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let members_root = root.join("members");
        private_dir(&members_root);
        let mut seats = Vec::new();
        for suffix in ["a", "b"] {
            let id = format!("code-{suffix}");
            let folder = members_root.join(&id);
            private_dir(&folder);
            let workdir = folder.join("work");
            private_dir(&workdir);
            let journal = folder.join("native");
            let config = codex::WorkConfig::new(
                &socket,
                &workdir,
                &journal,
                codex::RuntimePolicyDeclaration::DedicatedRuntimeWithExplicitLogin,
            )
            .unwrap();
            let port = codex::open_work_service(config.clone()).unwrap();
            seats.push(Seat {
                id,
                thread: format!("fresh-thread-{suffix}"),
                turn: format!("owned-turn-{suffix}"),
                workdir,
                journal,
                port,
                peer: None,
            });
        }
        let members = seats
            .iter()
            .map(|seat| Member {
                id: seat.id.clone(),
                label: seat.id.clone(),
                port: HeldWorkPort::Codex(seat.port.clone()),
            })
            .collect();
        let team = TeamHost::from_ports(&root.join("team"), members).unwrap();
        Self {
            _temp: temp,
            root,
            listener,
            seats,
            team,
        }
    }
    fn selected(&self) -> Vec<String> {
        self.seats.iter().map(|s| s.id.clone()).collect()
    }
    async fn start_all(&mut self) {
        for seat in &mut self.seats {
            let mut observed = seat.port.subscribe();
            native_until(&mut observed, |s| {
                s.phase == codex::WorkPhase::Ready && seat.journal.join("work-domain.json").exists()
            })
            .await;
            let start_id = format!("human-start-{}-0001", seat.id);
            let start_text = format!("Original explicit task for {}", seat.id);
            seat.port.start(&start_id, &start_text).unwrap();
            let (stream, _) = tokio::time::timeout(WAIT, self.listener.accept())
                .await
                .unwrap()
                .unwrap();
            let work_lines = lines(&seat.journal.join("work.jsonl"));
            assert_eq!(work_lines[0]["kind"], "intent");
            assert_eq!(work_lines[0]["intent"]["id"], start_id);
            assert_eq!(work_lines[0]["intent"]["cwd"], json!(seat.workdir));
            let mut peer = tokio::time::timeout(WAIT, tokio_tungstenite::accept_async(stream))
                .await
                .unwrap()
                .unwrap();
            let init = frame(&mut peer).await;
            assert_eq!(init["method"], "initialize");
            assert_eq!(
                init["params"]["capabilities"],
                json!({"explicitGatewayOauth":true,"experimentalApi":false,"requestAttestation":false})
            );
            send(&mut peer,json!({"id":init["id"],"result":{"userAgent":"synthetic-only","codexHome":"/fixture-not-projected","platformFamily":"unix","platformOs":"macos"}})).await;
            assert_eq!(frame(&mut peer).await, json!({"method":"initialized"}));
            let thread = frame(&mut peer).await;
            assert_eq!(thread["method"], "thread/start");
            assert_eq!(thread["params"], json!({"cwd":seat.workdir}));
            send(
                &mut peer,
                json!({"method":"thread/started","params":{"thread":{"id":seat.thread}}}),
            )
            .await;
            send(&mut peer,json!({"id":thread["id"],"result":{"thread":{"id":seat.thread,"cwd":seat.workdir,"turns":[]}}})).await;
            let initial = frame(&mut peer).await;
            assert_eq!(initial["method"], "turn/start");
            assert_eq!(
                initial["params"],
                json!({"threadId":seat.thread,"clientUserMessageId":start_id,"input":[{"type":"text","text":start_text,"text_elements":[]}]})
            );
            send(&mut peer,json!({"method":"turn/started","params":{"threadId":seat.thread,"turn":turn(&seat.turn,"inProgress")}})).await;
            let active = native_until(&mut observed, |s| {
                s.target.is_some()
                    && s.last_submission
                        .as_ref()
                        .is_some_and(|r| r.id == start_id && r.saved && r.error.is_none())
            })
            .await;
            let target = active.target.unwrap();
            assert_eq!(target.thread_id(), seat.thread);
            assert_eq!(target.turn_id(), seat.turn);
            assert!(
                !active.start.unwrap().evidence.core_accepted,
                "initial RPC response is deliberately withheld"
            );
            seat.peer = Some(peer);
        }
        let mut observed = self.team.subscribe();
        team_until(&mut observed, |s| {
            s.members.len() == 2
                && s.members
                    .iter()
                    .all(|m| matches!(&m.native,NativeSnapshot::Codex(n) if n.target.is_some()))
        })
        .await;
    }
    fn assert_no_parent_intent(&self) {
        assert!(
            fs::read_dir(self.root.join("team/actions"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".jsonl"))
        );
    }
    async fn no_native_frames(&mut self) {
        for seat in &mut self.seats {
            if let Some(peer) = seat.peer.as_mut() {
                no_frame(peer).await;
            }
        }
    }
    async fn close(&mut self) {
        self.team.close_admission();
        for seat in &self.seats {
            seat.port.close().unwrap();
        }
        for seat in &mut self.seats {
            if let Some(peer) = seat.peer.as_mut() {
                closed_without_rpc(peer).await;
            }
            let mut observed = seat.port.subscribe();
            native_until(&mut observed, |s| s.phase == codex::WorkPhase::Closed).await;
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.team.close_admission();
        for seat in &self.seats {
            let _ = seat.port.close();
        }
    }
}
fn turn(id: &str, status: &str) -> Value {
    json!({"id":id,"status":status,"items":[]})
}
fn lines(path: &Path) -> Vec<Value> {
    let bytes = fs::read(path).unwrap();
    assert!(bytes.ends_with(b"\n"));
    bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}
async fn frame(peer: &mut Peer) -> Value {
    tokio::time::timeout(WAIT, async {
        loop {
            match peer.next().await.expect("fixture stream").unwrap() {
                Message::Text(text) => {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    assert!(value.get("jsonrpc").is_none());
                    return value;
                }
                Message::Ping(bytes) => peer.send(Message::Pong(bytes)).await.unwrap(),
                Message::Pong(_) => {}
                _ => panic!("expected one JSON Text application frame"),
            }
        }
    })
    .await
    .expect("bounded native application frame")
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
        "no fallback, duplicate or automatic RPC expected"
    );
}
async fn closed_without_rpc(peer: &mut Peer) {
    tokio::time::timeout(WAIT, async {
        loop {
            match peer.next().await {
                Some(Ok(Message::Ping(bytes))) => {
                    let _ = peer.send(Message::Pong(bytes)).await;
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                _ => panic!("Close must not dispatch an application RPC"),
            }
        }
    })
    .await
    .expect("bounded owner Close");
}
async fn native_until(
    receiver: &mut watch::Receiver<codex::WorkSnapshot>,
    predicate: impl Fn(&codex::WorkSnapshot) -> bool,
) -> codex::WorkSnapshot {
    tokio::time::timeout(WAIT, async {
        loop {
            let sample = receiver.borrow_and_update().clone();
            if predicate(&sample) {
                return sample;
            }
            receiver.changed().await.unwrap();
        }
    })
    .await
    .expect("bounded native snapshot")
}
async fn team_until(
    receiver: &mut watch::Receiver<TeamSnapshot>,
    predicate: impl Fn(&TeamSnapshot) -> bool,
) -> TeamSnapshot {
    tokio::time::timeout(WAIT, async {
        loop {
            let sample = receiver.borrow_and_update().clone();
            if predicate(&sample) {
                return sample;
            }
            receiver.changed().await.unwrap();
        }
    })
    .await
    .expect("bounded team snapshot")
}
fn assert_steer(frame: &Value, seat: &Seat, child: &str, text: &str) {
    assert_eq!(frame["method"], "turn/steer");
    assert_eq!(
        frame["params"],
        json!({"threadId":seat.thread,"expectedTurnId":seat.turn,"clientUserMessageId":child,"input":[{"type":"text","text":text,"text_elements":[]}]})
    );
}
async fn accepted(seat: &mut Seat, request: &Value, child: &str, text: &str) {
    let peer = seat.peer.as_mut().unwrap();
    send(peer,json!({"method":"item/completed","params":{"threadId":seat.thread,"turnId":seat.turn,"item":{"type":"userMessage","id":format!("item-{child}"),"clientId":child,"content":[{"type":"text","text":text,"text_elements":[]}]},"completedAtMs":17}})).await;
    send(
        peer,
        json!({"id":request["id"],"result":{"turnId":seat.turn}}),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_actual_codex_ports_receive_one_team_direction_on_their_exact_original_turns() {
    let mut f = Fixture::new();
    f.start_all().await;
    let selected = f.selected();
    let plan = f
        .team
        .plan(&selected, SHARED_TEXT, &BTreeMap::new())
        .unwrap();
    assert_eq!(plan.ready(), selected.as_slice());
    let capture = f
        .team
        .capture(
            &plan,
            &selected,
            1,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let saved = capture.saved.clone();
    let parent_id = capture.id().to_owned();
    let children: Vec<_> = saved
        .members
        .iter()
        .map(|m| m.child_id.clone().unwrap())
        .collect();
    assert_ne!(children[0], children[1]);
    assert_ne!(f.seats[0].journal, f.seats[1].journal);
    f.assert_no_parent_intent();
    f.no_native_frames().await;
    assert_eq!(f.team.submit(capture).unwrap(), parent_id);
    for (index, child) in children.iter().enumerate() {
        let request = frame(f.seats[index].peer.as_mut().unwrap()).await;
        assert_steer(&request, &f.seats[index], child, SHARED_TEXT);
        let parent = lines(
            &f.root
                .join("team/actions")
                .join(format!("{parent_id}.jsonl")),
        );
        assert_eq!(parent[0]["intent"]["text"], SHARED_TEXT);
        assert!(
            parent
                .iter()
                .any(|line| line["type"] == "claim" && line["member"] == selected[index]),
            "durable dispatch claim precedes native effect"
        );
        let native = lines(
            &f.seats[index]
                .journal
                .join("steers")
                .join(format!("{child}.jsonl")),
        );
        assert_eq!(native[0]["operation"]["id"], child.as_str());
        assert_eq!(
            native[0]["operation"]["expected_turn_id"],
            f.seats[index].turn
        );
        accepted(&mut f.seats[index], &request, child, SHARED_TEXT).await;
    }
    let mut observed = f.team.subscribe();
    let outcome=team_until(&mut observed,|s|s.directions.iter().any(|d|d.intent.id==parent_id&&d.stage_retired&&d.members.iter().all(|m|m.child_saved&&m.clear_safe&&matches!(&m.native,Some(NativeReceipt::Codex(r)) if r.evidence.core_accepted&&r.evidence.harness_recorded)))).await;
    let receipt = outcome
        .directions
        .iter()
        .find(|d| d.intent.id == parent_id)
        .unwrap();
    assert_eq!(receipt.intent.text, SHARED_TEXT);
    assert_eq!(receipt.intent.effective, selected);
    assert!(!receipt.persistence_failed);
    for (index, member) in receipt.members.iter().enumerate() {
        assert!(member.claimed);
        assert_eq!(member.admission, Some(LocalAdmission::Queued));
        let Some(NativeReceipt::Codex(native)) = &member.native else {
            panic!("original native receipt");
        };
        assert_eq!(native.operation.id, children[index]);
        assert_eq!(native.operation.thread_id, f.seats[index].thread);
        assert_eq!(native.operation.expected_turn_id, f.seats[index].turn);
        assert!(
            !f.seats[index]
                .port
                .subscribe()
                .borrow()
                .start
                .as_ref()
                .unwrap()
                .evidence
                .core_accepted,
            "team Steer works before initial ACK"
        );
    }
    f.team.lookup(&parent_id).unwrap();
    team_until(&mut observed, |s| {
        s.lookups
            .get(&parent_id)
            .is_some_and(|r| r.id == parent_id && r.kind == ReportKind::Lookup && r.stage_retired)
    })
    .await;
    f.no_native_frames().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), f.listener.accept())
            .await
            .is_err(),
        "no reconnect or extra owned task"
    );
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_team_capture_has_zero_native_effects_and_no_parent_intent() {
    let mut f = Fixture::new();
    let mut observed = f.team.subscribe();
    team_until(&mut observed, |s| s.members.len() == 2).await;
    let selected = f.selected();
    let inert = f
        .team
        .plan(&selected, SHARED_TEXT, &BTreeMap::new())
        .unwrap();
    assert!(inert.ready().is_empty());
    assert_eq!(
        f.team
            .capture(
                &inert,
                &selected,
                1,
                Instant::now() + Duration::from_secs(30)
            )
            .err(),
        Some(TeamError::StalePlan)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), f.listener.accept())
            .await
            .is_err()
    );
    f.start_all().await;
    let stale = f
        .team
        .plan(&selected, SHARED_TEXT, &BTreeMap::new())
        .unwrap();
    let seat = &mut f.seats[1];
    send(seat.peer.as_mut().unwrap(),json!({"method":"turn/completed","params":{"threadId":seat.thread,"turn":turn(&seat.turn,"completed")}})).await;
    let mut native = seat.port.subscribe();
    native_until(&mut native, |s| {
        s.phase == codex::WorkPhase::Finished && s.target.is_none()
    })
    .await;
    assert_eq!(
        f.team
            .capture(
                &stale,
                &selected,
                2,
                Instant::now() + Duration::from_secs(30)
            )
            .err(),
        Some(TeamError::StalePlan)
    );
    f.assert_no_parent_intent();
    f.no_native_frames().await;
    for seat in &f.seats {
        assert!(
            fs::read_dir(seat.journal.join("steers"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".jsonl"))
        );
    }
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_direct_native_input_invalidates_only_its_old_team_preparation() {
    let mut f = Fixture::new();
    f.start_all().await;
    let selected = f.selected();
    let plan = f
        .team
        .plan(&selected, SHARED_TEXT, &BTreeMap::new())
        .unwrap();
    let capture = f
        .team
        .capture(
            &plan,
            &selected,
            1,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let parent_id = capture.id().to_owned();
    let child_a = capture.saved.members[0].child_id.clone().unwrap();
    let child_b = capture.saved.members[1].child_id.clone().unwrap();
    let direct_id = "human-direct-window-steer-0001";
    let target = f.seats[0].port.subscribe().borrow().target.clone().unwrap();
    f.seats[0]
        .port
        .steer(&target, direct_id, "newer direct human input")
        .unwrap();
    let request = frame(f.seats[0].peer.as_mut().unwrap()).await;
    assert_steer(&request, &f.seats[0], direct_id, "newer direct human input");
    accepted(
        &mut f.seats[0],
        &request,
        direct_id,
        "newer direct human input",
    )
    .await;
    let mut native = f.seats[0].port.subscribe();
    native_until(&mut native, |s| {
        s.last_submission
            .as_ref()
            .is_some_and(|r| r.id == direct_id && r.saved && r.error.is_none())
    })
    .await;
    f.team.submit(capture).unwrap();
    let request = frame(f.seats[1].peer.as_mut().unwrap()).await;
    assert_steer(&request, &f.seats[1], &child_b, SHARED_TEXT);
    accepted(&mut f.seats[1], &request, &child_b, SHARED_TEXT).await;
    let mut observed = f.team.subscribe();
    let sample = team_until(&mut observed, |s| {
        s.directions.iter().any(|d| {
            d.intent.id == parent_id
                && d.stage_retired
                && d.members[0].admission == Some(LocalAdmission::Rejected)
                && d.members[1].child_saved
        })
    })
    .await;
    let receipt = sample
        .directions
        .iter()
        .find(|d| d.intent.id == parent_id)
        .unwrap();
    assert!(receipt.members[0].claimed && !receipt.members[0].child_saved);
    assert_eq!(receipt.members[1].admission, Some(LocalAdmission::Queued));
    assert!(
        !f.seats[0]
            .journal
            .join("steers")
            .join(format!("{child_a}.jsonl"))
            .exists()
    );
    assert!(
        f.seats[0]
            .journal
            .join("steers")
            .join(format!("{direct_id}.jsonl"))
            .exists()
    );
    f.no_native_frames().await;
    assert_eq!(
        f.team
            .capture(
                &plan,
                &selected,
                1,
                Instant::now() + Duration::from_secs(30)
            )
            .err(),
        Some(TeamError::ConsumedRevision)
    );
    f.close().await;
}
