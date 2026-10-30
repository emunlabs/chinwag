use crate::{
    api::{valid_text, valid_uuid},
    binary::{self, BinaryPin},
    journal::{Consume, InputJournal},
    wire::{self, Event},
    *,
};
#[cfg(test)]
use std::path::PathBuf;
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    pin::Pin,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{mpsc, oneshot, watch},
};
type ReadIo = Box<dyn AsyncRead + Send + Unpin>;
type WriteIo = Box<dyn AsyncWrite + Send + Unpin>;
type Wait = Pin<Box<dyn Future<Output = Result<Option<i32>>> + Send>>;
pub(crate) struct ChildIo {
    pub(crate) reader: ReadIo,
    pub(crate) writer: WriteIo,
    pub(crate) stderr: ReadIo,
    pub(crate) wait: Wait,
    pub(crate) valid: bool,
    pub(crate) verify: Arc<dyn Fn() -> Result<()> + Send + Sync>,
}
pub(crate) trait Spawner: Send + Sync {
    fn spawn(
        &self,
        config: WorkConfig,
        session: String,
        deadline: Instant,
        ended: Arc<AtomicBool>,
        admission: Arc<Mutex<()>>,
    ) -> Pin<Box<dyn Future<Output = Result<ChildIo>> + Send>>;
}
struct NativeSpawner;
fn argv(session: &str) -> Vec<String> {
    [
        "--print",
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--verbose",
        "--replay-user-messages",
        "--include-partial-messages",
        "--session-id",
        session,
        "--safe-mode",
        "--restricted",
        "--tools",
        "",
        "--disallowedTools",
        "mcp__*",
        "--permission-mode",
        "default",
        "--permission-prompts",
        "none",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}
impl Spawner for NativeSpawner {
    fn spawn(
        &self,
        config: WorkConfig,
        session: String,
        deadline: Instant,
        ended: Arc<AtomicBool>,
        admission: Arc<Mutex<()>>,
    ) -> Pin<Box<dyn Future<Output = Result<ChildIo>> + Send>> {
        Box::pin(async move {
            let pin_config = config.clone();
            let (pin, directory) = tokio::task::spawn_blocking(move || {
                let p = BinaryPin::open(&pin_config)?;
                let d = binary::work_directory(&pin_config.workdir)?;
                p.verify()?;
                binary::verify_directory(&pin_config.workdir, &d)?;
                Ok::<_, ClaudeError>((Arc::new(p), Arc::new(d)))
            })
            .await
            .map_err(|_| ClaudeError::Unavailable)??;
            // Fixed shell-free argv. Inherited process environment is not inspected,
            // logged, rewritten or interpreted by Chinwag.
            let mut child = {
                let _linearize = admission.lock().map_err(|_| ClaudeError::Unavailable)?;
                if ended.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err(ClaudeError::PermissionDenied);
                }
                tokio::process::Command::new(&config.binary)
                    .args(argv(&session))
                    .current_dir(&config.workdir)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(false)
                    .spawn()
                    .map_err(|_| ClaudeError::Unavailable)?
            };
            let writer = child.stdin.take().ok_or(ClaudeError::Unavailable)?;
            let reader = child.stdout.take().ok_or(ClaudeError::Unavailable)?;
            let stderr = child.stderr.take().ok_or(ClaudeError::Unavailable)?;
            let verify: Arc<dyn Fn() -> Result<()> + Send + Sync> = Arc::new(move || {
                pin.verify()?;
                binary::verify_directory(&config.workdir, &directory)
            });
            let checking = verify.clone();
            let valid = tokio::task::spawn_blocking(move || checking())
                .await
                .is_ok_and(|r| r.is_ok());
            let wait: Wait = Box::pin(async move {
                child
                    .wait()
                    .await
                    .map(|s| s.code())
                    .map_err(|_| ClaudeError::Unavailable)
            });
            Ok(ChildIo {
                reader: Box::new(reader),
                writer: Box::new(writer),
                stderr: Box::new(stderr),
                wait,
                valid,
                verify,
            })
        })
    }
}
#[derive(Clone)]
struct Captured {
    saved: SavedInput,
    deadline: Instant,
}
enum Command {
    Start {
        id: String,
        text: String,
        deadline: Instant,
    },
    Direction(Captured),
    Lookup(String),
}
struct Pending {
    saved: SavedInput,
    evidence: InputEvidence,
    may_written: bool,
}
struct State {
    snapshot: WorkSnapshot,
    records: BTreeMap<String, Pending>,
    started: bool,
    owner_deadline: Option<Instant>,
    initialized: bool,
    corroborated: bool,
    fenced: bool,
    session_id: String,
    epoch: String,
    init_waiter: Option<oneshot::Sender<Result<()>>>,
    init_id: String,
    deferred: VecDeque<Event>,
}
struct Shared {
    config: WorkConfig,
    identity: Arc<()>,
    state: Mutex<State>,
    snapshots: watch::Sender<WorkSnapshot>,
    ended: Arc<AtomicBool>,
    end: watch::Sender<bool>,
    writer: tokio::sync::Mutex<Option<WriteIo>>,
    write_gate: Arc<tokio::sync::Semaphore>,
    evidence: Mutex<Option<mpsc::Sender<(String, InputEvidence)>>>,
    flight: AtomicBool,
    admission: Arc<Mutex<()>>,
    #[cfg(test)]
    before_write: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}
impl Shared {
    fn publish(&self) {
        let snapshot = {
            let Ok(mut s) = self.state.lock() else {
                return;
            };
            s.snapshot.revision = s.snapshot.revision.saturating_add(1);
            s.snapshot.session = if s.corroborated
                && s.records
                    .values()
                    .any(|p| p.saved.kind == ActionKind::Start && p.may_written)
                && !s.fenced
                && !s.snapshot.lifecycle.child_exited
                && !s.snapshot.lifecycle.stdout_eof
                && !s.snapshot.lifecycle.stdin_ended
                && !self.ended.load(Ordering::Acquire)
                && s.owner_deadline.is_some_and(|d| Instant::now() < d)
            {
                Some(ObservedSession {
                    identity: self.identity.clone(),
                    epoch: s.epoch.clone(),
                    session_id: s.session_id.clone(),
                    generation: 1,
                })
            } else {
                None
            };
            if s.snapshot.lifecycle.child_exited {
                s.snapshot.phase = WorkPhase::Exited;
            } else if self.ended.load(Ordering::Acquire) {
                s.snapshot.phase = WorkPhase::InputEnded;
            } else if s.fenced {
                s.snapshot.phase = WorkPhase::OwnerActionRequired;
            }
            s.snapshot.clone()
        };
        self.snapshots.send_if_modified(|old| {
            if old.revision < snapshot.revision {
                *old = snapshot;
                true
            } else {
                false
            }
        });
    }
    fn fence(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.fenced = true;
        }
        self.publish();
    }
    fn end_input(&self) {
        {
            let _effect = self.admission.lock();
            let _linearize = self.state.lock();
            self.ended.store(true, Ordering::Release);
        }
        self.end.send_replace(true);
        self.publish();
    }
    fn receipt(&self, r: Receipt) {
        if let Ok(mut s) = self.state.lock() {
            if r.operation.kind == ActionKind::Start {
                s.snapshot.start = Some(r);
            } else if let Some(old) = s
                .snapshot
                .inputs
                .iter_mut()
                .find(|old| old.operation.id == r.operation.id)
            {
                *old = r;
            } else {
                s.snapshot.inputs.push(r);
            }
        }
        self.publish();
    }
    fn completed(&self, id: String, kind: ActionKind, saved: bool, error: Option<ClaudeError>) {
        if let Ok(mut s) = self.state.lock() {
            s.snapshot.last_submission = Some(WorkSubmission {
                id,
                kind,
                saved,
                error,
            });
        }
        self.flight.store(false, Ordering::Release);
        self.publish();
    }
    fn emit(&self, id: &str, e: InputEvidence) {
        let merged = {
            let Ok(mut s) = self.state.lock() else {
                return;
            };
            let Some(p) = s.records.get_mut(id) else {
                return;
            };
            let Ok(merged) = p.evidence.merged(e) else {
                s.fenced = true;
                return;
            };
            if p.evidence == merged {
                return;
            }
            p.evidence = merged;
            merged
        };
        let result = self
            .evidence
            .lock()
            .ok()
            .and_then(|s| s.as_ref().map(|s| s.try_send((id.into(), merged)).is_ok()))
            .unwrap_or(false);
        if !result {
            self.fence();
        }
    }
    fn valid(&self, saved: &SavedInput, deadline: Instant) -> Result<()> {
        if self.ended.load(Ordering::Acquire) {
            return Err(ClaudeError::Unavailable);
        }
        let s = self.state.lock().map_err(|_| ClaudeError::Unavailable)?;
        if s.snapshot.lifecycle.child_exited
            || s.snapshot.lifecycle.stdout_eof
            || s.snapshot.lifecycle.stdin_ended
        {
            return Err(ClaudeError::Unavailable);
        }
        if s.fenced {
            return Err(ClaudeError::OwnerInterventionRequired);
        }
        if Instant::now() >= deadline || !s.owner_deadline.is_some_and(|d| Instant::now() < d) {
            return Err(ClaudeError::PermissionDenied);
        }
        if !s.initialized || s.session_id != saved.session_id || s.epoch != saved.session_epoch {
            return Err(ClaudeError::StaleSession);
        }
        if saved.kind == ActionKind::Direction && !s.corroborated {
            return Err(ClaudeError::NoSession);
        }
        Ok(())
    }
}
struct Client {
    shared: Arc<Shared>,
    commands: mpsc::Sender<Command>,
}
impl Client {
    fn send(&self, c: Command) -> Result<()> {
        if self.shared.ended.load(Ordering::Acquire) {
            return Err(ClaudeError::Unavailable);
        }
        if self
            .shared
            .flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ClaudeError::Busy);
        }
        if self.commands.try_send(c).is_err() {
            self.shared.flight.store(false, Ordering::Release);
            return Err(ClaudeError::Busy);
        }
        Ok(())
    }
}
impl HumanWorkPort for Client {
    fn subscribe(&self) -> watch::Receiver<WorkSnapshot> {
        self.shared.snapshots.subscribe()
    }
    fn start(&self, id: &str, text: &str) -> Result<()> {
        if !valid_uuid(id) || !valid_text(text) {
            return Err(ClaudeError::InvalidInput);
        }
        self.send(Command::Start {
            id: id.into(),
            text: text.into(),
            deadline: Instant::now() + Duration::from_secs(30),
        })
    }
    fn direction(
        &self,
        target: &ObservedSession,
        id: &str,
        text: &str,
        timing: InputTiming,
    ) -> Result<()> {
        if !valid_uuid(id) || !valid_text(text) {
            return Err(ClaudeError::InvalidInput);
        }
        let s = self
            .shared
            .state
            .lock()
            .map_err(|_| ClaudeError::Unavailable)?;
        if !Arc::ptr_eq(&target.identity, &self.shared.identity)
            || target.epoch != s.epoch
            || target.session_id != s.session_id
            || target.generation != 1
        {
            return Err(ClaudeError::StaleSession);
        }
        if s.snapshot.lifecycle.child_exited
            || s.snapshot.lifecycle.stdout_eof
            || s.snapshot.lifecycle.stdin_ended
        {
            return Err(ClaudeError::Unavailable);
        }
        if self.shared.ended.load(Ordering::Acquire) {
            return Err(ClaudeError::Unavailable);
        }
        if s.fenced {
            return Err(ClaudeError::OwnerInterventionRequired);
        }
        if !s
            .owner_deadline
            .is_some_and(|deadline| Instant::now() < deadline)
        {
            return Err(ClaudeError::PermissionDenied);
        }
        if !s.corroborated {
            return Err(ClaudeError::NoSession);
        }
        let saved = SavedInput {
            schema: "chinwag-claude-input/v1".into(),
            id: id.into(),
            session_epoch: s.epoch.clone(),
            session_id: s.session_id.clone(),
            kind: ActionKind::Direction,
            timing,
            text: text.into(),
            startup: None,
        };
        drop(s);
        self.send(Command::Direction(Captured {
            saved,
            deadline: Instant::now() + Duration::from_secs(30),
        }))
    }
    fn lookup(&self, id: &str) -> Result<()> {
        if !valid_uuid(id) {
            return Err(ClaudeError::InvalidInput);
        }
        self.commands
            .try_send(Command::Lookup(id.into()))
            .map_err(|_| ClaudeError::Busy)
    }
    fn end_input(&self) -> Result<()> {
        self.shared.end_input();
        Ok(())
    }
}
pub fn open_work_service(config: WorkConfig) -> Result<Arc<dyn HumanWorkPort>> {
    open_with(config, Arc::new(NativeSpawner))
}
pub(crate) fn open_with(
    config: WorkConfig,
    spawner: Arc<dyn Spawner>,
) -> Result<Arc<dyn HumanWorkPort>> {
    let (shared, receiver) = new_shared(config.clone());
    let (tx, rx) = mpsc::channel(8);
    let port = Arc::new(Client {
        shared: shared.clone(),
        commands: tx.clone(),
    });
    std::thread::Builder::new()
        .name("chinwag-claude-owner".into())
        .spawn(move || {
            let _keep = tx;
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(run(shared, rx, receiver, spawner)),
                Err(_) => {
                    if let Ok(mut s) = shared.state.lock() {
                        s.snapshot.phase = WorkPhase::Unavailable;
                    }
                    shared.publish();
                }
            }
        })
        .map_err(|_| ClaudeError::Unavailable)?;
    Ok(port)
}
fn new_shared(config: WorkConfig) -> (Arc<Shared>, mpsc::Receiver<(String, InputEvidence)>) {
    let (snapshot, _) = watch::channel(WorkSnapshot::ready(config.folder_label()));
    let (end, _) = watch::channel(false);
    let (events, receiver) = mpsc::channel(MAX_OPERATIONS * 8);
    let initial = snapshot.borrow().clone();
    let shared = Arc::new(Shared {
        identity: Arc::new(()),
        state: Mutex::new(State {
            snapshot: initial,
            records: BTreeMap::new(),
            started: false,
            owner_deadline: None,
            initialized: false,
            corroborated: false,
            fenced: false,
            session_id: String::new(),
            epoch: String::new(),
            init_waiter: None,
            init_id: String::new(),
            deferred: VecDeque::new(),
        }),
        config: config.clone(),
        snapshots: snapshot,
        ended: Arc::new(AtomicBool::new(false)),
        end,
        writer: tokio::sync::Mutex::new(None),
        write_gate: Arc::new(tokio::sync::Semaphore::new(1)),
        evidence: Mutex::new(Some(events)),
        flight: AtomicBool::new(false),
        admission: Arc::new(Mutex::new(())),
        #[cfg(test)]
        before_write: Mutex::new(None),
    });
    (shared, receiver)
}
type Store = Arc<Mutex<InputJournal>>;
async fn store<T: Send + 'static>(
    j: &Store,
    f: impl FnOnce(&mut InputJournal) -> Result<T> + Send + 'static,
) -> Result<T> {
    let j = j.clone();
    tokio::task::spawn_blocking(move || {
        let mut guard = j.lock().map_err(|_| ClaudeError::Storage)?;
        f(&mut guard)
    })
    .await
    .map_err(|_| ClaudeError::Storage)?
}
async fn run(
    shared: Arc<Shared>,
    mut commands: mpsc::Receiver<Command>,
    mut events: mpsc::Receiver<(String, InputEvidence)>,
    spawner: Arc<dyn Spawner>,
) {
    let path = shared.config.journal.clone();
    let opened = tokio::task::spawn_blocking(move || InputJournal::open(&path)).await;
    let journal = match opened {
        Ok(Ok(j)) => Arc::new(Mutex::new(j)),
        _ => {
            if let Ok(mut s) = shared.state.lock() {
                s.snapshot.phase = WorkPhase::Unavailable;
                s.fenced = true;
            }
            shared.publish();
            while let Some(c) = commands.recv().await {
                let (id, kind) = command_label(&c);
                shared.completed(id, kind, false, Some(ClaudeError::Storage));
            }
            return;
        }
    };
    let recovered = store(&journal, |j| Ok((j.has_consumed(), j.receipts()?))).await;
    if let Ok((has, receipts)) = recovered {
        if has {
            if let Ok(mut s) = shared.state.lock() {
                s.started = true;
                s.fenced = true;
                s.snapshot.phase = WorkPhase::OutcomeUnknown;
            }
            for r in receipts {
                shared.receipt(r);
            }
        }
    } else {
        shared.fence();
    }
    let worker_shared = shared.clone();
    let worker_store = journal.clone();
    tokio::spawn(async move {
        while let Some((id, e)) = events.recv().await {
            let result = store(&worker_store, move |j| match j.apply(&id, e) {
                Ok(r) => Ok(r),
                Err(_) => j.mark_persistence_failure(&id),
            })
            .await;
            match result {
                Ok(r) => worker_shared.receipt(r),
                Err(_) => worker_shared.fence(),
            }
        }
    });
    while let Some(command) = commands.recv().await {
        match command {
            Command::Start { id, text, deadline } => {
                start(&shared, &journal, spawner.as_ref(), id, text, deadline).await
            }
            Command::Direction(action) => {
                let id = action.saved.id.clone();
                let kind = ActionKind::Direction;
                let result = submit(&shared, &journal, action).await;
                match result {
                    Ok(r) => {
                        shared.receipt(r);
                        shared.completed(id, kind, true, None)
                    }
                    Err(e) => shared.completed(id, kind, false, Some(e)),
                }
            }
            Command::Lookup(id) => {
                let copy = id.clone();
                match store(&journal, move |j| j.lookup(&copy)).await {
                    Ok(Some(r)) => {
                        shared.receipt(r);
                        shared.completed(id, ActionKind::Lookup, true, None)
                    }
                    Ok(None) => shared.completed(
                        id,
                        ActionKind::Lookup,
                        false,
                        Some(ClaudeError::Uncertain),
                    ),
                    Err(e) => shared.completed(id, ActionKind::Lookup, false, Some(e)),
                }
            }
        }
    }
}
fn command_label(c: &Command) -> (String, ActionKind) {
    match c {
        Command::Start { id, .. } => (id.clone(), ActionKind::Start),
        Command::Direction(a) => (a.saved.id.clone(), ActionKind::Direction),
        Command::Lookup(id) => (id.clone(), ActionKind::Lookup),
    }
}
async fn start(
    shared: &Arc<Shared>,
    journal: &Store,
    spawner: &dyn Spawner,
    id: String,
    text: String,
    deadline: Instant,
) {
    let requested = id.clone();
    let old = store(journal, move |j| j.lookup(&requested)).await;
    match old {
        Ok(Some(r)) => {
            let valid = r.operation.kind == ActionKind::Start
                && r.operation.text == text
                && r.operation.startup.as_ref().is_some_and(|s| {
                    s.binary == shared.config.binary
                        && s.sha256 == shared.config.sha256
                        && s.workdir == shared.config.workdir
                });
            if valid {
                shared.receipt(r);
                shared.completed(id, ActionKind::Start, true, None);
            } else {
                shared.completed(id, ActionKind::Start, false, Some(ClaudeError::Conflict));
            }
            return;
        }
        Err(e) => {
            shared.completed(id, ActionKind::Start, false, Some(e));
            return;
        }
        _ => {}
    }
    let fresh = {
        let Ok(mut s) = shared.state.lock() else {
            return;
        };
        if s.started || shared.ended.load(Ordering::Acquire) || Instant::now() >= deadline {
            false
        } else {
            s.started = true;
            true
        }
    };
    if !fresh {
        shared.completed(id, ActionKind::Start, false, Some(ClaudeError::Conflict));
        return;
    }
    let (Ok(epoch), Ok(session_id)) = (new_operation_id(), new_operation_id()) else {
        shared.completed(id, ActionKind::Start, false, Some(ClaudeError::Unavailable));
        return;
    };
    let saved = SavedInput {
        schema: "chinwag-claude-input/v1".into(),
        id: id.clone(),
        session_epoch: epoch.clone(),
        session_id: session_id.clone(),
        kind: ActionKind::Start,
        timing: InputTiming::Now,
        text,
        startup: Some(StartupRecord {
            binary: shared.config.binary.clone(),
            sha256: shared.config.sha256.clone(),
            workdir: shared.config.workdir.clone(),
            policy: "managed_policy_prose_only".into(),
        }),
    };
    let record = saved.clone();
    let consumed = store(journal, move |j| j.consume(record)).await;
    let receipt = match consumed {
        Ok(Consume::Created(r)) => r,
        Ok(Consume::Existing(r)) => {
            shared.receipt(r);
            shared.completed(id, ActionKind::Start, true, None);
            return;
        }
        Err(e) => {
            shared.completed(id, ActionKind::Start, false, Some(e));
            return;
        }
    };
    {
        if let Ok(mut s) = shared.state.lock() {
            s.epoch = epoch;
            s.session_id = session_id.clone();
            s.owner_deadline = deadline.checked_add(Duration::from_secs(870));
            s.records.insert(
                id.clone(),
                Pending {
                    saved: saved.clone(),
                    evidence: InputEvidence::default(),
                    may_written: false,
                },
            );
            s.snapshot.phase = WorkPhase::Starting;
        }
    }
    // Durable admission is visible immediately, while the original submission
    // flight remains held until its one bounded startup/input attempt finishes.
    shared.receipt(receipt);
    if shared.ended.load(Ordering::Acquire) || Instant::now() >= deadline {
        save_evidence(
            shared,
            journal,
            &id,
            InputEvidence {
                not_dispatched: true,
                ..Default::default()
            },
        )
        .await;
        shared.completed(
            id,
            ActionKind::Start,
            true,
            Some(ClaudeError::PermissionDenied),
        );
        return;
    }
    let io = match spawner
        .spawn(
            shared.config.clone(),
            session_id,
            deadline,
            shared.ended.clone(),
            shared.admission.clone(),
        )
        .await
    {
        Ok(io) => io,
        Err(e) => {
            save_evidence(
                shared,
                journal,
                &id,
                InputEvidence {
                    not_dispatched: true,
                    ..Default::default()
                },
            )
            .await;
            shared.fence();
            shared.completed(id, ActionKind::Start, true, Some(e));
            return;
        }
    };
    let valid = io.valid;
    let verify = io.verify.clone();
    install(shared.clone(), io).await;
    if !valid {
        shared.fence();
        save_evidence(
            shared,
            journal,
            &id,
            InputEvidence {
                not_dispatched: true,
                ..Default::default()
            },
        )
        .await;
        shared.completed(id, ActionKind::Start, true, Some(ClaudeError::Unavailable));
        return;
    }
    let init_id = match new_operation_id() {
        Ok(id) => id,
        Err(e) => {
            shared.fence();
            shared.completed(id, ActionKind::Start, true, Some(e));
            return;
        }
    };
    let (tx, rx) = oneshot::channel();
    if let Ok(mut s) = shared.state.lock() {
        s.init_id = init_id.clone();
        s.init_waiter = Some(tx);
    }
    let initialize = match wire::initialize(&init_id) {
        Ok(frame) => frame,
        Err(e) => {
            shared.completed(id, ActionKind::Start, true, Some(e));
            return;
        }
    };
    let initialized = if write_control(shared, initialize, deadline).await.is_ok() {
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(10));
        tokio::time::timeout(wait, rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some_and(|r| r.is_ok())
    } else {
        false
    };
    if !initialized {
        shared.fence();
        save_evidence(
            shared,
            journal,
            &id,
            InputEvidence {
                not_dispatched: true,
                ..Default::default()
            },
        )
        .await;
        shared.completed(id, ActionKind::Start, true, Some(ClaudeError::Unavailable));
        return;
    }
    let checked = tokio::task::spawn_blocking(move || verify())
        .await
        .is_ok_and(|r| r.is_ok());
    if !checked {
        shared.fence();
        save_evidence(
            shared,
            journal,
            &id,
            InputEvidence {
                not_dispatched: true,
                ..Default::default()
            },
        )
        .await;
        shared.completed(id, ActionKind::Start, true, Some(ClaudeError::Unavailable));
        return;
    }
    let evidence = write_input(shared, &saved, deadline).await;
    save_evidence(shared, journal, &id, evidence).await;
    shared.completed(
        id,
        ActionKind::Start,
        true,
        if evidence.write_uncertain {
            Some(ClaudeError::Uncertain)
        } else if evidence.not_dispatched {
            Some(ClaudeError::Unavailable)
        } else {
            None
        },
    );
}
async fn save_evidence(shared: &Arc<Shared>, journal: &Store, id: &str, e: InputEvidence) {
    let id = id.to_owned();
    match store(journal, move |j| match j.apply(&id, e) {
        Ok(r) => Ok(r),
        Err(_) => j.mark_persistence_failure(&id),
    })
    .await
    {
        Ok(r) => shared.receipt(r),
        Err(_) => shared.fence(),
    }
}
async fn submit(shared: &Arc<Shared>, journal: &Store, action: Captured) -> Result<Receipt> {
    let requested = action.saved.id.clone();
    if let Some(receipt) = store(journal, move |j| j.lookup(&requested)).await? {
        return if receipt.operation == action.saved {
            Ok(receipt)
        } else {
            Err(ClaudeError::Conflict)
        };
    }
    shared.valid(&action.saved, action.deadline)?;
    let record = action.saved.clone();
    let consumed = store(journal, move |j| j.consume(record)).await?;
    match consumed {
        Consume::Existing(r) => Ok(r),
        Consume::Created(r) => {
            shared.receipt(r);
            {
                let mut s = shared.state.lock().map_err(|_| ClaudeError::Unavailable)?;
                s.records.insert(
                    action.saved.id.clone(),
                    Pending {
                        saved: action.saved.clone(),
                        evidence: InputEvidence::default(),
                        may_written: false,
                    },
                );
            }
            let e = write_input(shared, &action.saved, action.deadline).await;
            let id = action.saved.id.clone();
            store(journal, move |j| match j.apply(&id, e) {
                Ok(r) => Ok(r),
                Err(_) => j.mark_persistence_failure(&id),
            })
            .await
        }
    }
}
async fn write_control(shared: &Arc<Shared>, frame: Vec<u8>, deadline: Instant) -> Result<()> {
    let _permit = shared
        .write_gate
        .clone()
        .try_acquire_owned()
        .map_err(|_| ClaudeError::Busy)?;
    let mut end = shared.end.subscribe();
    let write = async {
        let mut slot = shared.writer.lock().await;
        {
            let _effect = shared
                .admission
                .lock()
                .map_err(|_| ClaudeError::Unavailable)?;
            let s = shared.state.lock().map_err(|_| ClaudeError::Unavailable)?;
            if shared.ended.load(Ordering::Acquire)
                || Instant::now() >= deadline
                || s.fenced
                || s.snapshot.lifecycle.child_exited
                || s.snapshot.lifecycle.stdout_eof
            {
                return Err(ClaudeError::PermissionDenied);
            }
        }
        let writer = slot.as_mut().ok_or(ClaudeError::Unavailable)?;
        writer
            .write_all(&frame)
            .await
            .map_err(|_| ClaudeError::Uncertain)?;
        writer.flush().await.map_err(|_| ClaudeError::Uncertain)
    };
    tokio::select! {biased;_=end.changed()=>Err(ClaudeError::Unavailable),r=tokio::time::timeout(deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(2)),write)=>r.map_err(|_|ClaudeError::Uncertain)?}
}
async fn write_input(shared: &Arc<Shared>, saved: &SavedInput, deadline: Instant) -> InputEvidence {
    let frame = match wire::input(saved) {
        Ok(f) => f,
        Err(_) => {
            return InputEvidence {
                not_dispatched: true,
                ..Default::default()
            };
        }
    };
    let Ok(_permit) = shared.write_gate.clone().try_acquire_owned() else {
        return InputEvidence {
            not_dispatched: true,
            ..Default::default()
        };
    };
    let mut end = shared.end.subscribe();
    let id = saved.id.clone();
    let write = async {
        let mut slot = shared.writer.lock().await;
        let writer = slot.as_mut().ok_or(false)?;
        #[cfg(test)]
        {
            let pause = shared.before_write.lock().ok().and_then(|p| p.clone());
            if let Some((entered, resume)) = pause {
                entered.notify_one();
                resume.notified().await;
            }
        }
        {
            let _effect = shared.admission.lock().map_err(|_| false)?;
            let mut s = shared.state.lock().map_err(|_| false)?;
            if shared.ended.load(Ordering::Acquire)
                || s.fenced
                || s.snapshot.lifecycle.child_exited
                || s.snapshot.lifecycle.stdout_eof
                || s.snapshot.lifecycle.stdin_ended
                || !s.initialized
                || !s.owner_deadline.is_some_and(|d| Instant::now() < d)
                || Instant::now() >= deadline
                || s.session_id != saved.session_id
                || s.epoch != saved.session_epoch
                || (saved.kind == ActionKind::Direction && !s.corroborated)
            {
                return Err(false);
            } // EndInput takes this same lock: this is the final write-admission
            // linearization point. A later EndInput cancels this in-flight attempt.
            s.records.get_mut(&id).ok_or(false)?.may_written = true;
        }
        writer.write_all(&frame).await.map_err(|_| true)?;
        writer.flush().await.map_err(|_| true)
    };
    let result = tokio::select! {biased;_=end.changed()=>Err(true),r=tokio::time::timeout(deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(2)),write)=>r.unwrap_or(Err(true))};
    let e = match result {
        Ok(()) => InputEvidence {
            frame_written: true,
            ..Default::default()
        },
        Err(false) => InputEvidence {
            not_dispatched: true,
            ..Default::default()
        },
        Err(true) => {
            let written = shared
                .state
                .lock()
                .ok()
                .is_none_or(|s| s.records.get(&id).is_none_or(|p| p.may_written));
            shared.fence();
            if written {
                InputEvidence {
                    write_uncertain: true,
                    ..Default::default()
                }
            } else {
                InputEvidence {
                    not_dispatched: true,
                    ..Default::default()
                }
            }
        }
    };
    shared.emit(&id, e);
    if e.frame_written {
        let owner = shared.clone();
        let id = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let pending = owner.state.lock().ok().is_some_and(|s| {
                s.records.get(&id).is_some_and(|p| {
                    !p.evidence.user_replayed
                        && !p.evidence.reply_correlated
                        && !p.evidence.result_correlated
                })
            });
            if pending {
                owner.emit(
                    &id,
                    InputEvidence {
                        write_uncertain: true,
                        ..Default::default()
                    },
                );
            }
        });
    }
    e
}
async fn install(shared: Arc<Shared>, io: ChildIo) {
    *shared.writer.lock().await = Some(io.writer);
    let mut end = shared.end.subscribe();
    let closing = shared.clone();
    tokio::spawn(async move {
        if !closing.ended.load(Ordering::Acquire) {
            let _ = end.changed().await;
        }
        let writer = closing.writer.lock().await.take();
        let confirmed = if let Some(mut writer) = writer {
            let result = tokio::time::timeout(Duration::from_secs(2), writer.shutdown()).await;
            drop(writer);
            matches!(result, Ok(Ok(())))
        } else {
            true
        };
        if let Ok(mut s) = closing.state.lock() {
            s.snapshot.lifecycle.stdin_ended = confirmed;
            if !confirmed {
                s.fenced = true;
            }
        }
        closing.publish();
    });
    let reading = shared.clone();
    let read = tokio::spawn(async move { read_loop(reading, io.reader).await });
    let joining = shared.clone();
    tokio::spawn(async move {
        if read.await.is_err() {
            joining.fence();
        }
        if let Ok(mut s) = joining.state.lock() {
            s.snapshot.lifecycle.reader_joined = true;
        }
        joining.publish();
    });
    let stderr = shared.clone();
    let error = tokio::spawn(async move {
        let mut stream = io.stderr;
        let mut buffer = [0u8; 8192];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    if let Ok(mut s) = stderr.state.lock() {
                        s.snapshot.lifecycle.stderr_eof = true;
                    }
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        stderr.publish();
    });
    let joining = shared.clone();
    tokio::spawn(async move {
        let _ = error.await;
        if let Ok(mut s) = joining.state.lock() {
            s.snapshot.lifecycle.stderr_joined = true;
        }
        joining.publish();
    });
    let waiting = shared.clone();
    let child_wait = tokio::spawn(async move {
        let result = io.wait.await;
        if let Ok(mut s) = waiting.state.lock() {
            if let Ok(code) = result {
                s.snapshot.lifecycle.child_exited = true;
                s.snapshot.lifecycle.exit_code = code;
                s.fenced = true;
            } else {
                s.fenced = true;
            }
        }
        waiting.publish();
    });
    tokio::spawn(async move {
        let joined = child_wait.await.is_ok();
        if let Ok(mut s) = shared.state.lock() {
            s.snapshot.lifecycle.child_wait_joined = joined;
            if !joined {
                s.fenced = true;
            }
        }
        shared.publish();
    });
}
async fn read_loop(shared: Arc<Shared>, reader: ReadIo) {
    let mut reader = BufReader::new(reader);
    loop {
        let mut bytes = Vec::new();
        let result = (&mut reader)
            .take((wire::MAX_FRAME + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .await;
        match result {
            Ok(0) => {
                if let Ok(mut s) = shared.state.lock() {
                    s.snapshot.lifecycle.stdout_eof = true;
                    s.fenced = true;
                }
                shared.publish();
                break;
            }
            Ok(_) if bytes.len() <= wire::MAX_FRAME && bytes.ends_with(b"\n") => {
                match wire::parse(&bytes) {
                    Ok(e) => observe(&shared, e),
                    Err(_) => shared.fence(),
                }
            }
            _ => {
                shared.fence();
                break;
            }
        }
    }
}
fn observe(shared: &Arc<Shared>, event: Event) {
    if matches!(
        &event,
        Event::Reply { .. } | Event::Result { .. } | Event::Replay { .. }
    ) && !shared.state.lock().ok().is_some_and(|s| {
        s.records
            .values()
            .any(|p| p.saved.kind == ActionKind::Start && p.may_written)
    }) {
        shared.fence();
        return;
    }
    match event {
        Event::ControlSuccess {
            request_id,
            version,
        } => {
            let (waiter, deferred, valid) = {
                let Ok(mut s) = shared.state.lock() else {
                    return;
                };
                if request_id != s.init_id {
                    return;
                }
                let valid = wire::compatible(version.as_deref());
                s.initialized = valid;
                if !valid {
                    s.fenced = true;
                }
                (s.init_waiter.take(), std::mem::take(&mut s.deferred), valid)
            };
            if valid {
                for e in deferred {
                    observe(shared, e);
                }
            }
            if let Some(w) = waiter {
                let _ = w.send(if valid {
                    Ok(())
                } else {
                    Err(ClaudeError::Unavailable)
                });
            }
        }
        Event::ControlError { request_id } => {
            if let Ok(mut s) = shared.state.lock()
                && request_id == s.init_id
            {
                s.fenced = true;
                if let Some(w) = s.init_waiter.take() {
                    let _ = w.send(Err(ClaudeError::Unavailable));
                }
            }
        }
        Event::Init {
            session,
            version,
            cwd,
            manual_empty,
        } => {
            let deferred = {
                let Ok(mut s) = shared.state.lock() else {
                    return;
                };
                if !s.initialized {
                    if s.deferred.len() < 64 {
                        s.deferred.push_back(Event::Init {
                            session,
                            version,
                            cwd,
                            manual_empty,
                        });
                    } else {
                        s.fenced = true;
                    }
                    drop(s);
                    shared.publish();
                    return;
                }
                if session != s.session_id
                    || version != CLI_VERSION
                    || std::path::Path::new(&cwd) != shared.config.workdir.as_path()
                    || !manual_empty
                {
                    s.fenced = true;
                    VecDeque::new()
                } else {
                    s.corroborated = true;
                    if s.snapshot.phase == WorkPhase::Starting {
                        s.snapshot.phase = WorkPhase::Idle;
                    }
                    std::mem::take(&mut s.deferred)
                }
            };
            for e in deferred {
                observe(shared, e);
            }
        }
        Event::OwnerRequest => {
            shared.fence();
            return;
        }
        event => {
            let corroborated = shared.state.lock().ok().is_some_and(|s| s.corroborated);
            if !corroborated {
                if let Ok(mut s) = shared.state.lock() {
                    if s.deferred.len() < 64 {
                        s.deferred.push_back(event);
                    } else {
                        s.fenced = true;
                    }
                }
                shared.publish();
                return;
            }
            match event {
                Event::Replay { session, id, text } => {
                    let matched = shared.state.lock().ok().is_some_and(|s| {
                        session == s.session_id
                            && s.records
                                .get(&id)
                                .is_some_and(|p| p.may_written && p.saved.text == text)
                    });
                    if matched {
                        shared.emit(
                            &id,
                            InputEvidence {
                                user_replayed: true,
                                ..Default::default()
                            },
                        );
                    }
                }
                Event::Reply { session, ids, text } => {
                    let matches = correlated(shared, &session, &ids);
                    if let Ok(mut s) = shared.state.lock()
                        && session == s.session_id
                    {
                        s.snapshot.phase = WorkPhase::Working;
                        if let Some(text) = text
                            && !text.is_empty()
                        {
                            s.snapshot.agent_text = Some(text);
                        }
                    }
                    for id in matches {
                        shared.emit(
                            &id,
                            InputEvidence {
                                reply_correlated: true,
                                ..Default::default()
                            },
                        );
                    }
                }
                Event::Result {
                    session,
                    ids,
                    error,
                } => {
                    let matches = correlated(shared, &session, &ids);
                    if let Ok(mut s) = shared.state.lock()
                        && session == s.session_id
                    {
                        s.snapshot.phase = WorkPhase::Idle;
                    }
                    for id in matches {
                        shared.emit(
                            &id,
                            InputEvidence {
                                result_correlated: true,
                                peer_error_observed: error,
                                ..Default::default()
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }
    shared.publish();
}
fn correlated(shared: &Shared, session: &str, ids: &[String]) -> Vec<String> {
    let Ok(s) = shared.state.lock() else {
        return Vec::new();
    };
    if session != s.session_id {
        return Vec::new();
    }
    ids.iter()
        .filter(|id| s.records.get(*id).is_some_and(|p| p.may_written))
        .cloned()
        .collect()
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn observed_fixture_session() -> Result<ObservedSession> {
    let config = WorkConfig::new(
        std::path::Path::new("/fixture/claude"),
        &"0".repeat(64),
        std::path::Path::new("/fixture/work"),
        std::path::Path::new("/fixture/journal"),
        StartupPolicyDeclaration::ManagedPolicyProseOnly,
    )?;
    let (shared, _events) = new_shared(config);
    let init = new_operation_id()?;
    {
        let mut s = shared.state.lock().map_err(|_| ClaudeError::Unavailable)?;
        s.init_id = init.clone();
        s.session_id = new_operation_id()?;
        s.epoch = new_operation_id()?;
        s.owner_deadline = Some(Instant::now() + Duration::from_secs(900));
        let saved = SavedInput {
            schema: "chinwag-claude-input/v1".into(),
            id: new_operation_id()?,
            session_epoch: s.epoch.clone(),
            session_id: s.session_id.clone(),
            kind: ActionKind::Start,
            timing: InputTiming::Now,
            text: "synthetic observer input".into(),
            startup: Some(StartupRecord {
                binary: shared.config.binary.clone(),
                sha256: shared.config.sha256.clone(),
                workdir: shared.config.workdir.clone(),
                policy: "managed_policy_prose_only".into(),
            }),
        };
        s.records.insert(
            saved.id.clone(),
            Pending {
                saved,
                evidence: InputEvidence::default(),
                may_written: true,
            },
        );
    }
    observe(
        &shared,
        wire::parse(&wire::encode(
            serde_json::json!({"type":"control_response","response":{"subtype":"success","request_id":init,"response":{"claude_code_version":CLI_VERSION}}}),
        )?)?,
    );
    let session = shared
        .state
        .lock()
        .map_err(|_| ClaudeError::Unavailable)?
        .session_id
        .clone();
    observe(
        &shared,
        wire::parse(&wire::encode(
            serde_json::json!({"type":"system","subtype":"init","session_id":session,"claude_code_version":CLI_VERSION,"cwd":"/fixture/work","tools":[],"permissionMode":"default"}),
        )?)?,
    );
    let session = shared.snapshots.borrow().session.clone();
    session.ok_or(ClaudeError::NoSession)
}
#[cfg(test)]
mod tests;
