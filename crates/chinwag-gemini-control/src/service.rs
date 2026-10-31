use crate::{
    admission::{Admission, Ticket},
    api::{valid_text, valid_uuid},
    journal::{Consume, OperationJournal},
    wire::{self, Event, RpcId, Update},
    *,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, watch};
mod io;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use io::ChildIo;
pub(crate) use io::Spawner;
const MAX_PERMISSIONS: usize = 8;
type Store = Arc<Mutex<OperationJournal>>;
type EvidenceChannel = mpsc::Receiver<(String, Evidence)>;
#[derive(Clone)]
struct Captured {
    ticket: Ticket,
    saved: SavedOperation,
    deadline: Instant,
}
enum Command {
    Start {
        id: String,
        text: String,
        deadline: Instant,
    },
    Prompt(Captured),
    Cancel(Captured),
    Lookup(String),
}
struct Queued {
    command: Command,
    ticket: Option<Ticket>,
}
struct Pending {
    ticket: Ticket,
    saved: SavedOperation,
    evidence: Evidence,
    may_written: bool,
}
#[derive(Clone)]
struct Active {
    operation_id: String,
    rpc_id: String,
    generation: u64,
    may_written: bool,
}
struct CancelWindow {
    saved: SavedOperation,
    deadline: Instant,
    committed: bool,
    writer_retired: bool,
    terminal_seen: bool,
    jobs: usize,
    written: u32,
    scheduled: BTreeSet<RpcId>,
}
struct Permission {
    rpc_id: String,
    generation: u64,
}
struct State {
    snapshot: WorkSnapshot,
    records: BTreeMap<String, Pending>,
    started: bool,
    owner_deadline: Option<Instant>,
    epoch: String,
    session: Option<String>,
    initialized: bool,
    hard_fenced: bool,
    policy_blocked: bool,
    next_generation: u64,
    active: Option<Active>,
    cancel: Option<CancelWindow>,
    permissions: BTreeMap<RpcId, Permission>,
    bootstrap: BTreeMap<String, oneshot::Sender<Result<serde_json::Value>>>,
    deferred: VecDeque<(String, Update)>,
}
struct Shared {
    config: WorkConfig,
    identity: Arc<()>,
    state: Mutex<State>,
    snapshots: watch::Sender<WorkSnapshot>,
    ended: Arc<AtomicBool>,
    end: watch::Sender<bool>,
    writer: tokio::sync::Mutex<Option<io::WriteIo>>,
    write_gate: Arc<tokio::sync::Semaphore>,
    admission: Arc<Mutex<()>>,
    input_admission: Mutex<Admission>,
    events: mpsc::Sender<(String, Evidence)>,
    publication: mpsc::Sender<()>,
    publication_rx: Mutex<Option<mpsc::Receiver<()>>>,
    flight: AtomicBool,
    #[cfg(test)]
    fail_consume: AtomicBool,
    #[cfg(test)]
    before_write: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}
impl Shared {
    fn publish(&self) {
        let _ = self.publication.try_send(());
    }
    fn publish_now(&self) {
        let snapshot = {
            let Ok(mut s) = self.state.lock() else {
                return;
            };
            s.snapshot.revision = s.snapshot.revision.saturating_add(1);
            let expired = s.owner_deadline.is_some_and(|d| Instant::now() >= d);
            s.snapshot.control_expired = expired;
            let live = !self.ended.load(Ordering::Acquire)
                && !expired
                && !s.hard_fenced
                && !s.snapshot.lifecycle.child_exited
                && !s.snapshot.lifecycle.stdout_eof
                && !s.snapshot.lifecycle.stdin_ended;
            let session = if live && s.initialized {
                s.session.as_ref().map(|sid| ObservedSession {
                    identity: self.identity.clone(),
                    epoch: s.epoch.clone(),
                    session_id: sid.clone(),
                    generation: 1,
                })
            } else {
                None
            };
            s.snapshot.session = session.clone();
            s.snapshot.active_prompt = if live {
                s.active.as_ref().filter(|a| a.may_written).and_then(|a| {
                    session.clone().map(|session| ObservedActivePrompt {
                        session,
                        rpc_id: a.rpc_id.clone(),
                        operation_id: a.operation_id.clone(),
                        generation: a.generation,
                    })
                })
            } else {
                None
            };
            s.snapshot.cancel_pending = s.cancel.is_some();
            s.snapshot.pending_permissions = s.permissions.len();
            s.snapshot.can_prompt = live
                && session.is_some()
                && s.active.is_none()
                && s.cancel.is_none()
                && !s.policy_blocked
                && s.permissions.is_empty()
                && !self.flight.load(Ordering::Acquire);
            s.snapshot.phase = if s.snapshot.lifecycle.child_exited {
                WorkPhase::Exited
            } else if self.ended.load(Ordering::Acquire) {
                WorkPhase::InputEnded
            } else if s.hard_fenced || s.policy_blocked || !s.permissions.is_empty() {
                WorkPhase::OwnerActionRequired
            } else if s.cancel.is_some() {
                WorkPhase::Cancelling
            } else if s.active.is_some() {
                WorkPhase::Prompting
            } else if s.session.is_some() {
                WorkPhase::Idle
            } else if s.started {
                WorkPhase::Starting
            } else {
                s.snapshot.phase
            };
            s.snapshot.clone()
        };
        self.snapshots.send_if_modified(|old| {
            if snapshot.revision > old.revision {
                *old = snapshot;
                true
            } else {
                false
            }
        });
    }
    fn fence(&self) {
        let unresolved = if let Ok(mut s) = self.state.lock() {
            s.hard_fenced = true;
            s.records
                .iter()
                .filter(|(_, p)| {
                    p.saved.kind != ActionKind::Cancel
                        && p.may_written
                        && !p.evidence.not_dispatched
                        && p.evidence.terminal.is_none()
                        && !p.evidence.rpc_error
                        && !p.evidence.terminal_unknown
                })
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        for id in unresolved {
            self.emit(
                &id,
                Evidence {
                    terminal_unknown: true,
                    ..Default::default()
                },
            );
        }
        self.publish();
    }
    fn end_input(&self) {
        {
            let mut control = self
                .input_admission
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            control.invalidate();
            let _effect = self.admission.lock();
            let _state = self.state.lock();
            self.ended.store(true, Ordering::Release);
        }
        self.end.send_replace(true);
        self.publish();
    }
    fn receipt(&self, mut r: Receipt) {
        if let Ok(mut s) = self.state.lock() {
            let old = if r.operation.kind == ActionKind::Start {
                s.snapshot.start.as_ref()
            } else {
                s.snapshot
                    .operations
                    .iter()
                    .find(|old| old.operation.id == r.operation.id)
            };
            if let Some(old) = old
                && old.operation == r.operation
            {
                if let Ok(e) = old.evidence.merged(r.evidence.clone()) {
                    r.evidence = e;
                }
                r.persistence_failed |= old.persistence_failed;
            }
            if r.operation.kind == ActionKind::Start {
                s.snapshot.start = Some(r);
            } else if let Some(old) = s
                .snapshot
                .operations
                .iter_mut()
                .find(|old| old.operation.id == r.operation.id)
            {
                *old = r;
            } else {
                s.snapshot.operations.push(r);
            }
        }
        self.publish();
    }
    fn completed(&self, id: String, kind: ActionKind, saved: bool, error: Option<GeminiError>) {
        if let Ok(mut s) = self.state.lock() {
            s.snapshot.last_submission = Some(WorkSubmission {
                id,
                kind,
                saved,
                error,
            });
        }
        self.publish();
    }
    fn release(&self, ticket: Option<&Ticket>) {
        if let Some(ticket) = ticket
            && let Ok(mut control) = self.input_admission.lock()
            && control.release(ticket)
        {
            self.flight.store(false, Ordering::Release);
        }
        self.publish();
    }
    fn emit(&self, id: &str, e: Evidence) {
        let merged = {
            let Ok(mut s) = self.state.lock() else {
                return;
            };
            let Some(p) = s.records.get_mut(id) else {
                return;
            };
            let Ok(merged) = p.evidence.merged(e) else {
                drop(s);
                self.fence();
                return;
            };
            if merged == p.evidence {
                return;
            }
            p.evidence = merged.clone();
            merged
        };
        if self.events.try_send((id.into(), merged)).is_err() {
            self.fence();
        }
    }
    fn target(&self, s: &State, t: &ObservedSession) -> bool {
        Arc::ptr_eq(&self.identity, &t.identity)
            && t.epoch == s.epoch
            && s.session.as_deref() == Some(t.session_id())
            && t.generation == 1
    }
    fn control(&self, s: &State, deadline: Instant) -> Result<()> {
        if self.ended.load(Ordering::Acquire)
            || s.snapshot.lifecycle.child_exited
            || s.snapshot.lifecycle.stdout_eof
            || s.snapshot.lifecycle.stdin_ended
        {
            return Err(GeminiError::Unavailable);
        }
        if s.hard_fenced {
            return Err(GeminiError::OwnerInterventionRequired);
        }
        if Instant::now() >= deadline || !s.owner_deadline.is_some_and(|d| Instant::now() < d) {
            return Err(GeminiError::PermissionDenied);
        }
        Ok(())
    }
}
struct Client {
    shared: Arc<Shared>,
    commands: mpsc::Sender<Queued>,
}
impl Client {
    fn prompt_target(&self, s: &State, target: &ObservedSession, deadline: Instant) -> Result<()> {
        if !self.shared.target(s, target) {
            return Err(GeminiError::StaleTarget);
        }
        self.shared.control(s, deadline)?;
        if s.active.is_some() || s.cancel.is_some() {
            return Err(GeminiError::Busy);
        }
        if s.policy_blocked || !s.permissions.is_empty() {
            return Err(GeminiError::OwnerInterventionRequired);
        }
        Ok(())
    }
}
impl HumanWorkPort for Client {
    fn subscribe(&self) -> watch::Receiver<WorkSnapshot> {
        self.shared.snapshots.subscribe()
    }
    fn start(&self, id: &str, text: &str) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        if !valid_uuid(id) || !valid_text(text) {
            return Err(GeminiError::InvalidInput);
        }
        let mut control = self
            .shared
            .input_admission
            .lock()
            .map_err(|_| GeminiError::Unavailable)?;
        if self.shared.ended.load(Ordering::Acquire) {
            return Err(GeminiError::Unavailable);
        }
        let permit = self.commands.try_reserve().map_err(|_| GeminiError::Busy)?;
        let ticket = control.admit(None, id)?;
        self.shared.flight.store(true, Ordering::Release);
        permit.send(Queued {
            command: Command::Start {
                id: id.into(),
                text: text.into(),
                deadline,
            },
            ticket: Some(ticket),
        });
        self.shared.publish();
        Ok(())
    }
    fn prompt(&self, target: &ObservedSession, id: &str, text: &str) -> Result<()> {
        let prepared =
            self.prepare_prompt(target, id, text, Instant::now() + Duration::from_secs(30))?;
        self.submit_prepared_prompt(prepared)
    }
    fn prepare_prompt(
        &self,
        target: &ObservedSession,
        id: &str,
        text: &str,
        deadline: Instant,
    ) -> Result<PreparedPrompt> {
        if !valid_uuid(id) || !valid_text(text) {
            return Err(GeminiError::InvalidInput);
        }
        let now = Instant::now();
        if deadline <= now {
            return Err(GeminiError::PermissionDenied);
        }
        if deadline > now + Duration::from_secs(30) {
            return Err(GeminiError::InvalidInput);
        }
        let control = self
            .shared
            .input_admission
            .lock()
            .map_err(|_| GeminiError::Unavailable)?;
        let sequence = control.prepare_sequence()?;
        if self.commands.capacity() == 0 {
            return Err(GeminiError::Busy);
        }
        let s = self
            .shared
            .state
            .lock()
            .map_err(|_| GeminiError::Unavailable)?;
        self.prompt_target(&s, target, deadline)?;
        if s.records.len() >= MAX_OPERATIONS && !s.records.contains_key(id) {
            return Err(GeminiError::Capacity);
        }
        let operation = SavedOperation {
            schema: "chinwag-gemini-operation/v1".into(),
            id: id.into(),
            kind: ActionKind::Prompt,
            text: text.into(),
            session_epoch: s.epoch.clone(),
            session_id: s.session.clone(),
            prompt_rpc_id: format!("prompt-{id}"),
            prompt_generation: s.next_generation,
            startup: None,
        };
        Ok(PreparedPrompt {
            target: target.clone(),
            operation,
            deadline,
            sequence,
        })
    }
    fn submit_prepared_prompt(&self, prepared: PreparedPrompt) -> Result<()> {
        let mut control = self
            .shared
            .input_admission
            .lock()
            .map_err(|_| GeminiError::Unavailable)?;
        let mut s = self
            .shared
            .state
            .lock()
            .map_err(|_| GeminiError::Unavailable)?;
        self.prompt_target(&s, &prepared.target, prepared.deadline)?;
        if s.next_generation != prepared.operation.prompt_generation {
            return Err(GeminiError::StaleTarget);
        }
        let next = s
            .next_generation
            .checked_add(1)
            .ok_or(GeminiError::Capacity)?;
        let permit = self.commands.try_reserve().map_err(|_| GeminiError::Busy)?;
        let ticket = control.admit(Some(prepared.sequence), &prepared.operation.id)?;
        s.next_generation = next;
        self.shared.flight.store(true, Ordering::Release);
        permit.send(Queued {
            command: Command::Prompt(Captured {
                saved: prepared.operation,
                deadline: prepared.deadline,
                ticket: ticket.clone(),
            }),
            ticket: Some(ticket),
        });
        drop(s);
        self.shared.publish();
        Ok(())
    }
    fn cancel(&self, target: &ObservedActivePrompt, id: &str) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        if !valid_uuid(id) {
            return Err(GeminiError::InvalidInput);
        }
        let mut control = self
            .shared
            .input_admission
            .lock()
            .map_err(|_| GeminiError::Unavailable)?;
        let mut s = self
            .shared
            .state
            .lock()
            .map_err(|_| GeminiError::Unavailable)?;
        if !self.shared.target(&s, &target.session) {
            return Err(GeminiError::StaleTarget);
        }
        self.shared.control(&s, deadline)?;
        let Some(active) = s.active.as_ref().filter(|a| {
            a.rpc_id == target.rpc_id
                && a.generation == target.generation
                && a.operation_id == target.operation_id
                && a.may_written
        }) else {
            return Err(GeminiError::StaleTarget);
        };
        if s.cancel.is_some() {
            return Err(GeminiError::Busy);
        }
        let saved = SavedOperation {
            schema: "chinwag-gemini-operation/v1".into(),
            id: id.into(),
            kind: ActionKind::Cancel,
            text: String::new(),
            session_epoch: s.epoch.clone(),
            session_id: s.session.clone(),
            prompt_rpc_id: active.rpc_id.clone(),
            prompt_generation: active.generation,
            startup: None,
        };
        let permit = self.commands.try_reserve().map_err(|_| GeminiError::Busy)?;
        let ticket = control.admit(None, id)?;
        s.cancel = Some(CancelWindow {
            saved: saved.clone(),
            deadline,
            committed: false,
            writer_retired: false,
            terminal_seen: false,
            jobs: 0,
            written: 0,
            scheduled: BTreeSet::new(),
        });
        self.shared.flight.store(true, Ordering::Release);
        permit.send(Queued {
            command: Command::Cancel(Captured {
                saved,
                deadline,
                ticket: ticket.clone(),
            }),
            ticket: Some(ticket),
        });
        drop(s);
        self.shared.publish();
        Ok(())
    }
    fn lookup(&self, id: &str) -> Result<()> {
        if !valid_uuid(id) {
            return Err(GeminiError::InvalidInput);
        }
        self.commands
            .try_send(Queued {
                command: Command::Lookup(id.into()),
                ticket: None,
            })
            .map_err(|_| GeminiError::Busy)
    }
    fn end_input(&self) -> Result<()> {
        self.shared.end_input();
        Ok(())
    }
}
pub fn open_work_service(config: WorkConfig) -> Result<Arc<dyn HumanWorkPort>> {
    open_with(config, Arc::new(io::NativeSpawner))
}
pub(crate) fn open_with(
    config: WorkConfig,
    spawner: Arc<dyn Spawner>,
) -> Result<Arc<dyn HumanWorkPort>> {
    let (shared, events) = new_shared(config);
    launch_owner(shared, events, spawner)
}
fn launch_owner(
    shared: Arc<Shared>,
    events: EvidenceChannel,
    spawner: Arc<dyn Spawner>,
) -> Result<Arc<dyn HumanWorkPort>> {
    let (tx, commands) = mpsc::channel(8);
    let client = Arc::new(Client {
        shared: shared.clone(),
        commands: tx.clone(),
    });
    std::thread::Builder::new()
        .name("chinwag-gemini-owner".into())
        .spawn(move || {
            let _keep = tx;
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(run(shared, commands, events, spawner)),
                Err(_) => {
                    shared.fence();
                }
            }
        })
        .map_err(|_| GeminiError::Unavailable)?;
    Ok(client)
}
fn new_shared(config: WorkConfig) -> (Arc<Shared>, EvidenceChannel) {
    let (snapshots, _) = watch::channel(WorkSnapshot::ready(config.folder_label()));
    let snapshot = snapshots.borrow().clone();
    let (end, _) = watch::channel(false);
    let (events, rx) = mpsc::channel(MAX_OPERATIONS * 8);
    let (publication, publication_rx) = mpsc::channel(1);
    (
        Arc::new(Shared {
            config,
            identity: Arc::new(()),
            state: Mutex::new(State {
                snapshot,
                records: BTreeMap::new(),
                started: false,
                owner_deadline: None,
                epoch: String::new(),
                session: None,
                initialized: false,
                hard_fenced: false,
                policy_blocked: false,
                next_generation: 2,
                active: None,
                cancel: None,
                permissions: BTreeMap::new(),
                bootstrap: BTreeMap::new(),
                deferred: VecDeque::new(),
            }),
            snapshots,
            ended: Arc::new(AtomicBool::new(false)),
            end,
            writer: tokio::sync::Mutex::new(None),
            write_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            admission: Arc::new(Mutex::new(())),
            input_admission: Mutex::new(Admission::default()),
            events,
            publication,
            publication_rx: Mutex::new(Some(publication_rx)),
            flight: AtomicBool::new(false),
            #[cfg(test)]
            fail_consume: AtomicBool::new(false),
            #[cfg(test)]
            before_write: Mutex::new(None),
        }),
        rx,
    )
}
async fn store<T: Send + 'static>(
    j: &Store,
    f: impl FnOnce(&mut OperationJournal) -> Result<T> + Send + 'static,
) -> Result<T> {
    let j = j.clone();
    tokio::task::spawn_blocking(move || {
        let mut held = j.lock().map_err(|_| GeminiError::Storage)?;
        f(&mut held)
    })
    .await
    .map_err(|_| GeminiError::Storage)?
}
async fn persist(shared: &Arc<Shared>, j: &Store, id: &str, e: Evidence) -> Result<Receipt> {
    let id = id.to_owned();
    let r = store(j, move |j| match j.apply(&id, e) {
        Ok(r) => Ok(r),
        Err(_) => j.mark_persistence_failure(&id),
    })
    .await?;
    shared.receipt(r.clone());
    Ok(r)
}
async fn run(
    shared: Arc<Shared>,
    mut commands: mpsc::Receiver<Queued>,
    mut events: EvidenceChannel,
    spawner: Arc<dyn Spawner>,
) {
    let publications = shared
        .publication_rx
        .lock()
        .ok()
        .and_then(|mut rx| rx.take());
    if let Some(mut publications) = publications {
        let publisher = shared.clone();
        tokio::spawn(async move {
            while publications.recv().await.is_some() {
                let target = publisher.clone();
                if tokio::task::spawn_blocking(move || target.publish_now())
                    .await
                    .is_err()
                {
                    publisher.fence();
                }
            }
        });
    }
    let p = shared.config.journal.clone();
    let journal = match tokio::task::spawn_blocking(move || OperationJournal::open(&p)).await {
        Ok(Ok(j)) => Arc::new(Mutex::new(j)),
        _ => {
            shared.fence();
            while let Some(c) = commands.recv().await {
                let (id, kind) = label(&c.command);
                shared.completed(id, kind, false, Some(GeminiError::Storage));
                shared.release(c.ticket.as_ref());
            }
            return;
        }
    };
    #[cfg(test)]
    if shared.fail_consume.swap(false, Ordering::AcqRel) {
        let _ = store(&journal, |j| {
            j.fail_next_create_for_fixture();
            Ok(())
        })
        .await;
    }
    match store(&journal, |j| Ok((j.has_consumed(), j.receipts()?))).await {
        Ok((has, receipts)) => {
            if has && let Ok(mut s) = shared.state.lock() {
                s.started = true;
                s.hard_fenced = true;
            }
            for r in receipts {
                shared.receipt(r);
            }
        }
        Err(_) => shared.fence(),
    };
    let target = shared.clone();
    let disk = journal.clone();
    tokio::spawn(async move {
        while let Some((id, e)) = events.recv().await {
            if persist(&target, &disk, &id, e).await.is_err() {
                target.fence();
            }
        }
    });
    while let Some(queued) = commands.recv().await {
        match queued.command {
            Command::Start { id, text, deadline } => {
                start(
                    &shared,
                    &journal,
                    spawner.as_ref(),
                    id,
                    text,
                    deadline,
                    queued.ticket.as_ref().expect("input ticket"),
                )
                .await
            }
            Command::Prompt(action) => {
                let id = action.saved.id.clone();
                match submit_prompt(&shared, &journal, action).await {
                    Ok(r) => {
                        shared.receipt(r);
                        shared.completed(id, ActionKind::Prompt, true, None)
                    }
                    Err(e) => shared.completed(id, ActionKind::Prompt, false, Some(e)),
                }
            }
            Command::Cancel(action) => {
                let id = action.saved.id.clone();
                match submit_cancel(&shared, &journal, action).await {
                    Ok(r) => {
                        shared.receipt(r);
                        shared.completed(id, ActionKind::Cancel, true, None)
                    }
                    Err(e) => {
                        if let Ok(mut s) = shared.state.lock() {
                            abandon_cancel_reservation(&mut s);
                        }
                        shared.completed(id, ActionKind::Cancel, false, Some(e));
                    }
                }
            }
            Command::Lookup(id) => {
                let wanted = id.clone();
                match store(&journal, move |j| j.lookup(&wanted)).await {
                    Ok(Some(r)) => {
                        shared.receipt(r);
                        shared.completed(id, ActionKind::Lookup, true, None)
                    }
                    Ok(None) => shared.completed(
                        id,
                        ActionKind::Lookup,
                        false,
                        Some(GeminiError::Uncertain),
                    ),
                    Err(e) => shared.completed(id, ActionKind::Lookup, false, Some(e)),
                }
            }
        }
        shared.release(queued.ticket.as_ref());
    }
}
fn label(c: &Command) -> (String, ActionKind) {
    match c {
        Command::Start { id, .. } => (id.clone(), ActionKind::Start),
        Command::Prompt(a) => (a.saved.id.clone(), ActionKind::Prompt),
        Command::Cancel(a) => (a.saved.id.clone(), ActionKind::Cancel),
        Command::Lookup(id) => (id.clone(), ActionKind::Lookup),
    }
}
async fn start(
    shared: &Arc<Shared>,
    j: &Store,
    spawner: &dyn Spawner,
    id: String,
    text: String,
    deadline: Instant,
    ticket: &Ticket,
) {
    let wanted = id.clone();
    match store(j, move |j| j.lookup(&wanted)).await {
        Ok(Some(r)) => {
            if r.operation.kind == ActionKind::Start
                && r.operation.text == text
                && r.operation.startup.as_ref().is_some_and(|s| {
                    s.binary == shared.config.binary
                        && s.sha256 == shared.config.sha256
                        && s.workdir == shared.config.workdir
                })
            {
                shared.receipt(r);
                shared.completed(id, ActionKind::Start, true, None);
            } else {
                shared.completed(id, ActionKind::Start, false, Some(GeminiError::Conflict));
            }
            return;
        }
        Err(e) => {
            shared.completed(id, ActionKind::Start, false, Some(e));
            return;
        }
        _ => {}
    }
    let allowed = {
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
    if !allowed {
        shared.completed(id, ActionKind::Start, false, Some(GeminiError::Conflict));
        return;
    }
    let epoch = match new_operation_id() {
        Ok(s) => s,
        Err(e) => {
            shared.completed(id, ActionKind::Start, false, Some(e));
            return;
        }
    };
    let saved = SavedOperation {
        schema: "chinwag-gemini-operation/v1".into(),
        id: id.clone(),
        kind: ActionKind::Start,
        text,
        session_epoch: epoch.clone(),
        session_id: None,
        prompt_rpc_id: format!("prompt-{id}"),
        prompt_generation: 1,
        startup: Some(StartupRecord {
            binary: shared.config.binary.clone(),
            sha256: shared.config.sha256.clone(),
            workdir: shared.config.workdir.clone(),
            policy: "configured_runtime_effects_manual_mode_extensions_disabled".into(),
        }),
    };
    let copy = saved.clone();
    let receipt = match store(j, move |j| j.consume(copy)).await {
        Ok(Consume::Created(r)) => r,
        Ok(Consume::Existing(r)) => {
            shared.receipt(r);
            shared.completed(id, ActionKind::Start, true, None);
            return;
        }
        Err(e) => {
            project_consume_failure(shared, j, &saved).await;
            shared.completed(id, ActionKind::Start, false, Some(e));
            return;
        }
    };
    {
        let mut s = shared.state.lock().unwrap();
        s.epoch = epoch.clone();
        s.owner_deadline = deadline.checked_add(Duration::from_secs(870));
        s.records.insert(
            id.clone(),
            Pending {
                ticket: ticket.clone(),
                saved: saved.clone(),
                evidence: Evidence::default(),
                may_written: false,
            },
        );
    }
    shared.receipt(receipt);
    let result = start_effects(shared, j, spawner, &saved, deadline).await;
    if let Err(e) = result {
        let may = shared
            .state
            .lock()
            .ok()
            .is_none_or(|s| s.records.get(&id).is_none_or(|p| p.may_written));
        if !may {
            let _ = persist(
                shared,
                j,
                &id,
                Evidence {
                    not_dispatched: true,
                    ..Default::default()
                },
            )
            .await;
        }
        shared.fence();
        shared.completed(id, ActionKind::Start, true, Some(e));
    } else {
        shared.completed(id, ActionKind::Start, true, None);
    }
}
async fn start_effects(
    shared: &Arc<Shared>,
    j: &Store,
    spawner: &dyn Spawner,
    saved: &SavedOperation,
    deadline: Instant,
) -> Result<()> {
    if shared.ended.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err(GeminiError::PermissionDenied);
    }
    let child = spawner
        .spawn(
            shared.config.clone(),
            deadline,
            shared.ended.clone(),
            shared.admission.clone(),
        )
        .await?;
    let valid = child.valid;
    let verify = child.verify.clone();
    io::install(shared.clone(), child).await;
    if !valid {
        return Err(GeminiError::Unavailable);
    }
    let init_id = format!("init-{}", saved.session_epoch);
    let init = bootstrap(shared, &init_id, wire::initialize(&init_id)?, deadline).await?;
    wire::initialization(&init)?;
    {
        shared
            .state
            .lock()
            .map_err(|_| GeminiError::Unavailable)?
            .initialized = true;
    }
    let session_id = format!("session-{}", saved.session_epoch);
    let session = bootstrap(
        shared,
        &session_id,
        wire::create_session(&session_id, &shared.config.workdir)?,
        deadline,
    )
    .await?;
    let sid = wire::new_session(&session)?;
    persist(
        shared,
        j,
        &saved.id,
        Evidence {
            bound_session_id: Some(sid.clone()),
            ..Default::default()
        },
    )
    .await?;
    let deferred = {
        let mut s = shared.state.lock().map_err(|_| GeminiError::Unavailable)?;
        s.session = Some(sid);
        std::mem::take(&mut s.deferred)
    };
    for (session, update) in deferred {
        observe(shared, Event::Update { session, update });
    }
    tokio::task::spawn_blocking(move || verify())
        .await
        .map_err(|_| GeminiError::Unavailable)??;
    let evidence = io::write_prompt(shared, saved, deadline).await;
    persist(shared, j, &saved.id, evidence.clone()).await?;
    if evidence.not_dispatched {
        return Err(GeminiError::Unavailable);
    }
    if evidence.write_uncertain {
        return Err(GeminiError::Uncertain);
    }
    let owner = shared.clone();
    let remaining = shared
        .state
        .lock()
        .ok()
        .and_then(|s| s.owner_deadline)
        .map(|d| d.saturating_duration_since(Instant::now()))
        .unwrap_or_default();
    tokio::spawn(async move {
        tokio::time::sleep(remaining).await;
        owner.publish();
    });
    Ok(())
}
async fn bootstrap(
    shared: &Arc<Shared>,
    id: &str,
    frame: Vec<u8>,
    deadline: Instant,
) -> Result<serde_json::Value> {
    let (tx, rx) = oneshot::channel();
    {
        let mut s = shared.state.lock().map_err(|_| GeminiError::Unavailable)?;
        if s.bootstrap.len() >= 2 {
            return Err(GeminiError::Capacity);
        }
        s.bootstrap.insert(id.into(), tx);
    }
    io::write_bootstrap(shared, frame, deadline).await?;
    tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), rx)
        .await
        .map_err(|_| GeminiError::Uncertain)?
        .map_err(|_| GeminiError::Unavailable)?
}
async fn consume(
    shared: &Arc<Shared>,
    j: &Store,
    saved: &SavedOperation,
    ticket: &Ticket,
) -> Result<Option<Receipt>> {
    if !ticket.permits(&saved.id) {
        return Err(GeminiError::PermissionDenied);
    }
    let wanted = saved.id.clone();
    if let Some(r) = store(j, move |j| j.lookup(&wanted)).await? {
        return if r.operation == *saved {
            Ok(Some(r))
        } else {
            Err(GeminiError::Conflict)
        };
    }
    let copy = saved.clone();
    let consumed = match store(j, move |j| j.consume(copy)).await {
        Ok(c) => c,
        Err(e) => {
            project_consume_failure(shared, j, saved).await;
            return Err(e);
        }
    };
    match consumed {
        Consume::Existing(r) => Ok(Some(r)),
        Consume::Created(r) => {
            shared.receipt(r);
            shared
                .state
                .lock()
                .map_err(|_| GeminiError::Unavailable)?
                .records
                .insert(
                    saved.id.clone(),
                    Pending {
                        ticket: ticket.clone(),
                        saved: saved.clone(),
                        evidence: Evidence::default(),
                        may_written: false,
                    },
                );
            Ok(None)
        }
    }
}
async fn project_consume_failure(shared: &Arc<Shared>, j: &Store, saved: &SavedOperation) {
    let wanted = saved.id.clone();
    if let Ok(Some(receipt)) = store(j, move |j| j.lookup(&wanted)).await {
        shared.receipt(receipt);
    }
    if let Ok(mut s) = shared.state.lock() {
        s.policy_blocked = true;
    }
    shared.publish();
}
async fn submit_prompt(shared: &Arc<Shared>, j: &Store, action: Captured) -> Result<Receipt> {
    if let Some(r) = consume(shared, j, &action.saved, &action.ticket).await? {
        return Ok(r);
    }
    let e = io::write_prompt(shared, &action.saved, action.deadline).await;
    persist(shared, j, &action.saved.id, e).await
}
async fn submit_cancel(shared: &Arc<Shared>, j: &Store, action: Captured) -> Result<Receipt> {
    if let Some(r) = consume(shared, j, &action.saved, &action.ticket).await? {
        if let Ok(mut s) = shared.state.lock() {
            abandon_cancel_reservation(&mut s);
        }
        return Ok(r);
    }
    let pending = {
        let mut s = shared.state.lock().map_err(|_| GeminiError::Unavailable)?;
        let Some(c) = s.cancel.as_mut().filter(|c| c.saved == action.saved) else {
            return Err(GeminiError::StaleTarget);
        };
        c.committed = true;
        s.permissions.keys().cloned().collect::<Vec<_>>()
    };
    for request in pending {
        schedule_permission(shared, request);
    }
    let e = io::write_cancel(shared, &action.saved, action.deadline).await;
    let receipt = persist(shared, j, &action.saved.id, e).await?;
    finish_cancel_writer(shared, &action.saved);
    shared.publish();
    Ok(receipt)
}
fn abandon_cancel_reservation(s: &mut State) {
    if s.cancel.as_ref().is_some_and(|c| !c.committed) {
        s.cancel = None;
        return;
    }
    let absent = s.cancel.as_ref().is_some_and(|c| {
        !s.active.as_ref().is_some_and(|a| {
            a.rpc_id == c.saved.prompt_rpc_id && a.generation == c.saved.prompt_generation
        })
    });
    if let Some(c) = s.cancel.as_mut() {
        c.writer_retired = true;
        c.terminal_seen |= absent;
    }
    retire_cancel(s);
}
fn finish_cancel_writer(shared: &Arc<Shared>, saved: &SavedOperation) {
    if let Ok(mut s) = shared.state.lock() {
        let terminal_seen = s.active.is_none();
        if let Some(c) = s.cancel.as_mut().filter(|c| c.saved == *saved) {
            c.writer_retired = true;
            c.terminal_seen |= terminal_seen;
        }
        retire_cancel(&mut s);
    }
    shared.publish();
}
fn retire_cancel(s: &mut State) {
    if s.cancel
        .as_ref()
        .is_some_and(|c| c.writer_retired && c.terminal_seen && c.jobs == 0)
    {
        s.cancel = None;
    }
}
fn observe(shared: &Arc<Shared>, event: Event) {
    match event {
        Event::Response { id, result, error } => {
            let Some(id) = id.string() else {
                shared.fence();
                return;
            };
            let waiter = shared
                .state
                .lock()
                .ok()
                .and_then(|mut s| s.bootstrap.remove(id));
            if let Some(waiter) = waiter {
                let _ = waiter.send(if error {
                    Err(GeminiError::Unavailable)
                } else {
                    result.ok_or(GeminiError::Unavailable)
                });
                return;
            }
            let (record_id, active_matches) = {
                let Ok(s) = shared.state.lock() else {
                    return;
                };
                let Some((record_id, _p)) = s.records.iter().find(|(_, p)| {
                    p.saved.kind != ActionKind::Cancel
                        && p.saved.prompt_rpc_id == id
                        && p.may_written
                }) else {
                    drop(s);
                    shared.fence();
                    return;
                };
                (
                    record_id.clone(),
                    s.active.as_ref().is_some_and(|a| a.rpc_id == id),
                )
            };
            let e = if error {
                if let Ok(mut s) = shared.state.lock() {
                    s.policy_blocked = true;
                }
                Evidence {
                    rpc_error: true,
                    ..Default::default()
                }
            } else {
                let Some(v) = result else {
                    shared.fence();
                    return;
                };
                match wire::terminal(&v) {
                    Ok(reason) => Evidence {
                        terminal: Some(reason),
                        ..Default::default()
                    },
                    Err(_) => {
                        shared.fence();
                        return;
                    }
                }
            };
            shared.emit(&record_id, e);
            if let Ok(mut s) = shared.state.lock()
                && active_matches
            {
                s.active = None;
                s.permissions.retain(|_, p| p.rpc_id != id);
                if let Some(c) = s.cancel.as_mut().filter(|c| c.saved.prompt_rpc_id == id) {
                    c.terminal_seen = true;
                }
                retire_cancel(&mut s);
            }
        }
        Event::Update { session, update } => {
            let mut s = match shared.state.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            let Some(sid) = s.session.as_ref() else {
                if s.deferred.len() < 64 {
                    s.deferred.push_back((session, update));
                } else {
                    s.hard_fenced = true;
                }
                let needs_fence = s.hard_fenced;
                drop(s);
                if needs_fence {
                    shared.fence();
                } else {
                    shared.publish();
                }
                return;
            };
            if sid != &session {
                s.hard_fenced = true;
            } else {
                match update {
                    Update::Mode(mode) if mode != "default" => s.policy_blocked = true,
                    Update::Text(text) => {
                        if s.records
                            .values()
                            .any(|p| p.saved.kind != ActionKind::Cancel && p.may_written)
                        {
                            if !text.is_empty() {
                                let current = s.snapshot.agent_text.get_or_insert_with(String::new);
                                for c in text.chars() {
                                    if current.len() + c.len_utf8() > MAX_TEXT_BYTES {
                                        break;
                                    }
                                    current.push(c);
                                }
                            }
                        } else {
                            s.hard_fenced = true;
                        }
                    }
                    _ => {}
                }
            }
        }
        Event::Permission { id, session } => {
            let schedule = {
                let mut s = match shared.state.lock() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                if s.session.as_ref() != Some(&session)
                    || s.permissions.contains_key(&id)
                    || s.permissions.len() >= MAX_PERMISSIONS
                {
                    s.hard_fenced = true;
                    false
                } else if let Some(a) = s.active.as_ref().filter(|a| a.may_written).cloned() {
                    s.permissions.insert(
                        id.clone(),
                        Permission {
                            rpc_id: a.rpc_id,
                            generation: a.generation,
                        },
                    );
                    s.cancel.as_ref().is_some_and(|c| c.committed)
                } else {
                    s.hard_fenced = true;
                    false
                }
            };
            if schedule {
                schedule_permission(shared, id);
            }
        }
        Event::OwnerRequest => {
            if let Ok(mut s) = shared.state.lock() {
                s.policy_blocked = true;
            }
        }
        Event::Other => {}
    }
    let needs_fence = shared.state.lock().map(|s| s.hard_fenced).unwrap_or(true);
    if needs_fence {
        shared.fence();
    } else {
        shared.publish();
    }
}
fn schedule_permission(shared: &Arc<Shared>, request: RpcId) {
    let accepted = {
        let mut s = match shared.state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        let Some(p) = s.permissions.get(&request) else {
            return;
        };
        let rpc = p.rpc_id.clone();
        let generation = p.generation;
        let Some(c) = s.cancel.as_mut().filter(|c| {
            c.committed && c.saved.prompt_rpc_id == rpc && c.saved.prompt_generation == generation
        }) else {
            return;
        };
        if c.scheduled.contains(&request) {
            return;
        }
        if c.scheduled.len() >= MAX_PERMISSIONS {
            drop(s);
            shared.fence();
            return;
        }
        c.scheduled.insert(request.clone());
        c.jobs += 1;
        Some((c.saved.clone(), c.deadline))
    };
    if let Some((saved, deadline)) = accepted {
        let owner = shared.clone();
        tokio::spawn(async move {
            let outcome = io::write_permission_cancel(&owner, &saved, &request, deadline).await;
            let e = {
                let mut s = match owner.state.lock() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let Some(c) = s.cancel.as_mut().filter(|c| c.saved == saved) else {
                    return;
                };
                c.jobs = c.jobs.saturating_sub(1);
                if outcome == io::PermissionWrite::Written {
                    c.written += 1;
                }
                let e = Evidence {
                    permission_cancel_responses_written: c.written,
                    permission_cancel_responses_uncertain: outcome
                        == io::PermissionWrite::Uncertain,
                    ..Default::default()
                };
                retire_cancel(&mut s);
                e
            };
            owner.emit(&saved.id, e);
            owner.publish();
        });
    }
}
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn fixture_targets() -> Result<(ObservedSession, ObservedActivePrompt)> {
    let config = WorkConfig::new(
        std::path::Path::new("/fixture/gemini"),
        &"0".repeat(64),
        std::path::Path::new("/fixture/work"),
        std::path::Path::new("/fixture/journal"),
        StartupPolicyDeclaration::ConfiguredRuntimeEffectsManualModeExtensionsDisabled,
    )?;
    let (shared, _) = new_shared(config);
    {
        let mut s = shared.state.lock().map_err(|_| GeminiError::Unavailable)?;
        s.epoch = new_operation_id()?;
        s.initialized = true;
        s.session = Some(new_operation_id()?);
        s.owner_deadline = Some(Instant::now() + Duration::from_secs(900));
        let id = new_operation_id()?;
        s.active = Some(Active {
            operation_id: id.clone(),
            rpc_id: format!("prompt-{id}"),
            generation: 1,
            may_written: true,
        });
    }
    let sid = shared
        .state
        .lock()
        .map_err(|_| GeminiError::Unavailable)?
        .session
        .clone()
        .ok_or(GeminiError::NoSession)?;
    observe(
        &shared,
        wire::parse(&wire::encode(
            serde_json::json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":sid,"update":{"sessionUpdate":"current_mode_update","currentModeId":"default"}}}),
        )?)?,
    );
    shared.publish_now();
    let snapshot = shared.snapshots.borrow().clone();
    Ok((
        snapshot.session.ok_or(GeminiError::NoSession)?,
        snapshot.active_prompt.ok_or(GeminiError::NoSession)?,
    ))
}
#[cfg(test)]
mod tests;
