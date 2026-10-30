//! One narrowly delegated, already initialized app-server stream. Construction
//! is a trusted host ownership boundary, never an editor/session discovery API.

use crate::{
    Evidence, MAX_OPERATIONS, SavedSteer, SteerError,
    record::{OPERATION_SCHEMA, valid_target_id},
    wire::{self, Incoming, WireId},
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
};

const MAX_LEASE: Duration = Duration::from_secs(900);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Owner-declared privileged human-input scope. No process name, bus record,
/// MCP permission or serialized request can construct human authority here.
pub struct OwnerControlScope {
    thread_id: String,
    deadline: Instant,
    _reference: String,
    fresh: Option<(String, String)>,
}
impl OwnerControlScope {
    pub fn new(
        decision_reference: String,
        thread_id: String,
        lease: Duration,
    ) -> crate::Result<Self> {
        if decision_reference.is_empty()
            || decision_reference.len() > 256
            || decision_reference.chars().any(char::is_control)
            || !valid_target_id(&thread_id)
            || lease.is_zero()
            || lease > MAX_LEASE
        {
            return Err(SteerError::InvalidInput);
        }
        let deadline = Instant::now()
            .checked_add(lease)
            .ok_or(SteerError::InvalidInput)?;
        Ok(Self {
            thread_id,
            deadline,
            _reference: decision_reference,
            fresh: None,
        })
    }
}
struct Identity;
#[derive(Clone)]
pub struct HumanSteerGrant {
    identity: Arc<Identity>,
    revoked: Arc<AtomicBool>,
    deadline: Instant,
    action: Option<HumanSteerAction>,
}
/// Exact captured native human action; cloning never extends its deadline.
#[derive(Clone)]
pub(crate) struct HumanSteerAction {
    target: ObservedActiveTurn,
    id: String,
    text: String,
    deadline: Instant,
}
impl HumanSteerAction {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
    pub(crate) fn target(&self) -> &ObservedActiveTurn {
        &self.target
    }
}
#[derive(Clone)]
pub struct ObservedActiveTurn {
    identity: Arc<Identity>,
    epoch: String,
    thread_id: String,
    turn_id: String,
    generation: u64,
}
impl ObservedActiveTurn {
    pub fn thread_id(&self) -> &str {
        &self.thread_id
    }
    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn matches_record(&self, record: &SavedSteer) -> bool {
        self.epoch == record.transport_epoch
            && self.thread_id == record.thread_id
            && self.turn_id == record.expected_turn_id
    }
}
pub struct PreparedSteer {
    record: SavedSteer,
    target: ObservedActiveTurn,
    grant: HumanSteerGrant,
}
impl PreparedSteer {
    pub fn record(&self) -> &SavedSteer {
        &self.record
    }
}
/// Only the controller may mint this after consuming its exact durable record.
pub(crate) struct CommittedSteerAttempt(PreparedSteer);
impl CommittedSteerAttempt {
    pub(crate) fn new(prepared: PreparedSteer) -> Self {
        Self(prepared)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TransportEvidence {
    pub id: String,
    pub evidence: Evidence,
}
struct Pending {
    record: SavedSteer,
    rpc_id: String,
    evidence: Evidence,
    may_have_written: bool,
}
#[derive(Clone)]
pub(crate) struct InitialEvidence {
    pub id: String,
    pub accepted_turn_id: Option<String>,
    pub evidence: Evidence,
}
#[derive(Clone)]
pub(crate) struct ConnectionActivity {
    pub target: Option<ObservedActiveTurn>,
    pub completed: bool,
    pub initial: Option<InitialEvidence>,
    pub agent_text: Option<String>,
    pub intervention: bool,
    pub write_fenced: bool,
    pub closed: bool,
    pub revision: u64,
}
struct InitialPending {
    id: String,
    text: String,
    rpc_id: String,
    evidence: Evidence,
    accepted_turn_id: Option<String>,
    may_have_written: bool,
}
pub(crate) struct CommittedInitialTurn {
    id: String,
    text: String,
    epoch: String,
    thread: String,
    deadline: Instant,
}
impl CommittedInitialTurn {
    pub(crate) fn new(
        id: String,
        text: String,
        epoch: String,
        thread: String,
        deadline: Instant,
    ) -> crate::Result<Self> {
        if !crate::record::valid_operation_id(&id)
            || !crate::record::valid_text(&text)
            || !valid_target_id(&thread)
            || epoch.len() != 32
            || !epoch
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SteerError::InvalidInput);
        }
        Ok(Self {
            id,
            text,
            epoch,
            thread,
            deadline,
        })
    }
}
struct Job {
    join: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}
struct State {
    active: Option<(String, u64)>,
    generation: u64,
    records: BTreeMap<String, Pending>,
    write_fenced: bool,
    intervention: bool,
    jobs: Vec<Arc<Job>>,
    initial: Option<InitialPending>,
    owned_turn: Option<String>,
    ended: bool,
    agent_text: Option<String>,
    revision: u64,
}
struct Shared {
    identity: Arc<Identity>,
    epoch: String,
    scope: OwnerControlScope,
    revoked: Arc<AtomicBool>,
    closed: AtomicBool,
    close: watch::Sender<bool>,
    state: Mutex<State>,
    events: Mutex<Option<mpsc::Sender<TransportEvidence>>>,
    receiver: Mutex<Option<mpsc::Receiver<TransportEvidence>>>,
    write_gate: Arc<Semaphore>,
    runtime: tokio::runtime::Handle,
    reader_job: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    activity: watch::Sender<ConnectionActivity>,
}
impl Shared {
    fn ready(&self, state: &State) -> crate::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(SteerError::Unavailable);
        }
        if self.revoked.load(Ordering::Acquire)
            || (self.scope.fresh.is_none() && Instant::now() >= self.scope.deadline)
            || (self.scope.fresh.is_some() && state.ended)
        {
            return Err(SteerError::PermissionDenied);
        }
        if state.intervention {
            return Err(SteerError::OwnerInterventionRequired);
        }
        if state.write_fenced {
            return Err(SteerError::Unavailable);
        }
        Ok(())
    }
    fn permits(&self, state: &State, prepared: &PreparedSteer) -> crate::Result<()> {
        self.ready(state)?;
        if !Arc::ptr_eq(&self.identity, &prepared.grant.identity)
            || !Arc::ptr_eq(&self.identity, &prepared.target.identity)
            || prepared.grant.revoked.load(Ordering::Acquire)
            || Instant::now() >= prepared.grant.deadline
        {
            return Err(SteerError::PermissionDenied);
        }
        if self.scope.fresh.is_some() {
            let action = prepared
                .grant
                .action
                .as_ref()
                .ok_or(SteerError::PermissionDenied)?;
            if action.id != prepared.record.id
                || action.text != prepared.record.text
                || action.target.epoch != prepared.target.epoch
                || action.target.generation != prepared.target.generation
                || action.target.turn_id != prepared.target.turn_id
                || Instant::now() >= action.deadline
            {
                return Err(SteerError::PermissionDenied);
            }
        }
        if prepared.record.transport_epoch != self.epoch
            || prepared.record.thread_id != self.scope.thread_id
        {
            return Err(SteerError::PermissionDenied);
        }
        if state.active.as_ref()
            != Some(&(prepared.target.turn_id.clone(), prepared.target.generation))
        {
            return Err(SteerError::StaleTarget);
        }
        Ok(())
    }
    fn notify_activity(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.revision = state.revision.saturating_add(1);
            let target = if self.ready(&state).is_ok() {
                state
                    .active
                    .as_ref()
                    .map(|(turn, generation)| ObservedActiveTurn {
                        identity: self.identity.clone(),
                        epoch: self.epoch.clone(),
                        thread_id: self.scope.thread_id.clone(),
                        turn_id: turn.clone(),
                        generation: *generation,
                    })
            } else {
                None
            };
            self.activity.send_replace(ConnectionActivity {
                target,
                completed: state.ended,
                initial: state.initial.as_ref().map(|p| InitialEvidence {
                    id: p.id.clone(),
                    accepted_turn_id: p.accepted_turn_id.clone(),
                    evidence: p.evidence,
                }),
                agent_text: state.agent_text.clone(),
                intervention: state.intervention,
                write_fenced: state.write_fenced,
                closed: self.closed.load(Ordering::Acquire),
                revision: state.revision,
            });
        }
    }
    fn publish_initial(&self, add: Evidence) {
        if let Ok(mut state) = self.state.lock()
            && let Some(initial) = state.initial.as_mut()
            && let Ok(merged) = initial.evidence.merged(add)
        {
            initial.evidence = merged;
        }
        self.notify_activity();
    }
    fn publish(&self, id: &str, add: Evidence) {
        let event = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            let Some(pending) = state.records.get_mut(id) else {
                return;
            };
            let Ok(merged) = pending.evidence.merged(add) else {
                return;
            };
            if merged == pending.evidence {
                return;
            }
            pending.evidence = merged;
            TransportEvidence {
                id: id.into(),
                evidence: merged,
            }
        };
        if let Ok(sender) = self.events.lock()
            && let Some(sender) = sender.as_ref()
            && sender.try_send(event).is_err()
            && let Ok(mut state) = self.state.lock()
        {
            state.write_fenced = true;
        }
    }
    fn fence(&self, intervention: bool) {
        let updates = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            state.write_fenced = true;
            state.intervention |= intervention;
            if !intervention {
                state.active = None;
            }
            state
                .records
                .iter()
                .filter(|(_, pending)| {
                    !pending.evidence.not_dispatched && !pending.evidence.core_accepted
                })
                .map(|(id, pending)| {
                    (
                        id.clone(),
                        if pending.may_have_written {
                            Evidence {
                                write_uncertain: true,
                                ..Evidence::default()
                            }
                        } else {
                            Evidence {
                                not_dispatched: true,
                                ..Evidence::default()
                            }
                        },
                    )
                })
                .collect::<Vec<_>>()
        };
        for (id, evidence) in updates {
            self.publish(&id, evidence);
        }
        let initial = self.state.lock().ok().and_then(|s| {
            s.initial
                .as_ref()
                .filter(|p| !p.evidence.core_accepted && !p.evidence.not_dispatched)
                .map(|p| p.may_have_written)
        });
        if let Some(written) = initial {
            self.publish_initial(if written {
                Evidence {
                    write_uncertain: true,
                    ..Evidence::default()
                }
            } else {
                Evidence {
                    not_dispatched: true,
                    ..Evidence::default()
                }
            });
        }
        self.notify_activity();
    }
    fn request_close(&self) {
        if let Ok(mut state) = self.state.lock() {
            self.closed.store(true, Ordering::Release);
            state.write_fenced = true;
            state.active = None;
        } else {
            self.closed.store(true, Ordering::Release);
        }
        self.close.send_replace(true);
        self.fence(false);
        self.close_events();
    }
    fn close_events(&self) {
        if let Ok(mut sender) = self.events.lock() {
            sender.take();
        }
    }
}

#[derive(Clone)]
pub struct CodexSteerConnection {
    shared: Arc<Shared>,
    writer: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
}
pub struct ConnectionOwner {
    shared: Arc<Shared>,
}
impl ConnectionOwner {
    pub fn human_grant(&self) -> crate::Result<HumanSteerGrant> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| SteerError::Unavailable)?;
        self.shared.ready(&state)?;
        if self.shared.scope.fresh.is_some() {
            return Err(SteerError::PermissionDenied);
        }
        Ok(HumanSteerGrant {
            identity: self.shared.identity.clone(),
            revoked: self.shared.revoked.clone(),
            deadline: self.shared.scope.deadline,
            action: None,
        })
    }
    pub(crate) fn authorize_action(
        &self,
        action: &HumanSteerAction,
    ) -> crate::Result<HumanSteerGrant> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| SteerError::Unavailable)?;
        self.shared.ready(&state)?;
        if self.shared.scope.fresh.is_none()
            || !Arc::ptr_eq(&self.shared.identity, &action.target.identity)
            || Instant::now() >= action.deadline
            || state.active.as_ref()
                != Some(&(action.target.turn_id.clone(), action.target.generation))
        {
            return Err(SteerError::PermissionDenied);
        }
        Ok(HumanSteerGrant {
            identity: self.shared.identity.clone(),
            revoked: self.shared.revoked.clone(),
            deadline: action.deadline,
            action: Some(action.clone()),
        })
    }
    pub fn revoke(&self) {
        self.shared.revoked.store(true, Ordering::Release);
        self.shared.notify_activity();
    }
    pub fn request_close(&self) {
        self.shared.request_close();
    }
    pub fn intervention_required(&self) -> bool {
        self.shared
            .state
            .lock()
            .map_or(true, |state| state.intervention)
    }
}
impl Drop for ConnectionOwner {
    fn drop(&mut self) {
        self.request_close();
    }
}
impl CodexSteerConnection {
    /// Requires a serviced Tokio runtime and IO exclusively delegated by its
    /// already initialized protocol owner. This never initializes/adopts a peer.
    pub fn from_established_io<R, W>(
        scope: OwnerControlScope,
        reader: R,
        writer: W,
    ) -> crate::Result<(Self, ConnectionOwner)>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| SteerError::Unavailable)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| SteerError::Unavailable)?;
        let epoch = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let (close, _) = watch::channel(false);
        let (activity, _) = watch::channel(ConnectionActivity {
            target: None,
            completed: false,
            initial: None,
            agent_text: None,
            intervention: false,
            write_fenced: false,
            closed: false,
            revision: 0,
        });
        let (events, receiver) = mpsc::channel(MAX_OPERATIONS * 6);
        let shared = Arc::new(Shared {
            identity: Arc::new(Identity),
            epoch,
            scope,
            revoked: Arc::new(AtomicBool::new(false)),
            closed: AtomicBool::new(false),
            close,
            state: Mutex::new(State {
                active: None,
                generation: 0,
                records: BTreeMap::new(),
                write_fenced: false,
                intervention: false,
                jobs: Vec::new(),
                initial: None,
                owned_turn: None,
                ended: false,
                agent_text: None,
                revision: 0,
            }),
            events: Mutex::new(Some(events)),
            receiver: Mutex::new(Some(receiver)),
            write_gate: Arc::new(Semaphore::new(1)),
            runtime: runtime.clone(),
            reader_job: tokio::sync::Mutex::new(None),
            activity,
        });
        let input = shared.clone();
        let job = runtime.spawn(async move {
            read_pump(input, reader).await;
        });
        *shared
            .reader_job
            .try_lock()
            .map_err(|_| SteerError::Unavailable)? = Some(job);
        let owner = ConnectionOwner {
            shared: shared.clone(),
        };
        Ok((
            Self {
                shared,
                writer: Arc::new(tokio::sync::Mutex::new(Box::new(writer))),
            },
            owner,
        ))
    }
    pub(crate) fn from_fresh_thread<R, W>(
        proof: crate::work_bootstrap::FreshThreadProof,
        reader: R,
        writer: W,
    ) -> crate::Result<(Self, ConnectionOwner)>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (thread, id, text, deadline, prefix) = proof.into_parts();
        let scope = OwnerControlScope {
            thread_id: thread,
            deadline,
            _reference: "committed-fresh-human-work".into(),
            fresh: Some((id, text)),
        };
        Self::from_established_io(scope, std::io::Cursor::new(prefix).chain(reader), writer)
    }
    pub fn active_turn(&self) -> Option<ObservedActiveTurn> {
        let state = self.shared.state.lock().ok()?;
        self.shared.ready(&state).ok()?;
        let (turn_id, generation) = state.active.as_ref()?;
        Some(ObservedActiveTurn {
            identity: self.shared.identity.clone(),
            epoch: self.shared.epoch.clone(),
            thread_id: self.shared.scope.thread_id.clone(),
            turn_id: turn_id.clone(),
            generation: *generation,
        })
    }
    pub(crate) fn owns_target(&self, target: &ObservedActiveTurn) -> bool {
        Arc::ptr_eq(&self.shared.identity, &target.identity)
            && self.shared.epoch == target.epoch
            && self.shared.scope.thread_id == target.thread_id
    }
    pub(crate) fn transport_epoch(&self) -> &str {
        &self.shared.epoch
    }
    pub fn request_close(&self) {
        self.shared.request_close();
    }
    pub(crate) fn subscribe_activity(&self) -> watch::Receiver<ConnectionActivity> {
        self.shared.activity.subscribe()
    }
    pub(crate) fn capture_human_action(
        &self,
        target: &ObservedActiveTurn,
        id: &str,
        text: &str,
    ) -> crate::Result<HumanSteerAction> {
        if !crate::record::valid_operation_id(id) || !crate::record::valid_text(text) {
            return Err(SteerError::InvalidInput);
        }
        let current = self.active_turn().ok_or(SteerError::NoActiveTurn)?;
        if !self.owns_target(target)
            || current.turn_id != target.turn_id
            || current.generation != target.generation
        {
            return Err(SteerError::StaleTarget);
        }
        Ok(HumanSteerAction {
            target: target.clone(),
            id: id.into(),
            text: text.into(),
            deadline: Instant::now()
                .checked_add(Duration::from_secs(30))
                .ok_or(SteerError::Unavailable)?,
        })
    }
    pub fn prepare(
        &self,
        grant: &HumanSteerGrant,
        target: &ObservedActiveTurn,
        id: &str,
        text: &str,
    ) -> crate::Result<PreparedSteer> {
        let record = SavedSteer {
            schema: OPERATION_SCHEMA.into(),
            id: id.into(),
            transport_epoch: self.shared.epoch.clone(),
            thread_id: target.thread_id.clone(),
            expected_turn_id: target.turn_id.clone(),
            text: text.into(),
        };
        record.validate()?;
        let prepared = PreparedSteer {
            record,
            target: target.clone(),
            grant: grant.clone(),
        };
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| SteerError::Unavailable)?;
        self.shared.permits(&state, &prepared)?;
        if state.records.len() >= MAX_OPERATIONS && !state.records.contains_key(id) {
            return Err(SteerError::Capacity);
        }
        Ok(prepared)
    }
    pub(crate) fn take_events(&self) -> Option<mpsc::Receiver<TransportEvidence>> {
        self.shared.receiver.lock().ok()?.take()
    }
    #[cfg(test)]
    pub(crate) fn evidence(&self, id: &str) -> Option<Evidence> {
        self.shared
            .state
            .lock()
            .ok()?
            .records
            .get(id)
            .map(|pending| pending.evidence)
    }

    /// Only a consumed controller capsule can reach this lane. Completion is a
    /// bounded frame-write observation, not Core acceptance or model awareness.
    pub(crate) async fn dispatch_committed(&self, attempt: CommittedSteerAttempt) -> Evidence {
        let prepared = attempt.0;
        let id = prepared.record.id.clone();
        let (reply, result) = oneshot::channel();
        {
            let Ok(mut state) = self.shared.state.lock() else {
                return Evidence {
                    not_dispatched: true,
                    ..Evidence::default()
                };
            };
            if let Some(existing) = state.records.get(&id) {
                return if existing.record == prepared.record {
                    existing.evidence
                } else {
                    Evidence {
                        not_dispatched: true,
                        ..Evidence::default()
                    }
                };
            }
            if state.records.len() >= MAX_OPERATIONS {
                return Evidence {
                    not_dispatched: true,
                    ..Evidence::default()
                };
            }
            let rpc_id = format!(
                "chinwag-steer-{}-{}",
                self.shared.epoch,
                state.records.len()
            );
            state.records.insert(
                id.clone(),
                Pending {
                    record: prepared.record.clone(),
                    rpc_id: rpc_id.clone(),
                    evidence: Evidence::default(),
                    may_have_written: false,
                },
            );
            let valid = self.shared.permits(&state, &prepared).is_ok();
            let permit = if valid {
                self.shared.write_gate.clone().try_acquire_owned().ok()
            } else {
                None
            };
            let Some(permit) = permit else {
                drop(state);
                let evidence = Evidence {
                    not_dispatched: true,
                    ..Evidence::default()
                };
                self.shared.publish(&id, evidence);
                return evidence;
            };
            let shared = self.shared.clone();
            let writer = self.writer.clone();
            let job = self.shared.runtime.spawn(async move {
                let evidence = write_attempt(&shared, writer, &prepared, &rpc_id).await;
                shared.publish(&prepared.record.id, evidence);
                drop(permit);
                if evidence.frame_written {
                    schedule_ack_deadline(&shared, &prepared.record.id);
                }
                let _ = reply.send(evidence);
            });
            state.jobs.push(Arc::new(Job {
                join: tokio::sync::Mutex::new(Some(job)),
            }));
        }
        result.await.unwrap_or(Evidence {
            write_uncertain: true,
            ..Evidence::default()
        })
    }
    pub(crate) async fn dispatch_initial(&self, attempt: CommittedInitialTurn) -> Evidence {
        let (reply, result) = oneshot::channel();
        {
            let Ok(mut state) = self.shared.state.lock() else {
                return Evidence {
                    not_dispatched: true,
                    ..Evidence::default()
                };
            };
            if let Some(existing) = state.initial.as_ref() {
                return if existing.id == attempt.id && existing.text == attempt.text {
                    existing.evidence
                } else {
                    Evidence {
                        not_dispatched: true,
                        ..Evidence::default()
                    }
                };
            }
            if self.shared.scope.fresh.as_ref() != Some(&(attempt.id.clone(), attempt.text.clone()))
                || attempt.epoch != self.shared.epoch
                || attempt.thread != self.shared.scope.thread_id
                || attempt.deadline != self.shared.scope.deadline
            {
                return Evidence {
                    not_dispatched: true,
                    ..Evidence::default()
                };
            }
            let rpc_id = format!("chinwag-initial-{}", self.shared.epoch);
            state.initial = Some(InitialPending {
                id: attempt.id.clone(),
                text: attempt.text.clone(),
                rpc_id: rpc_id.clone(),
                evidence: Evidence::default(),
                accepted_turn_id: None,
                may_have_written: false,
            });
            let permit = if self.shared.ready(&state).is_ok() && Instant::now() < attempt.deadline {
                self.shared.write_gate.clone().try_acquire_owned().ok()
            } else {
                None
            };
            let Some(permit) = permit else {
                drop(state);
                let e = Evidence {
                    not_dispatched: true,
                    ..Evidence::default()
                };
                self.shared.publish_initial(e);
                return e;
            };
            let shared = self.shared.clone();
            let writer = self.writer.clone();
            let job = self.shared.runtime.spawn(async move {
                let evidence = write_initial(&shared, writer, &attempt, &rpc_id).await;
                shared.publish_initial(evidence);
                drop(permit);
                if evidence.frame_written {
                    schedule_initial_deadline(&shared);
                }
                let _ = reply.send(evidence);
            });
            state.jobs.push(Arc::new(Job {
                join: tokio::sync::Mutex::new(Some(job)),
            }));
        }
        self.shared.notify_activity();
        result.await.unwrap_or(Evidence {
            write_uncertain: true,
            ..Evidence::default()
        })
    }
    pub async fn shutdown(&self) -> crate::Result<()> {
        self.shared.request_close();
        let mut failed = false;
        {
            let mut reader = self.shared.reader_job.lock().await;
            if let Some(job) = reader.as_mut() {
                let result = job.await;
                reader.take();
                failed |= result.is_err();
            }
        }
        self.shared.close_events();
        let jobs = self
            .shared
            .state
            .lock()
            .map_err(|_| SteerError::Unavailable)?
            .jobs
            .clone();
        for job in jobs {
            let mut slot = job.join.lock().await;
            if let Some(handle) = slot.as_mut() {
                let result = handle.await;
                slot.take();
                failed |= result.is_err();
            }
        }
        let close = async {
            let mut slot = self.writer.lock().await;
            let mut owned = std::mem::replace(&mut *slot, Box::new(tokio::io::sink()));
            drop(slot);
            // Dropping owned on success, error, or timeout releases the actual
            // writer even while read-only controller clones remain retained.
            owned.shutdown().await
        };
        if !matches!(tokio::time::timeout(WRITE_TIMEOUT, close).await, Ok(Ok(()))) {
            failed = true;
        }
        if failed {
            Err(SteerError::Unavailable)
        } else {
            Ok(())
        }
    }
}

async fn write_attempt(
    shared: &Arc<Shared>,
    writer: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    prepared: &PreparedSteer,
    rpc_id: &str,
) -> Evidence {
    let Ok(frame) = wire::steer_frame(rpc_id, &prepared.record) else {
        return Evidence {
            not_dispatched: true,
            ..Evidence::default()
        };
    };
    let mut close = shared.close.subscribe();
    let write = async {
        let mut writer = writer.lock().await;
        {
            let mut state = shared.state.lock().map_err(|_| false)?;
            shared.permits(&state, prepared).map_err(|_| false)?;
            state
                .records
                .get_mut(&prepared.record.id)
                .ok_or(false)?
                .may_have_written = true;
        }
        writer.write_all(&frame).await.map_err(|_| true)?;
        writer.flush().await.map_err(|_| true)
    };
    let result = tokio::select! {
        biased;
        _=close.changed()=>Err(true),
        result=tokio::time::timeout(WRITE_TIMEOUT,write)=>result.unwrap_or(Err(true)),
    };
    match result {
        Ok(()) => Evidence {
            frame_written: true,
            ..Evidence::default()
        },
        Err(false) => Evidence {
            not_dispatched: true,
            ..Evidence::default()
        },
        Err(true) => {
            let may_have_written = shared
                .state
                .lock()
                .ok()
                .and_then(|state| {
                    state
                        .records
                        .get(&prepared.record.id)
                        .map(|pending| pending.may_have_written)
                })
                .unwrap_or(true);
            shared.fence(false);
            if may_have_written {
                Evidence {
                    write_uncertain: true,
                    ..Evidence::default()
                }
            } else {
                Evidence {
                    not_dispatched: true,
                    ..Evidence::default()
                }
            }
        }
    }
}
async fn write_initial(
    shared: &Arc<Shared>,
    writer: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    attempt: &CommittedInitialTurn,
    rpc: &str,
) -> Evidence {
    let Ok(frame) = wire::initial_frame(rpc, &attempt.thread, &attempt.id, &attempt.text) else {
        return Evidence {
            not_dispatched: true,
            ..Evidence::default()
        };
    };
    let mut close = shared.close.subscribe();
    let write = async {
        let mut writer = writer.lock().await;
        {
            let mut state = shared.state.lock().map_err(|_| false)?;
            shared.ready(&state).map_err(|_| false)?;
            if Instant::now() >= attempt.deadline {
                return Err(false);
            }
            let pending = state.initial.as_mut().ok_or(false)?;
            if pending.id != attempt.id || pending.evidence.not_dispatched {
                return Err(false);
            }
            pending.may_have_written = true;
        }
        writer.write_all(&frame).await.map_err(|_| true)?;
        writer.flush().await.map_err(|_| true)
    };
    let remaining = attempt
        .deadline
        .saturating_duration_since(Instant::now())
        .min(WRITE_TIMEOUT);
    let result = tokio::select! {biased;_=close.changed()=>Err(true),result=tokio::time::timeout(remaining,write)=>result.unwrap_or(Err(true))};
    match result {
        Ok(()) => Evidence {
            frame_written: true,
            ..Evidence::default()
        },
        Err(false) => Evidence {
            not_dispatched: true,
            ..Evidence::default()
        },
        Err(true) => {
            let written = shared
                .state
                .lock()
                .ok()
                .and_then(|s| s.initial.as_ref().map(|p| p.may_have_written))
                .unwrap_or(true);
            shared.fence(false);
            if written {
                Evidence {
                    write_uncertain: true,
                    ..Evidence::default()
                }
            } else {
                Evidence {
                    not_dispatched: true,
                    ..Evidence::default()
                }
            }
        }
    }
}
fn schedule_initial_deadline(shared: &Arc<Shared>) {
    let Ok(mut state) = shared.state.lock() else {
        return;
    };
    if shared.closed.load(Ordering::Acquire) {
        return;
    }
    let owner = shared.clone();
    let mut close = shared.close.subscribe();
    let task=shared.runtime.spawn(async move{tokio::select!{biased;_=close.changed()=>{},_=tokio::time::sleep(ACK_TIMEOUT)=>{
   let pending=owner.state.lock().ok().is_some_and(|s|s.initial.as_ref().is_some_and(|p|!p.evidence.core_accepted&&!p.evidence.not_dispatched));
   if pending{owner.publish_initial(Evidence{write_uncertain:true,..Evidence::default()});}
 }}});
    state.jobs.push(Arc::new(Job {
        join: tokio::sync::Mutex::new(Some(task)),
    }));
}
fn schedule_ack_deadline(shared: &Arc<Shared>, id: &str) {
    let Ok(mut state) = shared.state.lock() else {
        return;
    };
    if shared.closed.load(Ordering::Acquire) {
        return;
    }
    let owner = shared.clone();
    let id = id.to_owned();
    let mut close = shared.close.subscribe();
    let deadline = tokio::time::Instant::now() + ACK_TIMEOUT;
    let task=shared.runtime.spawn(async move {
        tokio::select!{biased;_=close.changed()=>{},_=tokio::time::sleep_until(deadline)=>{
            let pending=owner.state.lock().ok().and_then(|state|state.records.get(&id).map(|record|!record.evidence.core_accepted && !record.evidence.not_dispatched)).unwrap_or(false);
            if pending {owner.publish(&id,Evidence{write_uncertain:true,..Evidence::default()});}
        }}
    });
    state.jobs.push(Arc::new(Job {
        join: tokio::sync::Mutex::new(Some(task)),
    }));
}

async fn read_pump<R: AsyncRead + Send + Unpin>(shared: Arc<Shared>, reader: R) {
    let mut reader = BufReader::new(reader);
    let mut close = shared.close.subscribe();
    loop {
        if shared.closed.load(Ordering::Acquire) {
            break;
        }
        let mut frame = Vec::new();
        let read = async {
            let mut bounded = (&mut reader).take((wire::MAX_FRAME_BYTES + 1) as u64);
            bounded.read_until(b'\n', &mut frame).await
        };
        let result = tokio::select! {biased;_=close.changed()=>break,result=read=>result};
        match result {
            Ok(0) | Err(_) => {
                shared.fence(false);
                break;
            }
            Ok(_) if frame.len() > wire::MAX_FRAME_BYTES || !frame.ends_with(b"\n") => {
                shared.fence(false);
                shared.close_events();
                while !shared.closed.load(Ordering::Acquire) {
                    if close.changed().await.is_err() {
                        break;
                    }
                }
                break;
            }
            Ok(_) => match wire::parse(&frame) {
                Ok(event) => observe(&shared, event),
                Err(_) => shared.fence(false),
            },
        }
    }
    shared.closed.store(true, Ordering::Release);
    shared.notify_activity();
    shared.close_events();
}
fn observe(shared: &Arc<Shared>, event: Incoming) {
    match event {
        Incoming::Started { thread_id, turn_id } if thread_id == shared.scope.thread_id => {
            if let Ok(mut state) = shared.state.lock() {
                if shared.scope.fresh.is_some() {
                    if state.ended {
                        return;
                    }
                    if !state.initial.as_ref().is_some_and(|p| p.may_have_written) {
                        drop(state);
                        shared.fence(true);
                        return;
                    }
                    if state.owned_turn.as_ref().is_some_and(|id| id != &turn_id) {
                        drop(state);
                        shared.fence(true);
                        return;
                    }
                    if state
                        .initial
                        .as_ref()
                        .and_then(|p| p.accepted_turn_id.as_ref())
                        .is_some_and(|id| id != &turn_id)
                    {
                        drop(state);
                        shared.fence(true);
                        return;
                    }
                    state.owned_turn = Some(turn_id.clone());
                }
                if state
                    .active
                    .as_ref()
                    .is_some_and(|(active, _)| *active == turn_id)
                {
                    return;
                }
                if let Some(next) = state.generation.checked_add(1) {
                    state.generation = next;
                    state.active = Some((turn_id, next));
                } else {
                    state.write_fenced = true;
                    state.active = None;
                }
            }
        }
        Incoming::Completed { thread_id, turn_id } if thread_id == shared.scope.thread_id => {
            if let Ok(mut state) = shared.state.lock() {
                if shared.scope.fresh.is_some()
                    && !state.ended
                    && !state.initial.as_ref().is_some_and(|p| p.may_have_written)
                {
                    drop(state);
                    shared.fence(true);
                    return;
                }
                if shared.scope.fresh.is_some()
                    && state.initial.as_ref().is_some_and(|p| p.may_have_written)
                    && state.owned_turn.as_ref().is_none_or(|id| id == &turn_id)
                {
                    state.owned_turn = Some(turn_id.clone());
                    state.ended = true;
                }
                if state
                    .active
                    .as_ref()
                    .is_some_and(|(active, _)| *active == turn_id)
                {
                    state.active = None;
                    state.generation = state.generation.saturating_add(1);
                }
            }
        }
        Incoming::InitialSuccess {
            id: WireId::String(rpc_id),
            turn_id,
            terminal,
        } => {
            let matching = shared.state.lock().ok().and_then(|mut state| {
                let owned_turn_matches = state.owned_turn.as_ref().is_none_or(|id| id == &turn_id);
                let initial = state.initial.as_mut()?;
                if initial.rpc_id != rpc_id || !initial.may_have_written {
                    return None;
                }
                let turn_matches = owned_turn_matches
                    && initial
                        .accepted_turn_id
                        .as_ref()
                        .is_none_or(|id| id == &turn_id);
                if turn_matches {
                    initial.accepted_turn_id = Some(turn_id.clone());
                    if terminal {
                        state.owned_turn = Some(turn_id);
                        state.ended = true;
                        state.active = None;
                        state.generation = state.generation.saturating_add(1);
                    }
                }
                Some(turn_matches)
            });
            match matching {
                Some(true) => shared.publish_initial(Evidence {
                    core_accepted: true,
                    ..Evidence::default()
                }),
                Some(false) => {
                    shared.publish_initial(Evidence {
                        write_uncertain: true,
                        ..Evidence::default()
                    });
                    shared.fence(true);
                }
                None => {}
            }
        }
        Incoming::Success {
            id: WireId::String(rpc_id),
            turn_id,
        } => {
            let matched = shared.state.lock().ok().and_then(|state| {
                state
                    .records
                    .iter()
                    .find(|(_, p)| p.rpc_id == rpc_id && p.may_have_written)
                    .map(|(id, p)| (id.clone(), p.record.expected_turn_id == turn_id))
            });
            if let Some((id, true)) = matched {
                shared.publish(
                    &id,
                    Evidence {
                        core_accepted: true,
                        ..Evidence::default()
                    },
                );
            } else if let Some((id, false)) = matched {
                shared.publish(
                    &id,
                    Evidence {
                        write_uncertain: true,
                        ..Evidence::default()
                    },
                );
                shared.fence(false);
            }
        }
        Incoming::Error {
            id: WireId::String(rpc_id),
        } => {
            let initial = shared.state.lock().ok().is_some_and(|s| {
                s.initial
                    .as_ref()
                    .is_some_and(|p| p.rpc_id == rpc_id && p.may_have_written)
            });
            if initial {
                shared.publish_initial(Evidence {
                    write_uncertain: true,
                    peer_error_observed: true,
                    ..Evidence::default()
                });
            }
            let id = shared.state.lock().ok().and_then(|s| {
                s.records
                    .iter()
                    .find(|(_, p)| p.rpc_id == rpc_id && p.may_have_written)
                    .map(|(id, _)| id.clone())
            });
            if let Some(id) = id {
                shared.publish(
                    &id,
                    Evidence {
                        write_uncertain: true,
                        peer_error_observed: true,
                        ..Evidence::default()
                    },
                );
            }
        }
        Incoming::Recorded {
            thread_id,
            turn_id,
            client_id,
            text,
        } => {
            let matched = shared.state.lock().ok().is_some_and(|s| {
                s.records.get(&client_id).is_some_and(|p| {
                    p.may_have_written
                        && p.record.thread_id == thread_id
                        && p.record.expected_turn_id == turn_id
                        && p.record.text == text
                })
            });
            if matched {
                shared.publish(
                    &client_id,
                    Evidence {
                        harness_recorded: true,
                        ..Evidence::default()
                    },
                );
            }
            let initial = shared.state.lock().ok().is_some_and(|s| {
                thread_id == shared.scope.thread_id
                    && s.owned_turn.as_ref().is_none_or(|id| id == &turn_id)
                    && s.initial
                        .as_ref()
                        .is_some_and(|p| p.may_have_written && p.id == client_id && p.text == text)
            });
            if initial {
                if let Ok(mut state) = shared.state.lock() {
                    if state
                        .initial
                        .as_ref()
                        .and_then(|p| p.accepted_turn_id.as_ref())
                        .is_some_and(|id| id != &turn_id)
                    {
                        drop(state);
                        shared.fence(true);
                        return;
                    }
                    if state.owned_turn.is_none() {
                        state.owned_turn = Some(turn_id.clone());
                    }
                }
                shared.publish_initial(Evidence {
                    harness_recorded: true,
                    ..Evidence::default()
                });
            }
        }
        Incoming::AgentText {
            thread_id,
            turn_id,
            text,
        } if thread_id == shared.scope.thread_id => {
            if let Ok(mut state) = shared.state.lock()
                && state.owned_turn.as_ref().is_some_and(|id| id == &turn_id)
            {
                state.agent_text = Some(text);
            }
        }
        Incoming::ServerRequest => shared.fence(true),
        _ => {}
    }
    shared.notify_activity();
}

#[cfg(test)]
mod tests;
