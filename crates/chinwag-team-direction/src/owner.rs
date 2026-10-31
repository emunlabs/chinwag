use crate::{
    api::{PreparedNative, Target, new_id, valid_id, valid_text},
    config::{self, StateLease},
    journal::{Journal, Stored},
    projection, *,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
struct Admission {
    active: Option<String>,
    consumed: BTreeSet<u64>,
    known_parents: BTreeSet<String>,
    lookup_serial: u64,
}
struct State {
    snapshot: TeamSnapshot,
    records: Vec<Stored>,
    failed: BTreeSet<String>,
}
struct Shared {
    identity: Arc<()>,
    instance: String,
    members: Vec<Member>,
    state: Mutex<State>,
    admission: Mutex<Admission>,
    ended: AtomicBool,
    publication: mpsc::Sender<()>,
    refresh_requests: mpsc::Sender<()>,
    snapshots: watch::Sender<TeamSnapshot>,
    lease: Option<StateLease>,
    #[cfg(test)]
    fail_admission_append: AtomicBool,
    #[cfg(test)]
    fail_before_save: AtomicBool,
    #[cfg(test)]
    before_invoke: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}
impl Shared {
    fn refresh(&self) {
        let _ = self.refresh_requests.try_send(());
    }
    // Only the retained actor (or its disjoint runtime-failure thread) samples
    // native watches. API/Quit callers only signal; old samples cannot race.
    fn refresh_now(&self) {
        let members = projection::snapshots(&self.members);
        if let Ok(mut s) = self.state.lock() {
            let directions = s
                .records
                .iter()
                .map(|v| projection::receipt(v, &members, s.failed.contains(&v.intent.id)))
                .collect();
            s.snapshot.members = members;
            s.snapshot.directions = directions;
            s.snapshot.revision = s.snapshot.revision.saturating_add(1);
        }
        let _ = self.publication.try_send(());
    }
    fn remember(&self, record: Stored) -> Result<()> {
        {
            let mut state = self.state.lock().map_err(|_| TeamError::Unavailable)?;
            if let Some(old) = state
                .records
                .iter_mut()
                .find(|v| v.intent.id == record.intent.id)
            {
                *old = record;
            } else {
                state.records.push(record);
            }
        }
        self.refresh();
        Ok(())
    }
    fn publish_now(&self) {
        let sample = self.state.lock().ok().map(|s| s.snapshot.clone());
        if let Some(sample) = sample {
            self.snapshots.send_if_modified(|old| {
                if old.revision <= sample.revision {
                    *old = sample;
                    true
                } else {
                    false
                }
            });
        }
    }
    fn verify(&self) -> Result<()> {
        if let Some(lease) = &self.lease {
            lease.verify()?
        }
        Ok(())
    }
    fn report(&self, id: &str, kind: ReportKind, serial: Option<u64>, error: Option<TeamError>) {
        if let Ok(mut s) = self.state.lock() {
            let report = SubmissionReport {
                id: id.into(),
                kind,
                lookup_serial: serial,
                admitted: true,
                stage_retired: true,
                error,
            };
            match kind {
                ReportKind::Submit => {
                    s.snapshot.submissions.insert(id.into(), report);
                }
                ReportKind::Lookup => {
                    s.snapshot.lookups.insert(id.into(), report);
                }
            }
        }
        self.refresh();
    }
    fn finish(&self, id: &str, error: Option<TeamError>) {
        if let Ok(mut a) = self.admission.lock()
            && a.active.as_deref() == Some(id)
        {
            a.active = None;
            if let Ok(mut s) = self.state.lock() {
                s.snapshot.busy = false;
            }
        }
        self.report(id, ReportKind::Submit, None, error);
    }
    fn failed(&self, id: &str) {
        if let Ok(mut s) = self.state.lock() {
            s.failed.insert(id.into());
        }
        self.refresh();
    }
}
enum Command {
    Submit(CapturedTeamDirection),
    Lookup { id: String, serial: u64 },
}
pub struct TeamHost {
    members: Vec<Member>,
    shared: Arc<Shared>,
    commands: mpsc::Sender<Command>,
}
impl TeamHost {
    /// Startup-only composition. On error the fresh entry process must exit;
    /// an inert native service may already have retained its owner thread. This
    /// is not an in-app reconfiguration/retry API. No native Start is called here.
    pub fn open(config_path: &Path, state_root: &Path) -> Result<Arc<Self>> {
        let loaded = config::load(config_path, state_root)?;
        Self::build(loaded.actions.as_path(), loaded.members, Some(loaded.lease))
    }
    fn build(actions: &Path, members: Vec<Member>, lease: Option<StateLease>) -> Result<Arc<Self>> {
        validate_members(&members)?;
        let journal = Journal::open(actions)?;
        let records = journal.receipts()?;
        let known_parents = records.iter().map(|r| r.intent.id.clone()).collect();
        let (snapshot, _) = watch::channel(TeamSnapshot::default());
        let (publication, pubs) = mpsc::channel(1);
        let (commands, receiver) = mpsc::channel(1);
        let (updates, update_rx) = mpsc::channel(1);
        let shared = Arc::new(Shared {
            identity: Arc::new(()),
            instance: new_id("host-")?,
            members: members.clone(),
            state: Mutex::new(State {
                snapshot: TeamSnapshot::default(),
                records,
                failed: BTreeSet::new(),
            }),
            admission: Mutex::new(Admission {
                active: None,
                consumed: BTreeSet::new(),
                known_parents,
                lookup_serial: 0,
            }),
            ended: AtomicBool::new(false),
            publication,
            refresh_requests: updates.clone(),
            snapshots: snapshot,
            lease,
            #[cfg(test)]
            fail_admission_append: AtomicBool::new(false),
            #[cfg(test)]
            fail_before_save: AtomicBool::new(false),
            #[cfg(test)]
            before_invoke: Mutex::new(None),
        });
        let host = Arc::new(Self {
            members,
            shared: shared.clone(),
            commands,
        });
        std::thread::Builder::new()
            .name("chinwag-team-owner".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt.block_on(run(shared, receiver, journal, pubs, updates, update_rx)),
                    Err(_) => {
                        shared.ended.store(true, Ordering::Release);
                        if let Ok(mut s) = shared.state.lock() {
                            s.snapshot.admission_closed = true;
                        }
                        shared.refresh_now();
                        shared.publish_now();
                    }
                }
            })
            .map_err(|_| TeamError::Unavailable)?;
        Ok(host)
    }
    pub fn members(&self) -> &[Member] {
        &self.members
    }
    pub fn subscribe(&self) -> watch::Receiver<TeamSnapshot> {
        self.shared.snapshots.subscribe()
    }
    pub fn plan(
        &self,
        selected: &[String],
        text: &str,
        timings: &BTreeMap<String, ClaudeTiming>,
    ) -> Result<RenderedPlan> {
        if self.shared.ended.load(Ordering::Acquire) {
            return Err(TeamError::Closed);
        }
        if selected.is_empty() || selected.len() > MAX_MEMBERS || !valid_text(text) {
            return Err(TeamError::InvalidInput);
        }
        let set: BTreeSet<_> = selected.iter().collect();
        if set.len() != selected.len() {
            return Err(TeamError::InvalidInput);
        }
        let samples = self
            .shared
            .state
            .lock()
            .map_err(|_| TeamError::Unavailable)?
            .snapshot
            .members
            .clone();
        let mut rows = Vec::new();
        let mut targets = BTreeMap::new();
        let mut ready = Vec::new();
        for id in selected {
            let m = samples
                .iter()
                .find(|m| m.id == *id)
                .ok_or(TeamError::InvalidInput)?;
            let result = projection::target(
                &m.native,
                text,
                timings.get(id).copied().unwrap_or(ClaudeTiming::Now),
            );
            let (action, blocked) = match result {
                Ok((target, action)) => {
                    targets.insert(id.clone(), target);
                    ready.push(id.clone());
                    (Some(action), None)
                }
                Err(reason) => (None, Some(reason)),
            };
            rows.push(PlanRow {
                id: id.clone(),
                label: m.label.clone(),
                action,
                blocked,
            });
        }
        Ok(RenderedPlan {
            identity: self.shared.identity.clone(),
            rows,
            selected: selected.into(),
            ready,
            text: text.into(),
            targets,
        })
    }
    pub fn capture(
        &self,
        plan: &RenderedPlan,
        effective: &[String],
        human_revision: u64,
        deadline: Instant,
    ) -> Result<CapturedTeamDirection> {
        let now = Instant::now();
        if deadline <= now {
            return Err(TeamError::Expired);
        }
        if deadline.duration_since(now) > Duration::from_secs(30) {
            return Err(TeamError::InvalidInput);
        }
        if self.commands.capacity() == 0 {
            return Err(TeamError::Busy);
        }
        if !Arc::ptr_eq(&plan.identity, &self.shared.identity) || human_revision == 0 {
            return Err(TeamError::StalePlan);
        }
        if self.shared.ended.load(Ordering::Acquire) {
            return Err(TeamError::Closed);
        }
        {
            let a = self
                .shared
                .admission
                .lock()
                .map_err(|_| TeamError::Unavailable)?;
            if a.active.is_some() {
                return Err(TeamError::Busy);
            }
            if a.consumed.contains(&human_revision) {
                return Err(TeamError::ConsumedRevision);
            }
        }
        let actual: BTreeSet<_> = effective.iter().collect();
        let ready: BTreeSet<_> = plan.ready.iter().collect();
        if effective.is_empty() || actual.len() != effective.len() || actual != ready {
            return Err(TeamError::StalePlan);
        }
        let id = new_id("team-")?;
        let mut saved_members = Vec::new();
        let mut tokens = Vec::new();
        for row in &plan.rows {
            if !actual.contains(&row.id) {
                saved_members.push(SavedMember {
                    id: row.id.clone(),
                    label: row.label.clone(),
                    child_id: None,
                    action: None,
                    excluded: row.blocked,
                    audit: None,
                });
                continue;
            }
            let m = self
                .members
                .iter()
                .find(|m| m.id == row.id)
                .ok_or(TeamError::StalePlan)?;
            let target = plan.targets.get(&row.id).ok_or(TeamError::StalePlan)?;
            let (child_id, token, audit) = match (&m.port, target) {
                (HeldWorkPort::Codex(port), Target::Codex(target)) => {
                    let child = new_id("ui-")?;
                    let token = port
                        .prepare_steer(target, &child, &plan.text, deadline)
                        .map_err(|_| TeamError::StalePlan)?;
                    let audit = NativeAudit::Codex {
                        operation: token.operation().clone(),
                        captured_sequence: token.captured_sequence(),
                    };
                    (child, PreparedNative::Codex(token), audit)
                }
                (HeldWorkPort::Claude(port), Target::Claude(target, timing)) => {
                    let child = chinwag_claude_control::new_operation_id()
                        .map_err(|_| TeamError::Unavailable)?;
                    let token = port
                        .prepare_direction(target, &child, &plan.text, *timing, deadline)
                        .map_err(|_| TeamError::StalePlan)?;
                    let audit = NativeAudit::Claude {
                        operation: token.operation().clone(),
                        captured_sequence: token.captured_sequence(),
                    };
                    (child, PreparedNative::Claude(token), audit)
                }
                (HeldWorkPort::Gemini(port), Target::Gemini(target)) => {
                    let child = chinwag_gemini_control::new_operation_id()
                        .map_err(|_| TeamError::Unavailable)?;
                    let token = port
                        .prepare_prompt(target, &child, &plan.text, deadline)
                        .map_err(|_| TeamError::StalePlan)?;
                    let audit = NativeAudit::Gemini {
                        operation: token.operation().clone(),
                        captured_sequence: token.captured_sequence(),
                    };
                    (child, PreparedNative::Gemini(token), audit)
                }
                _ => return Err(TeamError::StalePlan),
            };
            saved_members.push(SavedMember {
                id: row.id.clone(),
                label: row.label.clone(),
                child_id: Some(child_id),
                action: row.action,
                excluded: None,
                audit: Some(audit),
            });
            tokens.push((row.id.clone(), token));
        }
        let saved = SavedDirection {
            id,
            host_instance: self.shared.instance.clone(),
            text: plan.text.clone(),
            human_revision,
            selected: plan.selected.clone(),
            effective: effective.into(),
            members: saved_members,
        };
        crate::journal::check_intent(&saved)?;
        Ok(CapturedTeamDirection {
            identity: self.shared.identity.clone(),
            saved,
            tokens,
            deadline,
        })
    }
    pub fn submit(&self, capture: CapturedTeamDirection) -> Result<String> {
        if !Arc::ptr_eq(&capture.identity, &self.shared.identity) {
            return Err(TeamError::StalePlan);
        }
        if Instant::now() >= capture.deadline {
            return Err(TeamError::Expired);
        }
        let mut admission = self
            .shared
            .admission
            .lock()
            .map_err(|_| TeamError::Unavailable)?;
        if self.shared.ended.load(Ordering::Acquire) {
            return Err(TeamError::Closed);
        }
        if admission.active.is_some() {
            return Err(TeamError::Busy);
        }
        if admission.consumed.contains(&capture.saved.human_revision) {
            return Err(TeamError::ConsumedRevision);
        }
        if admission.known_parents.len() >= MAX_DIRECTIONS {
            return Err(TeamError::Capacity);
        }
        let permit = self.commands.try_reserve().map_err(|_| TeamError::Busy)?;
        let id = capture.saved.id.clone();
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| TeamError::Unavailable)?;
        state.snapshot.busy = true;
        state.snapshot.submissions.insert(
            id.clone(),
            SubmissionReport {
                id: id.clone(),
                kind: ReportKind::Submit,
                lookup_serial: None,
                admitted: true,
                stage_retired: false,
                error: None,
            },
        );
        admission.consumed.insert(capture.saved.human_revision);
        admission.known_parents.insert(id.clone());
        admission.active = Some(id.clone());
        drop(state);
        permit.send(Command::Submit(capture));
        drop(admission);
        self.shared.refresh();
        Ok(id)
    }
    pub fn lookup(&self, parent_id: &str) -> Result<u64> {
        if !parent_id.starts_with("team-") || parent_id.len() != 69 {
            return Err(TeamError::InvalidInput);
        }
        let mut admission = self
            .shared
            .admission
            .lock()
            .map_err(|_| TeamError::Unavailable)?;
        if !admission.known_parents.contains(parent_id) {
            return Err(TeamError::InvalidInput);
        }
        let permit = self.commands.try_reserve().map_err(|_| TeamError::Busy)?;
        let serial = admission
            .lookup_serial
            .checked_add(1)
            .ok_or(TeamError::Capacity)?;
        admission.lookup_serial = serial;
        permit.send(Command::Lookup {
            id: parent_id.into(),
            serial,
        });
        Ok(serial)
    }
    pub fn close_admission(&self) {
        if let Ok(_gate) = self.shared.admission.lock() {
            self.shared.ended.store(true, Ordering::Release);
            if let Ok(mut s) = self.shared.state.lock() {
                s.snapshot.admission_closed = true;
            }
        }
        self.shared.refresh();
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_ports(state_root: &Path, members: Vec<Member>) -> Result<Arc<Self>> {
        private::open_root(state_root, true)?;
        Self::build(&state_root.join("actions"), members, None)
    }
}
fn validate_members(members: &[Member]) -> Result<()> {
    if members.is_empty() || members.len() > MAX_MEMBERS {
        return Err(TeamError::InvalidInput);
    }
    let mut ids = BTreeSet::new();
    for (i, m) in members.iter().enumerate() {
        if !valid_id(&m.id)
            || !ids.insert(&m.id)
            || m.label.trim().is_empty()
            || m.label.len() > 64
            || m.label.chars().any(char::is_control)
        {
            return Err(TeamError::InvalidInput);
        }
        for old in &members[..i] {
            let same = match (&old.port, &m.port) {
                (HeldWorkPort::Codex(a), HeldWorkPort::Codex(b)) => Arc::ptr_eq(a, b),
                (HeldWorkPort::Claude(a), HeldWorkPort::Claude(b)) => Arc::ptr_eq(a, b),
                (HeldWorkPort::Gemini(a), HeldWorkPort::Gemini(b)) => Arc::ptr_eq(a, b),
                _ => false,
            };
            if same {
                return Err(TeamError::InvalidInput);
            }
        }
    }
    Ok(())
}
async fn store<T: Send + 'static>(
    journal: &Arc<Mutex<Journal>>,
    f: impl FnOnce(&mut Journal) -> Result<T> + Send + 'static,
) -> Result<T> {
    let journal = journal.clone();
    tokio::task::spawn_blocking(move || {
        let mut locked = journal.lock().map_err(|_| TeamError::Storage)?;
        f(&mut locked)
    })
    .await
    .map_err(|_| TeamError::Storage)?
}
async fn refresh_records(shared: &Shared, journal: &Arc<Mutex<Journal>>) -> Result<()> {
    let records = store(journal, |j| j.receipts()).await?;
    if let Ok(mut s) = shared.state.lock() {
        s.records = records;
    }
    shared.refresh_now();
    Ok(())
}
async fn run(
    shared: Arc<Shared>,
    mut commands: mpsc::Receiver<Command>,
    journal: Journal,
    mut pubs: mpsc::Receiver<()>,
    updates: mpsc::Sender<()>,
    mut update_rx: mpsc::Receiver<()>,
) {
    let publisher = shared.clone();
    tokio::spawn(async move {
        while pubs.recv().await.is_some() {
            let s = publisher.clone();
            if tokio::task::spawn_blocking(move || s.publish_now())
                .await
                .is_err()
            {
                publisher.ended.store(true, Ordering::Release);
                break;
            }
        }
    });
    for member in &shared.members {
        match &member.port {
            HeldWorkPort::Codex(p) => {
                let mut r = p.subscribe();
                let u = updates.clone();
                tokio::spawn(async move {
                    while r.changed().await.is_ok() {
                        let _ = u.try_send(());
                    }
                });
            }
            HeldWorkPort::Claude(p) => {
                let mut r = p.subscribe();
                let u = updates.clone();
                tokio::spawn(async move {
                    while r.changed().await.is_ok() {
                        let _ = u.try_send(());
                    }
                });
            }
            HeldWorkPort::Gemini(p) => {
                let mut r = p.subscribe();
                let u = updates.clone();
                tokio::spawn(async move {
                    while r.changed().await.is_ok() {
                        let _ = u.try_send(());
                    }
                });
            }
        }
    }
    let journal = Arc::new(Mutex::new(journal));
    shared.refresh_now();
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::Submit(capture) => {
                        let id = capture.saved.id.clone();
                        let result = dispatch(&shared, &journal, capture).await;
                        if result.is_err() { shared.failed(&id) }
                        let _ = refresh_records(&shared, &journal).await;
                        shared.finish(&id, result.err());
                    }
                    Command::Lookup { id, serial } => {
                        let key = id.clone();
                        let found = store(&journal, move |j| j.lookup(&key)).await;
                        let error = match found {
                            Ok(Some(record)) => {
                                for m in &record.intent.members {
                                    if let Some(child) = &m.child_id
                                        && let Some(owner) = shared.members.iter().find(|owner| owner.id == m.id)
                                    {
                                        match &owner.port {
                                            HeldWorkPort::Codex(p) => { let _ = p.lookup(child); }
                                            HeldWorkPort::Claude(p) => { let _ = p.lookup(child); }
                                            HeldWorkPort::Gemini(p) => { let _ = p.lookup(child); }
                                        }
                                    }
                                }
                                let _ = refresh_records(&shared, &journal).await;
                                None
                            }
                            Ok(None) => Some(TeamError::InvalidInput),
                            Err(e) => Some(e),
                        };
                        shared.report(&id, ReportKind::Lookup, Some(serial), error);
                    }
                }
            }
            update = update_rx.recv() => {
                if update.is_none() { break }
                shared.refresh_now();
            }
        }
    }
}
async fn dispatch(
    shared: &Shared,
    journal: &Arc<Mutex<Journal>>,
    capture: CapturedTeamDirection,
) -> Result<()> {
    #[cfg(test)]
    if shared.fail_before_save.load(Ordering::Acquire) {
        return Err(TeamError::Storage);
    }
    shared.verify()?;
    let saved = capture.saved.clone();
    let id = saved.id.clone();
    store(journal, move |j| j.save(saved)).await?;
    refresh_records(shared, journal).await?;
    for (member, token) in capture.tokens {
        if shared.ended.load(Ordering::Acquire) || Instant::now() >= capture.deadline {
            break;
        }
        let parent = id.clone();
        let who = member.clone();
        let claim = store(journal, move |j| j.claim(&parent, &who)).await?;
        // The committed license carries its exact post-claim history. Retain it
        // before invocation, even if the following admission append fails.
        shared.remember(claim.stored.clone())?;
        #[cfg(test)]
        {
            let pause = shared
                .before_invoke
                .lock()
                .ok()
                .and_then(|mut slot| slot.take());
            if let Some((reached, release)) = pause {
                reached.notify_one();
                release.notified().await;
            }
        }
        // Parent FS work never holds this admission gate. Quit linearizes here.
        shared.verify()?;
        let result = {
            let _gate = shared
                .admission
                .lock()
                .map_err(|_| TeamError::Unavailable)?;
            if shared.ended.load(Ordering::Acquire) || Instant::now() >= capture.deadline {
                None
            } else {
                let owner = shared
                    .members
                    .iter()
                    .find(|m| m.id == member)
                    .ok_or(TeamError::StalePlan)?;
                Some(match (&owner.port, token) {
                    (HeldWorkPort::Codex(p), PreparedNative::Codex(t)) => {
                        p.submit_prepared_steer(t).is_ok()
                    }
                    (HeldWorkPort::Claude(p), PreparedNative::Claude(t)) => {
                        p.submit_prepared_direction(t).is_ok()
                    }
                    (HeldWorkPort::Gemini(p), PreparedNative::Gemini(t)) => {
                        p.submit_prepared_prompt(t).is_ok()
                    }
                    _ => return Err(TeamError::StalePlan),
                })
            }
        };
        let Some(queued) = result else { break };
        let admission = if queued {
            LocalAdmission::Queued
        } else {
            LocalAdmission::Rejected
        };
        #[cfg(test)]
        if shared.fail_admission_append.swap(false, Ordering::AcqRel) {
            store(journal, |j| {
                j.fail_admission_for_fixture();
                Ok(())
            })
            .await?;
        }
        store(journal, move |j| j.admission(&claim, admission)).await?;
        refresh_records(shared, journal).await?;
    }
    let parent = id;
    store(journal, move |j| j.retire(&parent)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
