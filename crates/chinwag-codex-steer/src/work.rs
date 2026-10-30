//! A retained owner for one human-started fresh thread. UI waiters hold a port,
//! never the sole stream owner. Only explicit Close releases the connection.

use crate::{
    ConnectionOwner, HumanWorkPort, Result, SteerController, SteerError, WorkActionKind,
    WorkConfig, WorkPhase, WorkSnapshot, WorkSubmission,
    connection::{ConnectionActivity, HumanSteerAction},
    record::{valid_operation_id, valid_text},
    unix_wire::{WsRead, WsWrite},
    work_bootstrap,
    work_journal::{ConsumedWork, WorkJournal},
    work_socket::{SelectedDirectory, SelectedSocket},
};
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    sync::{mpsc, watch},
};

enum Command {
    Start {
        id: String,
        text: String,
        deadline: Instant,
    },
    Steer(HumanSteerAction),
    Lookup(String),
}

struct Client {
    commands: mpsc::Sender<Command>,
    snapshots: watch::Receiver<WorkSnapshot>,
    close: watch::Sender<bool>,
    flight: Arc<AtomicBool>,
    controller: Arc<Mutex<Option<SteerController>>>,
    #[cfg(test)]
    command_seen: Arc<tokio::sync::Notify>,
}

/// Opens an inert native control service. It starts no Codex process, connection
/// or task. The trusted host must retain its port until explicit Close/Quit.
pub fn open_work_service(config: WorkConfig) -> Result<Arc<dyn HumanWorkPort>> {
    Ok(open_client(config)?)
}

fn open_client(config: WorkConfig) -> Result<Arc<Client>> {
    let (commands, rx) = mpsc::channel(8);
    let (snapshots, observations) = watch::channel(WorkSnapshot::ready(config.work_folder_label()));
    let (close, closed) = watch::channel(false);
    let flight = Arc::new(AtomicBool::new(false));
    let controller = Arc::new(Mutex::new(None));
    #[cfg(test)]
    let command_seen = Arc::new(tokio::sync::Notify::new());
    let client = Arc::new(Client {
        commands: commands.clone(),
        snapshots: observations,
        close: close.clone(),
        flight: flight.clone(),
        controller: controller.clone(),
        #[cfg(test)]
        command_seen: command_seen.clone(),
    });
    std::thread::Builder::new()
        .name("chinwag-owned-work".into())
        .spawn(move || {
            // Keep the owner alive if a view or its observation receiver disappears.
            // No Drop implementation converts that disappearance into Close.
            let _command_lifetime = commands;
            let _close_lifetime = close;
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(run(
                    config,
                    rx,
                    closed,
                    snapshots,
                    flight,
                    controller,
                    #[cfg(test)]
                    command_seen,
                )),
                Err(_) => {
                    let mut s = snapshots.borrow().clone();
                    s.phase = WorkPhase::Unavailable;
                    snapshots.send_replace(s);
                }
            }
        })
        .map_err(|_| SteerError::Unavailable)?;
    Ok(client)
}

impl Client {
    fn submit(&self, command: Command) -> Result<()> {
        if *self.close.borrow() {
            return Err(SteerError::Unavailable);
        }
        if self
            .flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(SteerError::Busy);
        }
        if self.commands.try_send(command).is_err() {
            self.flight.store(false, Ordering::Release);
            return Err(SteerError::Busy);
        }
        Ok(())
    }
}

impl HumanWorkPort for Client {
    fn subscribe(&self) -> watch::Receiver<WorkSnapshot> {
        self.snapshots.clone()
    }
    fn start(&self, id: &str, text: &str) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        if !valid_operation_id(id) || !valid_text(text) {
            return Err(SteerError::InvalidInput);
        }
        self.submit(Command::Start {
            id: id.into(),
            text: text.into(),
            deadline,
        })
    }
    fn steer(&self, target: &crate::ObservedActiveTurn, id: &str, text: &str) -> Result<()> {
        let controller = self
            .controller
            .lock()
            .map_err(|_| SteerError::Unavailable)?;
        let controller = controller.as_ref().ok_or(SteerError::NoActiveTurn)?;
        // Capture exact authority and its original deadline at the human action,
        // before queueing or any blocking journal work.
        let action = controller.capture_human_action(target, id, text)?;
        self.submit(Command::Steer(action))
    }
    fn lookup(&self, id: &str) -> Result<()> {
        if !valid_operation_id(id) {
            return Err(SteerError::InvalidInput);
        }
        self.commands
            .try_send(Command::Lookup(id.into()))
            .map_err(|_| SteerError::Busy)
    }
    fn close(&self) -> Result<()> {
        self.close.send_replace(true);
        // Explicit human Close fences an already installed controller even if
        // the owner is awaiting blocking persistence for an admitted action.
        if let Ok(slot) = self.controller.lock()
            && let Some(controller) = slot.as_ref()
        {
            controller.request_close();
        }
        Ok(())
    }
}

struct Session {
    controller: SteerController,
    owner: ConnectionOwner,
}
type FailedIo = (BufReader<WsRead>, WsWrite);
enum Started {
    Session(Session),
    Held(FailedIo),
    None,
}
type Store = Arc<Mutex<WorkJournal>>;

async fn store<T: Send + 'static>(
    journal: &Store,
    f: impl FnOnce(&mut WorkJournal) -> Result<T> + Send + 'static,
) -> Result<T> {
    let journal = journal.clone();
    tokio::task::spawn_blocking(move || {
        let mut journal = journal.lock().map_err(|_| SteerError::Storage)?;
        f(&mut journal)
    })
    .await
    .map_err(|_| SteerError::Storage)?
}

fn publish(tx: &watch::Sender<WorkSnapshot>, snapshot: &mut WorkSnapshot) {
    snapshot.revision = snapshot.revision.saturating_add(1);
    tx.send_replace(snapshot.clone());
}
fn completed(
    snapshot: &mut WorkSnapshot,
    id: String,
    kind: WorkActionKind,
    saved: bool,
    error: Option<SteerError>,
) {
    snapshot.last_submission = Some(WorkSubmission {
        id,
        kind,
        saved,
        error,
    });
}

async fn run(
    config: WorkConfig,
    mut commands: mpsc::Receiver<Command>,
    mut close: watch::Receiver<bool>,
    tx: watch::Sender<WorkSnapshot>,
    flight: Arc<AtomicBool>,
    slot: Arc<Mutex<Option<SteerController>>>,
    #[cfg(test)] command_seen: Arc<tokio::sync::Notify>,
) {
    let mut snapshot = tx.borrow().clone();
    let open_config = config.clone();
    let journal = tokio::task::spawn_blocking(move || WorkJournal::open(open_config)).await;
    let journal = match journal {
        Ok(Ok(journal)) => Arc::new(Mutex::new(journal)),
        _ => {
            snapshot.phase = WorkPhase::Unavailable;
            publish(&tx, &mut snapshot);
            loop {
                tokio::select! {biased;
                    _=close.changed()=>break,
                    command=commands.recv()=>{
                        let Some(command)=command else {break;};
                        let (id,kind)=match command {Command::Start{id,..}=>(id,WorkActionKind::Start),
                            Command::Steer(action)=>(action.id().into(),WorkActionKind::Steer),
                            Command::Lookup(id)=>(id,WorkActionKind::Lookup)};
                        completed(&mut snapshot,id,kind,false,Some(SteerError::Storage));
                        flight.store(false,Ordering::Release); publish(&tx,&mut snapshot);
                    }
                }
            }
            snapshot.phase = WorkPhase::Closed;
            publish(&tx, &mut snapshot);
            return;
        }
    };
    snapshot.start = store(&journal, |j| Ok(j.receipt())).await.ok().flatten();
    if snapshot.start.is_some() {
        snapshot.phase = WorkPhase::StartUnknown;
    }
    let archive_open = if snapshot.start.is_some() {
        let path = config.journal.join("steers");
        tokio::task::spawn_blocking(move || match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => crate::journal::SteerJournal::open(&path)
                .map(|journal| Some(Arc::new(Mutex::new(journal)))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            _ => Err(SteerError::Storage),
        })
        .await
        .unwrap_or(Err(SteerError::Storage))
    } else {
        Ok(None)
    };
    let (archived, mut archive_error) = match archive_open {
        Ok(archive) => (archive, None),
        Err(error) => (None, Some(error)),
    };
    if let Some(archive) = &archived {
        let archive = archive.clone();
        match tokio::task::spawn_blocking(move || {
            archive.lock().map_err(|_| SteerError::Storage)?.receipts()
        })
        .await
        {
            Ok(Ok(receipts)) => snapshot.steers = receipts,
            Ok(Err(error)) => archive_error = Some(error),
            Err(_) => archive_error = Some(SteerError::Storage),
        }
    }
    if archive_error.is_some() {
        snapshot.phase = WorkPhase::OwnerActionRequired;
    }
    publish(&tx, &mut snapshot);
    let idle = ConnectionActivity {
        target: None,
        completed: false,
        initial: None,
        agent_text: None,
        intervention: false,
        write_fenced: false,
        closed: false,
        revision: 0,
    };
    let (idle_activity, mut activity) = watch::channel(idle);
    let (idle_receipts, mut receipts) = watch::channel(0u64);
    let mut session: Option<Session> = None;
    let mut held: Option<FailedIo> = None;
    let mut ids = BTreeSet::new();
    loop {
        tokio::select! {biased;
            _=close.changed()=>break,
            command=commands.recv()=>{
                let Some(command)=command else {continue;};
                match command {
                    Command::Start{id,text,deadline}=>{
                        let id_for_save=id.clone();
                        let consumed=store(&journal,move|j|j.consume(&id_for_save,&text,deadline)).await;
                        match consumed {
                            Ok(ConsumedWork::Existing(receipt))=>{
                                snapshot.start=Some(receipt);
                                completed(&mut snapshot,id,WorkActionKind::Start,true,None);
                            }
                            Ok(ConsumedWork::Created(work))=>{
                                snapshot.start=store(&journal,|j|Ok(j.receipt())).await.ok().flatten();
                                snapshot.phase=WorkPhase::Starting;
                                completed(&mut snapshot,id.clone(),WorkActionKind::Start,true,None);
                                publish(&tx,&mut snapshot);
                                let operation=start(work,&config,&journal,&mut snapshot,&tx,slot.clone(),close.clone());
                                let result=tokio::select! {biased;
                                    _=close.changed()=>{None},
                                    result=operation=>Some(result),
                                };
                                match result {
                                    Some(Ok(Started::Session(active)))=>{
                                        activity=active.controller.subscribe_activity();
                                        receipts=active.controller.subscribe_receipts();
                                        session=Some(active);
                                    }
                                    Some(Ok(Started::Held(io)))=>{held=Some(io);},
                                    Some(Ok(Started::None))=>{},
                                    Some(Err(error))=>{
                                        snapshot.start=store(&journal,|j|Ok(j.receipt())).await.ok().flatten().or(snapshot.start);
                                        snapshot.phase=if error==SteerError::OwnerInterventionRequired {WorkPhase::OwnerActionRequired}else{WorkPhase::StartUnknown};
                                        completed(&mut snapshot,id,WorkActionKind::Start,true,Some(error));
                                    }
                                    None=>{
                                        snapshot.phase=WorkPhase::Closed;
                                        completed(&mut snapshot,id,WorkActionKind::Start,true,Some(SteerError::Uncertain));
                                    }
                                }
                            }
                            Err(error)=>completed(&mut snapshot,id,WorkActionKind::Start,false,Some(error)),
                        }
                        flight.store(false,Ordering::Release);
                    }
                    Command::Steer(action)=>{
                        #[cfg(test)]
                        command_seen.notify_one();
                        let id=action.id().to_owned();
                        let result=if let Some(active)=&session {
                            match active.owner.authorize_action(&action) {
                                Ok(grant)=>active.controller.submit_human_text(&grant,action.target(),action.id(),action.text()).await,
                                Err(error)=>Err(error),
                            }
                        }else{Err(SteerError::NoActiveTurn)};
                        match result {
                            Ok(receipt)=>{ids.insert(id.clone()); upsert(&mut snapshot,receipt);
                                completed(&mut snapshot,id,WorkActionKind::Steer,true,None);},
                            Err(error)=>completed(&mut snapshot,id,WorkActionKind::Steer,false,Some(error)),
                        }
                        flight.store(false,Ordering::Release);
                    }
                    Command::Lookup(id)=>{
                        let result=if snapshot.start.as_ref().is_some_and(|r|r.id==id){
                            match store(&journal,|j|j.lookup()).await {
                                Ok(Some(receipt))=>{snapshot.start=Some(receipt);Ok(())},
                                Ok(None)=>Err(SteerError::Uncertain),Err(error)=>Err(error),
                            }
                        }else if let Some(active)=&session{
                            match active.controller.receipt(&id).await {
                                Ok(Some(receipt))=>{upsert(&mut snapshot,receipt);Ok(())},
                                Ok(None)=>Err(SteerError::Uncertain),Err(error)=>Err(error),
                            }
                        }else if let Some(archive)=&archived{
                            let archive=archive.clone();let requested=id.clone();
                            match tokio::task::spawn_blocking(move||{
                                archive.lock().map_err(|_|SteerError::Storage)?.lookup(&requested)
                            }).await{
                                Ok(Ok(Some(receipt)))=>{upsert(&mut snapshot,receipt);Ok(())},
                                Ok(Ok(None))=>Err(SteerError::Uncertain),
                                Ok(Err(error))=>Err(error),Err(_)=>Err(SteerError::Storage),
                            }
                    }else{Err(archive_error.unwrap_or(SteerError::Uncertain))};
                        completed(&mut snapshot,id,WorkActionKind::Lookup,result.is_ok(),result.err());
                    }
                }
                if let Some(active)=&session {refresh(active,&journal,&ids,&mut snapshot).await;}
                publish(&tx,&mut snapshot);
                if *close.borrow(){break;}
            }
            changed=activity.changed()=>{
                if changed.is_err(){activity=idle_activity.subscribe();}
                if let Some(active)=&session{refresh(active,&journal,&ids,&mut snapshot).await; publish(&tx,&mut snapshot);}
            }
            changed=receipts.changed()=>{
                if changed.is_err(){receipts=idle_receipts.subscribe();}
                if let Some(active)=&session{refresh(active,&journal,&ids,&mut snapshot).await; publish(&tx,&mut snapshot);}
            }
        }
    }
    // Only this explicit human Close reaches here. It owns no external process.
    let mut close_error = None;
    if let Some(active) = &session {
        if let Err(error) = active.controller.shutdown().await {
            close_error = Some(error);
        }
        refresh(active, &journal, &ids, &mut snapshot).await;
    } else {
        // A canceled Start can already have installed a controller; retain and join it.
        let pending = slot.lock().ok().and_then(|slot| slot.clone());
        if let Some(controller) = pending
            && let Err(error) = controller.shutdown().await
        {
            close_error = Some(error);
        }
    }
    if let Some((_reader, mut writer)) = held
        && !matches!(
            tokio::time::timeout(Duration::from_secs(2), writer.shutdown()).await,
            Ok(Ok(()))
        )
    {
        close_error = Some(SteerError::Unavailable);
    }
    if let Ok(mut slot) = slot.lock() {
        slot.take();
    }
    snapshot.phase = WorkPhase::Closed;
    snapshot.target = None;
    completed(
        &mut snapshot,
        "close-connection".into(),
        WorkActionKind::Close,
        false,
        close_error,
    );
    publish(&tx, &mut snapshot);
}

async fn start(
    work: crate::work_journal::CommittedWork,
    config: &WorkConfig,
    journal: &Store,
    snapshot: &mut WorkSnapshot,
    tx: &watch::Sender<WorkSnapshot>,
    slot: Arc<Mutex<Option<SteerController>>>,
    close: watch::Receiver<bool>,
) -> Result<Started> {
    let path = config.socket.clone();
    let cwd = config.workdir.clone();
    let directory = tokio::task::spawn_blocking(move || SelectedDirectory::observe(&cwd))
        .await
        .map_err(|_| SteerError::Unavailable)??;
    let connect = async {
        let pin = tokio::task::spawn_blocking(move || SelectedSocket::observe(&path))
            .await
            .map_err(|_| SteerError::Unavailable)??;
        let stream = pin.connect().await?;
        crate::unix_wire::connect(stream).await
    };
    let connected =
        tokio::time::timeout_at(tokio::time::Instant::from_std(work.deadline()), connect).await;
    let (reader, mut writer) = match connected {
        Ok(Ok(io)) => io,
        _ => {
            fail_start(journal, snapshot, SteerError::Unavailable).await;
            publish(tx, snapshot);
            return Ok(Started::None);
        }
    };
    let mut reader = BufReader::new(reader);
    let mut receipt = snapshot.start.clone().ok_or(SteerError::Storage)?;
    receipt.connected = true;
    snapshot.start = Some(store(journal, move |j| j.update(receipt)).await?);
    publish(tx, snapshot);
    let proof = match work_bootstrap::bootstrap(&work, &mut reader, &mut writer).await {
        Ok(proof) => proof,
        Err(error) => {
            snapshot.start = store(journal, |j| Ok(j.receipt()))
                .await
                .ok()
                .flatten()
                .or_else(|| snapshot.start.clone());
            fail_start(journal, snapshot, error).await;
            publish(tx, snapshot);
            // Retain original IO on ambiguous bootstrap. No reconnect/reinitialize.
            return Ok(Started::Held((reader, writer)));
        }
    };
    let thread = proof.thread_id().to_owned();
    let directory = tokio::task::spawn_blocking(move || {
        directory.verify()?;
        Ok::<_, SteerError>(directory)
    })
    .await
    .map_err(|_| SteerError::Unavailable)??;
    let (controller, owner) =
        SteerController::from_fresh_thread(proof, &config.journal.join("steers"), reader, writer)
            .await?;
    {
        let mut slot = slot.lock().map_err(|_| SteerError::Unavailable)?;
        *slot = Some(controller.clone());
        // Serialize installation with the port's explicit Close. A close that
        // saw an empty slot still fences this later-installed controller.
        if *close.borrow() {
            controller.request_close();
            return Ok(Started::Session(Session { controller, owner }));
        }
    }
    let epoch = controller.transport_epoch().to_owned();
    let capsule = match store(journal, move |j| j.commit_initial(&work, &thread, &epoch)).await {
        Ok(capsule) => capsule,
        Err(error) => {
            snapshot.phase = WorkPhase::StartUnknown;
            if let Some(receipt) = &snapshot.start {
                completed(
                    snapshot,
                    receipt.id.clone(),
                    WorkActionKind::Start,
                    true,
                    Some(error),
                );
            }
            // No initial Start is dispatched, but the same owner/connection is
            // retained until explicit Close. There is no rebootstrap or retry.
            return Ok(Started::Session(Session { controller, owner }));
        }
    };
    snapshot.start = store(journal, |j| Ok(j.receipt())).await?;
    publish(tx, snapshot);
    tokio::task::spawn_blocking(move || directory.verify())
        .await
        .map_err(|_| SteerError::Unavailable)??;
    controller.dispatch_initial(capsule).await;
    let session = Session { controller, owner };
    refresh(&session, journal, &BTreeSet::new(), snapshot).await;
    Ok(Started::Session(session))
}

async fn fail_start(journal: &Store, snapshot: &mut WorkSnapshot, error: SteerError) {
    if let Some(mut receipt) = snapshot.start.clone() {
        receipt.bootstrap_uncertain = true;
        receipt.evidence.not_dispatched = true;
        snapshot.start = match store(journal, move |j| j.update(receipt)).await {
            Ok(receipt) => Some(receipt),
            Err(_) => store(journal, |j| Ok(j.receipt()))
                .await
                .ok()
                .flatten()
                .or_else(|| snapshot.start.clone()),
        };
    }
    snapshot.phase = if error == SteerError::OwnerInterventionRequired {
        WorkPhase::OwnerActionRequired
    } else {
        WorkPhase::StartUnknown
    };
    if let Some(receipt) = &snapshot.start {
        completed(
            snapshot,
            receipt.id.clone(),
            WorkActionKind::Start,
            true,
            Some(error),
        );
    }
}

async fn refresh(
    session: &Session,
    journal: &Store,
    ids: &BTreeSet<String>,
    snapshot: &mut WorkSnapshot,
) {
    let activity = session.controller.subscribe_activity().borrow().clone();
    // This revision is a transient same-owner observation identity, not a clock
    // or an additional persistence/identity store.
    snapshot.revision = snapshot.revision.max(activity.revision);
    snapshot.target = activity.target.clone();
    snapshot.agent_text = activity.agent_text;
    snapshot.phase = if activity.intervention {
        WorkPhase::OwnerActionRequired
    } else if activity.completed {
        WorkPhase::Finished
    } else if activity.closed {
        WorkPhase::Closed
    } else if activity.write_fenced {
        WorkPhase::OwnerActionRequired
    } else if snapshot.target.is_some() {
        WorkPhase::Working
    } else if activity
        .initial
        .as_ref()
        .is_some_and(|initial| initial.evidence.not_dispatched)
    {
        WorkPhase::Unavailable
    } else if activity.initial.as_ref().is_some_and(|initial| {
        initial.evidence.write_uncertain || initial.evidence.peer_error_observed
    }) {
        WorkPhase::StartUnknown
    } else {
        WorkPhase::Starting
    };
    if let Some(initial) = activity.initial
        && let Some(mut receipt) = snapshot.start.clone()
        && receipt.id == initial.id
    {
        if let Ok(merged) = receipt.evidence.merged(initial.evidence) {
            receipt.evidence = merged;
        }
        if initial.accepted_turn_id.is_some() {
            receipt.accepted_turn_id = initial.accepted_turn_id;
        }
        snapshot.start = store(journal, move |j| j.update(receipt))
            .await
            .ok()
            .or_else(|| {
                snapshot.start.clone().map(|mut old| {
                    old.persistence_failed = true;
                    old
                })
            });
    }
    for id in ids {
        if let Ok(Some(receipt)) = session.controller.receipt(id).await {
            upsert(snapshot, receipt);
        }
    }
}
fn upsert(snapshot: &mut WorkSnapshot, receipt: crate::Receipt) {
    if let Some(existing) = snapshot
        .steers
        .iter_mut()
        .find(|old| old.operation.id == receipt.operation.id)
    {
        *existing = receipt;
    } else {
        snapshot.steers.push(receipt);
    }
}

#[cfg(test)]
mod tests;
