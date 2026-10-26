//! Operator-only Architect receive phase. No claim service, agent dispatch,
//! retry, or seal. Do not run beside an Architect claim endpoint. A private
//! control file only ends the network phase; it cannot prove sender acceptance.
//! Deadlines are cooperative and do not preempt synchronous filesystem work.

use crate::{
    bundle::GitCandidate,
    bundle_intake::{BundleOperatorConfig, BundleVerifier},
    bundle_io::{
        bounded_read, canonical, private_directory, private_empty_directory, private_file,
    },
    bundle_receive::{ReceivedFile, accept_one_bundle},
    bundle_wire::{BundleOffer, run_id},
    cargo::{CargoVerifier, CommandReport},
    private_trace::PrivateStageJournal,
};
use chinwag_swarm::{
    DiscoveryScope, bind_sovereign_swarm,
    identity::Identity,
    lan::LanInterfaces,
    relay_policy::RelayPolicy,
    room::{RoomClient, RoomSession},
    transport::DataPlane,
};
use iroh::{EndpointId, address_lookup::memory::MemoryLookup};
use rustix::fs::{Mode, OFlags, RenameFlags, openat, renameat_with};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File},
    io::Write,
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::time::{Instant, sleep_until, timeout_at};

const BUILDER: &str = "df7676a8680f06f1cddb51a793be9a07a0d022638cb25ebe681dd42328867931";
const ARCHITECT: &str = "63e44fbb5054e0730793b2be61daf203b912c7cc5777f86ebbfe5f73b096c3d0";
const COORDINATOR: &str = "366eb665b85888a6b5f265d340b29d0623c6c92c96e6c0746c7b4554b5949919";
const ORIGIN: &str = "https://bootstrap.chinwag.sh";
const CONFIG_LIMIT: usize = 16 * 1024;
const MARKER: &str = "receiver-attempt.json";
const CONTROL: &str = "finish-network";
const FINISH: &[u8] = b"finish-network\n";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("receiver operator configuration rejected")]
    Configuration,
    #[error("receiver own identity is unavailable or not the Architect")]
    Identity,
    #[error("receiver original guard unavailable; preserve it, do not retry")]
    Guard,
    #[error("receiver network phase failed or expired; preserve the original")]
    Network,
    #[error("receiver cleanup control failed or expired; preserve the original")]
    Control,
    #[error("receiver network cleanup failed; no offline intake")]
    Cleanup,
    #[error("receiver offline Git intake failed; preserve the quarantine")]
    Intake,
    #[error("receiver independent Cargo failed; preserve its receipts")]
    Cargo,
    #[error("receiver terminal receipt unavailable; outcome unknown, do not retry")]
    Unknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    relay: crate::relay_config::RelaySelection,
    own_key: PathBuf,
    lan_ipv4: Ipv4Addr,
    run: String,
    oid: String,
    tree: String,
    guard_directory: PathBuf,
    received_directory: PathBuf,
    trace_directory: PathBuf,
    quarantine: PathBuf,
    empty_templates: PathBuf,
    builder_signers: PathBuf,
    worktree: PathBuf,
    toolchain: PathBuf,
    cache: PathBuf,
}

struct Selected {
    config: Config,
    candidate: GitCandidate,
    peer: EndpointId,
    policy: Arc<RelayPolicy>,
}

fn select(path: &Path) -> Result<Selected, Error> {
    let path = canonical(path).map_err(|_| Error::Configuration)?;
    let bytes = bounded_read(
        &mut private_file(&path).map_err(|_| Error::Configuration)?,
        CONFIG_LIMIT,
    )
    .map_err(|_| Error::Configuration)?;
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| Error::Configuration)?;
    if config.schema != "chinwag-architect-receive/v3" {
        return Err(Error::Configuration);
    }
    let policy = config.relay.resolve().map_err(|_| Error::Configuration)?;
    run_id(&config.run).map_err(|_| Error::Configuration)?;
    let peer: EndpointId = BUILDER.parse().map_err(|_| Error::Configuration)?;
    let candidate = GitCandidate::new(&config.oid, &config.tree, *peer.as_bytes())
        .map_err(|_| Error::Configuration)?;
    LanInterfaces::new(vec![config.lan_ipv4]).map_err(|_| Error::Configuration)?;
    let writable = [
        &config.guard_directory,
        &config.received_directory,
        &config.trace_directory,
        &config.quarantine,
        &config.empty_templates,
        &config.worktree,
        &config.cache,
    ];
    for (index, directory) in writable.iter().enumerate() {
        canonical(directory).map_err(|_| Error::Configuration)?;
        for other in &writable[index + 1..] {
            if directory.starts_with(other) || other.starts_with(directory) {
                return Err(Error::Configuration);
            }
        }
        for protected in [
            &path,
            &config.own_key,
            &config.builder_signers,
            &config.toolchain,
        ] {
            canonical(protected).map_err(|_| Error::Configuration)?;
            if protected.starts_with(directory) {
                return Err(Error::Configuration);
            }
        }
        if **directory == config.cache {
            private_directory(directory).map_err(|_| Error::Configuration)?;
        } else {
            private_empty_directory(directory).map_err(|_| Error::Configuration)?;
        }
    }
    // Validate type/ownership without reading key bytes. Its loader owns that.
    private_file(&config.own_key).map_err(|_| Error::Configuration)?;
    private_file(&config.builder_signers).map_err(|_| Error::Configuration)?;
    if !config.toolchain.is_dir()
        || !["cargo", "rustc", "rustdoc"]
            .iter()
            .all(|name| config.toolchain.join(name).is_file())
    {
        return Err(Error::Configuration);
    }
    Ok(Selected {
        config,
        candidate,
        peer,
        policy,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: String,
    run: String,
    oid: String,
    tree: String,
}
impl Marker {
    fn new(selected: &Selected) -> Self {
        Self {
            schema: "chinwag-architect-original/v1".into(),
            run: selected.config.run.clone(),
            oid: selected.candidate.oid().into(),
            tree: selected.candidate.tree().into(),
        }
    }
    fn validate(&self) -> Result<(), Error> {
        if self.schema != "chinwag-architect-original/v1" {
            return Err(Error::Guard);
        }
        run_id(&self.run).map_err(|_| Error::Guard)?;
        let peer: EndpointId = BUILDER.parse().map_err(|_| Error::Guard)?;
        GitCandidate::new(&self.oid, &self.tree, *peer.as_bytes()).map_err(|_| Error::Guard)?;
        Ok(())
    }
}

struct Guard {
    path: PathBuf,
    directory: File,
}
impl Guard {
    fn arm(selected: &Selected) -> Result<Self, Error> {
        let path = canonical(&selected.config.guard_directory).map_err(|_| Error::Guard)?;
        let directory = private_empty_directory(&path).map_err(|_| Error::Guard)?;
        let guard = Self { path, directory };
        let bytes = serde_json::to_vec(&Marker::new(selected)).map_err(|_| Error::Guard)?;
        guard.write_new(MARKER, &bytes)?;
        Ok(guard)
    }
    fn check(&self) -> Result<(), Error> {
        canonical(&self.path).map_err(|_| Error::Guard)?;
        let actual = private_directory(&self.path)
            .map_err(|_| Error::Guard)?
            .metadata()
            .map_err(|_| Error::Guard)?;
        let held = self.directory.metadata().map_err(|_| Error::Guard)?;
        if (held.dev(), held.ino()) != (actual.dev(), actual.ino()) {
            return Err(Error::Guard);
        }
        Ok(())
    }
    fn write_new(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        self.check()?;
        let mut file = File::from(
            openat(
                &self.directory,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| Error::Guard)?,
        );
        file.write_all(bytes).map_err(|_| Error::Guard)?;
        file.sync_all().map_err(|_| Error::Guard)?;
        self.directory.sync_all().map_err(|_| Error::Guard)?;
        self.check()?;
        let actual = bounded_read(
            &mut private_file(&self.path.join(name)).map_err(|_| Error::Guard)?,
            bytes.len(),
        )
        .map_err(|_| Error::Guard)?;
        if actual != bytes {
            return Err(Error::Guard);
        }
        Ok(())
    }
    fn control_present(&self) -> Result<bool, Error> {
        self.check().map_err(|_| Error::Control)?;
        let path = self.path.join(CONTROL);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(Error::Control),
            Ok(_) => {}
        }
        let bytes = bounded_read(&mut private_file(&path).map_err(|_| Error::Control)?, 32)
            .map_err(|_| Error::Control)?;
        self.check().map_err(|_| Error::Control)?;
        if bytes != FINISH {
            return Err(Error::Control);
        }
        Ok(true)
    }
}

/// Move a complete operator-created control file from OUTSIDE the guard onto
/// its fixed initially absent name using atomic NOREPLACE. This starts no
/// receiver or network and grants no peer acceptance. It is never called by
/// `receive`; the operator owns the independent sender observation.
pub fn publish_finish(guard_path: &Path, prepared: &Path) -> Result<(), Error> {
    let path = canonical(guard_path).map_err(|_| Error::Control)?;
    let guard = Guard {
        directory: private_directory(&path).map_err(|_| Error::Control)?,
        path,
    };
    guard.check().map_err(|_| Error::Control)?;
    let marker: Marker = serde_json::from_slice(
        &bounded_read(
            &mut private_file(&guard.path.join(MARKER)).map_err(|_| Error::Control)?,
            4096,
        )
        .map_err(|_| Error::Control)?,
    )
    .map_err(|_| Error::Control)?;
    marker.validate().map_err(|_| Error::Control)?;
    if guard
        .path
        .join("receiver-finish.json")
        .try_exists()
        .map_err(|_| Error::Control)?
    {
        return Err(Error::Control);
    }
    let source = canonical(prepared).map_err(|_| Error::Control)?;
    if source.starts_with(&guard.path) {
        return Err(Error::Control);
    }
    let parent_path = source.parent().ok_or(Error::Control)?;
    let parent = private_directory(parent_path).map_err(|_| Error::Control)?;
    let mut file = private_file(&source).map_err(|_| Error::Control)?;
    let original = file.metadata().map_err(|_| Error::Control)?;
    if bounded_read(&mut file, 32).map_err(|_| Error::Control)? != FINISH {
        return Err(Error::Control);
    }
    // The publication command owns this durability step, rather than trusting
    // a caller to have synced the prepared bytes before the atomic rename.
    file.sync_all().map_err(|_| Error::Control)?;
    let current = fs::symlink_metadata(&source).map_err(|_| Error::Control)?;
    if (original.dev(), original.ino()) != (current.dev(), current.ino()) {
        return Err(Error::Control);
    }
    guard.check().map_err(|_| Error::Control)?;
    renameat_with(
        &parent,
        source.file_name().ok_or(Error::Control)?,
        &guard.directory,
        CONTROL,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| Error::Control)?;
    parent.sync_all().map_err(|_| Error::Control)?;
    guard.directory.sync_all().map_err(|_| Error::Control)?;
    let published = private_file(&guard.path.join(CONTROL)).map_err(|_| Error::Control)?;
    let actual = published.metadata().map_err(|_| Error::Control)?;
    if (actual.dev(), actual.ino()) != (original.dev(), original.ino())
        || !guard.control_present()?
    {
        return Err(Error::Control);
    }
    Ok(())
}

async fn wait_control(
    guard: &Guard,
    cutoff: Instant,
    fresh: impl Fn() -> Result<(), Error>,
) -> Result<(), Error> {
    loop {
        if Instant::now() >= cutoff {
            return Err(Error::Control);
        }
        fresh()?;
        if guard.control_present()? {
            if Instant::now() >= cutoff {
                return Err(Error::Control);
            }
            fresh()?;
            return Ok(());
        }
        sleep_until(std::cmp::min(
            cutoff,
            Instant::now() + Duration::from_millis(100),
        ))
        .await;
    }
}

#[derive(Default)]
struct Live {
    plane: Option<DataPlane>,
    room: Option<RoomSession>,
    saved: Option<ReceivedFile>,
}
struct Saved {
    path: PathBuf,
    offer: BundleOffer,
}
fn observation(offer: &BundleOffer) -> Value {
    let e = offer.expectation();
    json!({"run":offer.run(),"oid":e.oid(),"tree":e.tree(),"blake3":e.hash(),"size":e.size()})
}

async fn network(
    selected: &Selected,
    identity: &Identity,
    guard: &Guard,
    deadline: Instant,
    live: &mut Live,
    phase: &mut &'static str,
    journal: &mut PrivateStageJournal,
) -> Result<Saved, Error> {
    let config = &selected.config;
    let (plane, room, saved) = (&mut live.plane, &mut live.room, &mut live.saved);
    let book = MemoryLookup::new();
    let client = RoomClient::new(
        ORIGIN,
        COORDINATOR.parse().map_err(|_| Error::Configuration)?,
        Arc::clone(&selected.policy),
    )
    .map_err(|_| Error::Configuration)?;
    *phase = "bind";
    let active = plane.insert(
        bind_sovereign_swarm(
            identity,
            book.clone(),
            selected.peer,
            LanInterfaces::new(vec![config.lan_ipv4]).map_err(|_| Error::Configuration)?,
            DiscoveryScope::RoomOnly,
            client.relay_policy(),
        )
        .await
        .map_err(|_| Error::Network)?,
    );
    if active.endpoint_addr().id != identity.endpoint_id()
        || active.pinned_peer_id() != selected.peer
    {
        return Err(Error::Network);
    }
    client
        .relay_policy()
        .observe_relay_urls(active.endpoint_addr().relay_urls())
        .map_err(|_| Error::Configuration)?;
    *phase = "local_address";
    let mut addresses = Vec::new();
    // Only observe the same endpoint's selected LAN address; no new discovery,
    // bind, room request, or original deadline is created here.
    for _ in 0..100 {
        addresses = active
            .endpoint_addr()
            .ip_addrs()
            .copied()
            .filter(|address| address.ip() == IpAddr::V4(config.lan_ipv4))
            .collect();
        if !addresses.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if addresses.is_empty() {
        return Err(Error::Network);
    }
    *phase = "room_open";

    let session = room.insert(
        client
            .open(identity, selected.peer, addresses, book)
            .await
            .map_err(|_| Error::Network)?,
    );
    *phase = "peer_record";
    session.receive_peer().await.map_err(|_| Error::Network)?;
    *phase = "receive";
    let received = saved.insert(
        accept_one_bundle(
            active,
            session,
            selected.peer,
            &config.run,
            &selected.candidate,
            &config.received_directory,
            journal,
        )
        .await
        .map_err(|_| Error::Network)?,
    );
    guard.write_new(
        "saved-local.json",
        &serde_json::to_vec(&json!({
            "observation":observation(received.offer()),"local":"saved_then_ack_queued",
            "sender_acceptance":false,"Git_Cargo_model_or_seal":false,
        }))
        .map_err(|_| Error::Guard)?,
    )?;
    *phase = "hold";
    let measured = Instant::now();
    let remaining = session
        .remaining_peer_validity()
        .map_err(|_| Error::Control)?;
    let budget = remaining
        .checked_sub(Duration::from_secs(1))
        .filter(|d| !d.is_zero())
        .ok_or(Error::Control)?;
    let cutoff = std::cmp::min(deadline, measured + budget);
    wait_control(guard, cutoff, || {
        session.require_fresh_peer().map_err(|_| Error::Control)
    })
    .await?;
    let received = saved.take().ok_or(Error::Network)?;
    let result = Saved {
        path: received.path().to_owned(),
        offer: received.offer().clone(),
    };
    drop(received); // Leave the topic before closing the owned network.
    Ok(result)
}

fn log_report(guard: &Guard, name: &str, report: &CommandReport) -> Result<Value, Error> {
    let mut logs = Vec::new();
    for (stream, bytes) in [("stdout", &report.stdout), ("stderr", &report.stderr)] {
        if bytes.len() > 256 * 1024 {
            return Err(Error::Unknown);
        }
        let file = format!("{name}.{stream}");
        guard.write_new(&file, bytes).map_err(|_| Error::Unknown)?;
        logs.push(json!({"file":file,"bytes":bytes.len(),"sha256":hex(&Sha256::digest(bytes))}));
    }
    Ok(
        json!({"success":report.success,"exit_code":report.exit_code,"elapsed_ms":report.elapsed_ms,"logs":logs}),
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn offline(
    selected: &Selected,
    guard: &Guard,
    saved: Saved,
    phase: &mut &'static str,
) -> Result<Value, Error> {
    let config = &selected.config;
    *phase = "Git_intake";
    let verifier = BundleVerifier::open(BundleOperatorConfig {
        bundle: saved.path,
        quarantine: config.quarantine.clone(),
        empty_templates: config.empty_templates.clone(),
        builder_signers: config.builder_signers.clone(),
        expected: saved.offer.expectation().clone(),
    })
    .map_err(|_| Error::Intake)?;
    let verified = verifier.verify().await.map_err(|_| Error::Intake)?;
    *phase = "materialize";
    let materialized = verified
        .materialize(&config.worktree)
        .await
        .map_err(|_| Error::Intake)?;
    let target = materialized.path().join("target");
    DirBuilder::new()
        .mode(0o700)
        .create(&target)
        .map_err(|_| Error::Cargo)?;
    *phase = "received_Cargo";
    let report = CargoVerifier::new(
        materialized.path(),
        &config.toolchain,
        &config.cache,
        &target,
    )
    .map_err(|_| Error::Cargo)?
    .verify()
    .await
    .map_err(|_| Error::Cargo)?;
    let check = log_report(guard, "check", &report.check)?;
    let test = report
        .test
        .as_ref()
        .map(|r| log_report(guard, "test", r))
        .transpose()?;
    let receipt = json!({"observation":observation(&saved.offer),"check":check,"test":test,
        "passed":report.passed(),"network_cleanup_completed":true,
        "sender_acceptance":false,"model_review_or_seal_or_Genesis":false});
    guard
        .write_new(
            "received-cargo.json",
            &serde_json::to_vec(&receipt).map_err(|_| Error::Unknown)?,
        )
        .map_err(|_| Error::Unknown)?;
    if !report.passed() {
        return Err(Error::Cargo);
    }
    Ok(receipt)
}

/// Explicit current-thread operator command. Keep the runtime alive until
/// completion; abort/crash cannot promise graceful cleanup. No receiver recovery
/// is supported. A terminal-note failure remains Unknown, never replayable.
pub async fn receive(path: &Path) -> Result<(), Error> {
    let selected = select(path)?;
    let identity =
        Identity::from_ssh_signing_file(&selected.config.own_key).map_err(|_| Error::Identity)?;
    if identity.endpoint_id()
        != ARCHITECT
            .parse::<EndpointId>()
            .map_err(|_| Error::Configuration)?
    {
        return Err(Error::Identity);
    }
    let guard = Guard::arm(&selected)?;
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut live = Live::default();
    let mut phase = "armed";
    let primary = async {
        phase = "trace_open";
        let mut journal = PrivateStageJournal::create(
            &selected.config.trace_directory,
            identity.endpoint_id(),
            selected.peer,
        )
        .map_err(|_| Error::Guard)?;
        // Trace fsync consumes the original budget and cannot reset it.
        if Instant::now() >= deadline {
            return Err(Error::Network);
        }
        timeout_at(
            deadline,
            network(
                &selected,
                &identity,
                &guard,
                deadline,
                &mut live,
                &mut phase,
                &mut journal,
            ),
        )
        .await
        .unwrap_or(Err(Error::Network))
    }
    .await;
    drop(live.saved.take());
    let room_close_attempted = live.room.is_some();
    if let Some(mut session) = live.room.take() {
        session.close().await;
    }
    let plane_returned = live.plane.is_some();
    let cleanup = match live.plane.take() {
        Some(active) => active.shutdown().await.map_err(|_| Error::Cleanup),
        None => Ok(()),
    };
    let cleanup_ok = cleanup.is_ok();
    let result = match (primary, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(observed), Ok(())) => offline(&selected, &guard, observed, &mut phase).await,
    };
    let note = json!({"schema":"chinwag-architect-finish/v1","run":selected.config.run,
        "phase":phase,"local_result":if result.is_ok() { "received_git_and_Cargo_checked" } else { "failed_preserve_original" },
        "owned_plane_shutdown_observed":if plane_returned { Some(cleanup_ok) } else { None },
        "room_close_attempted":room_close_attempted,"error":result.as_ref().err().map(ToString::to_string),
        "sender_acceptance":false,"model_review_or_seal_or_Genesis":false});
    guard
        .write_new(
            "receiver-finish.json",
            &serde_json::to_vec(&note).map_err(|_| Error::Unknown)?,
        )
        .map_err(|_| Error::Unknown)?;
    result.map(|_| ())
}

#[cfg(test)]
#[path = "receiver_driver_tests.rs"]
mod tests;
