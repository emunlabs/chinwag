use super::*;
use chinwag_client_discovery::{
    ClientFamily, Coverage, ExecutableFormat, ExecutableMetadata, HostObservation,
    InstallationKind, InstalledCoverage, catalogue::InstallationMatch,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};
use tempfile::TempDir;

const ID: &str = "native-open-fixture-0001";
const OTHER_ID: &str = "native-open-fixture-0002";

#[test]
fn action_journals_cannot_change_domain_across_restart_or_adopt_legacy_setup() {
    let temporary = TempDir::new().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let ordinary_path = root.join("ordinary");
    let mut ordinary = Journal::open(&ordinary_path).unwrap();
    ordinary.begin(ID, &"a".repeat(64)).unwrap();
    ordinary
        .finish(receipt(
            ID,
            &"a".repeat(64),
            NativeOpenState::OpenedOrReused,
        ))
        .unwrap();
    drop(ordinary);
    assert!(Journal::open_in_domain(&ordinary_path, Domain::CursorMcpSetup).is_err());
    let legacy_path = root.join("legacy");
    fs::create_dir(&legacy_path).unwrap();
    fs::set_permissions(&legacy_path, fs::Permissions::from_mode(0o700)).unwrap();
    let record = fs::read(ordinary_path.join(format!("{ID}.json"))).unwrap();
    let legacy_record = legacy_path.join(format!("{ID}.json"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&legacy_record)
        .unwrap();
    file.write_all(&record).unwrap();
    drop(file);
    assert!(Journal::open_in_domain(&legacy_path, Domain::CursorMcpSetup).is_err());
    assert!(!legacy_path.join("native-action-domain.json").exists());
    assert_eq!(fs::read(&legacy_record).unwrap(), record);
    let adopted_ordinary = Journal::open(&legacy_path).unwrap();
    assert_eq!(
        adopted_ordinary.lookup(ID).unwrap().unwrap().state,
        NativeOpenState::OpenedOrReused
    );
    assert_eq!(fs::read(legacy_record).unwrap(), record);
}

#[test]
fn cursor_domain_keeps_crash_pending_uncertain_and_rejects_unknown_marker_bytes() {
    let temporary = TempDir::new().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap().join("cursor");
    let mut journal = Journal::open_in_domain(&root, Domain::CursorMcpSetup).unwrap();
    journal.begin(ID, &"a".repeat(64)).unwrap();
    drop(journal);
    assert!(Journal::open(&root).is_err());
    let mut reopened = Journal::open_in_domain(&root, Domain::CursorMcpSetup).unwrap();
    assert_eq!(
        reopened.lookup(ID).unwrap().unwrap().state,
        NativeOpenState::Uncertain
    );
    assert!(matches!(
        reopened.begin(ID, &"a".repeat(64)),
        Err(OnboardingError::Conflict)
    ));
    drop(reopened);
    let marker = root.join("native-action-domain.json");
    fs::write(&marker, b"partial or foreign domain bytes").unwrap();
    assert!(Journal::open_in_domain(&root, Domain::CursorMcpSetup).is_err());
    assert_eq!(
        fs::read(marker).unwrap(),
        b"partial or foreign domain bytes"
    );
}

#[test]
fn vscode_journal_cannot_adopt_other_action_domains_legacy_records_or_orphans() {
    let temporary = TempDir::new().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    for (name, domain) in [
        ("ordinary", Domain::OrdinaryOpen),
        ("cursor", Domain::CursorMcpSetup),
    ] {
        let path = root.join(name);
        let mut journal = Journal::open_in_domain(&path, domain).unwrap();
        journal.begin(ID, &"a".repeat(64)).unwrap();
        journal
            .finish(receipt(
                ID,
                &"a".repeat(64),
                NativeOpenState::OpenedOrReused,
            ))
            .unwrap();
        drop(journal);
        let marker = fs::read(path.join("native-action-domain.json")).unwrap();
        let original = fs::read(path.join(format!("{ID}.json"))).unwrap();
        assert!(Journal::open_in_domain(&path, Domain::VsCodeMcpSetup).is_err());
        assert_eq!(
            fs::read(path.join("native-action-domain.json")).unwrap(),
            marker
        );
        assert_eq!(fs::read(path.join(format!("{ID}.json"))).unwrap(), original);
    }
    for orphan in [false, true] {
        let path = root.join(if orphan { "orphan" } else { "legacy" });
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let entry = if orphan {
            write_orphan(&path, ID, b"{crash-left-write");
            format!(".{ID}-write.tmp")
        } else {
            write_record(
                &path,
                ID,
                &receipt(ID, &"a".repeat(64), NativeOpenState::OpenedOrReused),
            );
            format!("{ID}.json")
        };
        let original = fs::read(path.join(&entry)).unwrap();
        assert!(Journal::open_in_domain(&path, Domain::VsCodeMcpSetup).is_err());
        assert!(!path.join("native-action-domain.json").exists());
        assert_eq!(fs::read(path.join(entry)).unwrap(), original);
    }
}

#[test]
fn vscode_domain_is_immutable_and_crash_pending_cannot_replay_after_restart() {
    let temporary = TempDir::new().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap().join("vscode");
    let mut journal = Journal::open_in_domain(&root, Domain::VsCodeMcpSetup).unwrap();
    journal.begin(ID, &"d".repeat(64)).unwrap();
    let original = fs::read(root.join(format!("{ID}.json"))).unwrap();
    drop(journal);
    for wrong_domain in [Domain::OrdinaryOpen, Domain::CursorMcpSetup] {
        assert!(Journal::open_in_domain(&root, wrong_domain).is_err());
    }
    let mut reopened = Journal::open_in_domain(&root, Domain::VsCodeMcpSetup).unwrap();
    assert_eq!(
        reopened.lookup(ID).unwrap().unwrap().state,
        NativeOpenState::Uncertain
    );
    assert!(matches!(
        reopened.begin(ID, &"d".repeat(64)),
        Err(OnboardingError::Conflict)
    ));
    assert_eq!(fs::read(root.join(format!("{ID}.json"))).unwrap(), original);
    reopened.begin(OTHER_ID, &"d".repeat(64)).unwrap();
    drop(reopened);
    let marker = root.join("native-action-domain.json");
    fs::write(&marker, b"unknown or partial setup action marker").unwrap();
    assert!(Journal::open_in_domain(&root, Domain::VsCodeMcpSetup).is_err());
    assert_eq!(
        fs::read(marker).unwrap(),
        b"unknown or partial setup action marker"
    );
}

struct FakeLauncher {
    calls: Arc<AtomicUsize>,
    panic: bool,
}
impl NativeApplicationLauncher for FakeLauncher {
    fn open_or_reuse(
        &mut self,
        target: &chinwag_native_launch::LaunchTarget,
        _: Instant,
    ) -> Result<OpenReceipt, LaunchFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic, "fixture launcher panic");
        Ok(OpenReceipt {
            application_path: target.application_path().into(),
            bundle_id: target.bundle_id().into(),
            process_id: Some(42),
        })
    }
}

fn installation() -> Installation {
    Installation {
        id: "a".repeat(64),
        family: ClientFamily::GrokBot,
        kind: InstallationKind::Application,
        match_basis: InstallationMatch::PublicBundleIdentity,
        canonical_path: "/Applications/Grok Bot.app".into(),
        observed_paths: vec!["/Applications/Grok Bot.app".into()],
        display_name: "Grok Bot".into(),
        bundle_id: Some("com.anysphere.sand".into()),
        version: Some("fixture".into()),
        executable_path: "/Applications/Grok Bot.app/Contents/MacOS/Grok Bot".into(),
        executable: ExecutableMetadata {
            device: 1,
            inode: 2,
            size: 123,
            modified_seconds: 10,
            modified_nanoseconds: 1,
            mode: 0o100755,
            format: ExecutableFormat::MachO,
        },
        metadata_fingerprint: "b".repeat(64),
    }
}

fn snapshots() -> (InventorySnapshot, InstalledSnapshot) {
    (
        InventorySnapshot {
            observed_at_unix_ms: 100,
            host: HostObservation {
                label: "host-fixture".into(),
                boot_uuid: "boot-fixture".into(),
            },
            uid: 42,
            coverage: Coverage::default(),
            candidates: vec![],
            limitations: vec![],
        },
        InstalledSnapshot {
            observed_at_unix_ms: 100,
            installations: vec![installation()],
            coverage: InstalledCoverage::default(),
            limitations: vec![],
        },
    )
}

fn named_installation(family: ClientFamily) -> Installation {
    let mut application = installation();
    let (id, path, name, bundle, executable) = match family {
        ClientFamily::Cursor => (
            "c",
            "/Applications/Cursor.app",
            "Cursor",
            "com.todesktop.230313mzl4w4u92",
            "Cursor",
        ),
        ClientFamily::VisualStudioCode => (
            "d",
            "/Applications/Visual Studio Code.app",
            "Code",
            "com.microsoft.VSCode",
            "Code",
        ),
        _ => panic!("unsupported named fixture"),
    };
    application.id = id.repeat(64);
    application.family = family;
    application.canonical_path = path.into();
    application.observed_paths = vec![application.canonical_path.clone()];
    application.display_name = name.into();
    application.bundle_id = Some(bundle.into());
    application.executable_path = application
        .canonical_path
        .join("Contents/MacOS")
        .join(executable);
    application
}

#[test]
fn vscode_cache_rejects_other_families_before_verification_or_native_effect() {
    let (_directory, path) = private_temp_directory();
    let calls = Arc::new(AtomicUsize::new(0));
    let verifications = Arc::new(AtomicUsize::new(0));
    let now = Instant::now();
    let counted = Arc::clone(&verifications);
    let mut service = OnboardingService::new_parts_in_domain(
        &path,
        Arc::new(move |host, installation| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(NativeObservation::new(
                host.clone(),
                installation.clone(),
                now,
            ))
        }),
        Box::new(FakeLauncher {
            calls: Arc::clone(&calls),
            panic: false,
        }),
        Arc::new(move || now),
        Domain::VsCodeMcpSetup,
    )
    .unwrap();
    service.family = Some(ClientFamily::VisualStudioCode);
    let (process, mut installed) = snapshots();
    installed
        .installations
        .push(named_installation(ClientFamily::Cursor));
    installed
        .installations
        .push(named_installation(ClientFamily::VisualStudioCode));
    service.observe(&process, &installed).unwrap();
    let vscode_id = observed_installation_id(&process, &installed.installations[2]);
    assert_eq!(
        service.status().unwrap().openable_installation_ids,
        vec![vscode_id.clone()]
    );
    for (id, installation) in [ID, OTHER_ID]
        .into_iter()
        .zip(&installed.installations[..2])
    {
        let request = NativeOpenRequest {
            installation_id: observed_installation_id(&process, installation),
        };
        assert_eq!(
            service.open(id, &request).unwrap().state,
            NativeOpenState::Rejected
        );
    }
    assert_eq!(verifications.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let request = NativeOpenRequest {
        installation_id: vscode_id,
    };
    let request_id = "vscode-valid-fixture-0001";
    let result = service.open(request_id, &request).unwrap();
    assert_eq!(result.state, NativeOpenState::OpenedOrReused);
    assert_eq!(verifications.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(service.lookup(request_id).unwrap(), Some(result.clone()));
    assert_eq!(service.open(request_id, &request).unwrap(), result);
    assert!(service.status().unwrap().native_open_allowed);
    assert_eq!(verifications.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    service: OnboardingService,
    process: InventorySnapshot,
    installed: InstalledSnapshot,
    request: NativeOpenRequest,
    calls: Arc<AtomicUsize>,
    now: Arc<Mutex<Instant>>,
}

fn service_at(path: &Path, calls: Arc<AtomicUsize>, now: Arc<Mutex<Instant>>) -> OnboardingService {
    let verify_now = Arc::clone(&now);
    OnboardingService::new_parts(
        path,
        Arc::new(move |host, installation| {
            Ok(NativeObservation::new(
                host.clone(),
                installation.clone(),
                *verify_now.lock().unwrap(),
            ))
        }),
        Box::new(FakeLauncher {
            calls,
            panic: false,
        }),
        Arc::new(move || *now.lock().unwrap()),
    )
    .unwrap()
}

fn private_temp_directory() -> (TempDir, PathBuf) {
    let directory = TempDir::new().unwrap();
    let path = directory.path().canonicalize().unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    (directory, path)
}

fn fixture() -> Fixture {
    let (directory, path) = private_temp_directory();
    let calls = Arc::new(AtomicUsize::new(0));
    let now = Arc::new(Mutex::new(Instant::now()));
    let service = service_at(&path, Arc::clone(&calls), Arc::clone(&now));
    let (process, installed) = snapshots();
    service.observe(&process, &installed).unwrap();
    let request = NativeOpenRequest {
        installation_id: observed_installation_id(&process, &installed.installations[0]),
    };
    Fixture {
        _directory: directory,
        path,
        service,
        process,
        installed,
        request,
        calls,
        now,
    }
}

fn write_record(path: &Path, id: &str, result: &NativeOpenReceipt) {
    let bytes = serde_json::to_vec(
        &serde_json::json!({"schema":"chinwag-native-open-record/v1","receipt":result}),
    )
    .unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(format!("{id}.json")))
        .unwrap();
    file.write_all(&bytes).unwrap();
}

#[test]
fn durable_pending_precedes_verifier_and_launcher_and_cached_result_never_replays() {
    let mut fixture = fixture();
    let path = fixture.path.clone();
    let now = Arc::clone(&fixture.now);
    fixture.service.verifier = Arc::new(move |host, installation| {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join(format!("{ID}.json"))).unwrap()).unwrap();
        assert_eq!(value["receipt"]["state"], "pending");
        Ok(NativeObservation::new(
            host.clone(),
            installation.clone(),
            *now.lock().unwrap(),
        ))
    });
    let result = fixture.service.open(ID, &fixture.request).unwrap();
    assert!(matches!(result.state, NativeOpenState::OpenedOrReused));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    fixture.service.invalidate().unwrap();
    assert!(matches!(
        fixture.service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::OpenedOrReused
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    let mut conflict = fixture.request.clone();
    conflict.installation_id = "f".repeat(64);
    assert!(matches!(
        fixture.service.open(ID, &conflict),
        Err(OnboardingError::Conflict)
    ));
    assert!(
        fixture
            .service
            .lookup("unknown-request-id-0001")
            .unwrap()
            .is_none()
    );
}

#[test]
fn crash_pending_is_uncertain_after_restart_and_different_id_can_continue() {
    let fixture = fixture();
    fixture
        .service
        .journal
        .lock()
        .unwrap()
        .begin(ID, &fixture.request.installation_id)
        .unwrap();
    let original = fs::read(fixture.path.join(format!("{ID}.json"))).unwrap();
    drop(fixture.service);
    let service = service_at(
        &fixture.path,
        Arc::clone(&fixture.calls),
        Arc::clone(&fixture.now),
    );
    assert!(matches!(
        service.lookup(ID).unwrap().unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert!(matches!(
        service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    service
        .observe(&fixture.process, &fixture.installed)
        .unwrap();
    assert!(matches!(
        service.open(OTHER_ID, &fixture.request).unwrap().state,
        NativeOpenState::OpenedOrReused
    ));
    assert_eq!(
        fs::read(fixture.path.join(format!("{ID}.json"))).unwrap(),
        original
    );
}

#[test]
fn expiry_at_exact_deadline_records_rejection_and_refresh_allows_a_new_human_id() {
    let fixture = fixture();
    *fixture.now.lock().unwrap() += CACHE_LIFETIME;
    assert!(!fixture.service.status().unwrap().native_open_allowed);
    assert!(matches!(
        fixture.service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Rejected
    ));
    assert!(matches!(
        fixture.service.lookup(ID).unwrap().unwrap().state,
        NativeOpenState::Rejected
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    fixture
        .service
        .observe(&fixture.process, &fixture.installed)
        .unwrap();
    assert!(matches!(
        fixture.service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Rejected
    ));
    assert!(matches!(
        fixture
            .service
            .open(OTHER_ID, &fixture.request)
            .unwrap()
            .state,
        NativeOpenState::OpenedOrReused
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn replacement_and_wrong_boot_are_rejected_before_native_dispatch() {
    for wrong_boot in [false, true] {
        let mut fixture = fixture();
        let now = Arc::clone(&fixture.now);
        fixture.service.verifier = Arc::new(move |host, installation| {
            let mut installation = installation.clone();
            let host = if wrong_boot {
                HostIdentity::new(host.host_id().into(), "different-boot".into()).unwrap()
            } else {
                installation.metadata_fingerprint = "c".repeat(64);
                host.clone()
            };
            Ok(NativeObservation::new(
                host,
                installation,
                *now.lock().unwrap(),
            ))
        });
        assert!(matches!(
            fixture.service.open(ID, &fixture.request).unwrap().state,
            NativeOpenState::Rejected
        ));
        assert!(matches!(
            fixture.service.open(ID, &fixture.request).unwrap().state,
            NativeOpenState::Rejected
        ));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn busy_before_mutation_and_pending_lookup_remains_available_during_verifier() {
    let mut fixture = fixture();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    let first = AtomicBool::new(true);
    let now = Arc::clone(&fixture.now);
    fixture.service.verifier = Arc::new(move |host, installation| {
        if first.swap(false, Ordering::SeqCst) {
            ready_tx.send(()).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
        Ok(NativeObservation::new(
            host.clone(),
            installation.clone(),
            *now.lock().unwrap(),
        ))
    });
    let service = Arc::new(fixture.service);
    let worker_service = Arc::clone(&service);
    let request = fixture.request.clone();
    let worker = thread::spawn(move || worker_service.open(ID, &request));
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        service.lookup(ID).unwrap().unwrap().state,
        NativeOpenState::Pending
    ));
    assert!(matches!(
        service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Pending
    ));
    assert!(matches!(
        service.open(OTHER_ID, &fixture.request),
        Err(OnboardingError::Busy)
    ));
    assert!(service.lookup(OTHER_ID).unwrap().is_none());
    release_tx.send(()).unwrap();
    assert!(matches!(
        worker.join().unwrap().unwrap().state,
        NativeOpenState::OpenedOrReused
    ));
    assert!(matches!(
        service.open(OTHER_ID, &fixture.request).unwrap().state,
        NativeOpenState::OpenedOrReused
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn observation_invalidation_during_verification_prevents_dispatch() {
    let mut fixture = fixture();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    let now = Arc::clone(&fixture.now);
    fixture.service.verifier = Arc::new(move |host, installation| {
        ready_tx.send(()).unwrap();
        release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        Ok(NativeObservation::new(
            host.clone(),
            installation.clone(),
            *now.lock().unwrap(),
        ))
    });
    let service = Arc::new(fixture.service);
    let worker_service = Arc::clone(&service);
    let request = fixture.request.clone();
    let worker = thread::spawn(move || worker_service.open(ID, &request));
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    service.invalidate().unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(
        worker.join().unwrap().unwrap().state,
        NativeOpenState::Rejected
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn terminal_storage_failure_is_uncertain_disables_native_only_and_never_replays() {
    let fixture = fixture();
    fixture.service.journal.lock().unwrap().fail_terminal_write = true;
    assert!(matches!(
        fixture.service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert!(matches!(
        fixture.service.lookup(ID).unwrap().unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert!(!fixture.service.status().unwrap().native_open_allowed);
    assert!(matches!(
        fixture.service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert!(matches!(
        fixture.service.open(OTHER_ID, &fixture.request),
        Err(OnboardingError::Storage)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    drop(fixture.service);
    let service = service_at(
        &fixture.path,
        Arc::clone(&fixture.calls),
        Arc::clone(&fixture.now),
    );
    assert!(matches!(
        service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn pending_storage_failure_never_reaches_verifier_or_native_dispatch() {
    let mut fixture = fixture();
    fixture.service.verifier = Arc::new(|_, _| panic!("must not verify before durable pending"));
    fixture.service.journal.lock().unwrap().fail_next_write = true;
    assert!(matches!(
        fixture.service.open(ID, &fixture.request),
        Err(OnboardingError::Storage)
    ));
    assert!(!fixture.service.status().unwrap().native_open_allowed);
    assert!(matches!(
        fixture.service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn launcher_panic_is_uncertain_without_poisoning_unrelated_native_attempts() {
    let fixture = fixture();
    fixture.service.launcher.lock().unwrap().0 = Box::new(FakeLauncher {
        calls: Arc::clone(&fixture.calls),
        panic: true,
    });
    assert!(matches!(
        fixture.service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Uncertain
    ));
    fixture.service.launcher.lock().unwrap().0 = Box::new(FakeLauncher {
        calls: Arc::clone(&fixture.calls),
        panic: false,
    });
    assert!(matches!(
        fixture
            .service
            .open(OTHER_ID, &fixture.request)
            .unwrap()
            .state,
        NativeOpenState::OpenedOrReused
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn lookup_and_terminal_wire_payloads_remain_redacted() {
    let fixture = fixture();
    let result = fixture.service.open(ID, &fixture.request).unwrap();
    for raw in [
        serde_json::to_string(&result).unwrap(),
        serde_json::to_string(&fixture.service.lookup(ID).unwrap()).unwrap(),
        serde_json::to_string(&fixture.service.status().unwrap()).unwrap(),
    ] {
        for private in [
            "/Applications",
            "host-fixture",
            "boot-fixture",
            "com.anysphere.sand",
            "process_id",
            "Grok Bot",
            "metadata_fingerprint",
        ] {
            assert!(!raw.contains(private));
        }
    }
    assert!(
        result
            .message
            .contains("Connection and sign-in are unconfirmed")
    );
}

#[test]
fn invalid_observation_clears_prior_targets_and_hints_never_become_openable() {
    let mut fixture = fixture();
    fixture.installed.installations[0].match_basis = InstallationMatch::NameAndExecutableHint;
    fixture
        .service
        .observe(&fixture.process, &fixture.installed)
        .unwrap();
    assert!(!fixture.service.status().unwrap().native_open_allowed);
    fixture.installed.installations[0] = installation();
    fixture
        .service
        .observe(&fixture.process, &fixture.installed)
        .unwrap();
    fixture.process.host.label.clear();
    assert!(matches!(
        fixture
            .service
            .observe(&fixture.process, &fixture.installed),
        Err(OnboardingError::Invalid)
    ));
    assert!(!fixture.service.status().unwrap().native_open_allowed);
}

#[test]
fn host_and_boot_namespace_the_exact_existing_discovery_installation_id() {
    let (process, installed) = snapshots();
    let original = observed_installation_id(&process, &installed.installations[0]);
    let mut other = process.clone();
    other.host.label = "other-host".into();
    assert_ne!(
        original,
        observed_installation_id(&other, &installed.installations[0])
    );
    other = process;
    other.host.boot_uuid = "other-boot".into();
    assert_ne!(
        original,
        observed_installation_id(&other, &installed.installations[0])
    );
}

#[test]
fn invalid_wire_identifiers_never_create_a_journal_record() {
    let fixture = fixture();
    assert!(matches!(
        fixture
            .service
            .open("../escape-request-0001", &fixture.request),
        Err(OnboardingError::Invalid)
    ));
    assert!(matches!(
        fixture.service.lookup("short"),
        Err(OnboardingError::Invalid)
    ));
    assert!(matches!(
        fixture.service.open(
            ID,
            &NativeOpenRequest {
                installation_id: "/Applications/Grok Bot.app".into()
            }
        ),
        Err(OnboardingError::Invalid)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn exclusive_journal_lock_and_non_symlink_owned_scope_fail_closed() {
    let fixture = fixture();
    assert!(matches!(
        Journal::open(&fixture.path),
        Err(OnboardingError::Unavailable)
    ));
    let (_outer_directory, outer) = private_temp_directory();
    symlink(&fixture.path, outer.join("alias")).unwrap();
    assert!(matches!(
        Journal::open(&outer.join("alias")),
        Err(OnboardingError::Storage)
    ));
    let real = outer.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(
        fixture.path.join("native-open.lock"),
        real.join("native-open.lock"),
    )
    .unwrap();
    assert!(matches!(
        Journal::open(&real),
        Err(OnboardingError::Storage)
    ));
}

#[test]
fn corruption_oversize_and_record_symlink_are_rejected_on_restart() {
    for case in 0..4 {
        let (_directory, path) = private_temp_directory();
        let record = receipt(ID, &"a".repeat(64), NativeOpenState::Pending);
        if case == 0 {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join(format!("{ID}.json")))
                .unwrap();
            file.write_all(b"not JSON").unwrap();
        } else if case == 1 {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join(format!("{ID}.json")))
                .unwrap();
            file.write_all(&vec![b' '; 4097]).unwrap();
        } else if case == 2 {
            symlink("/does-not-exist", path.join(format!("{ID}.json"))).unwrap();
        } else {
            let mut wrong = record;
            wrong.request_id = OTHER_ID.into();
            write_record(&path, ID, &wrong);
        }
        assert!(matches!(
            Journal::open(&path),
            Err(OnboardingError::Storage)
        ));
    }
}

#[test]
fn journal_record_capacity_is_bounded_and_cached_receipts_remain_readable() {
    let (_directory, path) = private_temp_directory();
    for index in 0..journal::MAX_RECORDS {
        let id = format!("capacity-fixture-{index:04}");
        write_record(
            &path,
            &id,
            &receipt(&id, &"a".repeat(64), NativeOpenState::Uncertain),
        );
    }
    let mut journal = Journal::open(&path).unwrap();
    assert!(!journal.available());
    assert!(journal.lookup("capacity-fixture-0000").unwrap().is_some());
    assert!(matches!(
        journal.begin(ID, &"a".repeat(64)),
        Err(OnboardingError::Storage)
    ));
    drop(journal);
    write_record(
        &path,
        ID,
        &receipt(ID, &"a".repeat(64), NativeOpenState::Uncertain),
    );
    assert!(matches!(
        Journal::open(&path),
        Err(OnboardingError::Storage)
    ));
}

#[test]
fn unknown_observation_id_is_a_durable_redacted_rejection() {
    let fixture = fixture();
    let request = NativeOpenRequest {
        installation_id: "f".repeat(64),
    };
    let result = fixture.service.open(ID, &request).unwrap();
    assert!(matches!(result.state, NativeOpenState::Rejected));
    assert_eq!(
        result.message,
        "Opening was not acknowledged; refresh before another explicit request."
    );
    assert!(matches!(
        fixture.service.open(ID, &request).unwrap().state,
        NativeOpenState::Rejected
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn invalidation_cancels_the_opaque_operation_while_native_work_is_queued() {
    struct QueuedLauncher {
        ready: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
        effects: Arc<AtomicUsize>,
    }
    impl NativeApplicationLauncher for QueuedLauncher {
        fn open_or_reuse(
            &mut self,
            target: &chinwag_native_launch::LaunchTarget,
            _: Instant,
        ) -> Result<OpenReceipt, LaunchFailure> {
            self.ready.send(()).unwrap();
            self.release.recv_timeout(Duration::from_secs(5)).unwrap();
            if target.is_cancelled() {
                return Err(LaunchFailure::Rejected(
                    "cancelled before fixture submission",
                ));
            }
            self.effects.fetch_add(1, Ordering::SeqCst);
            Ok(OpenReceipt {
                application_path: target.application_path().into(),
                bundle_id: target.bundle_id().into(),
                process_id: Some(42),
            })
        }
    }
    let fixture = fixture();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    fixture.service.launcher.lock().unwrap().0 = Box::new(QueuedLauncher {
        ready: ready_tx,
        release: release_rx,
        effects: Arc::clone(&fixture.calls),
    });
    let service = Arc::new(fixture.service);
    let worker_service = Arc::clone(&service);
    let request = fixture.request.clone();
    let worker = thread::spawn(move || worker_service.open(ID, &request));
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    service.invalidate().unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(
        worker.join().unwrap().unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

fn write_orphan(path: &Path, id: &str, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(format!(".{id}-write.tmp")))
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn truncated_crash_temp_reserves_only_its_id_and_unrelated_open_continues() {
    let fixture = fixture();
    drop(fixture.service);
    write_orphan(&fixture.path, ID, b"{truncated");
    let original = fs::read(fixture.path.join(format!(".{ID}-write.tmp"))).unwrap();
    let service = service_at(
        &fixture.path,
        Arc::clone(&fixture.calls),
        Arc::clone(&fixture.now),
    );
    service
        .observe(&fixture.process, &fixture.installed)
        .unwrap();
    assert!(service.status().unwrap().native_open_allowed);
    assert!(matches!(service.lookup(ID), Err(OnboardingError::Storage)));
    assert!(matches!(
        service.open(ID, &fixture.request),
        Err(OnboardingError::Storage)
    ));
    assert!(matches!(
        service.open(OTHER_ID, &fixture.request).unwrap().state,
        NativeOpenState::OpenedOrReused
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read(fixture.path.join(format!(".{ID}-write.tmp"))).unwrap(),
        original
    );
}

#[test]
fn persisted_pending_dominates_orphan_bytes_and_remains_uncertain_without_replay() {
    let fixture = fixture();
    fixture
        .service
        .journal
        .lock()
        .unwrap()
        .begin(ID, &fixture.request.installation_id)
        .unwrap();
    drop(fixture.service);
    let claimed_success = receipt(
        ID,
        &fixture.request.installation_id,
        NativeOpenState::OpenedOrReused,
    );
    write_orphan(
        &fixture.path,
        ID,
        &serde_json::to_vec(&claimed_success).unwrap(),
    );
    let service = service_at(
        &fixture.path,
        Arc::clone(&fixture.calls),
        Arc::clone(&fixture.now),
    );
    service
        .observe(&fixture.process, &fixture.installed)
        .unwrap();
    assert!(matches!(
        service.lookup(ID).unwrap().unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert!(matches!(
        service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert!(matches!(
        service.open(OTHER_ID, &fixture.request).unwrap().state,
        NativeOpenState::OpenedOrReused
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn reserved_orphan_ids_count_toward_capacity_and_symlink_orphans_fail_closed() {
    let (_directory, path) = private_temp_directory();
    for index in 0..journal::MAX_RECORDS {
        write_orphan(&path, &format!("orphan-capacity-{index:04}"), b"{");
    }
    let journal = Journal::open(&path).unwrap();
    assert!(!journal.available());
    assert!(matches!(
        journal.lookup("orphan-capacity-0000"),
        Err(OnboardingError::Storage)
    ));
    drop(journal);
    write_orphan(&path, ID, b"{");
    assert!(matches!(
        Journal::open(&path),
        Err(OnboardingError::Storage)
    ));
    let (_directory2, path) = private_temp_directory();
    symlink("/does-not-exist", path.join(format!(".{ID}-write.tmp"))).unwrap();
    assert!(matches!(
        Journal::open(&path),
        Err(OnboardingError::Storage)
    ));
}

#[test]
fn an_unexpected_existing_temp_is_never_deleted_by_a_failed_new_write() {
    let fixture = fixture();
    write_orphan(&fixture.path, ID, b"preserved unknown write");
    assert!(matches!(
        fixture.service.open(ID, &fixture.request),
        Err(OnboardingError::Storage)
    ));
    assert_eq!(
        fs::read(fixture.path.join(format!(".{ID}-write.tmp"))).unwrap(),
        b"preserved unknown write"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn fifo_socket_and_directory_journal_entries_fail_without_a_blocking_open() {
    for kind in 0..3 {
        for name in [
            format!("{ID}.json"),
            format!(".{ID}-write.tmp"),
            "native-open.lock".into(),
        ] {
            let (directory, path) = private_temp_directory();
            let target = path.join(name);
            let socket = if kind == 0 {
                make_fixture_fifo(&target);
                None
            } else if kind == 1 {
                // Only a temporary filesystem socket node, no accept/send or
                // client protocol traffic. Bind a short path, then rename it.
                let short = directory.path().join("s");
                let socket = std::os::unix::net::UnixListener::bind(&short).unwrap();
                fs::rename(short, &target).unwrap();
                Some(socket)
            } else {
                fs::create_dir(&target).unwrap();
                None
            };
            let (sender, receiver) = mpsc::sync_channel(1);
            let worker = thread::spawn(move || {
                let _ = sender.send(matches!(
                    Journal::open(&path),
                    Err(OnboardingError::Storage)
                ));
            });
            assert!(receiver.recv_timeout(Duration::from_secs(5)).unwrap());
            worker.join().unwrap();
            drop(socket);
        }
    }
}

#[test]
fn fifo_appearing_as_a_pending_target_is_preserved_and_never_dispatches() {
    let fixture = fixture();
    let target = fixture.path.join(format!("{ID}.json"));
    make_fixture_fifo(&target);
    let service = Arc::new(fixture.service);
    let worker_service = Arc::clone(&service);
    let request = fixture.request.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let _ = sender.send(matches!(
            worker_service.open(ID, &request),
            Err(OnboardingError::Storage)
        ));
    });
    assert!(receiver.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.join().unwrap();
    assert!(!fs::symlink_metadata(target).unwrap().is_file());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

fn make_fixture_fifo(path: &Path) {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the NUL-terminated path is an owned temporary fixture location;
    // mkfifo retains no pointer and creates only a private filesystem node.
    let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
}

#[test]
fn a_late_canonical_record_is_preserved_before_any_native_effect() {
    let fixture = fixture();
    let target = fixture.path.join(format!("{ID}.json"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&target)
        .unwrap();
    file.write_all(b"unknown canonical bytes").unwrap();
    assert!(matches!(
        fixture.service.open(ID, &fixture.request),
        Err(OnboardingError::Storage)
    ));
    assert_eq!(fs::read(target).unwrap(), b"unknown canonical bytes");
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_changed_pending_record_is_preserved_and_terminal_outcome_stays_uncertain() {
    let mut fixture = fixture();
    let target = fixture.path.join(format!("{ID}.json"));
    let verifier_target = target.clone();
    let now = Arc::clone(&fixture.now);
    fixture.service.verifier = Arc::new(move |host, installation| {
        fs::write(&verifier_target, b"changed pending bytes").unwrap();
        Ok(NativeObservation::new(
            host.clone(),
            installation.clone(),
            *now.lock().unwrap(),
        ))
    });
    assert!(matches!(
        fixture.service.open(ID, &fixture.request).unwrap().state,
        NativeOpenState::Uncertain
    ));
    assert_eq!(fs::read(target).unwrap(), b"changed pending bytes");
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert!(!fixture.service.status().unwrap().native_open_allowed);
}
