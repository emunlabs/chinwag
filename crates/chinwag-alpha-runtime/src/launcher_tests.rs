use super::*;
use std::collections::{HashMap, VecDeque};
use tempfile::TempDir;

struct Fixture {
    _temporary: TempDir,
    state: PathBuf,
    desktop: PathBuf,
    platform: FakePlatform,
}

struct FakePlatform {
    executable: PathBuf,
    statuses: VecDeque<Result<Option<Value>>>,
    commands: HashMap<u32, String>,
    spawns: Vec<Vec<String>>,
    opens: Vec<Vec<String>>,
    exit_code: Option<i32>,
    fail_open: bool,
    pauses: usize,
    forward_processes: HashMap<u32, forward::ProcessIdentity>,
    forward_ports: VecDeque<Result<bool>>,
    forward_spawns: Vec<Vec<String>>,
    forward_exit: Option<i32>,
    fail_forward_spawn: bool,
    lose_forward_during_status: bool,
    foreign_listener_after_spawn: bool,
    forward_listeners: std::collections::HashSet<u32>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let executable = bin.join("chinwag-alpha-runtime");
        fs::write(&executable, b"Rust runtime fixture; never executed").unwrap();
        let desktop = bin.join("chinwag-desktop-alpha");
        fs::write(&desktop, b"\xcf\xfa\xed\xfenative executable fixture").unwrap();
        let state = root.join("operator state");
        fs::create_dir_all(&state).unwrap();
        Self {
            _temporary: temporary,
            state,
            desktop,
            platform: FakePlatform {
                executable,
                statuses: VecDeque::new(),
                commands: HashMap::new(),
                spawns: Vec::new(),
                opens: Vec::new(),
                exit_code: None,
                fail_open: false,
                pauses: 0,
                forward_processes: HashMap::new(),
                forward_ports: VecDeque::new(),
                forward_spawns: Vec::new(),
                forward_exit: None,
                fail_forward_spawn: false,
                lose_forward_during_status: false,
                foreign_listener_after_spawn: false,
                forward_listeners: std::collections::HashSet::new(),
            },
        }
    }

    fn options(&self) -> Options {
        Options {
            state: self.state.clone(),
            desktop: self.desktop.clone(),
            bus_url: None,
            cursor_onboarding: false,
            studio_forward: false,
        }
    }

    fn status(&self, pid: u32) -> Value {
        json!({
            "ok": true, "mode": LOCAL_MODE, "transport": LOCAL_TRANSPORT,
            "live_fleet": false, "signed": false, "agent_wake": false,
            "storage_healthy": true, "data_dir":self.state.join("local-bus"), "pid":pid,
            "read_only":false,"send_allowed":true
        })
    }

    fn live(&mut self, pid: u32) {
        self.platform.commands.insert(
            pid,
            bus_command(&self.state, &self.platform.executable)
                .unwrap()
                .join(" "),
        );
    }

    fn receipt(&self, pid: u32) -> ProcessReceipt {
        ProcessReceipt {
            runtime: "rust".into(),
            pid,
            url: LOCAL_URL.into(),
            command: bus_command(&self.state, &self.platform.executable).unwrap(),
            started_unix_ms: 123,
        }
    }
}

impl Platform for FakePlatform {
    fn current_exe(&self) -> &Path {
        &self.executable
    }

    fn status(&mut self, _: &str) -> Result<Option<Value>> {
        if self.lose_forward_during_status {
            self.forward_processes.remove(&999);
        }
        self.statuses.pop_front().unwrap_or(Ok(None))
    }

    fn process_command(&mut self, pid: u32) -> Result<Option<String>> {
        Ok(self.commands.get(&pid).cloned())
    }

    fn spawn_local(&mut self, command: &[String], _: &Path) -> Result<u32> {
        self.spawns.push(command.to_vec());
        self.commands.insert(888, command.join(" "));
        Ok(888)
    }

    fn poll_local(&mut self, _: u32) -> Result<Option<i32>> {
        Ok(self.exit_code)
    }

    fn open_app(&mut self, arguments: &[String]) -> Result<()> {
        self.opens.push(arguments.to_vec());
        if self.fail_open {
            unavailable("injected activation failure")
        } else {
            Ok(())
        }
    }

    fn pause(&mut self) {
        self.pauses += 1;
    }

    fn forward_identity(&mut self, pid: u32) -> Result<Option<forward::ProcessIdentity>> {
        Ok(self.forward_processes.get(&pid).cloned())
    }

    fn forward_port_free(&mut self) -> Result<bool> {
        self.forward_ports.pop_front().unwrap_or(Ok(true))
    }

    fn spawn_forward(&mut self, command: &[String], log: &Path) -> Result<u32> {
        let journal: Value = serde_json::from_slice(
            &fs::read(log.parent().unwrap().join("studio-forward-process.json")).unwrap(),
        )
        .unwrap();
        let attempt = journal["attempts"].as_array().unwrap().last().unwrap();
        assert_eq!(
            attempt["phase"], "spawn_pending",
            "durable consumed intent precedes possible SSH spawn"
        );
        assert!(attempt["pid"].is_null());
        self.forward_spawns.push(command.to_vec());
        if self.fail_forward_spawn {
            return unavailable("injected uncertain SSH spawn");
        }
        self.forward_processes.insert(
            999,
            forward::ProcessIdentity {
                command: command.join(" "),
                started: "Fri Oct 30 00:00:00 2026".into(),
            },
        );
        if !self.foreign_listener_after_spawn {
            self.forward_listeners.insert(999);
        }
        Ok(999)
    }

    fn poll_forward(&mut self, _: u32) -> Result<Option<i32>> {
        Ok(self.forward_exit)
    }

    fn forward_listens(&mut self, pid: u32) -> Result<bool> {
        Ok(self.forward_listeners.contains(&pid))
    }
}

#[test]
fn parser_rejects_build_python_and_unsafe_endpoints() {
    let fixture = Fixture::new();
    for args in [
        vec!["--build", "true"],
        vec!["--live-url", "http://localhost:1234"],
        vec!["--state-dir"],
        vec!["--state-dir", "a", "--state-dir", "b"],
        vec!["--bus-url", "https://localhost:1234"],
        vec!["--bus-url", "http://user:pass@localhost:1234"],
        vec!["--bus-url", "http://example.com:1234"],
        vec!["--bus-url", "http://localhost:1234/path"],
    ] {
        let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
        assert!(
            Options::parse(&args, &fixture.platform.executable).is_err(),
            "{args:?}"
        );
    }
    let parsed = Options::parse(&[], &fixture.platform.executable).unwrap();
    assert_eq!(parsed.desktop, fixture.desktop);
}

#[test]
fn default_launch_starts_only_current_rust_runtime_and_saves_exact_ownership() {
    let mut fixture = Fixture::new();
    fixture.platform.statuses = VecDeque::from([Ok(None), Ok(Some(fixture.status(888)))]);
    let options = fixture.options();
    let receipt = launch(options, &mut fixture.platform).unwrap();
    assert_eq!(
        fixture.platform.spawns,
        [bus_command(&fixture.state, &fixture.platform.executable).unwrap()]
    );
    assert_eq!(fixture.platform.spawns[0][1], "serve-local");
    let saved: ProcessReceipt =
        serde_json::from_reader(File::open(fixture.state.join("local-bus-process.json")).unwrap())
            .unwrap();
    assert_eq!(saved.runtime, "rust");
    assert_eq!(saved.pid, 888);
    assert_eq!(saved.command, fixture.platform.spawns[0]);
    assert_eq!(receipt["bus"]["action"], "started");
    assert_eq!(receipt["connection_verified"], false);
}

#[test]
fn repeated_healthy_launch_reuses_server_with_exact_pid_proof() {
    let mut fixture = Fixture::new();
    fixture.live(777);
    fixture.platform.statuses =
        VecDeque::from([Ok(Some(fixture.status(777))), Ok(Some(fixture.status(777)))]);
    let options = fixture.options();
    let first = launch(options.clone(), &mut fixture.platform).unwrap();
    let second = launch(options, &mut fixture.platform).unwrap();
    assert!(fixture.platform.spawns.is_empty());
    assert_eq!(first["bundle_id"], second["bundle_id"]);
    assert_eq!(first["bus"]["action"], "reused");
    assert_eq!(fixture.platform.opens.len(), 2);
    assert!(
        !fixture.platform.opens[0]
            .iter()
            .any(|argument| argument == "-n")
    );
}

#[test]
fn unhealthy_contradictory_or_other_ledger_status_never_starts_or_opens() {
    for (field, value) in [
        ("mode", json!("other-service")),
        ("signed", json!(true)),
        ("agent_wake", json!(true)),
        ("live_fleet", json!(true)),
        ("storage_healthy", json!(false)),
        ("data_dir", json!("/other/ledger")),
        ("pid", json!(0)),
        ("transport", json!("quic-live")),
    ] {
        let mut fixture = Fixture::new();
        fixture.live(777);
        let mut status = fixture.status(777);
        status[field] = value;
        fixture.platform.statuses.push_back(Ok(Some(status)));
        let options = fixture.options();
        assert!(launch(options, &mut fixture.platform).is_err(), "{field}");
        assert!(fixture.platform.spawns.is_empty());
        assert!(fixture.platform.opens.is_empty());
    }
}

#[test]
fn mode_label_without_identity_and_wrong_process_command_are_rejected() {
    for wrong_command in [false, true] {
        let mut fixture = Fixture::new();
        fixture.live(777);
        let mut status = fixture.status(777);
        if wrong_command {
            fixture
                .platform
                .commands
                .insert(777, "python3 unrelated-service".into());
        } else {
            status.as_object_mut().unwrap().remove("data_dir");
        }
        fixture.platform.statuses.push_back(Ok(Some(status)));
        let options = fixture.options();
        assert!(launch(options, &mut fixture.platform).is_err());
        assert!(fixture.platform.spawns.is_empty());
        assert!(fixture.platform.opens.is_empty());
    }
}

#[test]
fn running_original_without_listener_never_gets_a_duplicate() {
    let mut fixture = Fixture::new();
    fixture.live(777);
    atomic_json(
        &fixture.state.join("local-bus-process.json"),
        &fixture.receipt(777),
    )
    .unwrap();
    let options = fixture.options();
    let error = launch(options, &mut fixture.platform)
        .unwrap_err()
        .to_string();
    assert!(error.contains("retained without duplicate"));
    assert!(fixture.platform.spawns.is_empty());
}

#[test]
fn python_original_receipt_requires_root_migration_instead_of_adoption() {
    let mut fixture = Fixture::new();
    atomic_json(
        &fixture.state.join("local-bus-process.json"),
        &json!({"pid":777,"url":LOCAL_URL,"command":["python3","local_bus.py"]}),
    )
    .unwrap();
    let options = fixture.options();
    let error = launch(options, &mut fixture.platform)
        .unwrap_err()
        .to_string();
    assert!(error.contains("root owns migration"));
    assert!(fixture.platform.spawns.is_empty());
}

#[test]
fn readiness_timeout_retains_receipt_and_retry_cannot_duplicate_original() {
    let mut fixture = Fixture::new();
    let options = fixture.options();
    assert!(
        launch(options.clone(), &mut fixture.platform)
            .unwrap_err()
            .to_string()
            .contains("retained")
    );
    assert_eq!(fixture.platform.spawns.len(), 1);
    assert_eq!(fixture.platform.pauses, 30);
    assert!(fixture.state.join("local-bus-process.json").is_file());
    assert!(
        launch(options, &mut fixture.platform)
            .unwrap_err()
            .to_string()
            .contains("retained without duplicate")
    );
    assert_eq!(fixture.platform.spawns.len(), 1);
    assert!(fixture.platform.opens.is_empty());
}

#[test]
fn uncertain_probe_or_child_exit_does_not_retry_or_activate_application() {
    let mut fixture = Fixture::new();
    fixture
        .platform
        .statuses
        .push_back(unavailable("HTTP403; unknown port owner"));
    let options = fixture.options();
    assert!(launch(options, &mut fixture.platform).is_err());
    assert!(fixture.platform.spawns.is_empty());
    fixture.platform.exit_code = Some(3);
    let options = fixture.options();
    assert!(
        launch(options, &mut fixture.platform)
            .unwrap_err()
            .to_string()
            .contains("exited 3")
    );
    assert_eq!(fixture.platform.spawns.len(), 1);
    assert!(fixture.platform.opens.is_empty());
}

#[test]
fn lock_excludes_competing_state_directory_and_releases_on_error() {
    let mut fixture = Fixture::new();
    let guard = lock_launcher(&fixture.platform.executable).unwrap();
    let options = fixture.options();
    assert!(
        launch(options.clone(), &mut fixture.platform)
            .unwrap_err()
            .to_string()
            .contains("another alpha launcher")
    );
    assert!(fixture.platform.spawns.is_empty());
    drop(guard);
    fixture
        .platform
        .statuses
        .push_back(unavailable("stop before any spawn"));
    assert!(launch(options, &mut fixture.platform).is_err());
    assert!(lock_launcher(&fixture.platform.executable).is_ok());
}

#[test]
fn native_bundle_id_starts_each_hash_component_with_letter_and_preserves_user_data() {
    let mut fixture = Fixture::new();
    fs::create_dir_all(fixture.state.join("local-bus")).unwrap();
    let ledger = fixture.state.join("local-bus/messages.jsonl");
    let drafts = fixture.state.join("human-drafts.json");
    fs::write(&ledger, b"existing ledger bytes\n").unwrap();
    fs::write(&drafts, b"existing human draft bytes").unwrap();
    let mut options = fixture.options();
    options.bus_url = Some("http://localhost:44341".into());
    let status = fixture.status(777);
    fixture.platform.statuses.push_back(Ok(Some(status)));
    let receipt = launch(options, &mut fixture.platform).unwrap();
    let bundled = PathBuf::from(receipt["binary"].as_str().unwrap());
    assert_eq!(
        fs::read(&bundled).unwrap(),
        fs::read(&fixture.desktop).unwrap()
    );
    assert_ne!(bundled, fixture.desktop);
    assert!(bundled.metadata().unwrap().permissions().mode() & 0o111 != 0);
    let bundle_id = receipt["bundle_id"].as_str().unwrap();
    assert!(
        bundle_id
            .split('.')
            .all(|component| component.starts_with(|c: char| c.is_ascii_alphabetic()))
    );
    assert!(bundle_id.starts_with("com.emunlabs.chinwag.alpha.a"));
    assert_eq!(fs::read(ledger).unwrap(), b"existing ledger bytes\n");
    assert_eq!(fs::read(drafts).unwrap(), b"existing human draft bytes");
    assert_eq!(
        fixture.platform.opens[0],
        [
            "--env",
            "CHINWAG_BUS_URL=http://localhost:44341",
            "--env",
            &format!(
                "CHINWAG_ALPHA_DRAFTS_PATH={}",
                fixture.state.join("human-drafts.json").display()
            ),
            receipt["app"].as_str().unwrap(),
        ]
    );
    assert!(fixture.platform.spawns.is_empty());
    assert_eq!(receipt["fleet_delivery_verified"], false);
}

#[test]
fn separate_state_bundles_have_distinct_stable_ids() {
    let fixture = Fixture::new();
    let (_, _, first) = package_app(&fixture.state, &fixture.desktop, false).unwrap();
    let (_, _, repeated) = package_app(&fixture.state, &fixture.desktop, false).unwrap();
    let (_, _, second) = package_app(&fixture.state.join("qa"), &fixture.desktop, false).unwrap();
    assert_eq!(first, repeated);
    assert_ne!(first, second);
}

#[test]
fn failed_open_does_not_create_successful_launch_receipt() {
    let mut fixture = Fixture::new();
    fixture.platform.fail_open = true;
    let mut options = fixture.options();
    options.bus_url = Some("http://localhost:44341".into());
    let status = fixture.status(777);
    fixture.platform.statuses.push_back(Ok(Some(status)));
    assert!(launch(options, &mut fixture.platform).is_err());
    assert!(!fixture.state.join("latest-launch.json").exists());
}

#[test]
fn bounded_artifacts_reject_symlinks_and_unknown_runtime_receipts() {
    let fixture = Fixture::new();
    let link = fixture.state.join("desktop-link");
    std::os::unix::fs::symlink(&fixture.desktop, &link).unwrap();
    assert!(open_regular(&link, MAX_DESKTOP).is_err());
    let oversized = fixture.state.join("oversized.json");
    fs::write(&oversized, vec![b' '; MAX_RECEIPT as usize + 1]).unwrap();
    assert!(open_regular(&oversized, MAX_RECEIPT).is_err());
}

#[test]
fn actual_refused_ephemeral_loopback_is_absence_without_starting_any_service() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let fixture = Fixture::new();
    let mut system = System {
        executable: fixture.platform.executable,
        child: None,
        forward_child: None,
    };
    assert!(
        system
            .status(&format!("http://{address}"))
            .unwrap()
            .is_none()
    );
}

impl Fixture {
    fn studio_options(&self) -> Options {
        Options {
            bus_url: Some(forward::URL.into()),
            cursor_onboarding: true,
            studio_forward: true,
            ..self.options()
        }
    }

    fn ready_studio(&mut self) {
        self.platform.forward_ports = VecDeque::from([Ok(true), Ok(false), Ok(false)]);
        self.platform.statuses.push_back(Ok(Some(shared_status())));
    }
}

fn shared_status() -> Value {
    json!({"ok":true,"mode":"fleet-ledger-read-only","transport":"local-ledger-read-only",
        "read_only":true,"send_allowed":false,"storage_healthy":true,"agent_wake":false})
}

#[test]
fn onboarding_and_forward_flags_are_explicit_fixed_and_normalized() {
    let fixture = Fixture::new();
    for args in [
        vec!["--onboarding", "cursor"],
        vec!["--studio-forward"],
        vec!["--bus-url", forward::URL, "--onboarding", "other"],
        vec![
            "--bus-url",
            forward::URL,
            "--studio-forward",
            "--studio-forward",
        ],
        vec![
            "--bus-url",
            forward::URL,
            "--onboarding",
            "cursor",
            "--onboarding",
            "cursor",
        ],
        vec!["--bus-url", "http://127.0.0.1:44346", "--studio-forward"],
        vec!["--bus-url", "http://[::1]:44345", "--studio-forward"],
        vec!["--bus-url", forward::URL, "--ssh-host", "other"],
    ] {
        assert!(
            Options::parse(
                &args.into_iter().map(str::to_owned).collect::<Vec<_>>(),
                &fixture.platform.executable
            )
            .is_err()
        );
    }
    let args = [
        "--studio-forward",
        "--bus-url",
        "http://localhost:44345/",
        "--onboarding",
        "cursor",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let parsed = Options::parse(&args, &fixture.platform.executable).unwrap();
    assert_eq!(parsed.bus_url.as_deref(), Some(forward::URL));
    assert!(parsed.cursor_onboarding && parsed.studio_forward);
}

#[test]
fn external_bus_must_pass_health_before_packaging_or_activation() {
    for response in [
        Ok(None),
        unavailable("injected HTTP403"),
        Ok(Some(json!({"ok":true}))),
        Ok(Some(
            json!({"ok":true,"mode":LOCAL_MODE,"storage_healthy":false}),
        )),
    ] {
        let mut fixture = Fixture::new();
        let mut options = fixture.options();
        options.bus_url = Some("http://127.0.0.1:44341".into());
        fixture.platform.statuses.push_back(response);
        assert!(launch(options, &mut fixture.platform).is_err());
        assert!(fixture.platform.opens.is_empty());
        assert!(fixture.platform.forward_spawns.is_empty());
        assert!(!fixture.state.join("latest-launch.json").exists());
        assert!(!fixture.state.join("Chinwag Alpha.app").exists());
    }
}

#[test]
fn focused_launch_uses_separate_bundle_and_explicit_env_without_claiming_connection() {
    let mut fixture = Fixture::new();
    let (_, _, ordinary) = package_app(&fixture.state, &fixture.desktop, false).unwrap();
    let mut options = fixture.options();
    options.cursor_onboarding = true;
    options.bus_url = Some(forward::URL.into());
    fixture
        .platform
        .statuses
        .push_back(Ok(Some(shared_status())));
    let receipt = launch(options, &mut fixture.platform).unwrap();
    assert_ne!(receipt["bundle_id"], ordinary);
    assert!(
        receipt["app"]
            .as_str()
            .unwrap()
            .ends_with("Chinwag Cursor Setup.app")
    );
    assert!(fixture.state.join("Chinwag Alpha.app").is_dir());
    let plist = fs::read_to_string(
        fixture
            .state
            .join("Chinwag Cursor Setup.app/Contents/Info.plist"),
    )
    .unwrap();
    assert!(plist.contains("<key>CFBundleDisplayName</key><string>Chinwag Cursor Setup</string>"));
    assert!(
        fixture.platform.opens[0]
            .iter()
            .any(|arg| arg == "CHINWAG_ALPHA_ONBOARDING=cursor")
    );
    assert!(!fixture.platform.opens[0].iter().any(|arg| arg == "-n"));
    assert!(
        fixture.platform.forward_spawns.is_empty(),
        "external URL alone never authorizes SSH"
    );
    assert_eq!(receipt["endpoint_preflight"]["http_status_checked"], true);
    assert_eq!(receipt["connection_verified"], false);
    assert_eq!(receipt["endpoint_preflight"]["client_connected"], false);
}

#[test]
fn owned_forward_starts_once_reuses_and_preserves_absent_original_history() {
    let mut fixture = Fixture::new();
    fixture.ready_studio();
    let options = fixture.studio_options();
    let first = launch(options.clone(), &mut fixture.platform).unwrap();
    assert_eq!(first["studio_forward"]["action"], "started");
    assert_eq!(fixture.platform.forward_spawns, vec![forward::command()]);
    assert!(fixture.platform.spawns.is_empty());
    assert!(
        fixture.platform.opens[0]
            .iter()
            .any(|arg| arg == "CHINWAG_ALPHA_TARGET_HOST=Studio")
    );
    fixture.platform.forward_ports = VecDeque::from([Ok(false), Ok(false)]);
    fixture
        .platform
        .statuses
        .push_back(Ok(Some(shared_status())));
    let reused = launch(options.clone(), &mut fixture.platform).unwrap();
    assert_eq!(reused["studio_forward"]["action"], "reused");
    assert_eq!(fixture.platform.forward_spawns.len(), 1);
    fixture.platform.forward_processes.remove(&999);
    fixture.ready_studio();
    launch(options, &mut fixture.platform).unwrap();
    let history: Value = serde_json::from_slice(
        &fs::read(fixture.state.join("studio-forward-process.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(history["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(history["attempts"][0]["pid"], 999);
    assert_eq!(history["attempts"][1]["phase"], "identified");
    assert_eq!(fixture.platform.forward_spawns.len(), 2);
}

#[test]
fn active_unready_changed_pid_proof_and_busy_unowned_port_never_duplicate() {
    for mutation in 0..3 {
        let mut fixture = Fixture::new();
        fixture.ready_studio();
        let options = fixture.studio_options();
        launch(options.clone(), &mut fixture.platform).unwrap();
        match mutation {
            0 => fixture.platform.forward_ports = VecDeque::from([Ok(true)]),
            1 => {
                fixture
                    .platform
                    .forward_processes
                    .get_mut(&999)
                    .unwrap()
                    .command = "unrelated process".into()
            }
            _ => {
                fixture
                    .platform
                    .forward_processes
                    .get_mut(&999)
                    .unwrap()
                    .started = "different process birth".into()
            }
        }
        assert!(launch(options, &mut fixture.platform).is_err());
        assert_eq!(fixture.platform.forward_spawns.len(), 1);
        assert_eq!(fixture.platform.opens.len(), 1);
    }
    let mut fixture = Fixture::new();
    fixture.platform.forward_ports = VecDeque::from([Ok(false), Ok(false)]);
    let options = fixture.studio_options();
    assert!(
        launch(options, &mut fixture.platform)
            .unwrap_err()
            .to_string()
            .contains("occupied")
    );
    assert!(fixture.platform.forward_spawns.is_empty());
    assert!(!fixture.state.join("studio-forward-process.json").exists());
}

#[test]
fn uncertain_spawn_and_unready_health_retain_original_without_replay() {
    let mut fixture = Fixture::new();
    fixture.platform.fail_forward_spawn = true;
    let options = fixture.studio_options();
    assert!(launch(options.clone(), &mut fixture.platform).is_err());
    assert!(launch(options, &mut fixture.platform).is_err());
    assert_eq!(fixture.platform.forward_spawns.len(), 1);
    assert!(fixture.platform.opens.is_empty());
    let mut fixture = Fixture::new();
    fixture.platform.forward_ports = VecDeque::from([Ok(true), Ok(false), Ok(false)]);
    fixture.platform.statuses.push_back(Ok(None));
    let options = fixture.studio_options();
    assert!(launch(options.clone(), &mut fixture.platform).is_err());
    assert_eq!(fixture.platform.forward_spawns.len(), 1);
    assert!(fixture.platform.opens.is_empty());
    fixture.platform.forward_ports = VecDeque::from([Ok(false), Ok(false)]);
    fixture
        .platform
        .statuses
        .push_back(Ok(Some(shared_status())));
    let receipt = launch(options, &mut fixture.platform).unwrap();
    assert_eq!(receipt["studio_forward"]["action"], "reused");
    assert_eq!(fixture.platform.forward_spawns.len(), 1);
}

#[test]
fn forward_child_exit_or_bind_timeout_never_opens_or_restarts_it() {
    for exited in [true, false] {
        let mut fixture = Fixture::new();
        if exited {
            fixture.platform.forward_exit = Some(255);
        }
        let options = fixture.studio_options();
        assert!(launch(options, &mut fixture.platform).is_err());
        assert_eq!(fixture.platform.forward_spawns.len(), 1);
        assert!(fixture.platform.opens.is_empty());
        assert_eq!(fixture.platform.pauses, if exited { 0 } else { 60 });
        assert!(fixture.state.join("studio-forward-process.json").is_file());
    }
}

#[test]
fn malformed_symlink_and_fifo_forward_receipts_refuse_before_spawn() {
    for kind in 0..3 {
        let mut fixture = Fixture::new();
        let path = fixture.state.join("studio-forward-process.json");
        match kind {
            0 => {
                fs::write(&path, b"{partial").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            1 => {
                let preserved = fixture.state.join("preserved");
                fs::write(&preserved, b"preserve").unwrap();
                std::os::unix::fs::symlink(preserved, &path).unwrap();
            }
            _ => {
                let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
        }
        let options = fixture.studio_options();
        assert!(launch(options, &mut fixture.platform).is_err());
        assert!(fixture.platform.forward_spawns.is_empty());
        assert!(fixture.platform.opens.is_empty());
    }
}

#[test]
fn lost_owned_forward_during_health_check_cannot_open_or_restart() {
    let mut fixture = Fixture::new();
    fixture.ready_studio();
    fixture.platform.lose_forward_during_status = true;
    let options = fixture.studio_options();
    assert!(launch(options, &mut fixture.platform).is_err());
    assert_eq!(fixture.platform.forward_spawns.len(), 1);
    assert!(fixture.platform.opens.is_empty());
    assert!(!fixture.state.join("latest-launch.json").exists());
}

#[test]
fn matching_ssh_pid_does_not_adopt_a_foreign_local_listener() {
    let mut fixture = Fixture::new();
    fixture.ready_studio();
    fixture.platform.foreign_listener_after_spawn = true;
    let options = fixture.studio_options();
    assert!(launch(options, &mut fixture.platform).is_err());
    assert_eq!(fixture.platform.forward_spawns.len(), 1);
    assert!(fixture.platform.opens.is_empty());
    let mut fixture = Fixture::new();
    fixture.ready_studio();
    let options = fixture.studio_options();
    launch(options.clone(), &mut fixture.platform).unwrap();
    fixture.platform.forward_listeners.clear();
    fixture.platform.forward_ports = VecDeque::from([Ok(false)]);
    assert!(launch(options, &mut fixture.platform).is_err());
    assert_eq!(fixture.platform.forward_spawns.len(), 1);
    assert_eq!(fixture.platform.opens.len(), 1);
}

#[test]
fn listener_proof_requires_the_exact_owned_pid_and_loopback_route() {
    assert!(forward::parse_listener_proof("p999\nn127.0.0.1:44345\n", 999).unwrap());
    assert!(!forward::parse_listener_proof("", 999).unwrap());
    for bad in [
        "p998\nn127.0.0.1:44345\n",
        "n127.0.0.1:44345\np999\n",
        "p999\nn*:44345\n",
        "p999\nn127.0.0.1:44346\n",
        "p999\np999\nn127.0.0.1:44345\n",
    ] {
        assert!(forward::parse_listener_proof(bad, 999).is_err());
    }
}
