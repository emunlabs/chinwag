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
            },
        }
    }

    fn options(&self) -> Options {
        Options {
            state: self.state.clone(),
            desktop: self.desktop.clone(),
            bus_url: None,
        }
    }

    fn status(&self, pid: u32) -> Value {
        json!({
            "ok": true, "mode": LOCAL_MODE, "transport": LOCAL_TRANSPORT,
            "live_fleet": false, "signed": false, "agent_wake": false,
            "storage_healthy": true, "data_dir":self.state.join("local-bus"), "pid":pid
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
    let (_, _, first) = package_app(&fixture.state, &fixture.desktop).unwrap();
    let (_, _, repeated) = package_app(&fixture.state, &fixture.desktop).unwrap();
    let (_, _, second) = package_app(&fixture.state.join("qa"), &fixture.desktop).unwrap();
    assert_eq!(first, repeated);
    assert_ne!(first, second);
}

#[test]
fn failed_open_does_not_create_successful_launch_receipt() {
    let mut fixture = Fixture::new();
    fixture.platform.fail_open = true;
    let mut options = fixture.options();
    options.bus_url = Some("http://localhost:44341".into());
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
    };
    assert!(
        system
            .status(&format!("http://{address}"))
            .unwrap()
            .is_none()
    );
}
