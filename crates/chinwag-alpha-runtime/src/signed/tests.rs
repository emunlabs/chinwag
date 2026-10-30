use super::*;
use std::sync::{Arc, OnceLock};
use tempfile::TempDir;

struct CompiledMock {
    _directory: TempDir,
    executable: PathBuf,
}

fn mock_binary() -> &'static PathBuf {
    static MOCK: OnceLock<CompiledMock> = OnceLock::new();
    &MOCK.get_or_init(|| {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("mock.rs");
        let executable = directory.path().join("mock-signed-cli");
        fs::write(&source, r#"
use std::{env, fs, io::Write, thread, time::Duration};
fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    fs::write(".fake-arguments", format!("{arguments:?}")).unwrap();
    fs::write(".fake-bus-address-removed", env::var_os("CHINWAG_BUS_ADDR").is_none().to_string()).unwrap();
    let mut calls = fs::OpenOptions::new().create(true).append(true).open(".fake-calls").unwrap();
    writeln!(calls, "called").unwrap();
    let mode = fs::read_to_string(".fake-mode").unwrap();
    match mode.as_str() {
        "timeout" => thread::sleep(Duration::from_secs(30)),
        "gated" => while !std::path::Path::new(".fake-release").exists() { thread::sleep(Duration::from_millis(5)); },
        "flood_stdout" => { let _ = std::io::stdout().write_all(&vec![b'x'; 32768]); thread::sleep(Duration::from_secs(30)); },
        "flood_stderr" => { let _ = std::io::stderr().write_all(&vec![b'x'; 32768]); thread::sleep(Duration::from_secs(30)); },
        "fail" => { eprintln!("FAKE_PRIVATE_OUTPUT_MUST_NOT_LEAK"); std::process::exit(7); },
        _ => {}
    }
    std::io::stdout().write_all(&fs::read(".fake-response").unwrap()).unwrap();
}
"#).unwrap();
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let output = Command::new(rustc).arg("--edition=2024").arg(&source).arg("-o").arg(&executable).output().unwrap();
        assert!(output.status.success(), "mock Rust compiler failed: {}", String::from_utf8_lossy(&output.stderr));
        CompiledMock { _directory: directory, executable }
    }).executable
}

struct Fixture {
    _directory: TempDir,
    cli: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    fn new(mode: &str, request: &SendRequest) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let cli = directory.path().join("fake-rust-chinwag");
        let repo = directory.path().join("repository with spaces");
        fs::create_dir(&repo).unwrap();
        fs::copy(mock_binary(), &cli).unwrap();
        fs::write(repo.join(".fake-mode"), mode).unwrap();
        fs::write(repo.join(".fake-response"), receipt_json(request, false)).unwrap();
        Self {
            _directory: directory,
            cli,
            repo,
        }
    }

    fn sender(&self) -> CliSignedSender {
        CliSignedSender::new(self.cli.clone(), self.repo.clone()).unwrap()
    }

    fn count(&self) -> usize {
        fs::read_to_string(self.repo.join(".fake-calls"))
            .unwrap_or_default()
            .lines()
            .count()
    }
}

fn request() -> SendRequest {
    SendRequest {
        sender: "Brian".into(),
        room: "#alpha".into(),
        body: "  hello $world `uname` \"quoted\"\nsecond line  ".into(),
        to: Some("Nic".into()),
        task_id: Some("TASK-ALPHA".into()),
    }
}

fn receipt_json(request: &SendRequest, verified: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "ok": true,
        "message": {
            "id": "bus-fixture", "seq": 42, "ts_iso": "2026-10-30T12:00:00Z",
            "room": request.room, "sender": "Brian", "body": request.body.trim(),
            "to": request.to, "task_id": request.task_id, "sig_verified": verified
        },
        "ack": {
            "ok": true, "seq": 42, "message_id": "bus-fixture",
            "transport": "local-crdb+jsonl (daemon starting)",
            "room": request.room, "sig_verified": verified, "subscribers_notified": 0
        }
    }))
    .unwrap()
}

#[test]
fn construction_and_rejected_identity_do_not_invoke_cli() {
    let request = request();
    let fixture = Fixture::new("ok", &request);
    let sender = fixture.sender();
    assert_eq!(fixture.count(), 0);
    for identity in ["CODEX", "Nic", "brian", "Brian --wake"] {
        let mut invalid = request.clone();
        invalid.sender = identity.into();
        assert!(matches!(
            sender.send(&invalid),
            Err(RuntimeError::Rejected(_))
        ));
    }
    assert_eq!(fixture.count(), 0);
}

#[test]
fn exact_arguments_use_no_shell_or_wake_and_keep_real_receipt_outcome() {
    let request = request();
    let fixture = Fixture::new("ok", &request);
    let sender = fixture.sender();
    let receipt = sender.send(&request).unwrap();
    assert_eq!(receipt.message.body, request.body.trim());
    assert_eq!(receipt.message.sender, "Brian");
    assert_eq!(receipt.ack.seq, 42);
    assert_eq!(receipt.ack.transport, "local-crdb+jsonl (daemon starting)");
    assert!(!receipt.message.sig_verified);
    assert!(!receipt.ack.sig_verified);
    assert_eq!(fixture.count(), 1);
    let canonical_repo = fs::canonicalize(&fixture.repo).unwrap();
    let expected = vec![
        "bus",
        "send",
        "--repo",
        canonical_repo.to_str().unwrap(),
        "--from",
        "Brian",
        "--room",
        "#alpha",
        "--json",
        "--message",
        &request.body,
        "--to",
        "Nic",
        "--task",
        "TASK-ALPHA",
    ];
    assert_eq!(
        fs::read_to_string(fixture.repo.join(".fake-arguments")).unwrap(),
        format!("{expected:?}")
    );
    assert_eq!(
        fs::read_to_string(fixture.repo.join(".fake-bus-address-removed")).unwrap(),
        "true"
    );
    assert!(
        sender
            .command(&request)
            .get_envs()
            .any(|(key, value)| key == "CHINWAG_BUS_ADDR" && value.is_none())
    );
}

#[test]
fn verified_signature_flags_are_preserved_without_manufacturing_them() {
    let request = request();
    let fixture = Fixture::new("ok", &request);
    fs::write(
        fixture.repo.join(".fake-response"),
        receipt_json(&request, true),
    )
    .unwrap();
    let receipt = fixture.sender().send(&request).unwrap();
    assert!(receipt.message.sig_verified && receipt.ack.sig_verified);
}

#[test]
fn malformed_and_mismatched_receipts_are_uncertain_without_automatic_retry() {
    let request = request();
    for field in [
        "json",
        "sender",
        "room",
        "body",
        "id",
        "seq",
        "ack",
        "signature",
        "to",
    ] {
        let fixture = Fixture::new("ok", &request);
        let mut value: serde_json::Value =
            serde_json::from_slice(&receipt_json(&request, false)).unwrap();
        match field {
            "sender" => value["message"]["sender"] = "CODEX".into(),
            "room" => value["message"]["room"] = "#eng".into(),
            "body" => value["message"]["body"] = "different".into(),
            "id" => value["message"]["id"] = "other-id".into(),
            "seq" => value["message"]["seq"] = 0.into(),
            "ack" => value["ack"]["ok"] = false.into(),
            "signature" => value["ack"]["sig_verified"] = true.into(),
            "to" => value["message"]["to"] = "different recipient".into(),
            _ => {}
        }
        fs::write(
            fixture.repo.join(".fake-response"),
            if field == "json" {
                b"{not complete".to_vec()
            } else {
                serde_json::to_vec(&value).unwrap()
            },
        )
        .unwrap();
        let sender = fixture.sender();
        assert!(
            matches!(sender.send(&request), Err(RuntimeError::SendUncertain(_))),
            "{field}"
        );
        assert_eq!(fixture.count(), 1, "{field} must not automatically retry");

        let mut next = request.clone();
        next.body = "a distinct explicit human message".into();
        fs::write(
            fixture.repo.join(".fake-response"),
            receipt_json(&next, false),
        )
        .unwrap();
        assert!(
            sender.send(&next).is_ok(),
            "{field} must not freeze another message"
        );
        assert_eq!(fixture.count(), 2);
    }
}

#[test]
fn timeout_and_output_bounds_are_finite_without_poisoning_unrelated_send() {
    let request = request();
    for mode in ["timeout", "flood_stdout", "flood_stderr", "fail"] {
        let fixture = Fixture::new(mode, &request);
        let mut sender = fixture.sender();
        sender.timeout = Duration::from_millis(500);
        sender.max_stdout = 1024;
        sender.max_stderr = 1024;
        let started = Instant::now();
        let error = sender.send(&request).unwrap_err();
        assert!(matches!(error, RuntimeError::SendUncertain(_)), "{mode}");
        assert!(
            !error
                .to_string()
                .contains("FAKE_PRIVATE_OUTPUT_MUST_NOT_LEAK")
        );
        assert!(started.elapsed() < Duration::from_secs(3), "{mode}");
        // A deadline may expire before the OS schedules the mock's first
        // instruction. Either zero or one logged invocation is valid; a retry
        // would be a second invocation.
        let initial_calls = fixture.count();
        assert!(initial_calls <= 1, "{mode} must not automatically retry");

        let mut next = request.clone();
        next.body = "a distinct explicit human message after bounded cleanup".into();
        fs::write(fixture.repo.join(".fake-mode"), "ok").unwrap();
        fs::write(
            fixture.repo.join(".fake-response"),
            receipt_json(&next, false),
        )
        .unwrap();
        sender.timeout = CHILD_TIMEOUT;
        assert!(
            sender.send(&next).is_ok(),
            "{mode} must not freeze another message"
        );
        assert_eq!(fixture.count(), initial_calls + 1);
    }
}

#[test]
fn concurrent_request_cannot_spawn_an_additional_signed_child() {
    let request = request();
    let fixture = Fixture::new("gated", &request);
    let sender = Arc::new(fixture.sender());
    let first = {
        let sender = sender.clone();
        let request = request.clone();
        thread::spawn(move || sender.send(&request))
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while fixture.count() == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        fixture.count(),
        1,
        "mock must signal startup before contention is checked"
    );
    assert!(matches!(
        sender.send(&request),
        Err(RuntimeError::Unavailable(_))
    ));
    fs::write(fixture.repo.join(".fake-release"), b"release").unwrap();
    assert!(first.join().unwrap().is_ok());
    assert_eq!(fixture.count(), 1);
}

#[test]
fn unsafe_request_fields_are_rejected_before_process_start() {
    let request = request();
    let fixture = Fixture::new("ok", &request);
    let sender = fixture.sender();
    let mut bad = request.clone();
    bad.room = "#elsewhere".into();
    assert!(matches!(sender.send(&bad), Err(RuntimeError::Rejected(_))));
    bad = request.clone();
    bad.body = "x".repeat(MAX_BODY + 1);
    assert!(matches!(sender.send(&bad), Err(RuntimeError::Rejected(_))));
    bad = request.clone();
    bad.body = "NUL\0body".into();
    assert!(matches!(sender.send(&bad), Err(RuntimeError::Rejected(_))));
    bad = request.clone();
    bad.to = Some("invalid\nrecipient".into());
    assert!(matches!(sender.send(&bad), Err(RuntimeError::Rejected(_))));
    assert_eq!(fixture.count(), 0);
}
