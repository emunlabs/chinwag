#![cfg(target_os = "macos")]
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn actual_history_dispatch_is_bounded_approved_immutable_and_isolated() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("dataset");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let source = temp.path().join("events.jsonl");
    let manifest = temp.path().join("manifest.json");
    let event = json!({"id":"e1","chat_id":"chat-1","timestamp_utc":"2026-11-10T23:00:00Z","role":"assistant","channel":"final","text":"signed probe remains UNKNOWN","evidence":["public-receipt:1"],"supersedes":null});
    fs::write(&source, format!("{event}\n")).unwrap();
    let inspected = run(&["history", "inspect", source.to_str().unwrap()]);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let inspect: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    let hash = inspect["events"][0]["sha256"].as_str().unwrap();
    let mut m = json!({"schema":1,"dataset_id":"dataset-1","bucket":"chinwag-coordinator-history","account_id":"a9dce15ce0193da7d7f1d5dd3a53022b","coordinator_chat_id":"chat-1","approved_events":{"e1":hash}});
    let save = |m: &Value| fs::write(&manifest, m.to_string()).unwrap();
    save(&m);
    let call = || {
        run(&[
            "history",
            "ingest",
            manifest.to_str().unwrap(),
            source.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
    };
    m["bucket"] = json!("chinwag-decision-training");
    save(&m);
    assert!(!call().status.success());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    m["bucket"] = json!("chinwag-coordinator-history");
    m["coordinator_chat_id"] = json!("other-seat");
    save(&m);
    assert!(!call().status.success());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    m["coordinator_chat_id"] = json!("chat-1");
    save(&m);
    let ingest = call();
    assert!(
        ingest.status.success(),
        "{}",
        String::from_utf8_lossy(&ingest.stderr)
    );
    assert!(!call().status.success());
    let search = run(&["history", "search", root.to_str().unwrap(), "UNKNOWN", "1"]);
    assert!(
        search.status.success(),
        "{}",
        String::from_utf8_lossy(&search.stderr)
    );
    assert!(String::from_utf8_lossy(&search.stdout).contains("e1"));
    assert!(
        !run(&["history", "search", root.to_str().unwrap(), "UNKNOWN", "21"])
            .status
            .success()
    );
    let injection = run(&[
        "history",
        "search",
        root.to_str().unwrap(),
        "');ATTACH 'elsewhere';--",
        "1",
    ]);
    assert!(injection.status.success());
    assert!(!String::from_utf8_lossy(&injection.stdout).contains("e1"));
    let read = run(&["history", "read-event", root.to_str().unwrap(), "e1"]);
    assert!(read.status.success());
    assert!(String::from_utf8_lossy(&read.stdout).contains("UNKNOWN"));
    let evidence = run(&["history", "get-evidence", root.to_str().unwrap(), "e1"]);
    assert!(evidence.status.success());
    assert!(String::from_utf8_lossy(&evidence.stdout).contains("public-receipt:1"));
    for role in ["system", "developer", "tool"] {
        let mut bad = event.clone();
        bad["role"] = json!(role);
        fs::write(&source, bad.to_string()).unwrap();
        assert!(
            !run(&["history", "inspect", source.to_str().unwrap()])
                .status
                .success()
        );
    }
    let mut bad = event.clone();
    bad["channel"] = json!("analysis");
    fs::write(&source, bad.to_string()).unwrap();
    assert!(
        !run(&["history", "inspect", source.to_str().unwrap()])
            .status
            .success()
    );
    let linked = temp.path().join("linked.jsonl");
    std::os::unix::fs::symlink(&source, &linked).unwrap();
    assert!(
        !run(&["history", "inspect", linked.to_str().unwrap()])
            .status
            .success()
    );
    fs::write(&source, format!("{event}\n{event}\n")).unwrap();
    assert!(
        !run(&["history", "inspect", source.to_str().unwrap()])
            .status
            .success()
    );
    let object = fs::read_dir(root.join("objects"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().unwrap() == "parquet")
        .unwrap();
    fs::write(object, b"tampered").unwrap();
    assert!(
        !run(&["history", "read-event", root.to_str().unwrap(), "e1"])
            .status
            .success()
    );
}
