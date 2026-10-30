use super::*;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "cw-open-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("drafts.json.openings.json")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn receipt(attempt: &OpeningAttempt, state: NativeOpenState) -> NativeOpenReceipt {
    NativeOpenReceipt {
        schema: "chinwag-native-open/v1".into(),
        request_id: attempt.id.clone(),
        installation_id: attempt.installation_id.clone(),
        state,
        message: "Synthetic OS acknowledgement".into(),
    }
}

#[test]
fn pending_is_durable_before_dispatch_and_restart_never_creates_a_new_attempt() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let attempt = store
        .prepare(
            OpeningAction::OrdinaryOpen,
            "http://127.0.0.1:44341",
            &"a".repeat(64),
        )
        .unwrap();
    let value: Value = serde_json::from_slice(&fs::read(directory.file()).unwrap()).unwrap();
    assert_eq!(value["attempts"][0]["id"], attempt.id);
    assert_eq!(value["attempts"][0]["state"], "pending");
    drop(store);
    let mut store = OpeningStore::open(directory.file()).unwrap();
    assert_eq!(store.attempts, vec![attempt.clone()]);
    assert!(
        store
            .prepare(
                OpeningAction::OrdinaryOpen,
                &attempt.endpoint,
                &attempt.installation_id
            )
            .is_err()
    );
    assert!(
        store
            .prepare(
                OpeningAction::OrdinaryOpen,
                &attempt.endpoint,
                &"b".repeat(64)
            )
            .is_ok()
    );
    assert!(
        store
            .prepare(
                OpeningAction::OrdinaryOpen,
                "http://127.0.0.1:44342",
                &attempt.installation_id
            )
            .is_err(),
        "host-qualified IDs must remain blocked across endpoint aliases"
    );
}

#[test]
fn vscode_action_survives_restart_and_blocks_every_conflicting_action() {
    let directory = Directory::new();
    let endpoint = "http://127.0.0.1:44341";
    let id = "a".repeat(64);
    let attempt = {
        let mut store = OpeningStore::open(directory.file()).unwrap();
        store
            .prepare(OpeningAction::VsCodeMcpSetup, endpoint, &id)
            .unwrap()
    };
    let saved: Value = serde_json::from_slice(&fs::read(directory.file()).unwrap()).unwrap();
    assert_eq!(saved["attempts"][0]["action"], "vscode_mcp_setup");
    let mut store = OpeningStore::open(directory.file()).unwrap();
    assert_eq!(store.attempts, vec![attempt.clone()]);
    for action in [
        OpeningAction::OrdinaryOpen,
        OpeningAction::CursorMcpSetup,
        OpeningAction::VsCodeMcpSetup,
    ] {
        assert!(store.prepare(action, endpoint, &id).is_err());
        assert!(
            store
                .prepare(action, "http://127.0.0.1:44342", &id)
                .is_err()
        );
    }
    store
        .apply_receipt(
            &attempt.id,
            receipt(&attempt, NativeOpenState::OpenedOrReused),
        )
        .unwrap();
    assert!(store.has_acknowledged_vscode_setup(endpoint, &id));
    assert!(!store.has_acknowledged_vscode_setup("http://127.0.0.1:44342", &id));
    assert!(!store.has_acknowledged_vscode_setup(endpoint, &"b".repeat(64)));
    assert!(
        store
            .prepare(OpeningAction::VsCodeMcpSetup, endpoint, &id)
            .is_err()
    );
    assert!(
        store.attempts[0]
            .summary()
            .contains("inbox read are unverified")
    );
    assert!(store.confirm_cursor_tools_listed(endpoint, &id, 1).is_err());
}

fn write_full_history_fixture(path: &Path, endpoint: &str, protected: usize, pending: usize) {
    assert!(protected + pending <= MAX_ATTEMPTS);
    let rows: Vec<_> = (0..MAX_ATTEMPTS)
        .map(|index| {
            let request_id = format!("ui-history-capacity-{index:04}");
            let installation_id = format!("{index:064x}");
            let unresolved = index >= MAX_ATTEMPTS - pending;
            json!({
                "id":request_id, "endpoint":endpoint, "installation_id":installation_id,
                "action":if index < protected { "vscode_mcp_setup" } else { "ordinary_open" },
                "state":if unresolved { "pending" } else { "receipt" },
                "receipt":if unresolved { Value::Null } else { json!({
                    "schema":"chinwag-native-open/v1", "request_id":request_id,
                    "installation_id":installation_id, "state":"opened_or_reused",
                    "message":"Synthetic OS acknowledgement"
                }) }
            })
        })
        .collect();
    fs::write(
        path,
        serde_json::to_vec(&json!({
            "schema":"chinwag-opening-history/v1", "attempts":rows
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn vscode_ack_survives_capacity_eviction_and_blocks_repeat_before_dispatch() {
    let directory = Directory::new();
    let endpoint = "http://127.0.0.1:44341";
    let id = format!("{:064x}", 0);
    write_full_history_fixture(&directory.file(), endpoint, 1, 0);
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let original = store.attempts[0].clone();
    for index in 0..4 {
        let attempt = store
            .prepare(
                OpeningAction::OrdinaryOpen,
                endpoint,
                &format!("{:064x}", MAX_ATTEMPTS + index),
            )
            .unwrap();
        store
            .apply_receipt(
                &attempt.id,
                receipt(&attempt, NativeOpenState::OpenedOrReused),
            )
            .unwrap();
        assert_eq!(store.attempts.len(), MAX_ATTEMPTS);
        assert_eq!(store.attempts[0], original);
        assert!(store.has_acknowledged_vscode_setup(endpoint, &id));
    }
    assert!(
        !store
            .attempts
            .iter()
            .any(|attempt| attempt.id == "ui-history-capacity-0001"),
        "ordinary terminal rows keep their existing eviction behavior"
    );
    let saved = fs::read(directory.file()).unwrap();
    assert!(
        store
            .prepare(OpeningAction::VsCodeMcpSetup, endpoint, &id)
            .is_err(),
        "no fresh attempt is returned for a duplicate setup POST"
    );
    assert_eq!(fs::read(directory.file()).unwrap(), saved);
    drop(store);
    let store = OpeningStore::open(directory.file()).unwrap();
    assert_eq!(store.attempts[0], original);
    assert!(store.has_acknowledged_vscode_setup(endpoint, &id));
}

#[test]
fn full_protected_or_unresolved_history_refuses_capacity_without_changing_disk_or_memory() {
    for (protected, pending) in [(MAX_ATTEMPTS, 0), (64, 64), (0, MAX_ATTEMPTS)] {
        let directory = Directory::new();
        let endpoint = "http://127.0.0.1:44341";
        write_full_history_fixture(&directory.file(), endpoint, protected, pending);
        let saved = fs::read(directory.file()).unwrap();
        let mut store = OpeningStore::open(directory.file()).unwrap();
        let original = store.attempts.clone();
        assert!(
            store
                .prepare(OpeningAction::OrdinaryOpen, endpoint, &"f".repeat(64))
                .is_err()
        );
        assert_eq!(store.attempts, original);
        assert_eq!(fs::read(directory.file()).unwrap(), saved);
    }
}

#[test]
fn malformed_or_foreign_receipt_cannot_claim_opened_or_unblock_an_attempt() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let attempt = store
        .prepare(
            OpeningAction::OrdinaryOpen,
            "http://127.0.0.1:44341",
            &"a".repeat(64),
        )
        .unwrap();
    for mutation in 0..4 {
        let mut invalid = receipt(&attempt, NativeOpenState::OpenedOrReused);
        match mutation {
            0 => invalid.schema = "connected/v1".into(),
            1 => invalid.request_id = "different-valid-request-id".into(),
            2 => invalid.installation_id = "b".repeat(64),
            _ => invalid.message = "untrusted\nmessage".into(),
        }
        assert!(store.apply_receipt(&attempt.id, invalid).is_err());
        assert!(store.blocks(&attempt.endpoint, &attempt.installation_id));
        assert_eq!(store.attempts[0].state, OpeningState::Pending);
    }
}

#[test]
fn uncertain_and_pending_checks_never_downgrade_validated_opening() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let attempt = store
        .prepare(
            OpeningAction::OrdinaryOpen,
            "http://127.0.0.1:44341",
            &"a".repeat(64),
        )
        .unwrap();
    store
        .mark_uncertain(&attempt.id, "lost HTTP response")
        .unwrap();
    assert!(store.blocks(&attempt.endpoint, &attempt.installation_id));
    let actual = receipt(&attempt, NativeOpenState::OpenedOrReused);
    store.apply_receipt(&attempt.id, actual.clone()).unwrap();
    store
        .apply_receipt(&attempt.id, receipt(&attempt, NativeOpenState::Pending))
        .unwrap();
    store.mark_uncertain(&attempt.id, "late error").unwrap();
    assert_eq!(store.attempts[0].state, OpeningState::Receipt(actual));
    assert_eq!(
        store.attempts[0].summary(),
        "Opened/reused · connection setup pending"
    );
    assert!(!store.blocks(&attempt.endpoint, &attempt.installation_id));
}

#[test]
fn failed_pending_save_prevents_permission_to_dispatch() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    fs::create_dir(directory.file()).unwrap();
    assert!(
        store
            .prepare(
                OpeningAction::OrdinaryOpen,
                "http://127.0.0.1:44341",
                &"a".repeat(64)
            )
            .is_err()
    );
    assert!(store.attempts.is_empty());
}

#[test]
fn other_window_and_symlink_storage_cannot_replace_opening_history() {
    use std::os::unix::fs::symlink;
    let directory = Directory::new();
    let store = OpeningStore::open(directory.file()).unwrap();
    assert!(OpeningStore::open(directory.file()).is_err());
    drop(store);
    let preserved = directory.0.join("preserved");
    fs::write(&preserved, "preserve").unwrap();
    symlink(&preserved, directory.file()).unwrap();
    assert!(OpeningStore::open(directory.file()).is_err());
    assert_eq!(fs::read_to_string(preserved).unwrap(), "preserve");
}

#[test]
fn nonregular_opening_history_is_rejected_before_reading_bytes() {
    let directory = Directory::new();
    // Keep the fixture under macOS's small AF_UNIX SUN_LEN path limit.
    let path = directory.0.join("s");
    let _socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
    assert!(OpeningStore::open(path).is_err());
}

#[test]
fn action_is_durable_and_unknown_cursor_setup_blocks_both_actions_after_restart() {
    let directory = Directory::new();
    let endpoint = "http://127.0.0.1:44341";
    let id = "a".repeat(64);
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let attempt = store
        .prepare(OpeningAction::CursorMcpSetup, endpoint, &id)
        .unwrap();
    store.mark_uncertain(&attempt.id, "lost response").unwrap();
    drop(store);
    let mut store = OpeningStore::open(directory.file()).unwrap();
    assert_eq!(store.attempts[0].action, OpeningAction::CursorMcpSetup);
    for action in [OpeningAction::OrdinaryOpen, OpeningAction::CursorMcpSetup] {
        assert!(
            store
                .prepare(action, "http://localhost:44341", &id)
                .is_err()
        );
    }
    store
        .apply_receipt(
            &attempt.id,
            receipt(&attempt, NativeOpenState::OpenedOrReused),
        )
        .unwrap();
    assert_eq!(
        store.attempts[0].summary(),
        "Check Cursor to approve setup; connection unconfirmed."
    );
    assert!(
        store
            .prepare(OpeningAction::OrdinaryOpen, endpoint, &id)
            .is_ok()
    );
}

#[test]
fn old_rows_default_to_ordinary_open_and_unknown_actions_cannot_change_recovery_route() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    store
        .prepare(
            OpeningAction::OrdinaryOpen,
            "http://127.0.0.1:44341",
            &"a".repeat(64),
        )
        .unwrap();
    drop(store);
    let mut saved: Value = serde_json::from_slice(&fs::read(directory.file()).unwrap()).unwrap();
    saved["attempts"][0]
        .as_object_mut()
        .unwrap()
        .remove("action");
    fs::write(directory.file(), serde_json::to_vec(&saved).unwrap()).unwrap();
    let store = OpeningStore::open(directory.file()).unwrap();
    assert_eq!(store.attempts[0].action, OpeningAction::OrdinaryOpen);
    drop(store);
    for bad in [json!("post_anywhere"), Value::Null, json!("Connected")] {
        saved["attempts"][0]["action"] = bad;
        fs::write(directory.file(), serde_json::to_vec(&saved).unwrap()).unwrap();
        assert!(OpeningStore::open(directory.file()).is_err());
    }
}

fn acknowledged_setup(
    store: &mut OpeningStore,
    endpoint: &str,
    installation_id: &str,
) -> OpeningAttempt {
    let attempt = store
        .prepare(OpeningAction::CursorMcpSetup, endpoint, installation_id)
        .unwrap();
    store
        .apply_receipt(
            &attempt.id,
            receipt(&attempt, NativeOpenState::OpenedOrReused),
        )
        .unwrap();
    store.attempts.last().unwrap().clone()
}

#[test]
fn human_confirmation_is_durable_dated_and_preserves_the_original_os_receipt() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let original = acknowledged_setup(&mut store, "http://127.0.0.1:44345", &"a".repeat(64));
    let at_ms = 1_793_400_000_000;
    store
        .confirm_cursor_tools_listed(&original.endpoint, &original.installation_id, at_ms)
        .unwrap();
    let confirmed = store
        .latest_acknowledged_cursor_setup(&original.endpoint, &original.installation_id)
        .unwrap();
    assert_eq!(confirmed.id, original.id);
    assert_eq!(confirmed.state, original.state);
    assert_eq!(
        confirmed.human_confirmation,
        Some(HumanConfirmation {
            evidence: HumanConfirmationEvidence::HumanReportedEnabledWithTools,
            confirmed_at_unix_ms: at_ms,
        })
    );
    let saved = fs::read(directory.file()).unwrap();
    let json: Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(
        json["attempts"][0]["human_confirmation"],
        json!({"evidence":"human_reported_enabled_with_tools","confirmed_at_unix_ms":at_ms})
    );
    store
        .confirm_cursor_tools_listed(&original.endpoint, &original.installation_id, at_ms + 99)
        .unwrap();
    assert_eq!(fs::read(directory.file()).unwrap(), saved);
    assert!(
        store
            .apply_receipt(&original.id, receipt(&original, NativeOpenState::Rejected),)
            .is_err()
    );
    let expected = store.attempts.clone();
    drop(store);
    let reopened = OpeningStore::open(directory.file()).unwrap();
    assert_eq!(reopened.attempts, expected);
    assert!(!reopened.attempts[0].unresolved());
}

#[test]
fn repeated_human_confirmation_does_not_write_or_renew_its_timestamp() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let original = acknowledged_setup(&mut store, "http://127.0.0.1:44345", &"a".repeat(64));
    store
        .confirm_cursor_tools_listed(&original.endpoint, &original.installation_id, 1)
        .unwrap();
    fs::remove_file(directory.file()).unwrap();
    fs::create_dir(directory.file()).unwrap();
    store
        .confirm_cursor_tools_listed(&original.endpoint, &original.installation_id, 2)
        .unwrap();
    assert_eq!(
        store.attempts[0]
            .human_confirmation
            .unwrap()
            .confirmed_at_unix_ms,
        1
    );
    assert!(directory.file().is_dir());
}

#[test]
fn confirmation_requires_an_acknowledged_cursor_setup_and_exact_saved_scope() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let endpoint = "http://127.0.0.1:44345";
    let id = "a".repeat(64);
    assert!(store.confirm_cursor_tools_listed(endpoint, &id, 1).is_err());
    for (action, state) in [
        (OpeningAction::OrdinaryOpen, NativeOpenState::OpenedOrReused),
        (OpeningAction::CursorMcpSetup, NativeOpenState::Rejected),
        (OpeningAction::CursorMcpSetup, NativeOpenState::Pending),
        (OpeningAction::CursorMcpSetup, NativeOpenState::Uncertain),
    ] {
        let attempt = store
            .prepare(
                action,
                endpoint,
                &format!("{:064x}", store.attempts.len() + 1),
            )
            .unwrap();
        store
            .apply_receipt(&attempt.id, receipt(&attempt, state))
            .unwrap();
        assert!(
            store
                .confirm_cursor_tools_listed(endpoint, &attempt.installation_id, 1)
                .is_err()
        );
    }
    let original = acknowledged_setup(&mut store, endpoint, &id);
    let before = fs::read(directory.file()).unwrap();
    for (wrong_endpoint, wrong_id) in [
        ("http://localhost:44345", id.clone()),
        ("http://127.0.0.1:44346", id.clone()),
        (endpoint, "b".repeat(64)),
    ] {
        assert!(
            store
                .confirm_cursor_tools_listed(wrong_endpoint, &wrong_id, 1)
                .is_err()
        );
    }
    for bad_time in [0, MAX_CONFIRMATION_UNIX_MS + 1, u64::MAX] {
        assert!(
            store
                .confirm_cursor_tools_listed(endpoint, &id, bad_time)
                .is_err()
        );
    }
    assert_eq!(fs::read(directory.file()).unwrap(), before);
    assert!(
        store
            .latest_acknowledged_cursor_setup(endpoint, &original.installation_id)
            .unwrap()
            .human_confirmation
            .is_none()
    );
}

#[test]
fn unresolved_later_actions_cannot_confirm_an_older_setup_acknowledgement() {
    for action in [OpeningAction::OrdinaryOpen, OpeningAction::CursorMcpSetup] {
        let directory = Directory::new();
        let mut store = OpeningStore::open(directory.file()).unwrap();
        let original = acknowledged_setup(&mut store, "http://127.0.0.1:44345", &"a".repeat(64));
        store
            .prepare(action, &original.endpoint, &original.installation_id)
            .unwrap();
        let before = fs::read(directory.file()).unwrap();
        assert!(
            store
                .confirm_cursor_tools_listed(&original.endpoint, &original.installation_id, 123)
                .is_err()
        );
        assert!(store.attempts[0].human_confirmation.is_none());
        assert_eq!(fs::read(directory.file()).unwrap(), before);
    }
}

#[test]
fn latest_acknowledged_setup_searches_the_full_history_and_chooses_the_latest_exact_attempt() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let endpoint = "http://127.0.0.1:44345";
    let id = "a".repeat(64);
    let first = acknowledged_setup(&mut store, endpoint, &id);
    let latest = acknowledged_setup(&mut store, endpoint, &id);
    for index in 1..=12 {
        acknowledged_setup(&mut store, endpoint, &format!("{index:064x}"));
    }
    store
        .confirm_cursor_tools_listed(endpoint, &id, 123)
        .unwrap();
    assert!(store.attempts[0].human_confirmation.is_none());
    let selected = store
        .latest_acknowledged_cursor_setup(endpoint, &id)
        .unwrap();
    assert_eq!(selected.id, latest.id);
    assert_ne!(selected.id, first.id);
    assert_eq!(
        selected.human_confirmation.unwrap().confirmed_at_unix_ms,
        123
    );
}

#[test]
fn failed_confirmation_save_does_not_publish_human_evidence_in_memory() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let original = acknowledged_setup(&mut store, "http://127.0.0.1:44345", &"a".repeat(64));
    let saved = fs::read(directory.file()).unwrap();
    let preserved = directory.0.join("preserved.json");
    fs::rename(directory.file(), &preserved).unwrap();
    fs::create_dir(directory.file()).unwrap();
    assert!(
        store
            .confirm_cursor_tools_listed(&original.endpoint, &original.installation_id, 123)
            .is_err()
    );
    assert_eq!(store.attempts, vec![original]);
    assert_eq!(fs::read(preserved).unwrap(), saved);
}

#[test]
fn old_acknowledged_setup_rows_default_to_no_human_confirmation() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    acknowledged_setup(&mut store, "http://127.0.0.1:44345", &"a".repeat(64));
    drop(store);
    let mut saved: Value = serde_json::from_slice(&fs::read(directory.file()).unwrap()).unwrap();
    saved["attempts"][0]
        .as_object_mut()
        .unwrap()
        .remove("human_confirmation");
    fs::write(directory.file(), serde_json::to_vec(&saved).unwrap()).unwrap();
    let reopened = OpeningStore::open(directory.file()).unwrap();
    assert!(reopened.attempts[0].human_confirmation.is_none());
}

#[test]
fn invalid_or_contradictory_persisted_human_confirmation_is_rejected() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let original = acknowledged_setup(&mut store, "http://127.0.0.1:44345", &"a".repeat(64));
    store
        .confirm_cursor_tools_listed(&original.endpoint, &original.installation_id, 123)
        .unwrap();
    drop(store);
    let saved: Value = serde_json::from_slice(&fs::read(directory.file()).unwrap()).unwrap();
    for mutation in 0..11 {
        let mut bad = saved.clone();
        let row = &mut bad["attempts"][0];
        match mutation {
            0 => row["human_confirmation"]["evidence"] = json!("protocol_acknowledged"),
            1 => row["human_confirmation"]["confirmed_at_unix_ms"] = json!(0),
            2 => row["human_confirmation"]["confirmed_at_unix_ms"] = json!(u64::MAX),
            3 => row["human_confirmation"]["confirmed_at_unix_ms"] = json!("123"),
            4 => row["human_confirmation"]["connected"] = json!(true),
            5 => row["action"] = json!("ordinary_open"),
            6 => row["state"] = json!("pending"),
            7 => row["state"] = json!("uncertain"),
            8 => row["receipt"]["state"] = json!("rejected"),
            9 => row["receipt"]["request_id"] = json!("different-valid-request-id"),
            _ => row["receipt"]["installation_id"] = json!("b".repeat(64)),
        }
        fs::write(directory.file(), serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(
            OpeningStore::open(directory.file()).is_err(),
            "mutation {mutation}"
        );
    }
}
