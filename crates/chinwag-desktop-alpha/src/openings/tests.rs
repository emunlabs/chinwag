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
        .prepare("http://127.0.0.1:44341", &"a".repeat(64))
        .unwrap();
    let value: Value = serde_json::from_slice(&fs::read(directory.file()).unwrap()).unwrap();
    assert_eq!(value["attempts"][0]["id"], attempt.id);
    assert_eq!(value["attempts"][0]["state"], "pending");
    drop(store);
    let mut store = OpeningStore::open(directory.file()).unwrap();
    assert_eq!(store.attempts, vec![attempt.clone()]);
    assert!(
        store
            .prepare(&attempt.endpoint, &attempt.installation_id)
            .is_err()
    );
    assert!(store.prepare(&attempt.endpoint, &"b".repeat(64)).is_ok());
    assert!(
        store
            .prepare("http://127.0.0.1:44342", &attempt.installation_id)
            .is_err(),
        "host-qualified IDs must remain blocked across endpoint aliases"
    );
}

#[test]
fn malformed_or_foreign_receipt_cannot_claim_opened_or_unblock_an_attempt() {
    let directory = Directory::new();
    let mut store = OpeningStore::open(directory.file()).unwrap();
    let attempt = store
        .prepare("http://127.0.0.1:44341", &"a".repeat(64))
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
        .prepare("http://127.0.0.1:44341", &"a".repeat(64))
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
            .prepare("http://127.0.0.1:44341", &"a".repeat(64))
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
