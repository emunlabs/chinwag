use super::*;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "chinwag-outbox-tests-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("drafts.json.outbox.json")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn request(body: &str) -> SendRequest {
    SendRequest {
        sender: "Brian".into(),
        room: "#mgmt".into(),
        body: body.into(),
        to: None,
        task_id: None,
    }
}
fn receipt(request: &SendRequest) -> SendReceipt {
    serde_json::from_value(json!({
        "message":{"id":"native-fixture-17","seq":17,"ts_iso":"2026-10-30T12:00:00Z","room":request.room,
            "sender":request.sender,"body":request.body.trim(),"to":request.to,"task_id":request.task_id,"sig_verified":true},
        "ack":{"ok":true,"seq":17,"message_id":"native-fixture-17","room":request.room,
            "transport":"local-crdb+jsonl (daemon starting)","sig_verified":true,"subscribers_notified":0}
    })).unwrap()
}

#[test]
fn pending_attempt_survives_restart_and_blocks_only_original_payload() {
    let directory = Directory::new();
    let body = "  original message\n";
    let original = request(body);
    let mut outbox = Outbox::open(directory.file()).unwrap();
    let attempt = outbox
        .prepare("http://127.0.0.1:44341", original.clone())
        .unwrap();
    assert!(
        fs::read_to_string(directory.file())
            .unwrap()
            .contains(&attempt.id)
    );
    drop(outbox);
    let mut reopened = Outbox::open(directory.file()).unwrap();
    assert_eq!(reopened.attempts[0].request.body, body);
    assert_eq!(reopened.attempts[0].state, AttemptState::Pending);
    assert!(
        reopened
            .prepare(&attempt.endpoint, original.clone())
            .is_err()
    );
    reopened
        .update(
            &attempt.id,
            AttemptState::Uncertain("lost HTTP response".into()),
        )
        .unwrap();
    assert!(reopened.prepare(&attempt.endpoint, original).is_err());
    assert!(
        reopened
            .prepare(&attempt.endpoint, request("original message"))
            .is_err()
    );
    let unrelated = reopened
        .prepare(&attempt.endpoint, request("an unrelated draft"))
        .unwrap();
    assert_ne!(unrelated.id, attempt.id);
}

#[test]
fn late_pending_check_cannot_downgrade_an_already_received_receipt() {
    let directory = Directory::new();
    let mut outbox = Outbox::open(directory.file()).unwrap();
    let attempt = outbox
        .prepare("http://127.0.0.1:44341", request("original"))
        .unwrap();
    let actual = receipt(&attempt.request);
    outbox
        .update(
            &attempt.id,
            AttemptState::Delivered(Box::new(actual.clone())),
        )
        .unwrap();
    let state = outbox
        .apply_status(
            &attempt.id,
            SendOperation {
                request_id: attempt.id.clone(),
                state: OperationState::Pending,
            },
        )
        .unwrap();
    assert_eq!(state, AttemptState::Delivered(Box::new(actual)));
    assert!(!outbox.attempts[0].unresolved());
}

#[test]
fn delivery_status_restores_exact_receipt_without_changing_draft_file() {
    let directory = Directory::new();
    let drafts = directory.0.join("drafts.json");
    fs::write(&drafts, b"{\"#mgmt\":\"  original  \"}").unwrap();
    let mut outbox = Outbox::open(path_for_drafts(&drafts).unwrap()).unwrap();
    let attempt = outbox
        .prepare("http://127.0.0.1:44341", request("  original  "))
        .unwrap();
    let actual = receipt(&attempt.request);
    assert_eq!(
        outbox
            .apply_status(
                &attempt.id,
                SendOperation {
                    request_id: attempt.id.clone(),
                    state: OperationState::Delivered(Box::new(actual.clone()))
                }
            )
            .unwrap(),
        AttemptState::Delivered(Box::new(actual.clone()))
    );
    drop(outbox);
    let reopened = Outbox::open(directory.file()).unwrap();
    assert_eq!(
        reopened.attempts[0].state,
        AttemptState::Delivered(Box::new(actual))
    );
    assert_eq!(fs::read(&drafts).unwrap(), b"{\"#mgmt\":\"  original  \"}");
}

#[test]
fn mismatched_status_id_or_payload_never_clears_original_attempt() {
    let directory = Directory::new();
    let mut outbox = Outbox::open(directory.file()).unwrap();
    let attempt = outbox
        .prepare("http://127.0.0.1:44341", request("original"))
        .unwrap();
    assert!(
        outbox
            .apply_status(
                &attempt.id,
                SendOperation {
                    request_id: "different-request-123".into(),
                    state: OperationState::Pending
                }
            )
            .is_err()
    );
    let wrong = receipt(&request("different text"));
    assert!(
        outbox
            .apply_status(
                &attempt.id,
                SendOperation {
                    request_id: attempt.id.clone(),
                    state: OperationState::Delivered(Box::new(wrong))
                }
            )
            .is_err()
    );
    assert_eq!(outbox.attempts[0].state, AttemptState::Pending);
    drop(outbox);
    assert_eq!(
        Outbox::open(directory.file()).unwrap().attempts[0].state,
        AttemptState::Pending
    );
}

#[test]
fn active_second_window_is_rejected_and_crash_style_drop_releases_lock() {
    let directory = Directory::new();
    let outbox = Outbox::open(directory.file()).unwrap();
    assert!(Outbox::open(directory.file()).is_err());
    drop(outbox);
    assert!(Outbox::open(directory.file()).is_ok());
}

#[test]
fn invalid_or_unwritable_record_prevents_new_attempt_without_replacing_file() {
    let directory = Directory::new();
    fs::write(directory.file(), b"not json").unwrap();
    assert!(Outbox::open(directory.file()).is_err());
    assert_eq!(fs::read(directory.file()).unwrap(), b"not json");
    fs::remove_file(directory.file()).unwrap();
    let mut outbox = Outbox::open(directory.file()).unwrap();
    fs::create_dir(directory.file()).unwrap();
    assert!(
        outbox
            .prepare("http://127.0.0.1:44341", request("unsent"))
            .is_err()
    );
    assert!(outbox.attempts.is_empty());
}

#[test]
fn symlink_and_oversized_or_invalid_attempts_are_rejected() {
    use std::os::unix::fs::symlink;
    let directory = Directory::new();
    let target = directory.0.join("elsewhere.json");
    fs::write(&target, b"{}").unwrap();
    symlink(&target, directory.file()).unwrap();
    assert!(Outbox::open(directory.file()).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"{}");
    fs::remove_file(directory.file()).unwrap();
    let mut outbox = Outbox::open(directory.file()).unwrap();
    assert!(
        outbox
            .prepare("http://127.0.0.1:44341", request(&"x".repeat(16001)))
            .is_err()
    );
    assert!(outbox.attempts.is_empty());
}

#[test]
fn native_signed_local_receipt_remains_visible_after_restart_and_journal_check() {
    let directory = Directory::new();
    let mut outbox = Outbox::open(directory.file()).unwrap();
    let attempt = outbox
        .prepare(
            "http://127.0.0.1:44341",
            request("fixture human native post"),
        )
        .unwrap();
    let mut actual = receipt(&attempt.request);
    actual.message.id = "bus-1793361786-8ea53586".into();
    actual.message.seq = 839;
    actual.ack.message_id = actual.message.id.clone();
    actual.ack.seq = 839;
    outbox
        .update(
            &attempt.id,
            AttemptState::Delivered(Box::new(actual.clone())),
        )
        .unwrap();
    assert!(
        !outbox.attempts[0].unresolved(),
        "the actual publication receipt is known"
    );
    assert!(
        outbox.attempts[0].visible_in_send_history(),
        "native storage does not prove Grok Bot receipt"
    );
    let label = receipt_summary(&actual.ack.transport, Some(actual.ack.subscribers_notified));
    assert!(label.contains("Stored in native bus; Grok Bot receipt unconfirmed"));
    assert!(label.contains("local-crdb+jsonl (daemon starting)"));
    assert!(label.contains("native subscribers notified: 0"));
    drop(outbox);
    let mut reopened = Outbox::open(directory.file()).unwrap();
    let before = fs::read(directory.file()).unwrap();
    reopened
        .apply_status(
            &attempt.id,
            SendOperation {
                request_id: attempt.id.clone(),
                state: OperationState::Delivered(Box::new(actual.clone())),
            },
        )
        .unwrap();
    assert_eq!(fs::read(directory.file()).unwrap(), before);
    assert_eq!(reopened.attempts.len(), 1);
    assert_eq!(reopened.attempts[0].id, attempt.id);
    assert_eq!(reopened.attempts[0].receipt(), Some(&actual));
    assert!(
        reopened.attempts[0].visible_in_send_history(),
        "GET of the same backend receipt is not Grok confirmation"
    );
}

#[test]
fn isolated_alpha_receipt_can_complete_local_storage_without_grok_attention() {
    let directory = Directory::new();
    let mut outbox = Outbox::open(directory.file()).unwrap();
    let attempt = outbox
        .prepare("http://127.0.0.1:44339", request("isolated fixture"))
        .unwrap();
    let mut actual = receipt(&attempt.request);
    actual.ack.transport = "local-jsonl-alpha (unsigned, isolated)".into();
    actual.ack.sig_verified = false;
    actual.message.sig_verified = false;
    outbox
        .update(
            &attempt.id,
            AttemptState::Delivered(Box::new(actual.clone())),
        )
        .unwrap();
    assert!(!outbox.attempts[0].visible_in_send_history());
    let label = receipt_summary(&actual.ack.transport, Some(0));
    assert!(label.contains("Stored in isolated alpha; fleet delivery disabled"));
    assert!(!label.contains("Grok Bot receipt unconfirmed"));
}
