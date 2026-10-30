use chinwag_bus_client::{BusAck, BusMessage, SendReceipt};
use chinwag_bus_model::{Conversation, MAX_HISTORY, SendState};

fn message(room: &str, seq: u64, body: &str) -> BusMessage {
    BusMessage {
        id: format!("message-{seq}"),
        seq,
        ts_iso: "2026-10-30T12:00:00Z".to_owned(),
        room: room.to_owned(),
        sender: "CODEX".to_owned(),
        body: body.to_owned(),
        to: None,
        task_id: None,
        sig_verified: false,
    }
}

fn receipt(room: &str, seq: u64, body: &str) -> SendReceipt {
    let message = message(room, seq, body);
    let ack = BusAck {
        ok: true,
        seq,
        message_id: message.id.clone(),
        transport: "local-fallback".to_owned(),
        room: room.to_owned(),
        sig_verified: false,
        subscribers_notified: 0,
    };
    SendReceipt { message, ack }
}

#[test]
fn switched_room_drops_late_history_even_after_switching_back() {
    let mut conversation = Conversation::new("#mgmt");
    let old_generation = conversation.load_generation();
    let eng_generation = conversation.select_room("#eng");
    assert!(conversation.apply_messages(eng_generation, vec![message("#eng", 2, "eng")]));
    assert!(!conversation.apply_messages(old_generation, vec![message("#mgmt", 1, "old")]));
    assert_eq!(conversation.messages[0].body, "eng");

    let current_generation = conversation.select_room("#mgmt");
    assert!(conversation.messages.is_empty());
    assert!(!conversation.apply_messages(old_generation, vec![message("#mgmt", 1, "old")]));
    assert!(conversation.apply_messages(current_generation, vec![message("#mgmt", 3, "current")]));
    assert_eq!(conversation.messages[0].body, "current");
}

#[test]
fn rejects_a_mixed_room_page_without_inserting_any_of_it() {
    let mut conversation = Conversation::new("#mgmt");
    let generation = conversation.load_generation();
    assert!(conversation.apply_messages(generation, vec![message("#mgmt", 1, "existing")]));
    assert!(!conversation.apply_messages(
        generation,
        vec![message("#mgmt", 2, "new"), message("#eng", 3, "wrong")]
    ));
    assert_eq!(conversation.messages.len(), 1);
    assert_eq!(conversation.messages[0].body, "existing");
    assert!(conversation.last_error.is_some());
}

#[test]
fn history_is_deduplicated_ordered_and_bounded_to_recent_messages() {
    let mut conversation = Conversation::new("#mgmt");
    let generation = conversation.load_generation();
    let page = (0..MAX_HISTORY as u64 + 10)
        .rev()
        .map(|seq| message("#mgmt", seq, "history"))
        .collect();
    assert!(conversation.apply_messages(generation, page));
    assert_eq!(conversation.messages.len(), MAX_HISTORY);
    assert_eq!(conversation.messages[0].seq, 10);
    assert_eq!(conversation.messages.last().unwrap().seq, 509);
    assert!(conversation.apply_messages(generation, vec![message("#mgmt", 509, "updated")]));
    assert_eq!(conversation.messages.len(), MAX_HISTORY);
    assert_eq!(conversation.messages.last().unwrap().body, "updated");
    assert!(
        conversation
            .messages
            .windows(2)
            .all(|pair| pair[0].seq < pair[1].seq)
    );
}

#[test]
fn empty_or_concurrent_send_is_rejected_without_losing_pending_text() {
    let mut conversation = Conversation::new("#mgmt");
    assert!(conversation.begin_send(" \n\t").is_err());
    assert_eq!(conversation.send_state, SendState::Idle);
    let generation = conversation.begin_send("  keep spacing\n").unwrap();
    assert!(conversation.begin_send("duplicate").is_err());
    assert_eq!(
        conversation.send_state,
        SendState::Sending {
            body: "  keep spacing\n".to_owned()
        }
    );
    assert!(conversation.confirm_send(generation, receipt("#mgmt", 1, "  keep spacing\n")));
}

#[test]
fn trimmed_bus_echo_confirms_delivery_while_failure_retains_original_draft() {
    let draft = "  preserve this draft\n";
    let mut conversation = Conversation::new("#mgmt");
    let generation = conversation.begin_send(draft).unwrap();
    assert!(conversation.confirm_send(generation, receipt("#mgmt", 1, "preserve this draft")));
    assert!(matches!(
        conversation.send_state,
        SendState::Delivered { .. }
    ));
    assert_eq!(conversation.messages[0].body, "preserve this draft");

    let generation = conversation.begin_send(draft).unwrap();
    assert!(!conversation.confirm_send(generation, receipt("#mgmt", 2, "different text")));
    let SendState::Uncertain { body, .. } = &conversation.send_state else {
        panic!("a mismatched echo must remain uncertain")
    };
    assert_eq!(body, draft);
    assert_eq!(conversation.messages.len(), 1);
}

#[test]
fn uncertain_send_keeps_draft_and_requires_an_explicit_new_send() {
    let mut conversation = Conversation::new("#mgmt");
    let generation = conversation.begin_send("original draft").unwrap();
    conversation.fail_send(generation, "response timed out".to_owned());
    let uncertain = SendState::Uncertain {
        body: "original draft".to_owned(),
        error: "response timed out".to_owned(),
    };
    assert_eq!(conversation.send_state, uncertain);
    assert!(conversation.messages.is_empty());
    assert!(conversation.apply_messages(conversation.load_generation(), Vec::new()));
    assert_eq!(conversation.send_state, uncertain);
    assert!(!conversation.confirm_send(generation, receipt("#mgmt", 1, "original draft")));
    assert_eq!(conversation.send_state, uncertain);
    let new_generation = conversation.begin_send("edited by user").unwrap();
    assert_ne!(generation, new_generation);
    conversation.fail_send(generation, "old error".to_owned());
    assert_eq!(
        conversation.send_state,
        SendState::Sending {
            body: "edited by user".to_owned()
        }
    );
}

#[test]
fn room_change_retains_uncertain_text_and_rejects_old_send_completion() {
    let mut conversation = Conversation::new("#mgmt");
    let generation = conversation.begin_send("for management").unwrap();
    conversation.select_room("#eng");
    let SendState::Uncertain { body, error } = &conversation.send_state else {
        panic!("send must remain uncertain")
    };
    assert_eq!(body, "for management");
    assert!(error.contains("#mgmt"));
    assert!(!conversation.confirm_send(generation, receipt("#mgmt", 1, "for management")));
    conversation.fail_send(generation, "late failure".to_owned());
    assert!(conversation.messages.is_empty());
    assert!(matches!(
        conversation.send_state,
        SendState::Uncertain { .. }
    ));
}

#[test]
fn delivery_records_actual_transport_and_requires_both_signature_claims() {
    for (message_verified, ack_verified) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let mut conversation = Conversation::new("#mgmt");
        let generation = conversation.begin_send("body").unwrap();
        let mut delivered = receipt("#mgmt", 4, "body");
        delivered.message.sig_verified = message_verified;
        delivered.ack.sig_verified = ack_verified;
        assert!(conversation.confirm_send(generation, delivered));
        assert_eq!(
            conversation.send_state,
            SendState::Delivered {
                id: "message-4".to_owned(),
                seq: 4,
                transport: "local-fallback".to_owned(),
                sig_verified: message_verified && ack_verified
            }
        );
        assert_eq!(conversation.messages.len(), 1);
    }
}

#[test]
fn mismatched_receipts_never_declare_delivery() {
    for invalid_field in [
        "ok",
        "message-room",
        "ack-room",
        "id",
        "seq",
        "body",
        "transport",
    ] {
        let mut conversation = Conversation::new("#mgmt");
        let generation = conversation.begin_send("body").unwrap();
        let mut invalid = receipt("#mgmt", 4, "body");
        match invalid_field {
            "ok" => invalid.ack.ok = false,
            "message-room" => invalid.message.room = "#eng".to_owned(),
            "ack-room" => invalid.ack.room = "#eng".to_owned(),
            "id" => invalid.ack.message_id = "unrelated".to_owned(),
            "seq" => invalid.ack.seq = 9,
            "body" => invalid.message.body = "different text".to_owned(),
            "transport" => invalid.ack.transport.clear(),
            _ => unreachable!(),
        }
        assert!(
            !conversation.confirm_send(generation, invalid),
            "{invalid_field}"
        );
        assert!(
            matches!(conversation.send_state, SendState::Uncertain { .. }),
            "{invalid_field}"
        );
        assert!(conversation.messages.is_empty());
    }
}

#[test]
fn late_history_does_not_erase_a_send_receipt_and_duplicates_reconcile() {
    let mut conversation = Conversation::new("#mgmt");
    let generation = conversation.begin_send("new message").unwrap();
    assert!(conversation.confirm_send(generation, receipt("#mgmt", 3, "new message")));
    let load = conversation.load_generation();
    assert!(conversation.apply_messages(load, vec![message("#mgmt", 2, "older")]));
    assert_eq!(
        conversation
            .messages
            .iter()
            .map(|message| message.seq)
            .collect::<Vec<_>>(),
        [2, 3]
    );
    assert!(conversation.apply_messages(load, vec![message("#mgmt", 3, "new message")]));
    assert_eq!(conversation.messages.len(), 2);
    assert!(matches!(
        conversation.send_state,
        SendState::Delivered { .. }
    ));
}

#[test]
fn refreshing_same_room_invalidates_history_but_keeps_pending_send() {
    let mut conversation = Conversation::new("#mgmt");
    let stale_load = conversation.load_generation();
    let send = conversation.begin_send("body").unwrap();
    let current_load = conversation.select_room("#mgmt");
    assert_ne!(stale_load, current_load);
    assert!(!conversation.apply_messages(stale_load, Vec::new()));
    assert!(conversation.confirm_send(send, receipt("#mgmt", 1, "body")));
}
