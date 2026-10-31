use super::*;
use crate::StartupRecord;
use std::path::Path;

fn id(n: u32) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn saved(text: &str) -> SavedOperation {
    SavedOperation {
        schema: "chinwag-gemini-operation/v1".into(),
        id: id(1),
        kind: ActionKind::Prompt,
        text: text.into(),
        session_epoch: id(2),
        session_id: Some(id(3)),
        prompt_rpc_id: format!("prompt-{}", id(1)),
        prompt_generation: 4,
        startup: None,
    }
}
fn event(value: Value) -> crate::Result<Event> {
    parse(&serde_json::to_vec(&value).unwrap())
}

#[test]
fn fixed_bootstrap_is_acp_without_grants_or_authentication_requests() {
    let init: Value = serde_json::from_slice(&initialize("init-1").unwrap()).unwrap();
    assert_eq!(
        init,
        json!({"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{
            "protocolVersion":1,"clientCapabilities":{},"clientInfo":{"name":"chinwag-gemini-control","version":"1"}
        }})
    );
    let new: Value =
        serde_json::from_slice(&create_session("session-1", Path::new("/owner/work")).unwrap())
            .unwrap();
    assert_eq!(
        new,
        json!({"jsonrpc":"2.0","id":"session-1","method":"session/new","params":{"cwd":"/owner/work","mcpServers":[]}})
    );
    assert!(create_session("session-1", Path::new("relative/work")).is_err());
}

#[test]
fn strict_version_protocol_and_default_mode_are_compatibility_checks() {
    let valid = json!({"protocolVersion":1,"agentInfo":{"name":"gemini-cli","version":"0.66.0"}});
    initialization(&valid).unwrap();
    for changed in [
        json!({"protocolVersion":2,"agentInfo":{"name":"gemini-cli","version":"0.66.0"}}),
        json!({"protocolVersion":1,"agentInfo":{"name":"other","version":"0.66.0"}}),
        json!({"protocolVersion":1,"agentInfo":{"name":"gemini-cli","version":"0.65.0"}}),
    ] {
        assert!(initialization(&changed).is_err());
    }
    assert_eq!(
        new_session(&json!({"sessionId":id(3),"modes":{"currentModeId":"default"}})).unwrap(),
        id(3)
    );
    for mode in [json!("autoEdit"), json!(null), json!("yolo")] {
        assert_eq!(
            new_session(&json!({"sessionId":id(3),"modes":{"currentModeId":mode}})),
            Err(GeminiError::OwnerInterventionRequired)
        );
    }
    assert!(
        new_session(&json!({"sessionId":"foreign/unbounded","modes":{"currentModeId":"default"}}))
            .is_err()
    );
}

#[test]
fn literal_prompt_is_one_text_block_and_native_command_prefixes_are_rejected() {
    let literal = "Explain literal prose with @example and embedded /path or $value";
    let bytes = prompt(&saved(literal), &id(3)).unwrap();
    assert!(bytes.ends_with(b"\n"));
    let frame: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        frame,
        json!({"jsonrpc":"2.0","id":format!("prompt-{}",id(1)),"method":"session/prompt","params":{
            "sessionId":id(3),"prompt":[{"type":"text","text":literal}]
        }})
    );
    for text in [
        "/help",
        "  $command",
        "\n\t/quit",
        "\u{feff}/command",
        " \u{feff} $tool",
        "",
        "  ",
        "bad\0text",
    ] {
        assert!(
            prompt(&saved(text), &id(3)).is_err(),
            "reject {text:?} before wire"
        );
    }
    assert!(prompt(&saved(&"a".repeat(crate::MAX_TEXT_BYTES + 1)), &id(3)).is_err());
    assert!(
        prompt(&saved("ordinary text"), &id(7)).is_err(),
        "session cannot be substituted"
    );
    let mut start = saved("Start configured work");
    start.kind = ActionKind::Start;
    start.session_id = None;
    start.startup = Some(StartupRecord {
        binary: "/owner/bin/gemini".into(),
        sha256: "a".repeat(64),
        workdir: "/owner/work".into(),
        policy: "configured_runtime_effects_manual_mode_extensions_disabled".into(),
    });
    assert!(prompt(&start, &id(3)).is_ok());
}

#[test]
fn cancel_is_a_notification_and_permission_reply_can_only_cancel() {
    let frame: Value = serde_json::from_slice(&cancel(&id(3)).unwrap()).unwrap();
    assert_eq!(
        frame,
        json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":id(3)}})
    );
    assert!(frame.get("id").is_none(), "no invented cancellation ACK ID");
    for request_id in [RpcId::String("permission-1".into()), RpcId::Number(7)] {
        let reply: Value =
            serde_json::from_slice(&permission_cancel(&request_id).unwrap()).unwrap();
        assert_eq!(
            reply,
            json!({"jsonrpc":"2.0","id":request_id.value(),"result":{"outcome":{"outcome":"cancelled"}}})
        );
    }
    assert!(cancel("wrong-session").is_err());
}

#[test]
fn all_five_terminal_reasons_remain_distinct() {
    for (wire, expected) in [
        ("end_turn", StopReason::EndTurn),
        ("max_tokens", StopReason::MaxTokens),
        ("max_turn_requests", StopReason::MaxTurnRequests),
        ("refusal", StopReason::Refusal),
        ("cancelled", StopReason::Cancelled),
    ] {
        assert_eq!(terminal(&json!({"stopReason":wire})).unwrap(), expected);
    }
    for value in [
        json!({}),
        json!({"stopReason":"accepted"}),
        json!({"stopReason":true}),
    ] {
        assert!(terminal(&value).is_err());
    }
}

#[test]
fn session_only_output_is_not_an_input_echo_or_model_receipt() {
    let output = json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":id(3),"update":{
        "sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"some output\u{0000}\nkept"}
    }}});
    assert!(
        matches!(event(output).unwrap(),Event::Update{session,update:Update::Text(text)} if session==id(3)&&text=="some output\nkept")
    );
    let echo = json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":id(3),"update":{
        "sessionUpdate":"user_message_chunk","content":{"type":"text","text":"not a correlated echo"}
    }}});
    assert!(matches!(
        event(echo).unwrap(),
        Event::Update {
            update: Update::Other,
            ..
        }
    ));
    let mode = json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":id(3),"update":{"sessionUpdate":"current_mode_update","currentModeId":"autoEdit"}}});
    assert!(
        matches!(event(mode).unwrap(),Event::Update{update:Update::Mode(mode),..} if mode=="autoEdit")
    );
}

#[test]
fn malformed_and_ambiguous_correlation_frames_are_not_accepted() {
    for bytes in [
        br#"{"jsonrpc":"2.0","id":"a","id":"b","result":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":"a","result":{"stopReason":"end_turn","stopReason":"cancelled"}}"#.as_slice(),
        br#"{"id":"a","result":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":"a","result":{},"error":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"bad","update":{}}}"#.as_slice(),
    ] { assert!(parse(bytes).is_err()); }
    assert!(parse(&vec![b' '; MAX_FRAME + 1]).is_err());
    assert!(matches!(
        event(json!({"jsonrpc":"2.0","id":"a","error":{"code":-32000,"message":"failure"}}))
            .unwrap(),
        Event::Response { error: true, .. }
    ));
}

#[test]
fn permission_and_unsupported_owner_requests_never_become_approval() {
    let permission = json!({"jsonrpc":"2.0","id":9,"method":"session/request_permission","params":{
        "sessionId":id(3),"toolCall":{},"options":[{"optionId":"allow-once","name":"Allow once","kind":"allow_once"}]
    }});
    assert!(
        matches!(event(permission).unwrap(),Event::Permission{id:RpcId::Number(9),session} if session==id(3))
    );
    assert!(matches!(event(json!({"jsonrpc":"2.0","id":"fs-1","method":"fs/read_text_file","params":{"path":"/private/not-read"}})).unwrap(),Event::OwnerRequest));
    assert!(event(json!({"jsonrpc":"2.0","id":9,"method":"session/request_permission","params":{"sessionId":id(3),"toolCall":{},"options":"bad"}})).is_err());
}
