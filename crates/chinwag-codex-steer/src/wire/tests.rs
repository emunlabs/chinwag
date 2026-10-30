use super::*;
use serde_json::json;
fn saved() -> SavedSteer {
    SavedSteer {
        schema: crate::record::OPERATION_SCHEMA.into(),
        id: "steer-human-0001".into(),
        transport_epoch: "a".repeat(32),
        thread_id: "thread-1".into(),
        expected_turn_id: "turn-1".into(),
        text: "Human says \"change this\"\nthen continue".into(),
    }
}
#[test]
fn fixed_wire_is_one_escaped_text_frame_without_rpc_passthrough() {
    let record = saved();
    let bytes = steer_frame("rpc-owned-1", &record).unwrap();
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value,
        json!({"id":"rpc-owned-1","method":"turn/steer","params":{"threadId":"thread-1","expectedTurnId":"turn-1","clientUserMessageId":"steer-human-0001","input":[{"type":"text","text":record.text,"text_elements":[]}]}})
    );
    for key in [
        "jsonrpc",
        "trace",
        "responsesapiClientMetadata",
        "additionalContext",
        "permission",
        "turn/start",
    ] {
        assert!(!String::from_utf8_lossy(&bytes).contains(key));
    }
}
#[test]
fn full_started_and_omitted_items_view_project_no_invented_turn_kind() {
    for view in [Some("full"), None] {
        let mut value = json!({"method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-1","rootTurnId":null,"items":[],"status":"inProgress","error":null,"startedAt":17,"completedAt":null,"durationMs":null}}});
        if let Some(view) = view {
            value["params"]["turn"]["itemsView"] = json!(view);
        }
        assert!(
            matches!(parse(&serde_json::to_vec(&value).unwrap()).unwrap(),Incoming::Started{thread_id,turn_id} if thread_id=="thread-1" && turn_id=="turn-1")
        );
    }
}
#[test]
fn ambiguous_or_duplicate_correlation_fields_are_not_accepted() {
    for bytes in [
        br#"{"id":"x","id":"y","result":{"turnId":"turn-1"}}"#.as_slice(),
        br#"{"id":"x","result":{"turnId":"turn-1","turnId":"turn-2"}}"#,
        br#"{"id":"x","result":{"turnId":"turn-1"},"error":{"code":-32603,"message":"private"}}"#,
        br#"{"id":"x","method":"turn/steer","result":{"turnId":"turn-1"}}"#,
        br#"{"method":"turn/started","params":{"threadId":"thread-1","threadId":"thread-2","turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
    ] {assert!(parse(bytes).is_err());}
    assert!(matches!(
        parse(br#"{"id":123,"result":{"turnId":"turn-1"}}"#).unwrap(),
        Incoming::Success {
            id: WireId::Integer(123),
            ..
        }
    ));
}
#[test]
fn recorded_projection_keeps_only_exact_one_text_client_correlation() {
    let value = json!({"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","item":{"type":"userMessage","id":"item-1","clientId":"steer-human-0001","content":[{"type":"text","text":"human input","text_elements":[]}]},"completedAtMs":17}});
    assert!(
        matches!(parse(&serde_json::to_vec(&value).unwrap()).unwrap(),Incoming::Recorded{client_id,text,..} if client_id=="steer-human-0001" && text=="human input")
    );
    let mut wrong = value;
    wrong["params"]["item"]["content"][0]["type"] = json!("image");
    assert!(matches!(
        parse(&serde_json::to_vec(&wrong).unwrap()).unwrap(),
        Incoming::Other
    ));
}
#[test]
fn oversized_frames_and_unknown_server_requests_cannot_become_acceptance() {
    assert!(parse(&vec![b' '; MAX_FRAME_BYTES + 1]).is_err());
    assert!(matches!(parse(br#"{"id":"approval-1","method":"item/commandExecution/requestApproval","params":{"private":"do not retain"}}"#).unwrap(),Incoming::ServerRequest));
    assert!(matches!(
        parse(br#"{"method":"turn/plan/updated","params":{"private":"do not retain"}}"#).unwrap(),
        Incoming::Other
    ));
}

#[test]
fn fixed_initial_lane_is_distinct_from_steer_and_excludes_overrides() {
    let bytes = initial_frame(
        "initial-rpc",
        "thread-new",
        "initial-human-work1",
        "Initial human text",
    )
    .unwrap();
    let value = unique_value(&bytes).unwrap();
    assert_eq!(
        value,
        json!({"id":"initial-rpc","method":"turn/start","params":{"threadId":"thread-new","clientUserMessageId":"initial-human-work1","input":[{"type":"text","text":"Initial human text","text_elements":[]}]}})
    );
    assert!(matches!(parse(br#"{"id":"initial-rpc","result":{"turn":{"id":"turn-new","status":"inProgress","items":[]}}}"#).unwrap(),Incoming::InitialSuccess{..}));
    assert!(matches!(
        parse(br#"{"id":"steer-rpc","result":{"turnId":"turn-new"}}"#).unwrap(),
        Incoming::Success { .. }
    ));
}
