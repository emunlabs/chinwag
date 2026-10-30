use super::*;
use crate::{ActionKind, InputTiming, StartupRecord};
use std::path::PathBuf;

const ID: &str = "11111111-1111-4111-8111-111111111111";
const OTHER: &str = "22222222-2222-4222-8222-222222222222";
const SESSION: &str = "33333333-3333-4333-8333-333333333333";

fn saved() -> SavedInput {
    SavedInput {
        schema: "chinwag-claude-input/v1".into(),
        id: ID.into(),
        session_epoch: "44444444-4444-4444-8444-444444444444".into(),
        session_id: SESSION.into(),
        kind: ActionKind::Start,
        timing: InputTiming::Now,
        text: "Literal /compact @not-a-file\nsecond line".into(),
        startup: Some(StartupRecord {
            binary: PathBuf::from("/fixture/claude"),
            sha256: "a".repeat(64),
            workdir: PathBuf::from("/fixture/work"),
            policy: "managed_policy_prose_only".into(),
        }),
    }
}

fn frame(v: Value) -> crate::Result<Event> {
    parse(&serde_json::to_vec(&v).unwrap())
}

#[test]
fn human_input_is_one_literal_uuid_stamped_native_frame_with_explicit_timing() {
    let start = saved();
    let encoded = input(&start).unwrap();
    assert_eq!(encoded.iter().filter(|b| **b == b'\n').count(), 1);
    let actual: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(
        actual,
        json!({
            "type":"user","uuid":ID,"session_id":SESSION,
            "message":{"role":"user","content":[{"type":"text","text":start.text}]},
            "parent_tool_use_id":null,"priority":"now","origin":{"kind":"human"},"client_composed":true
        })
    );
    for (timing, priority) in [
        (InputTiming::AfterTools, "next"),
        (InputTiming::AfterTurn, "later"),
    ] {
        let mut direction = start.clone();
        direction.kind = ActionKind::Direction;
        direction.startup = None;
        direction.timing = timing;
        assert_eq!(
            value(&input(&direction).unwrap()).unwrap()["priority"],
            priority
        );
    }
    let init = value(&initialize("fixed-initialize-request").unwrap()).unwrap();
    assert_eq!(
        init,
        json!({"type":"control_request","request_id":"fixed-initialize-request","request":{"subtype":"initialize"}})
    );
    assert!(init.get("jsonrpc").is_none());
}

#[test]
fn only_the_pinned_version_is_compatible_and_control_reply_stays_correlated() {
    assert!(compatible(Some("2.1.314")));
    for version in [
        None,
        Some("2.1.313"),
        Some("2.1.314-extra"),
        Some("0.3.314"),
    ] {
        assert!(!compatible(version));
    }
    match frame(json!({"type":"control_response","response":{"subtype":"success","request_id":"our-request","response":{"claude_code_version":"2.1.314"}}})).unwrap() {
        Event::ControlSuccess { request_id, version } => { assert_eq!(request_id,"our-request"); assert_eq!(version.as_deref(),Some("2.1.314")); },
        _ => panic!("typed control success required"),
    }
    match frame(json!({"type":"control_response","response":{"subtype":"error","request_id":"our-request","error":"PRIVATE_REMOTE_TEXT_DO_NOT_REFLECT"}})).unwrap() {
        Event::ControlError { request_id } => assert_eq!(request_id,"our-request"),
        _ => panic!("fixed error without reflected peer body"),
    }
}

#[test]
fn ambiguous_nested_json_and_frame_caps_fail_before_interpretation() {
    for bytes in [
        br#"{"type":"result","type":"assistant"}"#.as_slice(),
        br#"{"type":"control_response","response":{"request_id":"one","request_id":"two","subtype":"success"}}"#.as_slice(),
        br#"{"type":"user","message":{"role":"user","content":"a","content":"b"}}"#.as_slice(),
        br#"{"type":"system"} {"type":"system"}"#.as_slice(),
        br#"{"type":"system""#.as_slice(),
        b"[]".as_slice(), b"null".as_slice(), b"".as_slice(),
    ] { assert!(parse(bytes).is_err()); }
    assert!(parse(&vec![b' '; MAX_FRAME + 1]).is_err());
}

#[test]
fn init_requires_public_policy_fields_and_reports_mismatch_without_promoting_it() {
    let good = json!({"type":"system","subtype":"init","session_id":SESSION,"claude_code_version":"2.1.314","cwd":"/fixture/work","tools":[],"permissionMode":"default"});
    match frame(good.clone()).unwrap() {
        Event::Init {
            session,
            version,
            cwd,
            manual_empty,
        } => {
            assert_eq!(session, SESSION);
            assert_eq!(version, "2.1.314");
            assert_eq!(cwd, "/fixture/work");
            assert!(manual_empty);
        }
        _ => panic!("init observation"),
    }
    let mut enabled = good.clone();
    enabled["tools"] = json!(["Bash"]);
    assert!(matches!(
        frame(enabled).unwrap(),
        Event::Init {
            manual_empty: false,
            ..
        }
    ));
    let mut bypass = good.clone();
    bypass["permissionMode"] = json!("bypassPermissions");
    assert!(matches!(
        frame(bypass).unwrap(),
        Event::Init {
            manual_empty: false,
            ..
        }
    ));
    for key in ["cwd", "claude_code_version", "tools"] {
        let mut incomplete = good.clone();
        incomplete.as_object_mut().unwrap().remove(key);
        assert!(frame(incomplete).is_err());
    }
}

#[test]
fn replay_is_a_separate_typed_echo_and_subagent_tool_content_is_not_human_input() {
    let replay = json!({"type":"user","isReplay":true,"uuid":ID,"session_id":SESSION,"parent_tool_use_id":null,"message":{"role":"user","content":[{"type":"text","text":"Exact original human text"}]}});
    match frame(replay.clone()).unwrap() {
        Event::Replay { session, id, text } => {
            assert_eq!(session, SESSION);
            assert_eq!(id, ID);
            assert_eq!(text, "Exact original human text");
        }
        _ => panic!("replay observation only"),
    }
    let mut not_replay = replay.clone();
    not_replay["isReplay"] = json!(false);
    assert!(matches!(frame(not_replay).unwrap(), Event::Other));
    let mut nested = replay.clone();
    nested["agent_id"] = json!("subagent");
    assert!(matches!(frame(nested).unwrap(), Event::Other));
    let mut tool = replay;
    tool["message"]["content"] =
        json!([{"type":"tool_result","tool_use_id":"tool","content":"not human direction"}]);
    assert!(matches!(frame(tool).unwrap(), Event::Other));
}

#[test]
fn merged_reply_and_result_uuids_are_bounded_attribution_not_an_echo_or_new_input() {
    let reply = json!({"type":"assistant","uuid":OTHER,"session_id":SESSION,"parent_tool_use_id":null,"user_message_uuid":OTHER,"user_message_uuids":[ID,OTHER],"message":{"id":"msg-fixture","type":"message","role":"assistant","content":[{"type":"text","text":"Observed prose"}]}});
    match frame(reply.clone()).unwrap() {
        Event::Reply { session, ids, text } => {
            assert_eq!(session, SESSION);
            assert_eq!(ids, vec![ID, OTHER]);
            assert_eq!(text.as_deref(), Some("Observed prose"));
        }
        _ => panic!("reply attribution"),
    }
    let mut nested = reply.clone();
    nested["parent_tool_use_id"] = json!("parent");
    assert!(matches!(frame(nested).unwrap(), Event::Other));
    let result = json!({"type":"result","uuid":OTHER,"subtype":"success","session_id":SESSION,"user_message_uuids":[ID,OTHER],"is_error":false,"result":"Observed result"});
    match frame(result.clone()).unwrap() {
        Event::Result {
            session,
            ids,
            error,
        } => {
            assert_eq!(session, SESSION);
            assert_eq!(ids, vec![ID, OTHER]);
            assert!(!error);
        }
        _ => panic!("result attribution"),
    }
    let mut oversized = result;
    oversized["user_message_uuids"] = json!(vec![ID; 65]);
    assert!(frame(oversized).is_err());
    let mut inconsistent = reply;
    inconsistent["user_message_uuid"] = json!(SESSION);
    assert!(
        frame(inconsistent).is_err(),
        "a scalar UUID outside its explicit list is ambiguous"
    );
}

#[test]
fn malformed_activity_frames_do_not_establish_work_or_positive_evidence() {
    for malformed in [
        json!({"type":"assistant","uuid":ID,"session_id":SESSION,"user_message_uuid":ID}),
        json!({"type":"stream_event","uuid":ID,"session_id":SESSION,"user_message_uuid":ID}),
        json!({"type":"result","uuid":ID,"session_id":SESSION,"user_message_uuid":ID,"is_error":false}),
    ] {
        assert!(frame(malformed).is_err());
    }
    assert!(matches!(
        frame(
            json!({"type":"stream_event","uuid":ID,"session_id":SESSION,"event":{"type":"ping"}})
        )
        .unwrap(),
        Event::Other
    ));
    assert!(matches!(frame(json!({"type":"control_request","request_id":"owner-request","request":{"subtype":"can_use_tool","tool_name":"Bash"}})).unwrap(),Event::OwnerRequest));
}
