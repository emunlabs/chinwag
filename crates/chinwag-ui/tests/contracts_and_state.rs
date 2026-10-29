// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
use chinwag_ui::{
    contracts::{ChannelInput, ChannelResponse, SendRequest, WiretapsData},
    view_model::{ComposerState, selected_channel},
};

fn fixture() -> WiretapsData {
    serde_json::from_str(include_str!("fixtures/wiretaps.json")).expect("fixture")
}

#[test]
fn contracts_accept_unknown_fields_and_preserve_mixed_casing() {
    let data = fixture();
    let channel = selected_channel(&data, "fixture-mgmt").expect("selected");
    assert_eq!(channel.item_key, None);
    assert_eq!(
        channel.messages[1].item_key.as_deref(),
        Some("CHWG-DIOXUS-1")
    );
    assert_eq!(channel.messages[0].sender_cast, "●");
    assert_eq!(
        channel
            .messages
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert!(selected_channel(&data, "missing").is_none());
    let encoded = serde_json::to_value(&data).expect("encode");
    assert!(encoded["channels"][0].get("item_key").is_some());
    assert!(
        encoded["channels"][0]["messages"][0]
            .get("createdAt")
            .is_some()
    );
}

#[test]
fn malformed_required_fields_fail_instead_of_becoming_empty_success() {
    assert!(serde_json::from_str::<WiretapsData>("{}").is_err());
    let mut data = serde_json::to_value(fixture()).unwrap();
    data["channels"][0]["messages"][0]
        .as_object_mut()
        .unwrap()
        .remove("sender");
    assert!(serde_json::from_value::<WiretapsData>(data).is_err());
}

#[test]
fn send_response_uses_a_flat_snapshot_and_actor() {
    let data = fixture();
    let mut response = serde_json::to_value(&data).unwrap();
    let object = response.as_object_mut().unwrap();
    object.insert("actor".into(), "TEST".into());
    object.insert("ok".into(), true.into());
    object.insert("channelId".into(), "fixture-mgmt".into());
    object.insert(
        "message".into(),
        serde_json::to_value(&data.channels[0].messages[0]).unwrap(),
    );
    let response: ChannelResponse = serde_json::from_value(response).unwrap();
    assert_eq!(response.wiretaps, data);
    assert_eq!(response.actor, "TEST");
}

#[test]
fn send_lifecycle_trims_disables_duplicates_and_clears_only_on_success() {
    let mut state = ComposerState {
        draft: "  Hello\nworld  ".into(),
        ..Default::default()
    };
    assert!(state.can_send());
    let input = state.begin("fixture-mgmt").unwrap();
    assert_eq!(input.body, "Hello\nworld");
    let json = serde_json::to_value(input).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"channelId":"fixture-mgmt","body":"Hello\nworld"})
    );
    assert!(!state.can_send());
    assert!(state.begin("fixture-empty").is_err());
    state.finish(Err("Uncertain send".into()));
    assert_eq!(state.draft, "  Hello\nworld  ");
    assert!(state.can_send());
    assert_eq!(state.error.as_deref(), Some("Uncertain send"));
    state.begin("fixture-mgmt").unwrap();
    assert!(state.error.is_none());
    state.finish(Ok(()));
    assert!(state.draft.is_empty());
    assert!(!state.can_send());
}

#[test]
fn validation_matches_planner_limits_including_utf16() {
    for draft in [
        "".to_owned(),
        " \n\t ".to_owned(),
        "x".repeat(8001),
        "😀".repeat(4001),
    ] {
        let mut state = ComposerState {
            draft: draft.clone(),
            ..Default::default()
        };
        assert!(!state.can_send());
        assert!(state.begin("fixture-mgmt").is_err());
        assert_eq!(state.draft, draft);
        assert!(!state.sending);
    }
    let mut state = ComposerState {
        draft: "😀".repeat(4000),
        ..Default::default()
    };
    assert!(state.can_send());
    assert!(state.begin("fixture-mgmt").is_ok());
    state.finish(Ok(()));
    state.draft = "ok".into();
    assert!(state.begin(" ").is_err());
    assert!(state.begin(&"x".repeat(81)).is_err());
}

#[test]
fn transport_validates_optional_metadata_even_when_constructed_directly() {
    let mut input = ChannelInput {
        channel_id: " test ".into(),
        body: " hi ".into(),
        sender: None,
        sender_cast: None,
        role: None,
        engine: None,
        item_key: None,
    };
    assert_eq!(input.normalized().unwrap().channel_id, "test");
    input.sender = Some("x".repeat(61));
    assert!(input.normalized().is_err());
    input.sender = None;
    input.sender_cast = Some("invalid".into());
    assert!(input.normalized().is_err());
}

#[test]
fn send_request_drops_client_supplied_actor_fields() {
    let forged: SendRequest = serde_json::from_value(serde_json::json!({
        "channelId": " test ",
        "body": " hi ",
        "sender": "BRIAN",
        "senderCast": "●",
        "role": "admin",
        "engine": "forged",
        "itemKey": "x"
    }))
    .unwrap();
    let input = forged.normalized().unwrap().into_channel_input();
    assert_eq!(
        (input.channel_id.as_str(), input.body.as_str()),
        ("test", "hi")
    );
    assert!(input.sender.is_none() && input.sender_cast.is_none());
    assert!(input.role.is_none() && input.engine.is_none() && input.item_key.is_none());
    let wire = serde_json::to_value(&input).unwrap();
    assert_eq!(wire, serde_json::json!({"channelId": "test", "body": "hi"}));
}
