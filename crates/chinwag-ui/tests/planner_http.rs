// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chinwag_ui::{
    contracts::{ChannelInput, ChannelResponse, SendRequest, WiretapsData},
    planner::PlannerClient,
    view_model::ComposerState,
};
use std::sync::{Arc, Mutex};

type Data = Arc<Mutex<WiretapsData>>;
async fn read(State(data): State<Data>) -> Json<WiretapsData> {
    Json(data.lock().unwrap().clone())
}
async fn send(State(data): State<Data>, Json(input): Json<ChannelInput>) -> Response {
    // These assertions verify the actual wire body and trimmed request.
    assert_eq!(input.channel_id, "fixture-mgmt");
    assert_eq!(input.body, input.body.trim());
    if input.body == "reject" {
        return (StatusCode::UNPROCESSABLE_ENTITY, "private upstream details").into_response();
    }
    if input.body == "invalid" {
        return Json(serde_json::json!({"ok":true})).into_response();
    }
    if input.body == "redirect" {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [("location", "/api/comms/wiretap")],
        )
            .into_response();
    }
    if input.body == "oversize" {
        return "x".repeat(5_000_001).into_response();
    }
    let mut data = data.lock().unwrap();
    let channel = &mut data.channels[0];
    let mut message = channel.messages[0].clone();
    message.id = "stub-sent".into();
    message.body = input.body.clone();
    channel.messages.push(message.clone());
    Json(ChannelResponse {
        actor: "TEST".into(),
        ok: input.body != "unconfirmed",
        channel_id: if input.body == "wrong" {
            "other".into()
        } else {
            input.channel_id
        },
        message,
        wiretaps: data.clone(),
    })
    .into_response()
}

#[tokio::test]
async fn real_http_roundtrip_and_failure_contracts_on_loopback_stub_only() {
    let fixture: WiretapsData =
        serde_json::from_str(include_str!("fixtures/wiretaps.json")).unwrap();
    let state: Data = Arc::new(Mutex::new(fixture.clone()));
    let app = Router::new()
        .route("/api/comms/wiretap", get(read))
        .route("/api/comms/channel", post(send))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:5598")
        .await
        .expect("scratch port 5598 must be free");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = PlannerClient::new("http://127.0.0.1:5598").unwrap();
    assert_eq!(client.wiretaps().await.unwrap(), fixture);
    let mut composer = ComposerState {
        draft: "  Local test send  ".into(),
        ..Default::default()
    };
    let result = client
        .send(composer.begin("fixture-mgmt").unwrap())
        .await
        .unwrap();
    assert_eq!(result.actor, "TEST");
    assert_eq!(result.message.body, "Local test send");
    assert_eq!(result.wiretaps.channels[0].messages.len(), 3);
    assert_eq!(client.wiretaps().await.unwrap(), result.wiretaps);
    for (body, expected) in [
        ("reject", "422"),
        ("invalid", "invalid response"),
        ("redirect", "307"),
        ("oversize", "5 MB"),
        ("unconfirmed", "did not confirm"),
        ("wrong", "did not confirm"),
    ] {
        composer.finish(Ok(()));
        composer.draft = body.into();
        let error = client
            .send(composer.begin("fixture-mgmt").unwrap())
            .await
            .unwrap_err();
        assert!(error.contains(expected), "{body}: {error}");
        assert!(!error.contains("private upstream details"));
        composer.finish(Err(error));
        assert_eq!(composer.draft, body);
        assert!(!composer.sending);
    }
    server.abort();
    let _ = server.await;
    assert!(
        client
            .wiretaps()
            .await
            .unwrap_err()
            .contains("Could not reach planner")
    );
}

#[test]
fn configuration_rejects_credentials_and_ambiguous_origins() {
    for value in [
        "not a url",
        "file:///tmp/planner",
        "http://name:password@localhost",
        "http://localhost/path",
        "http://localhost?secret=test",
        "http://localhost/#fragment",
    ] {
        assert!(PlannerClient::new(value).is_err());
    }
    assert!(PlannerClient::new("https://localhost:5598/").is_ok());
}

#[test]
fn plain_http_is_accepted_only_for_loopback_hosts() {
    for value in [
        "http://localhost:5598",
        "http://127.0.0.1:5598",
        "http://127.8.9.10:5598",
        "http://[::1]:5598",
        "http://planner.localhost:5598",
        "https://planner.example.com",
    ] {
        assert!(PlannerClient::new(value).is_ok(), "{value}");
    }
    for value in [
        "http://planner.example.com",
        "http://192.168.1.10:5598",
        "http://10.0.0.1",
        "http://[2001:db8::1]:5598",
        "http://localhost.example.com",
        "http://0.0.0.0:5598",
    ] {
        assert!(PlannerClient::new(value).is_err(), "{value}");
    }
}

#[tokio::test]
async fn forged_sender_in_browser_request_is_not_forwarded_to_planner() {
    let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    async fn capture(
        State(seen): State<Arc<Mutex<Option<serde_json::Value>>>>,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        *seen.lock().unwrap() = Some(body);
        StatusCode::UNPROCESSABLE_ENTITY
    }
    let app = Router::new()
        .route("/api/comms/channel", post(capture))
        .with_state(captured.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // Exactly what a hand-crafted browser POST could carry.
    let forged: SendRequest = serde_json::from_value(serde_json::json!({
        "channelId": "fixture-mgmt",
        "body": "hello",
        "sender": "BRIAN",
        "senderCast": "■",
        "role": "owner",
        "engine": "forged-engine",
        "itemKey": "forged-key"
    }))
    .unwrap();
    let _ = PlannerClient::new(&origin).unwrap().send(forged).await;
    server.abort();
    let wire = captured
        .lock()
        .unwrap()
        .clone()
        .expect("planner got a request");
    assert_eq!(
        wire,
        serde_json::json!({"channelId": "fixture-mgmt", "body": "hello"})
    );
    for field in ["sender", "senderCast", "role", "engine", "itemKey"] {
        assert!(wire.get(field).is_none(), "{field} must not be forwarded");
    }
}
