// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//! Synthetic, in-memory planner on loopback only. Never contacts another service.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    use axum::{
        Json, Router,
        extract::State,
        http::StatusCode,
        routing::{get, post},
    };
    use chinwag_ui::contracts::{ChannelInput, ChannelResponse, WiretapsData};
    use std::sync::{Arc, Mutex};
    type Data = Arc<Mutex<WiretapsData>>;
    async fn send(
        State(data): State<Data>,
        Json(input): Json<ChannelInput>,
    ) -> Result<Json<ChannelResponse>, StatusCode> {
        let input = input
            .normalized()
            .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
        let mut data = data.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let channel = data
            .channels
            .iter_mut()
            .find(|c| c.id == input.channel_id)
            .ok_or(StatusCode::NOT_FOUND)?;
        let message = chinwag_ui::contracts::CommsChannelMessage {
            id: format!("stub-{}", channel.messages.len()),
            sender: "TEST".into(),
            sender_cast: "●".into(),
            role: "tester".into(),
            engine: "fixture".into(),
            body: input.body,
            item_key: input.item_key,
            created_at: "2026-10-28T12:02:00Z".into(),
        };
        channel.messages.push(message.clone());
        Ok(Json(ChannelResponse {
            actor: "TEST".into(),
            ok: true,
            channel_id: input.channel_id,
            message,
            wiretaps: data.clone(),
        }))
    }
    let fixture: WiretapsData =
        serde_json::from_str(include_str!("../tests/fixtures/wiretaps.json"))
            .expect("synthetic fixture");
    let state: Data = Arc::new(Mutex::new(fixture));
    let app = Router::new()
        .route(
            "/api/comms/wiretap",
            get(|State(data): State<Data>| async move {
                Json(data.lock().expect("fixture lock").clone())
            }),
        )
        .route("/api/comms/channel", post(send))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:5598")
        .await
        .expect("scratch port 5598 must be free");
    println!("Synthetic in-memory planner listening on loopback port 5598.");
    axum::serve(listener, app).await.expect("stub server");
}

#[cfg(target_arch = "wasm32")]
fn main() {}
