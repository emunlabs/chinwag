// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//! The browser uses same-origin Dioxus calls; only the server contacts the planner.
use crate::contracts::{ChannelInput, ChannelResponse, WiretapsData};
use dioxus::prelude::*;

#[get("/api/ui/comms")]
pub async fn load_comms() -> Result<WiretapsData, ServerFnError> {
    crate::planner::PlannerClient::from_env()
        .map_err(ServerFnError::new)?
        .wiretaps()
        .await
        .map_err(ServerFnError::new)
}

#[post("/api/ui/comms/send")]
pub async fn send_comms(input: ChannelInput) -> Result<ChannelResponse, ServerFnError> {
    crate::planner::PlannerClient::from_env()
        .map_err(ServerFnError::new)?
        .send(input)
        .await
        .map_err(ServerFnError::new)
}
