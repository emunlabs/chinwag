// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! The browser uses same-origin Dioxus calls; only the server contacts the planner.
use crate::contracts::{ChannelResponse, SendRequest, WiretapsData};
use dioxus::prelude::*;

#[get("/api/ui/comms")]
pub async fn load_comms() -> Result<WiretapsData, ServerFnError> {
    crate::planner::PlannerClient::from_env()
        .map_err(ServerFnError::new)?
        .wiretaps()
        .await
        .map(WiretapsData::browser_view)
        .map_err(ServerFnError::new)
}

#[post("/api/ui/comms/send")]
pub async fn send_comms(request: SendRequest) -> Result<ChannelResponse, ServerFnError> {
    crate::planner::PlannerClient::from_env()
        .map_err(ServerFnError::new)?
        .send(request)
        .await
        .map(|mut response| {
            response.wiretaps = response.wiretaps.browser_view();
            response
        })
        .map_err(ServerFnError::new)
}
