// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Native planner adapter; configuration and errors never expose URLs or response bodies.
use crate::contracts::{ChannelResponse, SendRequest, WiretapsData};
use std::time::Duration;

#[derive(Clone)]
pub struct PlannerClient {
    base: reqwest::Url,
    http: reqwest::Client,
}

impl PlannerClient {
    pub fn from_env() -> Result<Self, String> {
        let base = std::env::var("CHINWAG_PLANNER_URL")
            .map_err(|_| "Set CHINWAG_PLANNER_URL to the test planner's HTTP origin.".to_owned())?;
        Self::new(&base)
    }

    pub fn new(base: &str) -> Result<Self, String> {
        let base =
            reqwest::Url::parse(base).map_err(|_| "Invalid planner HTTP origin.".to_owned())?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err("Planner URL must be an HTTP(S) origin without credentials, path, query or fragment.".into());
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "Could not initialize planner HTTP client.".to_owned())?;
        Ok(Self { base, http })
    }

    fn endpoint(&self, path: &str) -> Result<reqwest::Url, String> {
        self.base
            .join(path)
            .map_err(|_| "Invalid planner endpoint.".into())
    }

    async fn decode<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, String> {
        if !response.status().is_success() {
            return Err(format!(
                "Planner returned HTTP {}. Check the planner before retrying a send.",
                response.status().as_u16()
            ));
        }
        // Enforce the contract's 5 MB ceiling without trusting Content-Length.
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Could not read planner response.".to_owned())?
        {
            if bytes.len() + chunk.len() > 5_000_000 {
                return Err("Planner response exceeds 5 MB.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| "Planner returned an invalid response.".into())
    }

    pub async fn wiretaps(&self) -> Result<WiretapsData, String> {
        let response = self
            .http
            .get(self.endpoint("/api/comms/wiretap")?)
            .send()
            .await
            .map_err(|_| {
                "Could not reach planner. Check its configuration and availability.".to_owned()
            })?;
        Self::decode(response).await
    }

    /// Builds the planner request here, with no client-supplied actor fields.
    pub async fn send(&self, request: SendRequest) -> Result<ChannelResponse, String> {
        let input = request.into_channel_input().normalized()?;
        let response = self.http.post(self.endpoint("/api/comms/channel")?).json(&input).send().await
            .map_err(|_| "Send was not confirmed. Check the channel before retrying; the planner may have accepted it.".to_owned())?;
        let result: ChannelResponse = Self::decode(response).await?;
        if !result.ok
            || result.channel_id != input.channel_id
            || !result.wiretaps.channels.iter().any(|channel| {
                channel.id == input.channel_id
                    && channel
                        .messages
                        .iter()
                        .any(|message| message == &result.message)
            })
        {
            return Err("Planner did not confirm this message in the requested channel. Check it before retrying.".into());
        }
        Ok(result)
    }
}
