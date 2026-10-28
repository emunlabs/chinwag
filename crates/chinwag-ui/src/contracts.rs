// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//! Planner wire contracts. Unknown fields are intentionally accepted by serde.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WiretapsData {
    pub channels: Vec<CommsChannel>,
    // The bare-bones channel UI does not interpret sessions or summary telemetry.
    #[serde(default)]
    pub sessions: Vec<serde_json::Value>,
    #[serde(default)]
    pub summary: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CommsChannel {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub description: String,
    pub members: Vec<String>,
    pub item_key: Option<String>,
    pub messages: Vec<CommsChannelMessage>,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommsChannelMessage {
    pub id: String,
    pub sender: String,
    pub sender_cast: String,
    pub role: String,
    pub engine: String,
    pub body: String,
    pub item_key: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelInput {
    pub channel_id: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_cast: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_key: Option<String>,
}

impl ChannelInput {
    /// Validate again at the transport boundary; callers can construct this wire type.
    pub fn normalized(&self) -> Result<Self, String> {
        let mut input = self.clone();
        input.channel_id = input.channel_id.trim().to_owned();
        input.body = input.body.trim().to_owned();
        if input.channel_id.is_empty() || input.channel_id.encode_utf16().count() > 80 {
            return Err("Channel ID must contain 1–80 characters.".into());
        }
        if input.body.is_empty() || input.body.encode_utf16().count() > 8_000 {
            return Err("Message must contain 1–8,000 characters (UTF-16 units).".into());
        }
        for (field, limit) in [
            (&mut input.sender, 60),
            (&mut input.role, 200),
            (&mut input.engine, 200),
            (&mut input.item_key, 80),
        ] {
            if let Some(value) = field {
                *value = value.trim().to_owned();
                if value.encode_utf16().count() > limit {
                    return Err("Optional message metadata exceeds the planner limit.".into());
                }
            }
        }
        if input
            .sender_cast
            .as_deref()
            .is_some_and(|cast| !matches!(cast, "●" | "■"))
        {
            return Err("Invalid sender cast.".into());
        }
        Ok(input)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelResponse {
    pub actor: String,
    pub ok: bool,
    pub channel_id: String,
    pub message: CommsChannelMessage,
    #[serde(flatten)]
    pub wiretaps: WiretapsData,
}
