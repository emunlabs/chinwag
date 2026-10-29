// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Pure view state; no renderer or network dependencies.
#[derive(Clone, Debug, PartialEq)]
pub enum LoadState<T> {
    Loading,
    Failed(String),
    Ready(T),
}

use crate::contracts::{CommsChannel, SendRequest, WiretapsData};

pub fn selected_channel<'a>(data: &'a WiretapsData, id: &str) -> Option<&'a CommsChannel> {
    data.channels.iter().find(|channel| channel.id == id)
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ComposerState {
    pub draft: String,
    pub sending: bool,
    pub error: Option<String>,
}

impl ComposerState {
    pub fn can_send(&self) -> bool {
        !self.sending
            && !self.draft.trim().is_empty()
            && self.draft.trim().encode_utf16().count() <= 8_000
    }

    pub fn begin(&mut self, channel_id: &str) -> Result<SendRequest, String> {
        if self.sending {
            return Err("A message is already being sent.".into());
        }
        let input = SendRequest {
            channel_id: channel_id.into(),
            body: self.draft.clone(),
        }
        .normalized();
        match input {
            Ok(input) => {
                self.sending = true;
                self.error = None;
                Ok(input)
            }
            Err(error) => {
                self.error = Some(error.clone());
                Err(error)
            }
        }
    }

    pub fn finish(&mut self, result: Result<(), String>) {
        self.sending = false;
        match result {
            Ok(()) => {
                self.draft.clear();
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }
}
