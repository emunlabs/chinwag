// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
use crate::{Route, contracts::CommsChannel};
use dioxus::prelude::*;
#[component]
pub fn ChannelList(channels: Vec<CommsChannel>, selected: Option<String>) -> Element {
    rsx! {
        nav { "aria-label": "Channels",
            h2 { "Channels" }
            if channels.is_empty() {
                p { "No channels available." }
            }
            ul { class: "channel-list",
                for channel in channels {
                    li { key: "{channel.id}",
                        Link {
                            to: Route::Channel {
                                channel_id: channel.id.clone(),
                            },
                            "aria-current": if selected.as_ref() == Some(&channel.id) { Some("page") } else { None },
                            "{channel.name}"
                        }
                    }
                }
            }
        }
    }
}
