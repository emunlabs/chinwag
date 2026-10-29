// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
use crate::{contracts::CommsChannelMessage, view_model::LoadState};
use dioxus::prelude::*;
#[component]
pub fn MessageView(state: LoadState<Vec<CommsChannelMessage>>) -> Element {
    rsx! {
        section {
            "aria-label": "Messages",
            "aria-busy": matches!(state, LoadState::Loading),
            match &state {
                LoadState::Loading => rsx! {
                    p { role: "status", "Loading messages…" }
                },
                LoadState::Failed(error) => rsx! {
                    p { role: "alert", class: "error", "{error}" }
                },
                LoadState::Ready(messages) => rsx! {
                    if messages.is_empty() {
                        p { "No messages yet." }
                    }
                    ol { class: "messages",
                        for message in messages {
                            li { key: "{message.id}", class: "message",
                                div {
                                    strong { "{message.sender}" }
                                    time { datetime: "{message.created_at}", "{message.created_at}" }
                                }
                                p { "{message.body}" }
                            }
                        }
                    }
                },
            }
        }
    }
}
/// Controlled form: all send and draft transitions belong to the view model.
#[component]
pub fn Composer(
    state: crate::view_model::ComposerState,
    on_edit: EventHandler<String>,
    on_send: EventHandler<()>,
) -> Element {
    rsx! {
        form {
            class: "composer",
            onsubmit: move |event| {
                event.prevent_default();
                on_send.call(());
            },
            label { r#for: "message-draft", "Message" }
            textarea {
                id: "message-draft",
                value: "{state.draft}",
                disabled: state.sending,
                oninput: move |event| on_edit.call(event.value()),
                "aria-describedby": "composer-help",
            }
            p { id: "composer-help",
                "Up to 8,000 characters. A failed send keeps your draft; check the channel before retrying."
            }
            button { r#type: "submit", disabled: !state.can_send(),
                if state.sending {
                    "Sending…"
                } else {
                    "Send"
                }
            }
            if let Some(error) = &state.error {
                p { role: "alert", class: "error", "{error}" }
            }
        }
    }
}
