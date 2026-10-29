// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//! Typed routing and the comms controller. Components contain no HTTP calls.
use crate::{
    api::{load_comms, send_comms},
    components::{
        channels::ChannelList,
        chat::{Composer, MessageView},
        shell::Shell,
    },
    contracts::WiretapsData,
    theme::STYLES,
    view_model::{ComposerState, LoadState, selected_channel},
};
use dioxus::prelude::*;
#[derive(Clone, Debug, PartialEq, Routable)]
pub enum Route {
    #[route("/")]
    Home {},
    #[route("/comms/:channel_id")]
    Channel { channel_id: String },
    #[route("/:..segments")]
    NotFound { segments: Vec<String> },
}
#[component]
pub fn App() -> Element {
    use_effect(|| {
        document::eval("document.documentElement.dataset.theme = 'midnight'");
    });
    rsx! {
        style { {STYLES} }
        Router::<Route> {}
    }
}
#[component]
fn Home() -> Element {
    rsx! {
        CommsPage { selected: None }
    }
}
#[component]
fn Channel(channel_id: String) -> Element {
    rsx! {
        CommsPage { key: "{channel_id}", selected: Some(channel_id.clone()) }
    }
}
#[component]
fn NotFound(segments: Vec<String>) -> Element {
    rsx! {
        Shell {
            sidebar: rsx! {
                Link { to: Route::Home {}, "Channels" }
            },
            h2 { "Page not found" }
            Link { to: Route::Home {}, "Return to comms" }
        }
    }
}
#[component]
fn CommsPage(selected: Option<String>) -> Element {
    let mut resource = use_resource(load_comms);
    let mut snapshot = use_signal(|| None::<WiretapsData>);
    let mut composer = use_signal(ComposerState::default);
    let state = match snapshot() {
        Some(data) => LoadState::Ready(data),
        None => match &*resource.read_unchecked() {
            None => LoadState::Loading,
            Some(Ok(data)) => LoadState::Ready(data.clone()),
            Some(Err(error)) => LoadState::Failed(error.to_string()),
        },
    };
    let channels = match &state {
        LoadState::Ready(data) => data.channels.clone(),
        _ => Vec::new(),
    };
    let channel = match &state {
        LoadState::Ready(data) => selected
            .as_deref()
            .and_then(|id| selected_channel(data, id))
            .cloned(),
        _ => None,
    };
    let can_compose = channel.is_some();
    let messages = match &state {
        LoadState::Loading => LoadState::Loading,
        LoadState::Failed(error) => LoadState::Failed(error.clone()),
        LoadState::Ready(_) => LoadState::Ready(
            channel
                .as_ref()
                .map(|channel| channel.messages.clone())
                .unwrap_or_default(),
        ),
    };
    let send_channel = channel.as_ref().map(|channel| channel.id.clone());
    let title = channel
        .as_ref()
        .map(|channel| channel.name.clone())
        .unwrap_or_else(|| "Comms".into());
    let edit = move |draft| {
        composer.write().draft = draft;
    };
    let on_send = move |_: ()| {
        let Some(channel_id) = send_channel.as_deref() else {
            return;
        };
        let Ok(input) = composer.write().begin(channel_id) else {
            return;
        };
        spawn(async move {
            match send_comms(input).await {
                Ok(response) => {
                    snapshot.set(Some(response.wiretaps));
                    composer.write().finish(Ok(()));
                }
                Err(error) => composer.write().finish(Err(error.to_string())),
            }
        });
    };
    rsx! {
        Shell {
            sidebar: rsx! {
                if matches!(state, LoadState::Loading) {
                    p { role: "status", "Loading channels…" }
                }
                if matches!(state, LoadState::Ready(_)) {
                    ChannelList { channels, selected: selected.clone() }
                } else {
                    h2 { "Channels" }
                }
                button {
                    disabled: composer.read().sending,
                    onclick: move |_| {
                        snapshot.set(None);
                        resource.restart();
                    },
                    "Refresh"
                }
            },
            h2 { "{title}" }
            if let Some(channel) = &channel {
                p { "{channel.description}" }
            }
            if matches!(state, LoadState::Ready(_)) && channel.is_none() {
                if selected.is_some() {
                    p { role: "alert", "Channel not found. Select an available channel." }
                } else {
                    p { "Select a channel to read and send messages." }
                }
            } else {
                MessageView { state: messages }
            }
            if can_compose {
                Composer {
                    state: composer(),
                    on_edit: edit,
                    on_send,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(app: fn() -> Element) -> String {
        let mut dom = VirtualDom::new(app);
        dom.rebuild_in_place();
        dioxus_ssr::render(&dom)
    }

    #[test]
    fn root_route_parses_to_home() {
        assert_eq!("/".parse::<Route>().ok(), Some(Route::Home {}));
    }

    #[test]
    fn channel_route_captures_the_id_and_round_trips() {
        let route = "/comms/fixture-mgmt".parse::<Route>().expect("route");
        assert_eq!(
            route,
            Route::Channel {
                channel_id: "fixture-mgmt".into()
            }
        );
        assert_eq!(route.to_string(), "/comms/fixture-mgmt");
    }

    #[test]
    fn unknown_paths_fall_through_to_not_found() {
        assert_eq!(
            "/no/such/page".parse::<Route>().ok(),
            Some(Route::NotFound {
                segments: vec!["no".into(), "such".into(), "page".into()]
            })
        );
    }

    #[test]
    fn app_renders_the_real_shell_with_styles_and_loading_state() {
        let html = render(App);
        for expected in [
            "<style>",
            "--bg:",
            "Chinwag Mission Control",
            "<aside",
            "<main",
            "Loading channels",
            "Comms",
        ] {
            assert!(html.contains(expected), "{expected}: {html}");
        }
        // Nothing is composable until a channel is loaded and selected.
        assert!(!html.contains("<textarea"), "{html}");
    }
}
