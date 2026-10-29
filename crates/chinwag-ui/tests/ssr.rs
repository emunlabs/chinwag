// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
use chinwag_ui::{
    Route,
    components::{
        channels::ChannelList,
        chat::{Composer, MessageView},
        shell::Shell,
    },
    contracts::WiretapsData,
    view_model::{ComposerState, LoadState},
};
use dioxus::prelude::*;
fn fixture() -> WiretapsData {
    serde_json::from_str(include_str!("fixtures/wiretaps.json")).unwrap()
}
fn render(app: fn() -> Element) -> String {
    let mut dom = VirtualDom::new(app);
    dom.rebuild_in_place();
    dioxus_ssr::render(&dom)
}
#[test]
fn actual_shell_has_header_sidebar_and_main() {
    let html = render(|| {
        rsx! {
            Shell {
                sidebar: rsx! {
                    p { "Test channels" }
                },
                p { "Test pane" }
            }
        }
    });
    for expected in [
        "Chinwag Mission Control",
        "<header",
        "<aside",
        "<main",
        "Test channels",
        "Test pane",
    ] {
        assert!(html.contains(expected), "{expected}: {html}");
    }
}
#[derive(Clone, PartialEq, Routable)]
enum TestRoute {
    #[route("/")]
    Index {},
}
#[component]
fn Index() -> Element {
    rsx! {
        ChannelList {
            channels: fixture().channels,
            selected: Some("fixture-mgmt"
                    .into()),
        }
    }
}
#[test]
fn actual_channel_list_has_typed_links_and_selection() {
    let html = render(|| {
        rsx! {
            Router::<TestRoute> {}
        }
    });
    assert!(html.contains("/comms/fixture-mgmt"), "{html}");
    assert!(html.contains("aria-current=\"page\""));
    assert!(html.contains("#fixture-empty"));
    let empty = render(|| {
        rsx! {
            ChannelList { channels: Vec::new(), selected: None }
        }
    });
    assert!(empty.contains("No channels available."));
}
#[test]
fn actual_message_view_handles_all_states_and_escapes_body() {
    let html = render(|| {
        rsx! {
            MessageView { state: LoadState::Ready(fixture().channels.remove(0).messages) }
        }
    });
    assert!(html.find("First fixture").unwrap() < html.find("Second fixture").unwrap());
    assert!(html.contains("TEST"));
    assert!(html.contains("datetime=\"2026-10-28T12:00:00Z\""));
    assert!(
        html.contains("&#60;script") || html.contains("&lt;script"),
        "{html}"
    );
    assert!(!html.contains("<script>"));
    assert!(
        render(|| {
            rsx! {
                MessageView { state : LoadState::Loading }
            }
        })
        .contains("Loading messages"),
    );
    assert!(
        render(|| {
            rsx! {
                MessageView { state : LoadState::Ready(Vec::new()) }
            }
        })
        .contains("No messages yet"),
    );
    let failed = render(|| {
        rsx! {
            MessageView { state: LoadState::Failed("Planner unavailable".into()) }
        }
    });
    assert!(failed.contains("role=\"alert\""));
    assert!(failed.contains("Planner unavailable"));
}
#[test]
fn actual_composer_renders_label_draft_error_and_disabled_states() {
    let empty = render(|| {
        rsx! {
            Composer {
                state: ComposerState::default(),
                on_edit: |_| {},
                on_send: |
                            _ | {},
            }
        }
    });
    assert!(empty.contains("for=\"message-draft\""));
    assert!(empty.contains("disabled"));
    let ready = render(|| {
        rsx! {
            Composer {
                state: ComposerState {
                    draft: "Hello".into(),
                    ..Default::default()
                },
                on_edit: |_| {},
                on_send: |_| {},
            }
        }
    });
    assert!(ready.contains("Hello"));
    assert!(!ready.contains("disabled"));
    let pending = render(|| {
        rsx! {
            Composer {
                state: ComposerState {
                    draft: "Hello".into(),
                    sending: true,
                    error: None,
                },
                on_edit: |_| {},
                on_send: |_| {},
            }
        }
    });
    assert!(pending.contains("Sending"));
    assert!(pending.contains("disabled"));
    let failed = render(|| {
        rsx! {
            Composer {
                state: ComposerState {
                    draft: "Keep me".into(),
                    error: Some("Send failed".into()),
                    ..Default::default()
                },
                on_edit: |_| {},
                on_send: |_| {},
            }
        }
    });
    assert!(failed.contains("Keep me"));
    assert!(failed.contains("Send failed"));
}
#[test]
fn channel_routes_roundtrip() {
    let route = Route::Channel {
        channel_id: "fixture-mgmt".into(),
    };
    assert_eq!(route.to_string(), "/comms/fixture-mgmt");
    assert_eq!(route.to_string().parse::<Route>().unwrap(), route);
    for id in ["#mgmt", "thread:CHWG-DIOXUS-1", "channel with spaces"] {
        let route = Route::Channel {
            channel_id: id.into(),
        };
        let path = route.to_string();
        assert!(
            !path.contains('#'),
            "Route must encode a fragment character: {path}"
        );
        assert_eq!(path.parse::<Route>().unwrap(), route);
    }
}
