// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
use dioxus::prelude::*;
/// Presentation only: callers supply navigation and the current view.
#[component]
pub fn Shell(sidebar: Element, children: Element) -> Element {
    rsx! {
        div { class: "mission-control",
            header { class: "topbar",
                h1 { "Chinwag Mission Control" }
            }
            div { class: "workspace",
                aside { "aria-label": "Comms channels", {sidebar} }
                main { id: "main-content", {children} }
            }
        }
    }
}
