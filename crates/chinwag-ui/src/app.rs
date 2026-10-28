// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Application shell and router. Only a placeholder Home view exists in Phase 1.

use dioxus::prelude::*;

use crate::{Theme, health};

/// Routes. The 13 workflow views are added per the milestones in DESIGN.md.
#[derive(Clone, Debug, PartialEq, Routable)]
pub enum Route {
    #[route("/")]
    Home {},
}

/// Root component.
#[component]
pub fn App() -> Element {
    rsx! { Router::<Route> {} }
}

#[component]
fn Home() -> Element {
    let theme = use_signal(Theme::default);
    let status = use_server_future(health)?;
    let status_text = match &*status.read() {
        Some(Ok(h)) => format!("{} {} (node-free: {})", h.service, h.version, h.node_free),
        Some(Err(_)) => "health check failed".to_owned(),
        None => "checking".to_owned(),
    };
    rsx! {
        main { class: "mission-control", "data-theme": "{theme.read()}",
            h1 { "Chinwag Mission Control" }
            p { class: "status", "{status_text}" }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_renders_shell() {
        let mut dom = VirtualDom::new(|| {
            let theme = Theme::default();
            rsx! { main { class: "mission-control", "data-theme": "{theme}", h1 { "Chinwag Mission Control" } } }
        });
        dom.rebuild_in_place();
        let html = dioxus_ssr::render(&dom);
        assert!(html.contains("Chinwag Mission Control"));
        assert!(html.contains("data-theme=\"midnight\""));
    }

    #[test]
    fn home_route_is_root() {
        assert_eq!(Route::Home {}.to_string(), "/");
    }
}
