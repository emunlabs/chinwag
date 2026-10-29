// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Dev entry point. Production embeds `chinwag_ui::App` behind `chinwag ui`.
#![forbid(unsafe_code)]

/// Native server: loopback only, with the Host/Origin guard and security headers.
#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
fn main() {
    let ip = std::env::var("IP").ok();
    let port = std::env::var("PORT").ok();
    let address = match chinwag_ui::guard::loopback_address(ip.as_deref(), port.as_deref()) {
        Ok(address) => address,
        Err(reason) => {
            eprintln!("chinwag-ui: {reason}");
            std::process::exit(1);
        }
    };
    let policy = chinwag_ui::guard::Policy {
        port: address.port(),
    };
    dioxus::serve(move || async move {
        Ok(
            dioxus::server::router(chinwag_ui::App).layer(axum::middleware::from_fn_with_state(
                policy,
                chinwag_ui::guard::guard,
            )),
        )
    });
}

#[cfg(not(all(feature = "server", not(target_arch = "wasm32"))))]
fn main() {
    dioxus::launch(chinwag_ui::App);
}
