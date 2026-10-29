// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
use axum::{Router, middleware::from_fn_with_state, routing::get};
use chinwag_ui::guard::{Policy, guard};

async fn serve() -> (reqwest::Client, String, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new()
        .route("/", get(|| async { "ok" }).post(|| async { "posted" }))
        .layer(from_fn_with_state(Policy { port }, guard));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (
        reqwest::Client::new(),
        format!("http://127.0.0.1:{port}/"),
        port,
    )
}

#[tokio::test]
async fn guard_enforces_host_origin_and_adds_security_headers() {
    let (http, url, port) = serve().await;

    let ok = http.get(&url).send().await.unwrap();
    assert_eq!(ok.status(), 200);
    let headers = ok.headers();
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["referrer-policy"], "no-referrer");
    let csp = headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'") && csp.contains("base-uri 'none'"));

    // DNS rebinding: right socket, attacker-controlled Host.
    let rebound = http
        .get(&url)
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status(), 403);
    let wrong_port = http
        .get(&url)
        .header("host", format!("127.0.0.1:{}", port.wrapping_add(1)))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_port.status(), 403);

    let cross_site = http
        .get(&url)
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(cross_site.status(), 403);

    // State-changing requests need a matching Origin.
    assert_eq!(http.post(&url).send().await.unwrap().status(), 403);
    let forged = http
        .post(&url)
        .header("origin", "http://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
    let same_origin = http
        .post(&url)
        .header("origin", format!("http://127.0.0.1:{port}"))
        .send()
        .await
        .unwrap();
    assert_eq!(same_origin.status(), 200);
}
