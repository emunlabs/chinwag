// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Server guard: "loopback only" is enforced in code, not just in the README.
//!
//! - the server refuses to start on a non-loopback `IP` until real auth lands;
//! - `Host` must name this loopback listener, which defeats DNS rebinding;
//! - state-changing requests must carry a matching `Origin`, and any request a
//!   browser marks `Sec-Fetch-Site: cross-site` is refused;
//! - every response carries clickjacking, sniffing and referrer protections.
use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Dioxus' own default when `IP`/`PORT` are unset.
const DEFAULT_PORT: u16 = 8080;

/// Scripts keep `'unsafe-inline'` because Dioxus SSR emits an inline hydration
/// bootstrap and the theme is applied with `document::eval`. Tightening this to
/// nonces needs a browser check that has not been done yet.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self' 'unsafe-inline' \
'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; \
form-action 'self'";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub port: u16,
}

/// Resolve the listen address from the `IP` and `PORT` values, refusing non-loopback.
pub fn loopback_address(ip: Option<&str>, port: Option<&str>) -> Result<SocketAddr, String> {
    let ip = match ip.map(str::trim).filter(|v| !v.is_empty()) {
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(value) => value
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map_err(|_| "IP must be a loopback address such as 127.0.0.1.".to_owned())?,
    };
    if !ip.is_loopback() {
        return Err(
            "Refusing to listen on a non-loopback address: this UI has no authentication yet."
                .to_owned(),
        );
    }
    let port = match port.map(str::trim).filter(|v| !v.is_empty()) {
        None => DEFAULT_PORT,
        Some(value) => value
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| "PORT must be a number from 1 to 65535.".to_owned())?,
    };
    Ok(SocketAddr::new(ip, port))
}

fn authorities(port: u16) -> [String; 3] {
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
}

pub fn host_allowed(host: &str, port: u16) -> bool {
    let host = host.to_ascii_lowercase();
    authorities(port).contains(&host)
}

pub fn origin_allowed(origin: &str, port: u16) -> bool {
    let origin = origin.to_ascii_lowercase();
    authorities(port)
        .iter()
        .any(|a| origin == format!("http://{a}"))
}

fn refuse(reason: &'static str) -> Response {
    (StatusCode::FORBIDDEN, reason).into_response()
}

fn header_text<'a>(request: &'a Request, name: &HeaderName) -> Option<&'a str> {
    request.headers().get(name).and_then(|v| v.to_str().ok())
}

/// Axum middleware: `from_fn_with_state(Policy { port }, guard)`.
pub async fn guard(State(policy): State<Policy>, request: Request, next: Next) -> Response {
    let host = header_text(&request, &header::HOST)
        .map(str::to_owned)
        .or_else(|| request.uri().authority().map(|a| a.as_str().to_owned()));
    if !host.is_some_and(|h| host_allowed(&h, policy.port)) {
        return refuse("forbidden host");
    }
    if header_text(&request, &HeaderName::from_static("sec-fetch-site"))
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
    {
        return refuse("forbidden cross-site request");
    }
    let safe = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if !safe
        && !header_text(&request, &header::ORIGIN).is_some_and(|o| origin_allowed(o, policy.port))
    {
        return refuse("forbidden origin");
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_address_defaults_to_loopback_and_refuses_everything_else() {
        assert_eq!(
            loopback_address(None, None).unwrap(),
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            loopback_address(Some("127.0.0.1"), Some("5599")).unwrap(),
            "127.0.0.1:5599".parse().unwrap()
        );
        assert!(loopback_address(Some("[::1]"), Some("5599")).is_ok());
        for ip in ["0.0.0.0", "192.168.1.5", "::", "100.64.0.1", "example.com"] {
            assert!(loopback_address(Some(ip), Some("5599")).is_err(), "{ip}");
        }
        for port in ["0", "70000", "x"] {
            assert!(loopback_address(None, Some(port)).is_err(), "{port}");
        }
    }

    #[test]
    fn host_and_origin_must_match_the_loopback_listener() {
        assert!(host_allowed("127.0.0.1:5599", 5599));
        assert!(host_allowed("LocalHost:5599", 5599));
        assert!(host_allowed("[::1]:5599", 5599));
        for host in [
            "evil.example:5599",
            "127.0.0.1:1",
            "127.0.0.1",
            "localhost.evil:5599",
        ] {
            assert!(!host_allowed(host, 5599), "{host}");
        }
        assert!(origin_allowed("http://localhost:5599", 5599));
        for origin in [
            "https://localhost:5599",
            "http://evil.example:5599",
            "null",
            "",
        ] {
            assert!(!origin_allowed(origin, 5599), "{origin}");
        }
    }
}
