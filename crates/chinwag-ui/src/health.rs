// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Health probe, the first server function. Plain HTTP so CLI clients can call it.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Response body of `GET /api/ui/health`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Health {
    pub service: String,
    pub version: String,
    pub node_free: bool,
}

impl Health {
    /// Build the health payload for this binary.
    ///
    /// `node_free` is probed at runtime: it is `false` only when this process is itself a
    /// Node-family runtime (see [`is_node_runtime`]). It is not a build-time constant.
    pub fn current() -> Self {
        let exe = std::env::current_exe().ok();
        Self::for_executable(exe.as_deref())
    }

    /// Build the payload for a given executable path (`None` when it cannot be determined).
    pub fn for_executable(exe: Option<&Path>) -> Self {
        Self {
            service: "chinwag-ui".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            node_free: !exe.is_some_and(is_node_runtime),
        }
    }
}

/// True when `exe` names a Node-family JavaScript runtime (`node`, `nodejs`, `bun`, `deno`).
pub fn is_node_runtime(exe: &Path) -> bool {
    exe.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| {
            ["node", "nodejs", "bun", "deno"]
                .iter()
                .any(|name| stem.eq_ignore_ascii_case(name))
        })
}

/// `GET /api/ui/health`
#[get("/api/ui/health")]
pub async fn health() -> Result<Health> {
    Ok(Health::current())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_reports_service_and_crate_version() {
        let h = Health::current();
        assert_eq!(h.service, "chinwag-ui");
        assert_eq!(h.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn node_runtimes_are_detected_by_file_stem() {
        for exe in [
            "/usr/local/bin/node",
            "/opt/homebrew/bin/nodejs",
            "/tools/NODE.EXE",
            "/usr/bin/bun",
            "deno",
        ] {
            assert!(is_node_runtime(Path::new(exe)), "{exe}");
        }
        for exe in [
            "/usr/local/bin/chinwag-ui",
            "/Users/x/target/debug/deps/chinwag_ui-abc123",
            "/usr/bin/nodemon",
            "",
        ] {
            assert!(!is_node_runtime(Path::new(exe)), "{exe}");
        }
    }

    #[test]
    fn node_free_follows_the_executable() {
        assert!(Health::for_executable(Some(Path::new("/bin/chinwag-ui"))).node_free);
        assert!(Health::for_executable(None).node_free);
        assert!(!Health::for_executable(Some(Path::new("/usr/local/bin/node"))).node_free);
    }

    #[test]
    fn running_test_binary_is_node_free() {
        assert!(Health::current().node_free);
    }

    #[test]
    fn json_has_exactly_the_documented_fields_and_round_trips() {
        let health = Health::current();
        let json = serde_json::to_value(&health).expect("serialize");
        let mut keys: Vec<_> = json.as_object().expect("object").keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["node_free", "service", "version"]);
        assert_eq!(json["service"], "chinwag-ui");
        assert_eq!(json["node_free"], serde_json::Value::Bool(health.node_free));
        let back: Health = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, health);
    }

    #[test]
    fn missing_field_is_rejected() {
        let bad = serde_json::json!({"service": "chinwag-ui", "version": "1"});
        assert!(serde_json::from_value::<Health>(bad).is_err());
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn server_function_returns_current_health() {
        let got = health().await.expect("health");
        assert_eq!(got, Health::current());
    }
}
