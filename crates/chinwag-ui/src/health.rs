// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Health probe, the first server function. Plain HTTP so CLI clients can call it.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Response body of `GET /api/ui/health`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Health {
    pub service: String,
    pub version: String,
    pub node_free: bool,
}

impl Health {
    /// Build the health payload for this binary.
    pub fn current() -> Self {
        Self {
            service: "chinwag-ui".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            node_free: true,
        }
    }
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
    fn health_reports_node_free() {
        let h = Health::current();
        assert_eq!(h.service, "chinwag-ui");
        assert!(h.node_free);
        assert!(!h.version.is_empty());
    }

    #[test]
    fn health_serializes_stable_field_names() {
        let json = serde_json::to_value(Health::current()).expect("serialize");
        assert!(json.get("service").is_some());
        assert!(json.get("node_free").is_some());
    }
}
