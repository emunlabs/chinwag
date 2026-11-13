// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! UI projections consume the fleet contract directly, without a second roster.

use chinwag_fleet::{FleetManifest, SeatLifecycle};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSeatStatus {
    pub id: String,
    pub display_name: Option<String>,
    pub lifecycle: SeatLifecycle,
    pub provider: String,
    pub model_id: String,
    pub target: chinwag_fleet::ExecutionTarget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStatus {
    pub configured: bool,
    pub schema_version: Option<u32>,
    pub node_count: usize,
    pub seats: Vec<FleetSeatStatus>,
}

pub fn inspect_fleet(manifest: Option<&FleetManifest>) -> FleetStatus {
    match manifest {
        Some(manifest) => FleetStatus {
            configured: true,
            schema_version: Some(manifest.schema_version),
            node_count: manifest.nodes.len(),
            seats: manifest
                .seats
                .iter()
                .map(|seat| FleetSeatStatus {
                    id: seat.id.as_str().to_owned(),
                    display_name: seat.display_name.clone(),
                    lifecycle: seat.lifecycle.clone(),
                    provider: seat.model.provider.clone(),
                    model_id: seat.model.model_id.clone(),
                    target: seat.target_selector.clone(),
                })
                .collect(),
        },
        None => FleetStatus {
            configured: false,
            schema_version: None,
            node_count: 0,
            seats: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_uses_manifest_and_reports_unconfigured_honestly() {
        assert!(!inspect_fleet(None).configured);
        let manifest = FleetManifest::starter_profile("solo").unwrap();
        let status = inspect_fleet(Some(&manifest));
        assert!(status.configured);
        assert_eq!(status.seats.len(), manifest.seats.len());
        for (status, seat) in status.seats.iter().zip(&manifest.seats) {
            assert_eq!(status.id, seat.id.as_str());
            assert_eq!(status.model_id, seat.model.model_id);
        }
    }
}
