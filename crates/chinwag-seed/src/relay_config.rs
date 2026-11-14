//! Explicit local operator selection (`Disabled`, `Own`, or `MultiRegion`).
//! Matching origin strings are a route pin, never evidence of approval. The
//! operator must review the complete config hash. Model/tool arguments, peer
//! advertisements, and room responses cannot select or widen relay origins.

#![forbid(unsafe_code)]

use chinwag_swarm::relay_policy::{PolicyError, RelayPolicy};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RelaySelection {
    Disabled {},
    Own {
        selected_origin: String,
        approved_origin: String,
    },
    MultiRegion {
        selected_origins: Vec<String>,
        approved_origins: Vec<String>,
    },
}

impl RelaySelection {
    pub(crate) fn resolve(&self) -> Result<Arc<RelayPolicy>, PolicyError> {
        let policy = match self {
            Self::Disabled {} => RelayPolicy::from_local_manifest(None, None),
            Self::Own {
                selected_origin,
                approved_origin,
            } => RelayPolicy::from_local_manifest(Some(selected_origin), Some(approved_origin)),
            Self::MultiRegion {
                selected_origins,
                approved_origins,
            } => RelayPolicy::from_multi_region_manifest(selected_origins, approved_origins),
        }?;
        Ok(Arc::new(policy))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_must_be_explicit_and_closed() {
        for text in [
            r#"{}"#,
            r#"{"mode":"auto"}"#,
            r#"{"mode":"disabled","selected_origin":"https://pair-relay.invalid"}"#,
            r#"{"mode":"own","selected_origin":"https://pair-relay.invalid"}"#,
            r#"{"mode":"own","selected_origin":"https://pair-relay.invalid","approved_origin":"https://pair-relay.invalid","peer":"untrusted"}"#,
            r#"{"mode":"multi_region","selected_origins":["https://us.pair-relay.invalid"]}"#,
            r#"{"mode":"multi_region","selected_origins":[],"approved_origins":[],"extra":1}"#,
        ] {
            assert!(
                serde_json::from_str::<RelaySelection>(text).is_err(),
                "accepted unexpected selection: {text}"
            );
        }
    }

    #[test]
    fn explicit_disabled_is_a_selected_route() {
        let choice: RelaySelection = serde_json::from_str(r#"{"mode":"disabled"}"#).unwrap();
        assert!(matches!(&*choice.resolve().unwrap(), RelayPolicy::Disabled));
    }

    #[test]
    fn own_selection_has_one_canonical_pin() {
        let choice: RelaySelection = serde_json::from_str(
            r#"{"mode":"own","selected_origin":"https://PAIR-RELAY.invalid:443/","approved_origin":"https://pair-relay.invalid"}"#,
        )
        .unwrap();
        assert_eq!(
            choice.resolve().unwrap().relay_url().unwrap().as_str(),
            "https://pair-relay.invalid/"
        );
    }

    #[test]
    fn multi_region_selection_resolves_ordered_failover_ring_and_rejects_mismatch() {
        let valid: RelaySelection = serde_json::from_str(
            r#"{
                "mode":"multi_region",
                "selected_origins":["https://US-EAST.pair-relay.invalid:443/","https://eu-west.pair-relay.invalid"],
                "approved_origins":["https://us-east.pair-relay.invalid","https://EU-WEST.pair-relay.invalid:443/"]
            }"#,
        )
        .unwrap();
        let resolved = valid.resolve().unwrap();
        let urls = resolved.ordered_relay_urls();
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].as_str(), "https://us-east.pair-relay.invalid/");
        assert_eq!(urls[1].as_str(), "https://eu-west.pair-relay.invalid/");

        let mismatched: RelaySelection = serde_json::from_str(
            r#"{
                "mode":"multi_region",
                "selected_origins":["https://us-east.pair-relay.invalid","https://eu-west.pair-relay.invalid"],
                "approved_origins":["https://eu-west.pair-relay.invalid","https://us-east.pair-relay.invalid"]
            }"#,
        )
        .unwrap();
        assert_eq!(mismatched.resolve().err().unwrap(), PolicyError::Mismatch);
    }

    #[test]
    fn refused_selection_never_falls_back_to_disabled() {
        let mismatch: RelaySelection = serde_json::from_str(
            r#"{"mode":"own","selected_origin":"https://pair-relay.invalid","approved_origin":"https://other-relay.invalid"}"#,
        )
        .unwrap();
        assert_eq!(mismatch.resolve().err().unwrap(), PolicyError::Mismatch);
        let malformed: RelaySelection = serde_json::from_str(
            r#"{"mode":"own","selected_origin":"https://relay.iroh.network","approved_origin":"https://relay.iroh.network"}"#,
        )
        .unwrap();
        assert_eq!(malformed.resolve().err().unwrap(), PolicyError::Url);
    }
}
