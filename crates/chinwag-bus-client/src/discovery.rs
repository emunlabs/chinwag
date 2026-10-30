//! Validated, redacted discovery snapshots returned by the configured bus host.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{BusClient, ClientError, read_json};

const SCHEMA: &str = "chinwag-client-inventory/v1";
const MAX_PIDS: usize = 4096;
const MAX_CANDIDATES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientInventory {
    pub schema: String,
    pub observed_at_unix_ms: u64,
    pub host_label: String,
    pub coverage: DiscoveryCoverage,
    pub clients: Vec<DiscoveredClient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installations: Option<InstallationInventory>,
}

/// Public installation observations from this same runtime host. Paths, bundle
/// identifiers and executable metadata stay on the host, not on this wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationInventory {
    pub observed_at_unix_ms: u64,
    pub apps: Vec<InstalledClient>,
    pub coverage: InstallationCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationCoverage {
    pub entry_capacity: usize,
    pub entries_examined: usize,
    pub installation_capacity: usize,
    pub capacity_reached: bool,
    pub unavailable_roots: usize,
    pub invalid_metadata: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledClient {
    pub id: String,
    pub family: String,
    pub kind: ClientKind,
    pub running_instances: usize,
    pub state: InstallationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<InstallationLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Public installation scope only; never an absolute path or connector grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationLocation {
    SharedApplications,
    UserApplications,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationState {
    InstalledUnverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryCoverage {
    pub pid_capacity: usize,
    pub candidate_capacity: usize,
    pub sampled_pid_count: usize,
    pub candidate_process_count: usize,
    pub omitted_candidate_count: usize,
    pub raced_processes: usize,
    pub permission_denied_processes: usize,
    pub unavailable_processes: usize,
    pub invalid_process_metadata: usize,
    pub unclassified_interpreters: usize,
    pub unresolved_components: usize,
    pub pid_capacity_reached: bool,
    pub candidate_capacity_reached: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredClient {
    pub id: String,
    pub family: String,
    pub kind: ClientKind,
    pub state: DiscoveryState,
    pub component_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    Application,
    CommandLine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryState {
    DetectedUnverified,
}

impl BusClient {
    /// One explicit bounded GET to this client's endpoint. There is no local
    /// scanner, admission, connection attempt or automatic retry behind it.
    pub fn clients(&self) -> Result<ClientInventory, ClientError> {
        let inventory: ClientInventory = read_json(
            self.http
                .get(self.endpoint("/api/bus/clients"))
                .header("X-Chinwag-Discovery-Intent", "1")
                .header("X-Chinwag-Discovery-Details", "1")
                .send()?,
        )?;
        inventory.validate()?;
        Ok(inventory)
    }
}

impl ClientInventory {
    pub fn validate(&self) -> Result<(), ClientError> {
        let invalid = |reason: &str| {
            ClientError::InvalidResponse(format!("invalid client inventory: {reason}"))
        };
        if self.schema != SCHEMA {
            return Err(invalid("unsupported schema"));
        }
        if self.observed_at_unix_ms == 0
            || self.host_label.is_empty()
            || self.host_label.len() > 128
            || self.host_label.trim() != self.host_label
            || self
                .host_label
                .chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\'))
        {
            return Err(invalid("bounded host label and observed time required"));
        }
        let c = &self.coverage;
        if !(1..=MAX_PIDS).contains(&c.pid_capacity)
            || !(1..=MAX_CANDIDATES).contains(&c.candidate_capacity)
            || c.sampled_pid_count > c.pid_capacity
            || c.candidate_process_count > c.candidate_capacity
            || c.candidate_process_count > c.sampled_pid_count
            || self.clients.len() > c.candidate_process_count
            || self.clients.len() > MAX_CANDIDATES
            || c.unresolved_components > c.candidate_process_count
        {
            return Err(invalid("coverage or row count exceeds declared bounds"));
        }
        if [
            c.omitted_candidate_count,
            c.raced_processes,
            c.permission_denied_processes,
            c.unavailable_processes,
            c.invalid_process_metadata,
            c.unclassified_interpreters,
        ]
        .into_iter()
        .any(|count| count > c.sampled_pid_count)
        {
            return Err(invalid("coverage counter exceeds sampled processes"));
        }
        let mut ids = HashSet::new();
        let mut component_sum = 0usize;
        for client in &self.clients {
            if client.id.len() != 64
                || !client
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || !ids.insert(&client.id)
            {
                return Err(invalid(
                    "client IDs must be unique opaque lowercase SHA256 values",
                ));
            }
            if client.family.is_empty()
                || client.family.len() > 64
                || !client.family.as_bytes()[0].is_ascii_lowercase()
                || client.family.ends_with('_')
                || client.family.contains("__")
                || !client
                    .family
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(invalid("client family must be bounded snake_case"));
            }
            if client.component_count == 0 || client.component_count > c.candidate_process_count {
                return Err(invalid("invalid component count"));
            }
            component_sum = component_sum
                .checked_add(client.component_count)
                .ok_or_else(|| invalid("component count overflow"))?;
        }
        if component_sum > c.candidate_process_count
            || component_sum.saturating_add(c.unresolved_components) > c.candidate_process_count
        {
            return Err(invalid("grouped components exceed observed candidates"));
        }
        if let Some(installed) = &self.installations {
            let coverage = &installed.coverage;
            if installed.observed_at_unix_ms == 0
                || !(1..=8192).contains(&coverage.entry_capacity)
                || coverage.entries_examined > coverage.entry_capacity
                || !(1..=128).contains(&coverage.installation_capacity)
                || installed.apps.len() > coverage.installation_capacity
                || coverage.unavailable_roots > 16
                || coverage.invalid_metadata > 8192
            {
                return Err(invalid("installation coverage exceeds bounds"));
            }
            let mut installations = HashSet::new();
            for app in &installed.apps {
                if app.id.len() != 64
                    || !app
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !installations.insert(&app.id)
                    || app.family.is_empty()
                    || app.family.len() > 64
                    || !app.family.as_bytes()[0].is_ascii_lowercase()
                    || app.family.ends_with('_')
                    || app.family.contains("__")
                    || !app
                        .family
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    || app.running_instances > c.candidate_process_count
                    || app
                        .version
                        .as_deref()
                        .is_some_and(|version| !is_public_installation_version(version))
                {
                    return Err(invalid("invalid installed application observation"));
                }
            }
        }
        Ok(())
    }
}

/// Conservative public version-display grammar. This validates an optional
/// hint; it does not authenticate a publisher, installation or executable.
pub fn is_public_installation_version(value: &str) -> bool {
    let bytes = value.as_bytes();
    let prefix = bytes.first().is_some_and(|byte| byte.is_ascii_digit())
        || (bytes.first() == Some(&b'v') && bytes.get(1).is_some_and(|byte| byte.is_ascii_digit()));
    if value.is_empty()
        || value.len() > 64
        || value.trim() != value
        || !prefix
        || !bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b' ' | b'_' | b'+' | b'-' | b'(' | b')')
        })
    {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    ![
        "auth",
        "bearer",
        "token",
        "secret",
        "credential",
        "password",
        "private",
        "api_key",
        "api-key",
        "api key",
        "apikey",
        "access_key",
        "access-key",
        "access key",
        "accesskey",
        "session",
        "cookie",
        "sk-",
        "sk_",
        "hf_",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

#[cfg(test)]
mod installed_wire_tests {
    use super::*;
    use serde_json::json;

    fn inventory() -> ClientInventory {
        serde_json::from_value(json!({
            "schema":"chinwag-client-inventory/v1", "observed_at_unix_ms":1,
            "host_label":"Studio",
            "coverage":{"pid_capacity":4096,"candidate_capacity":128,"sampled_pid_count":10,
                "candidate_process_count":0,"omitted_candidate_count":0,"raced_processes":0,
                "permission_denied_processes":0,"unavailable_processes":0,"invalid_process_metadata":0,
                "unclassified_interpreters":0,"unresolved_components":0,"pid_capacity_reached":false,
                "candidate_capacity_reached":false},
            "clients":[],
            "installations":{"observed_at_unix_ms":2,"apps":[{"id":"a".repeat(64),
                "family":"grok_bot","kind":"application","running_instances":0,
                "state":"installed_unverified"}],
                "coverage":{"entry_capacity":4096,"entries_examined":5,"installation_capacity":128,
                    "capacity_reached":false,"unavailable_roots":0,"invalid_metadata":0}}
        })).unwrap()
    }

    #[test]
    fn old_runtime_inventory_is_accepted_without_inventing_installed_results() {
        let mut value = serde_json::to_value(inventory()).unwrap();
        value.as_object_mut().unwrap().remove("installations");
        let old: ClientInventory = serde_json::from_value(value).unwrap();
        assert!(old.installations.is_none());
        old.validate().unwrap();
    }

    #[test]
    fn installed_unknown_claims_paths_or_connected_states_are_rejected() {
        let original = serde_json::to_value(inventory()).unwrap();
        let mut path = original.clone();
        path["installations"]["apps"][0]["canonical_path"] = json!("/private/marker");
        assert!(serde_json::from_value::<ClientInventory>(path).is_err());
        let mut connected = original;
        connected["installations"]["apps"][0]["state"] = json!("connected");
        assert!(serde_json::from_value::<ClientInventory>(connected).is_err());
    }

    #[test]
    fn installed_duplicate_identity_and_impossible_counts_are_rejected() {
        let mut value = inventory();
        value.validate().unwrap();
        let installed = value.installations.as_mut().unwrap();
        installed.apps.push(installed.apps[0].clone());
        assert!(value.validate().is_err());
        let mut value = inventory();
        value.installations.as_mut().unwrap().apps[0].running_instances = 1;
        assert!(value.validate().is_err());
        let mut value = inventory();
        value
            .installations
            .as_mut()
            .unwrap()
            .coverage
            .entries_examined = 4097;
        assert!(value.validate().is_err());
    }

    #[test]
    fn old_installation_rows_omit_optional_details_without_inventing_them() {
        let value = inventory();
        let app = &value.installations.as_ref().unwrap().apps[0];
        assert!(app.location.is_none());
        assert!(app.version.is_none());
        let wire = serde_json::to_value(&value).unwrap();
        assert!(wire["installations"]["apps"][0].get("location").is_none());
        assert!(wire["installations"]["apps"][0].get("version").is_none());
        value.validate().unwrap();
    }

    #[test]
    fn public_location_enum_round_trips_both_scopes_and_rejects_unknown_paths() {
        for (location, wire) in [
            (
                InstallationLocation::SharedApplications,
                "shared_applications",
            ),
            (InstallationLocation::UserApplications, "user_applications"),
        ] {
            let mut value = inventory();
            value.installations.as_mut().unwrap().apps[0].location = Some(location);
            let encoded = serde_json::to_value(&value).unwrap();
            assert_eq!(encoded["installations"]["apps"][0]["location"], wire);
            let parsed: ClientInventory = serde_json::from_value(encoded).unwrap();
            parsed.validate().unwrap();
            assert_eq!(
                parsed.installations.unwrap().apps[0].location,
                Some(location)
            );
        }
        for unsupported in [
            "other",
            "/Users/private/Applications",
            "connected",
            "SharedApplications",
        ] {
            let mut value = serde_json::to_value(inventory()).unwrap();
            value["installations"]["apps"][0]["location"] = json!(unsupported);
            assert!(serde_json::from_value::<ClientInventory>(value).is_err());
        }
    }

    #[test]
    fn public_version_accepts_bounded_numeric_versions_and_rejects_invalid_hints() {
        for version in [
            "1",
            "v1",
            "1.2.3",
            "2026.10.30",
            "v1.2-beta_4+abcdef",
            "1.2.3 (42)",
        ] {
            assert!(is_public_installation_version(version), "{version}");
            let mut value = inventory();
            value.installations.as_mut().unwrap().apps[0].version = Some(version.into());
            value.validate().unwrap();
        }
        for version in [
            "",
            " ",
            " 1.2",
            "1.2 ",
            "v",
            "V1.2",
            "preview",
            "vbeta",
            "1/Users",
            "1\\private",
            "1:secret",
            "1\n2",
            "1\t2",
            "1.2β",
            "1.0 PRIVATE_MARKER",
            "v1_auth_value",
            "1.0 bearer abc",
            "1.0 api-key abc",
            "1.0 sk-example",
            "1.0 cookie",
            "1.0 session",
        ] {
            assert!(!is_public_installation_version(version), "{version:?}");
            let mut value = inventory();
            value.installations.as_mut().unwrap().apps[0].version = Some(version.into());
            assert!(value.validate().is_err(), "{version:?}");
        }
    }

    #[test]
    fn public_version_byte_cap_is_enforced_at_the_wire_boundary() {
        let mut value = inventory();
        let at_limit = format!("1{}", "a".repeat(63));
        assert_eq!(at_limit.len(), 64);
        value.installations.as_mut().unwrap().apps[0].version = Some(at_limit.clone());
        value.validate().unwrap();
        value.installations.as_mut().unwrap().apps[0].version = Some(format!("{at_limit}a"));
        assert!(value.validate().is_err());
    }
}
