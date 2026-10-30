//! Explicit metadata discovery and a least-disclosure HTTP projection.
//!
//! Raw process metadata stays inside this module. These rows are observations,
//! never connector bindings, protocol handshakes or authenticated client identities.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use crate::onboarding::{OnboardingService, observed_installation_id};
use chinwag_bus_client::{
    ClientInventory, ClientKind, DiscoveredClient, DiscoveryCoverage, DiscoveryState,
    InstallationCoverage, InstallationInventory, InstallationLocation, InstallationState,
    InstalledClient, is_public_installation_version,
};
use chinwag_client_discovery::{
    CANDIDATE_CAPACITY, ClientCandidate, InventorySnapshot, PID_CAPACITY, ProcessBirth, ProcessRole,
};
use chinwag_connector_registry::{Limits, Registry};
use chinwag_connectors::{BuiltinConnector, ConnectorHost};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum DiscoveryFailure {
    #[error("a metadata discovery scan is already active; this request has not started")]
    Busy,
    #[error("client metadata discovery is unavailable")]
    Unavailable,
    #[error("client metadata snapshot failed validation")]
    InvalidSnapshot,
}

pub trait InventorySource: Send + Sync {
    fn snapshot(&self) -> std::result::Result<InventorySnapshot, DiscoveryFailure>;

    fn installed(&self) -> Option<chinwag_client_discovery::InstalledSnapshot> {
        None
    }
}

pub struct NativeInventorySource;

// All production providers in this process share the actual native-scan gate.
static NATIVE_SCAN: Mutex<()> = Mutex::new(());

impl InventorySource for NativeInventorySource {
    fn snapshot(&self) -> std::result::Result<InventorySnapshot, DiscoveryFailure> {
        let _guard = NATIVE_SCAN.try_lock().map_err(lock_failure)?;
        chinwag_client_discovery::snapshot().map_err(|_| DiscoveryFailure::Unavailable)
    }

    fn installed(&self) -> Option<chinwag_client_discovery::InstalledSnapshot> {
        let _guard = NATIVE_SCAN.try_lock().ok()?;
        chinwag_client_discovery::installed_snapshot().ok()
    }
}

pub struct DiscoveryService {
    source: Arc<dyn InventorySource>,
    host: Mutex<ConnectorHost>,
}

impl DiscoveryService {
    pub fn new(source: Arc<dyn InventorySource>) -> Self {
        let mut host = ConnectorHost::new(
            Registry::new(Limits {
                max_grants: 1,
                max_bindings: 1,
                max_lease: Duration::from_secs(60),
            })
            .expect("fixed registry limits are valid"),
        );
        host.set_enabled(BuiltinConnector::NativeClients, true)
            .expect("initial connector generation is available");
        Self {
            source,
            host: Mutex::new(host),
        }
    }

    pub fn inventory(&self) -> std::result::Result<ClientInventory, DiscoveryFailure> {
        self.inventory_with_onboarding(None)
    }

    /// Reuses this explicit scan's raw observations. Cache failure disables
    /// opening, while a healthy metadata response remains available.
    pub fn inventory_with_onboarding(
        &self,
        onboarding: Option<&OnboardingService>,
    ) -> std::result::Result<ClientInventory, DiscoveryFailure> {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut host = match self.host.try_lock() {
            Ok(host) => host,
            Err(error) => {
                if let Some(onboarding) = onboarding {
                    let _ = onboarding.invalidate();
                }
                return Err(lock_failure(error));
            }
        };
        let result = self.collect_inventory(&mut host, deadline);
        if let Some(onboarding) = onboarding {
            let cached = match &result {
                Ok((_, process, Some(installed))) if Instant::now() < deadline => {
                    onboarding.observe(process, installed).is_ok() && Instant::now() < deadline
                }
                _ => false,
            };
            if !cached {
                let _ = onboarding.invalidate();
            }
        }
        // Keep scan and cache publication under the same existing scan gate so
        // an older completion cannot overwrite a newer observation's targets.
        drop(host);
        result.map(|(inventory, _, _)| inventory)
    }

    fn collect_inventory(
        &self,
        host: &mut ConnectorHost,
        deadline: Instant,
    ) -> std::result::Result<
        (
            ClientInventory,
            InventorySnapshot,
            Option<chinwag_client_discovery::InstalledSnapshot>,
        ),
        DiscoveryFailure,
    > {
        let now = Instant::now();
        let invocation = host
            .begin(BuiltinConnector::NativeClients, deadline, now)
            .map_err(|_| DiscoveryFailure::Unavailable)?;
        host.clients(&invocation, Instant::now, || {
            let snapshot = self.source.snapshot()?;
            let installed = self.source.installed();
            let installations = installed
                .as_ref()
                .map(|installed| project_installed(&snapshot, installed))
                .transpose()?;
            let mut inventory = project(snapshot.clone())?;
            inventory.installations = installations;
            inventory
                .validate()
                .map_err(|_| DiscoveryFailure::InvalidSnapshot)?;
            if serde_json::to_vec(&inventory)
                .map_err(|_| DiscoveryFailure::InvalidSnapshot)?
                .len()
                > 900_000
            {
                return Err(DiscoveryFailure::InvalidSnapshot);
            }
            Ok((inventory, snapshot, installed))
        })
        .map_err(|_| DiscoveryFailure::Unavailable)?
    }
}

fn project_installed(
    process: &InventorySnapshot,
    installed: &chinwag_client_discovery::InstalledSnapshot,
) -> std::result::Result<InstallationInventory, DiscoveryFailure> {
    use chinwag_client_discovery::{DirectoryStatus, InstallationKind};
    let merged = chinwag_client_discovery::merge_installed(process, installed);
    let apps = merged
        .installations
        .into_iter()
        .map(|row| {
            let family = serde_json::to_value(row.installation.family)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or(DiscoveryFailure::InvalidSnapshot)?;
            Ok(InstalledClient {
                id: observed_installation_id(process, &row.installation),
                family,
                kind: match row.installation.kind {
                    InstallationKind::Application => ClientKind::Application,
                    InstallationKind::CommandLine => ClientKind::CommandLine,
                },
                running_instances: row.observed_instances.len(),
                state: InstallationState::InstalledUnverified,
                location: public_installation_location(&row.installation),
                version: public_installation_version(&row.installation),
            })
        })
        .collect::<std::result::Result<Vec<_>, DiscoveryFailure>>()?;
    let coverage = &installed.coverage;
    Ok(InstallationInventory {
        observed_at_unix_ms: installed.observed_at_unix_ms,
        apps,
        coverage: InstallationCoverage {
            entry_capacity: chinwag_client_discovery::APP_ENTRY_CAPACITY * 2,
            entries_examined: coverage
                .application_directories
                .iter()
                .map(|directory| directory.entries_examined)
                .sum(),
            installation_capacity: coverage.installation_capacity,
            capacity_reached: coverage.installation_cap_reached
                || coverage
                    .application_directories
                    .iter()
                    .any(|directory| directory.entry_cap_reached || directory.app_cap_reached),
            unavailable_roots: coverage
                .application_directories
                .iter()
                .filter(|directory| {
                    matches!(
                        directory.status,
                        DirectoryStatus::Unavailable | DirectoryStatus::Unsafe
                    )
                })
                .count(),
            invalid_metadata: coverage
                .invalid_metadata
                .saturating_add(coverage.oversized_plists)
                .saturating_add(coverage.changed_during_read)
                .saturating_add(coverage.unsafe_paths)
                .saturating_add(coverage.unavailable_paths),
        },
    })
}

fn public_installation_location(
    installation: &chinwag_client_discovery::Installation,
) -> Option<InstallationLocation> {
    if installation.kind != chinwag_client_discovery::InstallationKind::Application {
        return None;
    }
    let parent = installation.canonical_path.parent()?.as_os_str().to_str()?;
    if parent == "/Applications" {
        return Some(InstallationLocation::SharedApplications);
    }
    let user = parent
        .strip_prefix("/Users/")?
        .strip_suffix("/Applications")?;
    (!user.is_empty()
        && user.len() <= 256
        && !matches!(user, "." | "..")
        && !user.contains('/')
        && !user.chars().any(char::is_control))
    .then_some(InstallationLocation::UserApplications)
}

fn public_installation_version(
    installation: &chinwag_client_discovery::Installation,
) -> Option<String> {
    let raw = installation.version.as_deref()?;
    if !raw.is_ascii() || raw.chars().any(char::is_control) {
        return None;
    }
    let version = raw.trim();
    is_public_installation_version(version).then(|| version.to_owned())
}

fn lock_failure<T>(error: TryLockError<T>) -> DiscoveryFailure {
    match error {
        TryLockError::WouldBlock => DiscoveryFailure::Busy,
        TryLockError::Poisoned(_) => DiscoveryFailure::Unavailable,
    }
}

type BirthKey = (u32, u64, u32);

fn birth_key(birth: ProcessBirth) -> BirthKey {
    (birth.pid, birth.start_seconds, birth.start_microseconds)
}

fn host_label(raw: &str) -> std::result::Result<String, DiscoveryFailure> {
    let mut label = String::new();
    for character in raw.chars() {
        let character = if character.is_control() || matches!(character, '/' | '\\') {
            '_'
        } else {
            character
        };
        if label.len() + character.len_utf8() > 128 {
            break;
        }
        label.push(character);
    }
    if label.trim().is_empty() {
        return Err(DiscoveryFailure::InvalidSnapshot);
    }
    Ok(label.trim().to_owned())
}

fn opaque_id(snapshot: &InventorySnapshot, root: &ClientCandidate) -> String {
    let mut hash = Sha256::new();
    hash.update(b"chinwag-client-observation-id/v1\0");
    // Length-prefix strings so neither paths nor host labels can shift fields.
    for field in [
        snapshot.host.label.as_bytes(),
        snapshot.host.boot_uuid.as_bytes(),
        root.executable.as_bytes(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.update(root.birth.pid.to_be_bytes());
    hash.update(root.birth.start_seconds.to_be_bytes());
    hash.update(root.birth.start_microseconds.to_be_bytes());
    format!("{:x}", hash.finalize())
}

fn component_root(
    component: &ClientCandidate,
    rows: &BTreeMap<BirthKey, &ClientCandidate>,
) -> Option<BirthKey> {
    let declared = birth_key(component.instance_root?);
    let root = *rows.get(&declared)?;
    if root.role != ProcessRole::MainApplication
        || root.instance_root != Some(root.birth)
        || root.family != component.family
        || root.outer_application.is_none()
        || root.outer_application != component.outer_application
    {
        return None;
    }
    let mut current = component;
    let mut seen = BTreeSet::new();
    while seen.insert(birth_key(current.birth)) {
        let parent_birth = current.sampled_parent_birth?;
        let parent = *rows.get(&birth_key(parent_birth))?;
        if parent.birth.pid != current.parent_pid
            || parent.uid != current.uid
            || parent.family != component.family
            || parent.outer_application != component.outer_application
            || (parent.birth.start_seconds, parent.birth.start_microseconds)
                > (
                    current.birth.start_seconds,
                    current.birth.start_microseconds,
                )
        {
            return None;
        }
        if parent.birth == root.birth {
            return Some(declared);
        }
        if parent.role != ProcessRole::BundledComponent || parent.instance_root != Some(root.birth)
        {
            return None;
        }
        current = parent;
    }
    None
}

fn project(snapshot: InventorySnapshot) -> std::result::Result<ClientInventory, DiscoveryFailure> {
    let coverage = &snapshot.coverage;
    let count = snapshot.candidates.len();
    if snapshot.observed_at_unix_ms == 0
        || coverage.pid_capacity == 0
        || coverage.pid_capacity > PID_CAPACITY
        || coverage.candidate_capacity == 0
        || coverage.candidate_capacity > CANDIDATE_CAPACITY
        || coverage.sampled_pid_count > coverage.pid_capacity
        || count > coverage.candidate_capacity
        || count > coverage.sampled_pid_count
        || coverage.omitted_candidate_count > coverage.sampled_pid_count.saturating_sub(count)
        || [
            coverage.raced_processes,
            coverage.permission_denied_processes,
            coverage.unavailable_processes,
            coverage.invalid_process_metadata,
            coverage.unclassified_interpreters,
        ]
        .iter()
        .any(|&value| value > coverage.sampled_pid_count)
        || (coverage.omitted_candidate_count > 0 && !coverage.candidate_capacity_reached)
    {
        return Err(DiscoveryFailure::InvalidSnapshot);
    }
    let host_label = host_label(&snapshot.host.label)?;
    let mut rows = BTreeMap::new();
    let mut pids = BTreeSet::new();
    for row in &snapshot.candidates {
        if row.uid != snapshot.uid
            || row.birth.pid == 0
            || row.birth.start_seconds == 0
            || row.birth.start_microseconds >= 1_000_000
            || !pids.insert(row.birth.pid)
            || rows.insert(birth_key(row.birth), row).is_some()
        {
            return Err(DiscoveryFailure::InvalidSnapshot);
        }
    }
    let mut roots: BTreeMap<BirthKey, (ClientKind, usize)> = BTreeMap::new();
    for row in &snapshot.candidates {
        if row.instance_root != Some(row.birth) {
            continue;
        }
        let kind = match row.role {
            ProcessRole::MainApplication if row.outer_application.is_some() => {
                ClientKind::Application
            }
            ProcessRole::CommandLine if row.outer_application.is_none() => ClientKind::CommandLine,
            _ => continue,
        };
        roots.insert(birth_key(row.birth), (kind, 1));
    }
    let mut unresolved_components = 0;
    for row in &snapshot.candidates {
        if row.role != ProcessRole::BundledComponent {
            continue;
        }
        match component_root(row, &rows).and_then(|root| roots.get_mut(&root)) {
            Some((_, components)) => *components += 1,
            None => unresolved_components += 1,
        }
    }
    let clients = roots
        .into_iter()
        .map(|(key, (kind, component_count))| {
            let root = rows.get(&key).ok_or(DiscoveryFailure::InvalidSnapshot)?;
            let family = serde_json::to_value(root.family)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or(DiscoveryFailure::InvalidSnapshot)?;
            Ok(DiscoveredClient {
                id: opaque_id(&snapshot, root),
                family,
                kind,
                state: DiscoveryState::DetectedUnverified,
                component_count,
            })
        })
        .collect::<std::result::Result<Vec<_>, DiscoveryFailure>>()?;
    let inventory = ClientInventory {
        schema: "chinwag-client-inventory/v1".to_owned(),
        observed_at_unix_ms: snapshot.observed_at_unix_ms,
        host_label,
        coverage: DiscoveryCoverage {
            pid_capacity: coverage.pid_capacity,
            candidate_capacity: coverage.candidate_capacity,
            sampled_pid_count: coverage.sampled_pid_count,
            candidate_process_count: count,
            omitted_candidate_count: coverage.omitted_candidate_count,
            raced_processes: coverage.raced_processes,
            permission_denied_processes: coverage.permission_denied_processes,
            unavailable_processes: coverage.unavailable_processes,
            invalid_process_metadata: coverage.invalid_process_metadata,
            unclassified_interpreters: coverage.unclassified_interpreters,
            unresolved_components,
            pid_capacity_reached: coverage.pid_capacity_reached,
            candidate_capacity_reached: coverage.candidate_capacity_reached,
        },
        clients,
        installations: None,
    };
    inventory
        .validate()
        .map_err(|_| DiscoveryFailure::InvalidSnapshot)?;
    Ok(inventory)
}

#[cfg(test)]
pub(crate) fn fixture_snapshot() -> InventorySnapshot {
    use chinwag_client_discovery::{CandidateState, ClientFamily, Coverage, HostObservation};
    let birth = ProcessBirth {
        pid: 948_123,
        start_seconds: 100,
        start_microseconds: 432_187,
    };
    let helper_birth = ProcessBirth {
        pid: 948_124,
        start_seconds: 101,
        start_microseconds: 432_188,
    };
    let root = ClientCandidate {
        family: ClientFamily::ChatgptDesktop,
        role: ProcessRole::MainApplication,
        state: CandidateState::DetectedUnverified,
        birth,
        parent_pid: 1,
        uid: 887_321,
        process_group: 948_123,
        executable: "/Applications/Private-marker-client.app/Contents/MacOS/Private-marker-client"
            .to_owned(),
        outer_application: Some("/Applications/Private-marker-client.app".to_owned()),
        sampled_parent_birth: None,
        instance_root: Some(birth),
    };
    let mut helper = root.clone();
    helper.role = ProcessRole::BundledComponent;
    helper.birth = helper_birth;
    helper.parent_pid = birth.pid;
    helper.sampled_parent_birth = Some(birth);
    helper.executable =
        "/Applications/Private-marker-client.app/Contents/Resources/nested-codex".to_owned();
    InventorySnapshot {
        observed_at_unix_ms: 1_793_398_000_123,
        host: HostObservation {
            label: "observed-fixture-host".to_owned(),
            boot_uuid: "private-boot-identity-marker".to_owned(),
        },
        uid: 887_321,
        coverage: Coverage {
            pid_capacity: PID_CAPACITY,
            candidate_capacity: CANDIDATE_CAPACITY,
            sampled_pid_count: 8,
            raced_processes: 1,
            unclassified_interpreters: 2,
            ..Coverage::default()
        },
        candidates: vec![root, helper],
        limitations: vec!["private-raw-diagnostic-marker".to_owned()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed_fixture() -> chinwag_client_discovery::InstalledSnapshot {
        use chinwag_client_discovery::*;
        InstalledSnapshot {
            observed_at_unix_ms: 1_793_398_000_321,
            installations: vec![Installation {
                id: "a".repeat(64),
                family: ClientFamily::ChatgptDesktop,
                kind: InstallationKind::Application,
                match_basis: catalogue::InstallationMatch::PublicBundleIdentity,
                canonical_path: "/Applications/Private-marker-client.app".into(),
                observed_paths: vec!["/Applications/Private-marker-client.app".into()],
                display_name: "Private-marker-client".into(),
                bundle_id: Some("private-bundle-marker".into()),
                version: Some("private-version-marker".into()),
                executable_path:
                    "/Applications/Private-marker-client.app/Contents/MacOS/Private-marker-client"
                        .into(),
                executable: ExecutableMetadata {
                    device: 1,
                    inode: 2,
                    size: 100,
                    modified_seconds: 1,
                    modified_nanoseconds: 0,
                    mode: 0o755,
                    format: ExecutableFormat::MachO,
                },
                metadata_fingerprint: "private-fingerprint-marker".into(),
            }],
            coverage: InstalledCoverage {
                installation_capacity: 128,
                ..InstalledCoverage::default()
            },
            limitations: vec!["private-install-diagnostic-marker".into()],
        }
    }

    #[test]
    fn installed_projection_is_redacted_host_qualified_and_does_not_claim_connection() {
        let process = fixture_snapshot();
        let installed = installed_fixture();
        let projection = project_installed(&process, &installed).unwrap();
        assert_eq!(projection.apps.len(), 1);
        assert_eq!(projection.apps[0].running_instances, 1);
        assert_eq!(
            projection.apps[0].state,
            InstallationState::InstalledUnverified
        );
        let json = serde_json::to_string(&projection).unwrap();
        for private in [
            "Private-marker",
            "private-",
            "canonical_path",
            "executable",
            "bundle_id",
            "inode",
            "948123",
        ] {
            assert!(
                !json.contains(private),
                "raw installation data escaped: {private}"
            );
        }
        let mut other_host = process.clone();
        other_host.host.label = "another-host".into();
        assert_ne!(
            projection.apps[0].id,
            project_installed(&other_host, &installed).unwrap().apps[0].id
        );
        let mut no_running = process;
        no_running.candidates.clear();
        no_running.coverage.pid_capacity_reached = true;
        assert_eq!(
            project_installed(&no_running, &installed).unwrap().apps[0].running_instances,
            0
        );
    }

    #[test]
    fn installation_copy_hints_are_coarse_bounded_and_never_expose_location_names() {
        let process = fixture_snapshot();
        for (path, expected) in [
            (
                "/Applications/Private-marker-client.app",
                Some(InstallationLocation::SharedApplications),
            ),
            (
                "/Users/private-account-marker/Applications/Private-marker-client.app",
                Some(InstallationLocation::UserApplications),
            ),
            ("/Applications/nested/Private-marker-client.app", None),
            (
                "/Users/private-account-marker/Private/Private-marker-client.app",
                None,
            ),
            (
                "/Users/account/../Applications/Private-marker-client.app",
                None,
            ),
            ("/Network/Applications/Private-marker-client.app", None),
        ] {
            let mut installed = installed_fixture();
            installed.installations[0].canonical_path = path.into();
            installed.installations[0].version = Some("  v1.2.3-beta+4 (arm64)  ".into());
            let projection = project_installed(&process, &installed).unwrap();
            assert_eq!(projection.apps[0].location, expected);
            assert_eq!(
                projection.apps[0].version.as_deref(),
                Some("v1.2.3-beta+4 (arm64)")
            );
            let raw = serde_json::to_string(&projection).unwrap();
            for forbidden in [
                "/Applications",
                "/Users",
                "private-account-marker",
                "Private-marker",
                "bundle_id",
                "executable",
                "canonical_path",
            ] {
                assert!(
                    !raw.contains(forbidden),
                    "raw metadata escaped through copy hints: {forbidden}"
                );
            }
        }
        let mut installed = installed_fixture();
        installed.installations[0].kind = chinwag_client_discovery::InstallationKind::CommandLine;
        assert_eq!(
            project_installed(&process, &installed).unwrap().apps[0].location,
            None
        );
    }

    #[test]
    fn unsafe_or_unknown_versions_are_suppressed_instead_of_rejected_inventory() {
        let process = fixture_snapshot();
        let mut installed = installed_fixture();
        let oversized = "1".repeat(65);
        for unsafe_version in [
            "private-version-marker",
            "v",
            "vNext",
            "1.2/path",
            "1:2",
            "1.0\n",
            "\t1.0",
            "v1.0 🦀",
            "1.0 api key marker",
            "1.0 credential marker",
            "1.0;build",
            oversized.as_str(),
        ] {
            installed.installations[0].version = Some(unsafe_version.into());
            let projection = project_installed(&process, &installed).unwrap();
            assert_eq!(
                projection.apps[0].version, None,
                "unsafe public version was kept: {unsafe_version}"
            );
        }
        installed.installations[0].version = None;
        assert_eq!(
            project_installed(&process, &installed).unwrap().apps[0].version,
            None
        );
        installed.installations[0].version = Some("1".repeat(64));
        assert_eq!(
            project_installed(&process, &installed).unwrap().apps[0]
                .version
                .as_ref()
                .map(String::len),
            Some(64)
        );
    }

    #[test]
    fn plugin_collects_each_source_once_and_installed_failure_preserves_running_inventory() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Source {
            processes: AtomicUsize,
            installations: AtomicUsize,
            available: bool,
        }
        impl InventorySource for Source {
            fn snapshot(&self) -> std::result::Result<InventorySnapshot, DiscoveryFailure> {
                self.processes.fetch_add(1, Ordering::SeqCst);
                Ok(fixture_snapshot())
            }
            fn installed(&self) -> Option<chinwag_client_discovery::InstalledSnapshot> {
                self.installations.fetch_add(1, Ordering::SeqCst);
                self.available.then(installed_fixture)
            }
        }
        for available in [false, true] {
            let source = Arc::new(Source {
                processes: AtomicUsize::new(0),
                installations: AtomicUsize::new(0),
                available,
            });
            let service = DiscoveryService::new(source.clone());
            let result = service.inventory().unwrap();
            assert_eq!(result.clients.len(), 1);
            assert_eq!(result.installations.is_some(), available);
            assert_eq!(source.processes.load(Ordering::SeqCst), 1);
            assert_eq!(source.installations.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn projection_groups_sampled_helpers_and_does_not_expose_process_identity() {
        let projected = project(fixture_snapshot()).unwrap();
        assert_eq!(projected.clients.len(), 1);
        assert_eq!(projected.clients[0].component_count, 2);
        assert_eq!(projected.coverage.candidate_process_count, 2);
        assert_eq!(projected.coverage.unresolved_components, 0);
        assert_eq!(projected.coverage.raced_processes, 1);
        let value = serde_json::to_value(&projected).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        let row = &value["clients"][0];
        assert_eq!(row.as_object().unwrap().len(), 5);
        assert_eq!(row["state"], "detected_unverified");
        assert!(
            projected.clients[0].id.len() == 64
                && projected.clients[0]
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        let text = value.to_string();
        for secret in [
            "Private-marker-client",
            "private-boot-identity-marker",
            "private-raw-diagnostic-marker",
            "948123",
            "887321",
            "executable",
            "parent_pid",
            "boot_uuid",
            "process_group",
        ] {
            assert!(!text.contains(secret), "raw metadata escaped: {secret}");
        }
    }

    #[test]
    fn orphaned_or_forged_component_roots_are_unresolved_not_agents() {
        let mut raw = fixture_snapshot();
        raw.candidates[1].sampled_parent_birth = None;
        let projected = project(raw.clone()).unwrap();
        assert_eq!(projected.clients.len(), 1);
        assert_eq!(projected.clients[0].component_count, 1);
        assert_eq!(projected.coverage.unresolved_components, 1);
        raw.candidates.remove(0);
        raw.candidates[0].instance_root = Some(raw.candidates[0].birth);
        let projected = project(raw).unwrap();
        assert!(projected.clients.is_empty());
        assert_eq!(projected.coverage.unresolved_components, 1);
    }

    #[test]
    fn ids_are_stable_for_one_birth_and_change_after_replacement() {
        let raw = fixture_snapshot();
        let first = project(raw.clone()).unwrap();
        assert_eq!(
            first.clients[0].id,
            project(raw.clone()).unwrap().clients[0].id
        );
        let mut changed = raw;
        changed.candidates.truncate(1);
        changed.candidates[0].birth.start_seconds += 1;
        changed.candidates[0].instance_root = Some(changed.candidates[0].birth);
        assert_ne!(first.clients[0].id, project(changed).unwrap().clients[0].id);
    }

    #[test]
    fn caps_and_invalid_snapshot_counts_never_become_complete_success() {
        let mut raw = fixture_snapshot();
        raw.coverage.candidate_capacity_reached = true;
        raw.coverage.pid_capacity_reached = true;
        raw.coverage.omitted_candidate_count = 2;
        let projected = project(raw.clone()).unwrap();
        assert!(projected.coverage.pid_capacity_reached);
        assert!(projected.coverage.candidate_capacity_reached);
        assert_eq!(projected.coverage.omitted_candidate_count, 2);
        raw.coverage.sampled_pid_count = 1;
        assert_eq!(project(raw).unwrap_err(), DiscoveryFailure::InvalidSnapshot);
    }

    #[test]
    fn observed_host_label_is_bounded_and_has_no_controls_or_path_separators() {
        let mut raw = fixture_snapshot();
        raw.host.label = format!("/fixture\\host\n{}", "é".repeat(128));
        let label = project(raw).unwrap().host_label;
        assert!(
            !label
                .chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\'))
        );
        assert!(label.len() <= 128);
    }
}
