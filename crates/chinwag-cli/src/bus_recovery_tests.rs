use super::*;
use crate::bus_recovery_run::{diagnose, read_selected, run_recovery_cli};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    root: tempfile::TempDir,
    record: DeploymentRecord,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let parent = std::env::var_os("CHINWAG_RECOVERY_TEST_ROOT")
            .expect("set owned test root under /Users, not /private/tmp");
        let root = tempfile::Builder::new()
            .prefix("recovery-")
            .tempdir_in(parent)
            .unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let repo = root.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let binary = root.path().join("chinwag");
        fs::write(&binary, b"fixture binary bytes; never execute").unwrap();
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = |n| iroh::SecretKey::from_bytes(&[n; 32]).public().to_string();
        let label = format!(
            "sh.chinwag.nonexistent.recovery-fixture-{}",
            std::process::id()
        );
        let plist = root.path().join(format!("{label}.plist"));
        let record = DeploymentRecord {
            schema: SCHEMA.into(),
            deployment_id: "recovery-test".into(),
            revision: 1,
            captured_at_unix: t - 1,
            expires_at_unix: t + 300,
            node_role: NodeRole::BusNode,
            host_binding: "intentional-nonmatching-host".into(),
            repository: repo.to_str().unwrap().into(),
            service_domain: format!("gui/{}", rustix::process::geteuid().as_raw()),
            service_label: label.clone(),
            service_plist: plist.to_str().unwrap().into(),
            binary_path: binary.to_str().unwrap().into(),
            binary_sha256: format!("{:x}", Sha256::digest(fs::read(&binary).unwrap())),
            source_commit: "d326c7129979ca43499547842daac076d80fac35".into(),
            local_endpoint_id: id(1),
            peer_endpoint_id: id(2),
            coordinator_endpoint_id: id(3),
            coordinator_origin: "https://coordinator.example.test".into(),
            selected_relay_origin: "https://relay.example.test".into(),
            expected_relay_origin: "https://relay.example.test".into(),
            configuration_id: "fixture-generation".into(),
            generation: 1,
            route_lifecycle: RouteLifecycle::Temporary,
            cloud_account_reference: "fixture-account-reference".into(),
            required_cloud_capability: "relay-read".into(),
            captured_failure: Some(CapturedFailure {
                category: "historical_nxdomain".into(),
                observed_at_unix: t - 10,
                evidence_sha256: "a".repeat(64),
            }),
        };
        fs::write(plist,serde_json::to_vec(&serde_json::json!({"Label":label,"ProgramArguments":[record.binary_path,"bus","daemon"]})).unwrap()).unwrap();
        let path = root.path().join("deployment.json");
        let fixture = Self { root, record, path };
        fixture.save();
        fixture
    }
    fn save(&self) {
        fs::write(&self.path, serde_json::to_vec(&self.record).unwrap()).unwrap();
    }
    fn diagnose(&self, offline: bool) -> Diagnosis {
        diagnose(self.path.to_str().unwrap(), offline)
    }
    fn snapshot(&self) -> Vec<(PathBuf, Vec<u8>, u32)> {
        fn walk(root: &Path, path: &Path, out: &mut Vec<(PathBuf, Vec<u8>, u32)>) {
            let m = fs::symlink_metadata(path).unwrap();
            if m.is_dir() {
                out.push((
                    path.strip_prefix(root).unwrap().into(),
                    vec![],
                    m.permissions().mode(),
                ));
                for e in fs::read_dir(path).unwrap() {
                    walk(root, &e.unwrap().path(), out);
                }
            } else if m.is_file() {
                out.push((
                    path.strip_prefix(root).unwrap().into(),
                    fs::read(path).unwrap(),
                    m.permissions().mode(),
                ));
            }
        }
        let mut out = vec![];
        walk(self.root.path(), self.root.path(), &mut out);
        out.sort();
        out
    }
}
fn check(report: &Diagnosis, name: &str) -> Conclusion {
    report
        .checks
        .iter()
        .find(|c| c.check == name)
        .unwrap()
        .conclusion
}
#[test]
fn offline_checks_binary_and_configuration_without_creating_bus_state_or_promoting_captures() {
    let f = Fixture::new();
    let before = f.snapshot();
    for _ in 0..2 {
        let d = f.diagnose(true);
        assert_eq!(check(&d, "binary_bytes"), Conclusion::Observed);
        assert_eq!(
            check(&d, "native_route_configuration"),
            Conclusion::Observed
        );
        assert_eq!(check(&d, "route_lifecycle"), Conclusion::Refused);
        assert_eq!(check(&d, "service_job"), Conclusion::Unknown);
        assert_eq!(check(&d, "current_dns"), Conclusion::Unknown);
        assert_eq!(check(&d, "captured_failure"), Conclusion::Unknown);
        assert_eq!(check(&d, "operator_authority"), Conclusion::Unknown);
        assert!(!d.record_claims_authenticated);
        assert_eq!(d.transport_recovery, "UNKNOWN");
        assert!(
            d.checks
                .iter()
                .all(|c| c.expires_at_unix - c.observed_at_unix == OBSERVATION_TTL_SECONDS)
        );
    }
    assert!(!Path::new(&f.record.repository).join(".chinwag").exists());
    assert_eq!(before, f.snapshot());
}
#[test]
fn live_checks_exact_plist_and_named_missing_job_without_executing_selected_binary() {
    let f = Fixture::new();
    let before = f.snapshot();
    let d = f.diagnose(false);
    assert_eq!(check(&d, "binary_bytes"), Conclusion::Observed);
    assert_eq!(check(&d, "service_plist_binding"), Conclusion::Observed);
    assert_eq!(check(&d, "host_role_binding"), Conclusion::Refused);
    assert_eq!(check(&d, "service_job"), Conclusion::Unknown);
    assert_eq!(before, f.snapshot());
}
#[test]
fn stale_record_binary_mismatch_and_missing_record_remain_precise() {
    let mut f = Fixture::new();
    f.record.captured_at_unix = 1;
    f.record.expires_at_unix = 2;
    f.record.captured_failure = None;
    f.record.binary_sha256 = "b".repeat(64);
    f.save();
    let d = f.diagnose(true);
    assert_eq!(check(&d, "record_freshness"), Conclusion::Refused);
    assert_eq!(check(&d, "binary_bytes"), Conclusion::Refused);
    fs::remove_file(&f.path).unwrap();
    let before = f.snapshot();
    let d = f.diagnose(false);
    assert_eq!(check(&d, "deployment_record"), Conclusion::Unknown);
    assert!(d.selected_deployment.is_none());
    assert_eq!(before, f.snapshot());
}
#[test]
fn duplicate_unknown_and_claimed_authority_fields_refuse_before_any_live_probe() {
    for extra in [
        r#", "revision":2"#,
        r#", "authorized":true"#,
        r#", "private_key_path":"/secret""#,
    ] {
        let f = Fixture::new();
        let mut raw = fs::read_to_string(&f.path).unwrap();
        raw.pop();
        raw.push_str(extra);
        raw.push('}');
        fs::write(&f.path, raw).unwrap();
        let before = f.snapshot();
        let d = f.diagnose(false);
        assert_eq!(check(&d, "deployment_record"), Conclusion::Refused);
        assert_eq!(d.checks.len(), 1);
        assert_eq!(before, f.snapshot());
    }
}
#[test]
fn identity_collision_route_mismatch_and_unrelated_service_domains_refuse() {
    let mut f = Fixture::new();
    f.record.peer_endpoint_id = f.record.local_endpoint_id.clone();
    assert_eq!(f.record.validate(), Err("endpoint_identity_collision"));
    f = Fixture::new();
    f.record.expected_relay_origin = "https://different.example.test".into();
    assert_eq!(f.record.validate(), Err("invalid_native_route"));
    f = Fixture::new();
    f.record.service_domain = "gui/0".into();
    assert_eq!(f.record.validate(), Err("unrelated_service_domain"));
    for path in [
        "relative",
        "/Users/a/../secret",
        "/Users//a",
        "/Users/a/./secret",
        "/",
    ] {
        assert!(!absolute_path(path));
    }
}
#[test]
fn explicit_reader_refuses_symlinks_hardlinks_world_writable_and_oversize() {
    let f = Fixture::new();
    let alias = f.root.path().join("alias.json");
    symlink(&f.path, &alias).unwrap();
    assert!(read_selected(alias.to_str().unwrap(), MAX_RECORD_BYTES, true, true).is_err());
    fs::remove_file(&alias).unwrap();
    fs::hard_link(&f.path, &alias).unwrap();
    assert!(read_selected(f.path.to_str().unwrap(), MAX_RECORD_BYTES, true, true).is_err());
    fs::remove_file(&alias).unwrap();
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(read_selected(f.path.to_str().unwrap(), MAX_RECORD_BYTES, true, true).is_err());
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&f.path, vec![b' '; MAX_RECORD_BYTES as usize + 1]).unwrap();
    assert_eq!(
        read_selected(f.path.to_str().unwrap(), MAX_RECORD_BYTES, true, true),
        Err("file_size_limit")
    );
}
#[test]
fn actual_bus_dispatch_and_strict_cli_sop_share_typed_steps_and_have_no_effects() {
    let f = Fixture::new();
    let before = f.snapshot();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let args = vec![
        "recovery".into(),
        "diagnose".into(),
        "--deployment".into(),
        f.path.to_str().unwrap().into(),
        "--offline".into(),
        "--json".into(),
    ];
    assert_eq!(crate::bus_run::run_bus_cli(&args, &mut out, &mut err), 0);
    assert!(err.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["offline"], true);
    out.clear();
    assert_eq!(
        run_recovery_cli(&["sop".into(), "--json".into()], &mut out, &mut err),
        0
    );
    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["steps"].as_array().unwrap().len(), sop_steps().len());
    assert!(
        value["steps"].as_array().unwrap()[1..]
            .iter()
            .all(|s| s["command"].is_null())
    );
    for args in [
        vec!["activate", "--json"],
        vec!["diagnose", "--deployment", "relative", "--json"],
        vec!["sop", "--json", "--json"],
        vec![
            "diagnose",
            "--deployment",
            f.path.to_str().unwrap(),
            "--offline",
            "--offline",
            "--json",
        ],
    ] {
        assert_eq!(
            run_recovery_cli(
                &args.into_iter().map(String::from).collect::<Vec<_>>(),
                &mut vec![],
                &mut vec![]
            ),
            2
        );
    }
    assert_eq!(before, f.snapshot());
}
