// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use chinwag_fleet::{CredentialIsolation, DriverSpec, FleetManifest, SeatLifecycle};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args(args)
        .current_dir(root)
        .env("HOME", root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .env_remove("CHINWAG_INSTANCE_ID")
        .output()
        .unwrap()
}

fn fixture(script: &str) -> (TempDir, FleetManifest, PathBuf) {
    let temp = TempDir::new().unwrap();
    let initialized = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(temp.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", temp.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let binary = temp.path().join("worker");
    fs::write(&binary, format!("#!/bin/sh\n{script}\n")).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let mut manifest = FleetManifest::starter_profile("solo").unwrap();
    manifest.seats[0].lifecycle = SeatLifecycle::ActiveStanding;
    manifest.seats[0].driver = DriverSpec::CliSubprocess {
        executable: binary.display().to_string(),
        argv_template: Vec::new(),
        auth_isolation: CredentialIsolation::NoneLocal,
        env_allowlist: vec!["HOME".into(), "PATH".into()],
        env_overrides: BTreeMap::new(),
        framing: "stdin".into(),
        timeout_secs: 5,
    };
    let path = temp.path().join("fleet.json");
    save(&manifest, &path);
    (temp, manifest, path)
}

fn save(manifest: &FleetManifest, path: &Path) {
    fs::write(path, manifest.to_canonical_json().unwrap()).unwrap();
}

#[test]
fn fleet_init_then_validate_runs_offline_in_a_new_workspace() {
    let temp = TempDir::new().unwrap();
    let initialized = cli(temp.path(), &["fleet", "init", "--profile", "solo"]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let validated = cli(temp.path(), &["fleet", "validate", "--json"]);
    assert!(
        validated.status.success(),
        "{}",
        String::from_utf8_lossy(&validated.stderr)
    );
    let response: Value = serde_json::from_slice(&validated.stdout).unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(response["schema_version"], 1);
    assert!(temp.path().join(".chinwag/fleet.toml").is_file());
    let duplicate = cli(temp.path(), &["fleet", "init", "--profile", "solo"]);
    assert!(!duplicate.status.success());
}

#[test]
fn fleet_status_reports_missing_manifest_without_fabricating_seats() {
    let temp = TempDir::new().unwrap();
    let output = cli(temp.path(), &["fleet", "status", "--json"]);
    assert!(output.status.success());
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["status"], "unconfigured (no fleet manifest)");
    assert_eq!(status["seats"], serde_json::json!([]));
}

#[test]
fn fleet_launch_unknown_paused_and_retired_seats_never_start_a_child() {
    let (temp, mut manifest, path) = fixture("printf executed > marker; printf reply");
    for (seat, lifecycle, error) in [
        ("absent", SeatLifecycle::ActiveStanding, "UnknownSeat"),
        ("default", SeatLifecycle::Paused, "RetiredOrPausedSeat"),
        ("default", SeatLifecycle::Retired, "RetiredOrPausedSeat"),
    ] {
        manifest.seats[0].lifecycle = lifecycle;
        save(&manifest, &path);
        let output = cli(
            temp.path(),
            &[
                "fleet",
                "launch",
                "--seat",
                seat,
                "--manifest",
                path.to_str().unwrap(),
            ],
        );
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(error));
        assert!(!temp.path().join("marker").exists());
    }
}

#[test]
fn missing_driver_fails_without_substituting_another_executable() {
    let (temp, mut manifest, path) = fixture("printf executed > marker");
    if let DriverSpec::CliSubprocess { executable, .. } = &mut manifest.seats[0].driver {
        *executable = temp.path().join("does-not-exist").display().to_string();
    }
    save(&manifest, &path);
    let output = cli(
        temp.path(),
        &[
            "fleet",
            "launch",
            "--seat",
            "default",
            "--manifest",
            path.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("DriverBinaryMissing"));
    assert!(!temp.path().join("marker").exists());
}

#[test]
fn oauth_driver_scrubs_provider_overrides_from_the_real_child() {
    let (temp, mut manifest, path) = fixture(
        "printf '%s|%s|%s|%s' \"${ANTHROPIC_BASE_URL-unset}\" \"${ANTHROPIC_AUTH_TOKEN-unset}\" \"${ANTHROPIC_API_KEY-unset}\" \"$CHINWAG_ACTOR\"",
    );
    if let DriverSpec::CliSubprocess {
        auth_isolation,
        env_allowlist,
        ..
    } = &mut manifest.seats[0].driver
    {
        *auth_isolation = CredentialIsolation::FirstPartyCliOauth {
            scrub_env: vec![
                "ANTHROPIC_BASE_URL".into(),
                "ANTHROPIC_AUTH_TOKEN".into(),
                "ANTHROPIC_API_KEY".into(),
            ],
            preflight_cmd: Vec::new(),
        };
        env_allowlist.extend([
            "ANTHROPIC_BASE_URL".into(),
            "ANTHROPIC_AUTH_TOKEN".into(),
            "ANTHROPIC_API_KEY".into(),
        ]);
    }
    save(&manifest, &path);
    let output = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "fleet",
            "launch",
            "--seat",
            "default",
            "--manifest",
            path.to_str().unwrap(),
        ])
        .current_dir(temp.path())
        .env("HOME", temp.path())
        .env_remove("CHINWAG_ACTOR")
        .env("ANTHROPIC_BASE_URL", "hostile-endpoint")
        .env("ANTHROPIC_AUTH_TOKEN", "synthetic-token")
        .env("ANTHROPIC_API_KEY", "synthetic-key")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        response["stdout"]
            .as_str()
            .unwrap()
            .starts_with("unset|unset|unset|default#")
    );
}

#[test]
fn agent_dispatch_resolves_explicit_manifest_and_propagates_lineage() {
    let (temp, _manifest, path) = fixture(
        "printf '%s|%s|%s|%s|%s' \"$CHINWAG_ACTOR\" \"$CHINWAG_INSTANCE_ID\" \"$CHINWAG_CALLER\" \"$CHINWAG_PARENT_INSTANCE\" \"$CHINWAG_ALLOWED_SKILLS\"",
    );
    let output = cli(
        temp.path(),
        &[
            "agent-dispatch",
            "--agent",
            "default",
            "--sender",
            "operator#parent-instance",
            "--body",
            "fixture prompt",
            "--fleet-manifest",
            path.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    let reply = response["reply"].as_str().unwrap();
    assert!(reply.starts_with("default#"), "{reply}");
    assert!(
        reply.contains("|operator#parent-instance|operator#parent-instance|"),
        "{reply}"
    );
    assert_eq!(response["crdb_persisted"], false);
}

#[test]
fn agent_dispatch_policy_denials_have_nonzero_status_and_no_child() {
    let (temp, mut manifest, path) = fixture("printf executed > marker");
    manifest
        .policy
        .deny_providers
        .push(manifest.seats[0].model.provider.clone());
    save(&manifest, &path);
    let output = cli(
        temp.path(),
        &[
            "agent-dispatch",
            "--agent",
            "default",
            "--sender",
            "operator#parent-instance",
            "--body",
            "fixture prompt",
            "--fleet-manifest",
            path.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ProviderDenied"));
    assert!(!temp.path().join("marker").exists());
}

#[test]
fn explain_shows_manifest_model_and_target_without_running_the_driver() {
    let (temp, manifest, path) = fixture("printf executed > marker");
    let output = cli(
        temp.path(),
        &[
            "fleet",
            "explain",
            "--seat",
            "default",
            "--manifest",
            path.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response["plan"]["model"]["model_id"],
        manifest.seats[0].model.model_id
    );
    assert!(!temp.path().join("marker").exists());
}

#[test]
fn manifest_dispatch_accepts_dotted_and_maximum_length_seat_ids() {
    let (temp, mut manifest, path) =
        fixture("printf '%s|%s' \"$CHINWAG_ACTOR\" \"$CHINWAG_CALLER\"");
    for seat in ["agent.with.dots".to_owned(), "x".repeat(128)] {
        manifest.seats[0].id = chinwag_fleet::SeatId::new(&seat).unwrap();
        save(&manifest, &path);
        let output = cli(
            temp.path(),
            &[
                "agent-dispatch",
                "--agent",
                &seat,
                "--sender",
                "operator.with.dots#parent",
                "--body",
                "fixture",
                "--fleet-manifest",
                path.to_str().unwrap(),
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            response["reply"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{seat}#"))
        );
        assert!(
            response["reply"]
                .as_str()
                .unwrap()
                .ends_with("|operator.with.dots#parent")
        );
    }
}

#[test]
fn boot_files_reject_parent_symlinks_before_the_child_starts() {
    let (temp, mut manifest, path) = fixture("printf executed > marker");
    let outside = TempDir::new().unwrap();
    fs::write(
        outside.path().join("instructions.md"),
        "private outside instructions",
    )
    .unwrap();
    std::os::unix::fs::symlink(outside.path(), temp.path().join("boot")).unwrap();
    manifest.seats[0].boot_files = vec!["boot/instructions.md".into()];
    save(&manifest, &path);
    let output = cli(
        temp.path(),
        &[
            "agent-dispatch",
            "--agent",
            "default",
            "--sender",
            "operator#parent",
            "--body",
            "fixture",
            "--fleet-manifest",
            path.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("boot_file_invalid"));
    assert!(!temp.path().join("marker").exists());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private outside instructions"));
}

#[test]
fn explicit_native_store_cannot_be_authorized_by_a_fleet_manifest() {
    let (temp, _manifest, manifest_path) = fixture("printf executed > marker");
    let store = temp.path().join(".chinwag/state.crdb");
    let output = cli(
        temp.path(),
        &[
            "agent-dispatch",
            "--agent",
            "default",
            "--sender",
            "operator#parent",
            "--body",
            "fixture",
            "--repo",
            temp.path().to_str().unwrap(),
            "--crdb",
            store.to_str().unwrap(),
            "--fleet-manifest",
            manifest_path.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("execution_binding_held"));
    assert!(!temp.path().join("marker").exists());
    assert!(!store.exists());
}
