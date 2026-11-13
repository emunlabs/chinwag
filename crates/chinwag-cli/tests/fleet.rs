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

#[test]
fn fleet_launch_passes_prompt_timeout_and_json_via_argv_template() {
    let (temp, mut manifest, path) = fixture("printf '%s' \"$1\"");
    if let DriverSpec::CliSubprocess {
        argv_template,
        framing,
        ..
    } = &mut manifest.seats[0].driver
    {
        *framing = "argv".into();
        *argv_template = vec!["{prompt}".into()];
    }
    save(&manifest, &path);
    let output = cli(
        temp.path(),
        &[
            "fleet",
            "launch",
            "--seat",
            "default",
            "--prompt",
            "hello rust fleet",
            "--timeout",
            "15",
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
    assert_eq!(response["ok"], true);
    assert_eq!(response["stdout"], "hello rust fleet");
    assert_eq!(response["timed_out"], false);
}

#[test]
fn multicall_seat_agent_symlink_dispatches_pure_rust_fleet_launch_and_status() {
    let (temp, mut manifest, _path) = fixture("printf 'reply:%s' \"$1\"");
    manifest.seats[0].id = chinwag_fleet::SeatId::new("CUSTOM-SEAT").unwrap();
    if let DriverSpec::CliSubprocess {
        argv_template,
        framing,
        ..
    } = &mut manifest.seats[0].driver
    {
        *framing = "argv".into();
        *argv_template = vec!["{composed_prompt}".into()];
    }
    let root = temp.path().canonicalize().unwrap();
    let profile = root.join("profile");
    fs::create_dir_all(&profile).unwrap();
    fs::write(profile.join("SOUL.md"), "Custom seat identity\n").unwrap();
    manifest.seats[0].profile_dir = Some(profile);
    manifest.seats[0].boot_files = vec!["SOUL.md".into()];
    fs::create_dir_all(root.join(".chinwag")).unwrap();
    let toml_path = root.join(".chinwag/fleet.toml");
    fs::write(&toml_path, manifest.to_toml().unwrap()).unwrap();

    let symlink_bin = root.join("custom-seat-agent");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_chinwag"), &symlink_bin).unwrap();

    let status_out = Command::new(&symlink_bin)
        .args(["status", "--json"])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .output()
        .unwrap();
    assert!(
        status_out.status.success(),
        "{}",
        String::from_utf8_lossy(&status_out.stderr)
    );
    let status_json: Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status_json["seat"], "CUSTOM-SEAT");

    let run_out = Command::new(&symlink_bin)
        .args(["run", "--cwd", root.to_str().unwrap(), "perform", "task"])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert!(
        run_out.status.success(),
        "{}",
        String::from_utf8_lossy(&run_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&run_out.stdout);
    assert!(stdout.contains("Custom seat identity"), "{stdout}");
    assert!(stdout.contains("perform task"), "{stdout}");
}

fn spawn_mock_json_server(responses: Vec<String>) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for body in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    format!("http://{addr}")
}

#[test]
fn multicall_status_flag_and_prompt_file_and_locked_model_effort_enforced() {
    let (temp, mut manifest, _) = fixture("printf 'got:%s' \"$1\"");
    manifest.seats[0].id = chinwag_fleet::SeatId::new("LOCKED-SEAT").unwrap();
    manifest.seats[0].model.model_id = "locked-model-v2".into();
    manifest.seats[0].model.params = BTreeMap::from([
        ("effort".into(), Value::String("high".into())),
        ("lock_effort".into(), Value::Bool(true)),
        (
            "logical_model".into(),
            Value::String("vendor/locked-model-v2".into()),
        ),
    ]);
    if let DriverSpec::CliSubprocess {
        argv_template,
        framing,
        ..
    } = &mut manifest.seats[0].driver
    {
        *framing = "argv".into();
        *argv_template = vec!["{composed_prompt}".into()];
    }
    let root = temp.path().canonicalize().unwrap();
    fs::create_dir_all(root.join(".chinwag")).unwrap();
    fs::write(root.join(".chinwag/fleet.toml"), manifest.to_toml().unwrap()).unwrap();
    let prompt_file = root.join("task_prompt.txt");
    fs::write(&prompt_file, "prompt loaded from file\n").unwrap();

    let symlink_bin = root.join("locked-seat-agent");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_chinwag"), &symlink_bin).unwrap();

    // --status --json reports credentials_ready: true
    let status_out = Command::new(&symlink_bin)
        .args(["--status", "--json"])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .output()
        .unwrap();
    assert!(
        status_out.status.success(),
        "{}",
        String::from_utf8_lossy(&status_out.stderr)
    );
    let status_json: Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status_json["ok"], true);
    assert_eq!(status_json["credentials_ready"], true);

    // --prompt-file reads prompt text cleanly
    let run_out = Command::new(&symlink_bin)
        .args([
            "-m",
            "vendor/locked-model-v2",
            "--effort",
            "high",
            "--prompt-file",
            prompt_file.to_str().unwrap(),
        ])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert!(
        run_out.status.success(),
        "{}",
        String::from_utf8_lossy(&run_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run_out.stdout).contains("prompt loaded from file"),
        "{}",
        String::from_utf8_lossy(&run_out.stdout)
    );

    // Fail-closed unauthorized model
    let bad_model = Command::new(&symlink_bin)
        .args(["-m", "unauthorized-model", "-p", "ping"])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .output()
        .unwrap();
    assert_eq!(bad_model.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&bad_model.stderr).contains("ModelSwitchDenied"),
        "{}",
        String::from_utf8_lossy(&bad_model.stderr)
    );

    // Fail-closed effort override when lock_effort = true
    let bad_effort = Command::new(&symlink_bin)
        .args(["--effort", "xhigh", "-p", "ping"])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .output()
        .unwrap();
    assert_eq!(bad_effort.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&bad_effort.stderr).contains("EffortSwitchDenied"),
        "{}",
        String::from_utf8_lossy(&bad_effort.stderr)
    );
}

#[test]
fn multicall_aliases_and_anti_spoofing_and_seat_actions_work_via_manifest() {
    let base_url = spawn_mock_json_server(vec![
        r#"{"success":true,"result":{"answers":{"flag":0.05}}}"#.to_owned(),
        r#"{"success":true,"result":{"answers":{"dora_complexity_tier":"S"}}}"#.to_owned(),
    ]);
    let (temp, mut manifest, _) = fixture("printf 'target:%s' \"$1\"");
    manifest.seats[0].id = chinwag_fleet::SeatId::new("TARGET-SEAT").unwrap();
    if let DriverSpec::CliSubprocess {
        argv_template,
        framing,
        ..
    } = &mut manifest.seats[0].driver
    {
        *framing = "argv".into();
        *argv_template = vec!["{composed_prompt}".into()];
    }
    let root = temp.path().canonicalize().unwrap();
    let env_path = root.join("cf.env");
    fs::write(&env_path, "CF_TOKEN=test-token\n").unwrap();
    fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600)).unwrap();

    manifest.extensions.insert(
        "multicall_aliases".into(),
        serde_json::json!({ "mercury": "*" }),
    );
    manifest.extensions.insert(
        "seat_actions".into(),
        serde_json::json!({
            "TARGET-SEAT": {
                "clef": {
                    "kind": "workers_ai_structured",
                    "base_url": base_url,
                    "account_id": "0123456789abcdef0123456789abcdef",
                    "secret_env_file": env_path,
                    "secret_key": "CF_TOKEN",
                    "model": "@cf/example/clef",
                    "payload_mode": "clef_state",
                    "questions": {"flag": {"type": "noul"}}
                },
                "clairic": {
                    "kind": "workers_ai_structured",
                    "base_url": base_url,
                    "account_id": "0123456789abcdef0123456789abcdef",
                    "secret_env_file": env_path,
                    "secret_key": "CF_TOKEN",
                    "model": "@cf/example/clairic",
                    "payload_mode": "clairic_text",
                    "fields": {"dora_complexity_tier": {"type": "text"}}
                }
            }
        }),
    );

    fs::create_dir_all(root.join(".chinwag")).unwrap();
    fs::write(root.join(".chinwag/fleet.toml"), manifest.to_toml().unwrap()).unwrap();

    let alias_bin = root.join("mercury-agent");
    let direct_bin = root.join("target-seat-agent");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_chinwag"), &alias_bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_chinwag"), &direct_bin).unwrap();

    // Alias resolves --seat TARGET-SEAT cleanly
    let alias_run = Command::new(&alias_bin)
        .args(["--seat", "TARGET-SEAT", "-p", "hello alias"])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert!(
        alias_run.status.success(),
        "{}",
        String::from_utf8_lossy(&alias_run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&alias_run.stdout).contains("hello alias"),
        "{}",
        String::from_utf8_lossy(&alias_run.stdout)
    );

    // Direct seat launcher rejects mismatched --seat (SeatMismatch)
    let spoof = Command::new(&direct_bin)
        .args(["--seat", "OTHER-SEAT", "status"])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .output()
        .unwrap();
    assert_eq!(spoof.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&spoof.stderr).contains("SeatMismatch"),
        "{}",
        String::from_utf8_lossy(&spoof.stderr)
    );

    // Manifest-driven custom seat_actions: clef + clairic
    let clef_out = Command::new(&direct_bin)
        .args(["clef", "--json", "--prompt", "{\"task\":\"CHWG-1\"}"])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .output()
        .unwrap();
    assert!(
        clef_out.status.success(),
        "{}",
        String::from_utf8_lossy(&clef_out.stderr)
    );
    let clef_json: Value = serde_json::from_slice(&clef_out.stdout).unwrap();
    assert_eq!(clef_json["result"]["answers"]["flag"], 0.05);

    let clairic_out = Command::new(&alias_bin)
        .args([
            "--seat",
            "TARGET-SEAT",
            "clairic",
            "--json",
            "--prompt",
            "Estimate this slice",
        ])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .output()
        .unwrap();
    assert!(
        clairic_out.status.success(),
        "{}",
        String::from_utf8_lossy(&clairic_out.stderr)
    );
    let clairic_json: Value = serde_json::from_slice(&clairic_out.stdout).unwrap();
    assert_eq!(
        clairic_json["result"]["answers"]["dora_complexity_tier"],
        "S"
    );
}

fn spawn_mock_status_server(
    responses: Vec<(u16, String)>,
) -> (
    String,
    std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let cap_clone = Arc::clone(&captured);
    let handle = std::thread::spawn(move || {
        for (status, body) in responses {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            };
            let _ = stream.set_nonblocking(false);
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        raw.extend_from_slice(&buf[..n]);
                        if let Some(hdr_end) =
                            raw.windows(4).position(|w| w == b"\r\n\r\n")
                        {
                            let headers_str =
                                String::from_utf8_lossy(&raw[..hdr_end]);
                            let content_len = headers_str
                                .lines()
                                .find_map(|line| {
                                    let (k, v) = line.split_once(':')?;
                                    k.trim()
                                        .eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                            if raw.len() >= hdr_end + 4 + content_len {
                                let json_bytes =
                                    &raw[hdr_end + 4..hdr_end + 4 + content_len];
                                if let Ok(v) =
                                    serde_json::from_slice::<Value>(json_bytes)
                                {
                                    cap_clone.lock().unwrap().push(v);
                                }
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            let reason = if status == 400 { "Bad Request" } else { "OK" };
            let reply = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (format!("http://{addr}/v1"), captured, handle)
}

fn setup_openai_http_manifest(
    root: &Path,
    base_url: &str,
    lock_effort: bool,
) -> (PathBuf, PathBuf) {
    let mut manifest = FleetManifest::starter_profile("solo").unwrap();
    let seat = &mut manifest.seats[0];
    seat.id = chinwag_fleet::SeatId::new("QA").unwrap();
    seat.lifecycle = chinwag_fleet::SeatLifecycle::ActiveStanding;
    seat.model.provider = "vercel-ai-gateway".into();
    seat.model.model_id = "inception/mercury-3".into();
    seat.model.params = BTreeMap::from([
        ("effort".into(), Value::String("high".into())),
        ("reasoning_effort".into(), Value::String("high".into())),
        ("lock_effort".into(), Value::Bool(lock_effort)),
    ]);
    let env_path = root.join("vercel.env");
    fs::write(&env_path, "VERCEL_API_KEY=test-vercel-key\n").unwrap();
    fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600)).unwrap();
    seat.driver = DriverSpec::OpenAiCompatibleHttp {
        base_url: base_url.to_owned(),
        api_key_env: "VERCEL_API_KEY".into(),
        wire_mode: "chat_completions".into(),
        stream_mode: "none".into(),
        timeout_secs: 30,
        auth_isolation: CredentialIsolation::SecretEnvFile {
            path: env_path,
            key_map: BTreeMap::new(),
        },
        tools: chinwag_fleet::HttpToolConfig {
            enabled: true,
            allowed_write_roots: Vec::new(),
            auth_fetches: Vec::new(),
            env_injections: Vec::new(),
            max_turns: Some(8),
            max_tool_calls: Some(8),
            max_output_tokens: Some(1024),
        },
    };
    manifest.pubkey_map = BTreeMap::from([(
        seat.id.clone(),
        "01".repeat(32),
    )]);
    manifest.allowed_signers = manifest.pubkey_map.clone();
    fs::create_dir_all(root.join(".chinwag")).unwrap();
    let manifest_path = root.join(".chinwag/fleet.toml");
    fs::write(&manifest_path, manifest.to_toml().unwrap()).unwrap();
    let symlink_bin = root.join("qa-agent");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_chinwag"), &symlink_bin).unwrap();
    (manifest_path, symlink_bin)
}

#[test]
fn http_usage_multiturn_counted_and_readonly_tools_and_receipt_file() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let target_file = root.join("sample.txt");
    fs::write(&target_file, "hello readonly qa\n").unwrap();

    let turn1 = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "tc_1",
                    "type": "function",
                    "function": {
                        "name": "read_file",
                        "arguments": "{\"path\":\"sample.txt\"}"
                    }
                }]
            }
        }],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "total_tokens": 120,
            "prompt_tokens_details": {"cached_tokens": 10},
            "completion_tokens_details": {"reasoning_tokens": 5}
        }
    })
    .to_string();
    let turn2 = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "VERIFIED"
            }
        }],
        "usage": {
            "prompt_tokens": 150,
            "completion_tokens": 30,
            "total_tokens": 180,
            "prompt_tokens_details": {"cached_tokens": 25},
            "completion_tokens_details": {"reasoning_tokens": 7}
        }
    })
    .to_string();

    let (base_url, captured, handle) =
        spawn_mock_status_server(vec![(200, turn1), (200, turn2)]);
    let (_manifest_path, qa_bin) = setup_openai_http_manifest(&root, &base_url, true);
    let receipt_path = root.join("usage-receipt.json");

    let out = Command::new(&qa_bin)
        .args(["--cwd", root.to_str().unwrap(), "--json", "-p", "check"])
        .current_dir(&root)
        .env("HOME", &root)
        .env("CHINWAG_USAGE_RECEIPT_PATH", &receipt_path)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let _ = handle.join();

    let payload: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["usage"]["usage_status"], "COUNTED");
    assert_eq!(payload["usage"]["turns"], 2);
    assert_eq!(payload["usage"]["tool_calls"], 1);
    assert_eq!(payload["usage"]["prompt_tokens"], 250);
    assert_eq!(payload["usage"]["completion_tokens"], 50);
    assert_eq!(payload["usage"]["cached_tokens"], 35);
    assert_eq!(payload["usage"]["reasoning_tokens"], 12);
    assert_eq!(payload["usage"]["gross_tokens"], 300);

    let receipt: Value =
        serde_json::from_str(&fs::read_to_string(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["usage_status"], "COUNTED");
    assert_eq!(receipt["gross_tokens"], 300);

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    let tool_names: Vec<&str> = reqs[0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.pointer("/function/name").and_then(Value::as_str))
        .collect();
    assert_eq!(tool_names, vec!["read_file", "fetch_url", "run_command"]);
    assert_eq!(reqs[0]["reasoning_effort"], "high");
}

#[test]
fn http_usage_missing_turn2_fails_closed_to_unknown() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::write(root.join("sample.txt"), "hello\n").unwrap();

    let turn1 = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "tc_1",
                    "type": "function",
                    "function": {
                        "name": "read_file",
                        "arguments": "{\"path\":\"sample.txt\"}"
                    }
                }]
            }
        }],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "total_tokens": 120
        }
    })
    .to_string();
    let turn2_no_usage = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "DONE"
            }
        }]
    })
    .to_string();

    let (base_url, _captured, handle) =
        spawn_mock_status_server(vec![(200, turn1), (200, turn2_no_usage)]);
    let (_manifest_path, qa_bin) = setup_openai_http_manifest(&root, &base_url, true);

    let out = Command::new(&qa_bin)
        .args(["--cwd", root.to_str().unwrap(), "--json", "-p", "check"])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let _ = handle.join();

    let payload: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["usage"]["usage_status"], "UNKNOWN");
    assert_eq!(payload["usage"]["turns"], 2);
    assert_eq!(payload["usage"]["tool_calls"], 1);
    assert_eq!(payload["usage"]["prompt_tokens"], Value::Null);
    assert_eq!(payload["usage"]["completion_tokens"], Value::Null);
    assert_eq!(payload["usage"]["gross_tokens"], Value::Null);
    assert_eq!(payload["usage"]["observed_partial_gross_tokens"], 120);
}

#[test]
fn http_lock_effort_refuses_400_strip_and_env_override() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let receipt_path = root.join("failed-receipt.json");

    let err_400 = r#"{"error":{"message":"unsupported parameter: reasoning_effort"}}"#.to_owned();
    let (base_url, captured, handle) = spawn_mock_status_server(vec![(400, err_400)]);
    let (_manifest_path, qa_bin) = setup_openai_http_manifest(&root, &base_url, true);

    let out = Command::new(&qa_bin)
        .args(["--cwd", root.to_str().unwrap(), "--json", "-p", "check"])
        .current_dir(&root)
        .env("HOME", &root)
        .env("CHINWAG_USAGE_RECEIPT_PATH", &receipt_path)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = handle.join();
    // Locked effort must NEVER retry without reasoning_effort
    assert_eq!(captured.lock().unwrap().len(), 1);
    let err_payload: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(err_payload["ok"], false);
    assert_eq!(err_payload["usage"]["usage_status"], "UNKNOWN");
    assert_eq!(err_payload["usage"]["turns"], 1);
    let receipt: Value =
        serde_json::from_str(&fs::read_to_string(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["usage_status"], "UNKNOWN");

    // CHINWAG_EFFORT_OVERRIDE mismatch fails before egress
    let override_out = Command::new(&qa_bin)
        .args(["--cwd", root.to_str().unwrap(), "--json", "-p", "check"])
        .current_dir(&root)
        .env("HOME", &root)
        .env("CHINWAG_EFFORT_OVERRIDE", "low")
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert_eq!(override_out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&override_out.stderr).contains("EffortSwitchDenied"),
        "{}",
        String::from_utf8_lossy(&override_out.stderr)
    );
}

#[test]
fn multicall_explain_does_not_read_nontty_stdin() {
    use std::process::Stdio;
    use std::sync::mpsc;

    let (temp, mut manifest, _) = fixture("echo unused");
    manifest.seats[0].id = chinwag_fleet::SeatId::new("MOTION").unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::create_dir_all(root.join(".chinwag")).unwrap();
    fs::write(root.join(".chinwag/fleet.toml"), manifest.to_toml().unwrap()).unwrap();
    let motion_bin = root.join("motion-agent");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_chinwag"), &motion_bin).unwrap();

    // Open stdin pipe that stays open until child exits (simulating SSH without -n)
    let mut child = Command::new(&motion_bin)
        .args(["explain", "--json"])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _held_stdin = child.stdin.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let output = rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("motion-agent explain hung reading non-TTY open stdin")
        .unwrap();
    drop(_held_stdin);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["plan"]["seat"], "MOTION");
}

#[test]
fn explicit_bound_actor_preserved_in_launch_and_multicall_and_rejects_mismatch() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let reply = serde_json::json!({
        "choices": [{"message": {"role": "assistant", "content": "OK"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}
    })
    .to_string();
    let (base_url, _cap, handle) =
        spawn_mock_status_server(vec![(200, reply.clone()), (200, reply)]);
    let (manifest_path, qa_bin) = setup_openai_http_manifest(&root, &base_url, true);

    let bound = "QA#2427c46641e272de554b8e82a04af0d8";
    let launch_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "fleet",
            "launch",
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--seat",
            "QA",
            "--actor",
            bound,
            "--cwd",
            root.to_str().unwrap(),
            "--json",
            "-p",
            "ping",
        ])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert!(
        launch_out.status.success(),
        "{}",
        String::from_utf8_lossy(&launch_out.stderr)
    );
    let launch_json: Value = serde_json::from_slice(&launch_out.stdout).unwrap();
    assert_eq!(launch_json["actor"], bound);
    assert_eq!(launch_json["usage"]["usage_status"], "COUNTED");

    let multi_out = Command::new(&qa_bin)
        .args([
            "--actor",
            bound,
            "--cwd",
            root.to_str().unwrap(),
            "--json",
            "-p",
            "ping",
        ])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert!(
        multi_out.status.success(),
        "{}",
        String::from_utf8_lossy(&multi_out.stderr)
    );
    let _ = handle.join();
    let multi_json: Value = serde_json::from_slice(&multi_out.stdout).unwrap();
    assert_eq!(multi_json["actor"], bound);
    assert_eq!(multi_json["usage"]["gross_tokens"], 12);

    // Mismatched actor seat fails closed
    let mismatch = Command::new(&qa_bin)
        .args([
            "--actor",
            "OTHER#2427c46641e272de554b8e82a04af0d8",
            "--cwd",
            root.to_str().unwrap(),
            "-p",
            "ping",
        ])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .output()
        .unwrap();
    assert_eq!(mismatch.status.code(), Some(2));
}

#[test]
fn multicall_flags_before_explain_and_status_never_hit_network_and_explain_includes_actor() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let reply = serde_json::json!({
        "choices": [{"message": {"role": "assistant", "content": "DOUBLE_DASH_OK"}}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}
    })
    .to_string();
    let (base_url, captured, handle) = spawn_mock_status_server(vec![(200, reply)]);
    let (manifest_path, qa_bin) = setup_openai_http_manifest(&root, &base_url, true);
    let bound = "QA#2427c46641e272de554b8e82a04af0d8";

    // Flags before `explain` without `--seat` must NOT execute `run` or call HTTP
    let explain_out = Command::new(&qa_bin)
        .args([
            "--actor",
            bound,
            "--cwd",
            root.to_str().unwrap(),
            "explain",
            "--json",
        ])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert!(
        explain_out.status.success(),
        "{}",
        String::from_utf8_lossy(&explain_out.stderr)
    );
    let explain_json: Value = serde_json::from_slice(&explain_out.stdout).unwrap();
    assert_eq!(explain_json["ok"], true);
    assert_eq!(explain_json["plan"]["actor"], bound);
    assert!(captured.lock().unwrap().is_empty());

    // Flags before `status` without `--seat` must NOT execute `run` or call HTTP
    let status_out = Command::new(&qa_bin)
        .args([
            "--actor",
            bound,
            "--cwd",
            root.to_str().unwrap(),
            "status",
            "--json",
        ])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert!(
        status_out.status.success(),
        "{}",
        String::from_utf8_lossy(&status_out.stderr)
    );
    assert!(captured.lock().unwrap().is_empty());

    // Explicit `chinwag fleet explain --actor ...` also includes `plan.actor`
    let cli_explain = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "fleet",
            "explain",
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--seat",
            "QA",
            "--actor",
            bound,
            "--cwd",
            root.to_str().unwrap(),
            "--json",
        ])
        .current_dir(&root)
        .env("HOME", &root)
        .output()
        .unwrap();
    assert!(
        cli_explain.status.success(),
        "{}",
        String::from_utf8_lossy(&cli_explain.stderr)
    );
    let cli_json: Value = serde_json::from_slice(&cli_explain.stdout).unwrap();
    assert_eq!(cli_json["plan"]["actor"], bound);
    assert!(captured.lock().unwrap().is_empty());

    // Literal prompt "explain" after `--` runs against HTTP as a prompt
    let prompt_out = Command::new(&qa_bin)
        .args([
            "--cwd",
            root.to_str().unwrap(),
            "--json",
            "--",
            "explain",
        ])
        .current_dir(&root)
        .env("HOME", &root)
        .env_remove("CHINWAG_FLEET_MANIFEST")
        .env_remove("CHINWAG_ACTOR")
        .output()
        .unwrap();
    assert!(
        prompt_out.status.success(),
        "{}",
        String::from_utf8_lossy(&prompt_out.stderr)
    );
    let _ = handle.join();
    assert_eq!(captured.lock().unwrap().len(), 1);
}
