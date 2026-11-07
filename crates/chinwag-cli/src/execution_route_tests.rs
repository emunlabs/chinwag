//! Private integration tests link the actual binary route cores. These are
//! controlled fixture runs, never a production host/provider adapter proof.
use crate::execution_binding::{
    ExecutionAuthority,
    test_support::{BindingFixture, FixtureOptions},
};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

#[test]
#[ignore = "Owned Rust fake child; invoked only by its controlled parent test"]
fn p009_private_fake_worker_child() {
    let Some(output) = std::env::var_os("CHINWAG_P009_PRIVATE_PROBE_OUT") else {
        return;
    };
    let value = json!({
        "cwd": std::env::current_dir().unwrap(),
        "repo": std::env::var("CHINWAG_REPO_ROOT").unwrap(),
        "store": std::env::var("CHINWAG_STORE_PATH").unwrap(),
        "store_id": std::env::var("CHINWAG_STORE_ID").unwrap(),
        "binding": std::env::var("CHINWAG_EXECUTION_BINDING").unwrap(),
    });
    fs::write(output, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn probe_command(output: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "execution_route_tests::p009_private_fake_worker_child",
            "--ignored",
            "--nocapture",
        ])
        .env("CHINWAG_P009_PRIVATE_PROBE_OUT", output);
    command
}

fn launch_probe(binding: &crate::execution_binding::WorkspaceExecutionBinding) -> String {
    let files = tempfile::tempdir().unwrap();
    let output = files.path().join("probe.json");
    let status = probe_command(&output)
        .current_dir(binding.execution_root())
        .env("CHINWAG_REPO_ROOT", binding.execution_root())
        .env("CHINWAG_STORE_PATH", binding.store_path())
        .env("CHINWAG_STORE_ID", binding.store_id())
        .env("CHINWAG_EXECUTION_BINDING", binding.commitment_id())
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    fs::read_to_string(output).unwrap()
}

#[test]
fn p009_four_actual_route_cores_share_one_nondefault_binding_and_worker_context() {
    let fixture = BindingFixture::with_options(FixtureOptions {
        integration_target: "refs/heads/integration".into(),
        initial_files: vec![
            (
                "docs/example.md".into(),
                b"Controlled ordinary documentation\n".to_vec(),
            ),
            (
                "TASKS.md".into(),
                b"# Historical copied task labels\n".to_vec(),
            ),
        ],
        ..FixtureOptions::default()
    });
    let selected = fixture.selection();
    let binding = fixture.bind();
    let authority = fixture.authority();
    assert_ne!(binding.source_root(), binding.execution_root());
    assert_eq!(binding.source_root(), fixture.source_root());
    let bus =
        crate::task_scheduler::tests::probe_bound_bus_route(&binding, &authority, launch_probe);
    let files = tempfile::tempdir().unwrap();
    let output = files.path().join("agent.json");
    let agent = crate::agent_dispatch_run::probe_bound_route(
        &binding,
        &authority,
        &mut probe_command(&output),
    )
    .unwrap();
    assert_eq!(
        agent.effects,
        ["persona", "memory", "signing", "engine", "mock-persistence"]
    );
    assert!(!agent.stdout.is_empty());
    let agent = fs::read_to_string(output).unwrap();
    let feature = crate::feature_cli_run::with_feature_task_effect(
        &selected,
        &binding,
        &authority,
        launch_probe,
    )
    .unwrap();
    let ui =
        crate::ui_workbench_run::with_ui_task_effect(&selected, &binding, &authority, launch_probe)
            .unwrap();
    for report in [bus, agent, feature, ui] {
        let report: Value = serde_json::from_str(&report).unwrap();
        assert_eq!(report["cwd"], json!(fixture.root()));
        assert_eq!(report["repo"], json!(fixture.root()));
        assert_eq!(report["store"], json!(fixture.store_path()));
        assert_eq!(report["store_id"], binding.store_id());
        assert_eq!(report["binding"], binding.commitment_id());
    }
    // Exercise a real feature filesystem effect after the fake-worker probes.
    // This creates an approved output; it does not refresh the binding silently.
    let mut out = Vec::new();
    let mut error = Vec::new();
    assert_eq!(
        crate::feature_cli_run::run_openspec_cli_with_binding(
            &selected,
            &["archive".into(), "--json".into()],
            &binding,
            &authority,
            &mut out,
            &mut error,
        ),
        0,
        "{}",
        String::from_utf8_lossy(&error)
    );
    let result: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(result["task_authority"], false);
    assert!(Path::new(result["snapshot_path"].as_str().unwrap()).is_file());
    assert!(binding.revalidate(&authority).is_err());
}

#[test]
fn p009_actual_feature_ui_and_agent_guards_refuse_before_any_worker_on_epoch_change() {
    let fixture = BindingFixture::new();
    let selected = fixture.selection();
    let binding = fixture.bind();
    fixture.bump_epoch();
    let authority = fixture.authority();
    let mut calls = 0;
    assert!(
        crate::feature_cli_run::with_feature_task_effect(&selected, &binding, &authority, |_| {
            calls += 1;
        })
        .is_err()
    );
    assert!(
        crate::ui_workbench_run::with_ui_task_effect(&selected, &binding, &authority, |_| {
            calls += 1;
        })
        .is_err()
    );
    let files = tempfile::tempdir().unwrap();
    let out = files.path().join("must-not-exist.json");
    assert!(
        crate::agent_dispatch_run::probe_bound_route(
            &binding,
            &authority,
            &mut probe_command(&out)
        )
        .is_err()
    );
    assert_eq!(calls, 0);
    assert!(!out.exists());
    assert!(
        crate::feature_cli_run::with_feature_task_effect(
            &selected,
            &binding,
            &ExecutionAuthority::unsupported(),
            |_| {
                calls += 1;
            }
        )
        .is_err()
    );
    assert_eq!(calls, 0);
}
