// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

use base64::{Engine, engine::general_purpose::STANDARD};
use chinwag_ci::{CaptureLimits, ProcessOutcome, UnverifiedRunContext, capture};
use std::time::Duration;
use tokio::process::Command;

fn context() -> UnverifiedRunContext {
    UnverifiedRunContext {
        repository: "example/ci-test".into(),
        source_commit: "ab".repeat(20),
        workflow_ref: "example/ci-test/.github/workflows/ci.yml@refs/heads/test".into(),
        run_id: 42,
        run_attempt: 1,
        job: "failure-fixture".into(),
        initiating_intent_sha256: "cd".repeat(32),
    }
}

// Re-execute this test binary as a real child. This fixture does not depend on
// bash, Python, or a host-installed compiler and also runs on Linux Actions.
#[test]
fn process_fixture() {
    match std::env::var("CHINWAG_CI_CAPTURE_FIXTURE").as_deref() {
        Ok("verbose-failure") => {
            use std::io::Write;
            let output = vec![0xa5_u8; 192 * 1024];
            std::io::stdout().write_all(&output).unwrap();
            std::io::stderr().write_all(b"failure\0\xff\n").unwrap();
            std::process::exit(17);
        }
        Ok("deadline") => std::thread::sleep(Duration::from_secs(30)),
        Ok("pipe-holder") => std::thread::sleep(Duration::from_millis(600)),
        Ok("failed-with-held-pipe") => {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "process_fixture", "--nocapture", "--quiet"])
                .env("CHINWAG_CI_CAPTURE_FIXTURE", "pipe-holder")
                .spawn()
                .unwrap();
            std::process::exit(17);
        }
        Ok("green") => std::process::exit(0),
        _ => {}
    }
}

fn child(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "process_fixture", "--nocapture", "--quiet"]);
    command.env("CHINWAG_CI_CAPTURE_FIXTURE", mode);
    command
}

#[tokio::test]
async fn retains_binary_output_larger_than_a_pipe_and_original_failure() {
    let evidence = capture(
        &mut child("verbose-failure"),
        context(),
        CaptureLimits::default(),
    )
    .await
    .unwrap();
    assert!(matches!(
        evidence.outcome(),
        ProcessOutcome::Exited { code: 17 }
    ));
    assert!(evidence.output_is_complete());
    let json: serde_json::Value =
        serde_json::from_slice(&evidence.plaintext_for_sealing().unwrap()).unwrap();
    let stdout = STANDARD
        .decode(json["stdout"]["bytes_base64"].as_str().unwrap())
        .unwrap();
    assert!(stdout.ends_with(&vec![0xa5; 192 * 1024]));
    let stderr = STANDARD
        .decode(json["stderr"]["bytes_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(stderr, b"failure\0\xff\n");
    assert!(
        !STANDARD
            .decode(json["command"]["program_base64"].as_str().unwrap())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        json["timing"]["classification"],
        "LOCAL_HOST_OBSERVATION_NOT_K2_TRUSTED_TIME"
    );
    assert_eq!(
        json["provenance"],
        "UNVERIFIED_REQUIRES_SIGNED_INTENT_AND_WORKLOAD_ADMISSION"
    );
}

#[tokio::test]
async fn output_limit_never_turns_a_prefix_into_full_evidence() {
    let evidence = capture(
        &mut child("verbose-failure"),
        context(),
        CaptureLimits {
            bytes_per_stream: 100,
            ..CaptureLimits::default()
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        evidence.outcome(),
        ProcessOutcome::Exited { code: 17 }
    ));
    assert!(!evidence.output_is_complete());
    let json: serde_json::Value =
        serde_json::from_slice(&evidence.plaintext_for_sealing().unwrap()).unwrap();
    assert_eq!(json["stdout"]["reached_eof"], true);
    assert_eq!(json["stdout"]["output_limit_exceeded"], true);
    assert!(json["stdout"]["observed_bytes"].as_u64().unwrap() > 192 * 1024);
    assert_eq!(
        STANDARD
            .decode(json["stdout"]["bytes_base64"].as_str().unwrap())
            .unwrap()
            .len(),
        100
    );
}

#[tokio::test]
async fn a_deadline_is_not_a_green_exit_and_the_owned_child_is_reaped() {
    let evidence = capture(
        &mut child("deadline"),
        context(),
        CaptureLimits {
            deadline: Duration::from_millis(100),
            ..CaptureLimits::default()
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        evidence.outcome(),
        ProcessOutcome::DeadlineExceeded { child_reaped: true }
    ));
    assert!(!evidence.output_is_complete());
}

#[tokio::test]
async fn observes_a_real_green_exit_without_synthetic_attestation() {
    let evidence = capture(&mut child("green"), context(), CaptureLimits::default())
        .await
        .unwrap();
    assert!(matches!(
        evidence.outcome(),
        ProcessOutcome::Exited { code: 0 }
    ));
    assert!(evidence.output_is_complete());
}

#[tokio::test]
async fn invalid_provenance_is_refused_before_spawn() {
    let mut invalid = context();
    invalid.run_attempt = 0;
    assert!(matches!(
        capture(&mut child("green"), invalid, CaptureLimits::default()).await,
        Err(chinwag_ci::CaptureError::InvalidInput)
    ));
}

#[tokio::test]
async fn preserves_exit_when_a_descendant_keeps_the_pipe_open() {
    let evidence = capture(
        &mut child("failed-with-held-pipe"),
        context(),
        CaptureLimits {
            deadline: Duration::from_millis(200),
            ..CaptureLimits::default()
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        evidence.outcome(),
        ProcessOutcome::DeadlineExceeded { child_reaped: true }
    ));
    let exit = evidence
        .observed_child_exit()
        .expect("direct child exit was observed");
    assert_eq!(exit.code, Some(17));
    assert!(exit.observed_before_capture_failure);
    assert!(!evidence.output_is_complete());
    // This controlled descendant is finite. Give it time to close its inherited
    // pipes; production descendants belong to the runner's job sandbox.
    tokio::time::sleep(Duration::from_millis(700)).await;
}

#[test]
fn command_evidence_binds_argument_boundaries_without_collecting_environment() {
    use chinwag_ci::CommandEvidence;
    let mut first = Command::new("test-only-program");
    first
        .args(["ab", "c"])
        .env("TEST_ONLY_SECRET", "DO_NOT_SNAPSHOT_ENVIRONMENT");
    let mut second = Command::new("test-only-program");
    second.args(["a", "bc"]);
    let first = CommandEvidence::snapshot(&first).unwrap();
    let second = CommandEvidence::snapshot(&second).unwrap();
    assert_ne!(first.argv_sha256(), second.argv_sha256());
    let json = serde_json::to_string(&first).unwrap();
    assert!(!json.contains("DO_NOT_SNAPSHOT_ENVIRONMENT"));
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let args = value["arguments_base64"].as_array().unwrap();
    assert_eq!(STANDARD.decode(args[0].as_str().unwrap()).unwrap(), b"ab");
    assert_eq!(STANDARD.decode(args[1].as_str().unwrap()).unwrap(), b"c");
}

#[cfg(unix)]
#[test]
fn command_evidence_preserves_non_utf8_argument_bytes() {
    use std::os::unix::ffi::OsStrExt;
    let mut command = Command::new("never-executed");
    command.arg(std::ffi::OsStr::from_bytes(b"raw-\xff"));
    let evidence = chinwag_ci::CommandEvidence::snapshot(&command).unwrap();
    let value = serde_json::to_value(&evidence).unwrap();
    assert_eq!(value["os_string_encoding"], "unix-os-bytes");
    assert_eq!(
        STANDARD
            .decode(value["arguments_base64"][0].as_str().unwrap())
            .unwrap(),
        b"raw-\xff"
    );
}

#[test]
fn oversized_command_metadata_is_refused_without_spawning() {
    let mut command = Command::new("never-executed");
    command.arg("x".repeat(chinwag_ci::MAX_COMMAND_EVIDENCE_BYTES));
    assert!(matches!(
        chinwag_ci::CommandEvidence::snapshot(&command),
        Err(chinwag_ci::CaptureError::InvalidInput)
    ));
}
