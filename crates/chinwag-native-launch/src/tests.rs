use super::*;
use chinwag_client_discovery::ExecutableMetadata;

fn host() -> HostIdentity {
    HostIdentity::new("studio-fixture".into(), "boot-a".into()).unwrap()
}

fn installation(path: &str) -> Installation {
    Installation {
        id: "a".repeat(64),
        family: ClientFamily::GrokBot,
        kind: InstallationKind::Application,
        match_basis: InstallationMatch::PublicBundleIdentity,
        canonical_path: PathBuf::from(path),
        observed_paths: vec![PathBuf::from(path)],
        display_name: "Grok Bot".into(),
        bundle_id: Some("com.anysphere.sand".into()),
        version: Some("1.0-fixture".into()),
        executable_path: PathBuf::from(path).join("Contents/MacOS/Grok Bot"),
        executable: ExecutableMetadata {
            device: 1,
            inode: 20,
            size: 1234,
            modified_seconds: 100,
            modified_nanoseconds: 1,
            mode: 0o100755,
            format: ExecutableFormat::MachO,
        },
        metadata_fingerprint: "b".repeat(64),
    }
}

fn observation(now: Instant) -> NativeObservation {
    NativeObservation::new(host(), installation("/Applications/Grok Bot.app"), now)
}

fn coordinator() -> LaunchCoordinator {
    LaunchCoordinator::new(8, Duration::from_secs(10)).unwrap()
}

fn operation(coordinator: &mut LaunchCoordinator, now: Instant) -> HumanOperation {
    coordinator
        .begin_human_operation(host(), now + Duration::from_secs(60), now)
        .unwrap()
}

struct FakeLauncher<F> {
    calls: usize,
    callback: F,
}

impl<F> NativeApplicationLauncher for FakeLauncher<F>
where
    F: FnMut(&LaunchTarget, Instant) -> Result<OpenReceipt, LaunchFailure>,
{
    fn open_or_reuse(
        &mut self,
        target: &LaunchTarget,
        deadline: Instant,
    ) -> Result<OpenReceipt, LaunchFailure> {
        self.calls += 1;
        (self.callback)(target, deadline)
    }
}

fn success(target: &LaunchTarget, _: Instant) -> Result<OpenReceipt, LaunchFailure> {
    Ok(OpenReceipt {
        application_path: target.application_path().to_owned(),
        bundle_id: target.bundle_id().to_owned(),
        process_id: Some(42),
    })
}

type FakeOpen = fn(&LaunchTarget, Instant) -> Result<OpenReceipt, LaunchFailure>;

fn launcher() -> FakeLauncher<FakeOpen> {
    FakeLauncher {
        calls: 0,
        callback: success,
    }
}

#[test]
fn exact_selected_copy_and_host_reach_one_executor_without_connection_claims() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    let initial = observation(now);
    let plan = coordinator.plan(&operation, &initial, now).unwrap();
    assert_eq!(plan.generation(), operation.generation());
    assert_eq!(plan.deadline(), operation.deadline());
    assert_eq!(plan.target().host().host_id(), "studio-fixture");
    assert_eq!(plan.target().host().boot_id(), "boot-a");
    assert_eq!(plan.target().display_name(), "Grok Bot");
    assert_eq!(plan.target().metadata_fingerprint(), "b".repeat(64));
    assert_eq!(
        plan.target().executable_path(),
        Path::new("/Applications/Grok Bot.app/Contents/MacOS/Grok Bot")
    );
    let fresh = observation(now + Duration::from_secs(1));
    let mut launcher = launcher();
    let receipt = coordinator
        .execute(&plan, &fresh, &mut launcher, || {
            now + Duration::from_secs(2)
        })
        .unwrap();
    assert_eq!(
        receipt.application_path,
        Path::new("/Applications/Grok Bot.app")
    );
    assert_eq!(receipt.bundle_id, "com.anysphere.sand");
    assert_eq!(launcher.calls, 1);
    assert_eq!(
        coordinator.execute(&plan, &fresh, &mut launcher, || now),
        Err(LaunchError::AlreadyAttempted)
    );
    assert_eq!(launcher.calls, 1);
}

#[test]
fn configuration_host_labels_and_operation_deadlines_are_bounded() {
    assert!(matches!(
        LaunchCoordinator::new(0, Duration::from_secs(1)),
        Err(LaunchError::InvalidConfiguration)
    ));
    assert!(matches!(
        LaunchCoordinator::new(129, Duration::from_secs(1)),
        Err(LaunchError::InvalidConfiguration)
    ));
    assert!(matches!(
        LaunchCoordinator::new(1, Duration::ZERO),
        Err(LaunchError::InvalidConfiguration)
    ));
    assert!(matches!(
        LaunchCoordinator::new(1, Duration::from_secs(31)),
        Err(LaunchError::InvalidConfiguration)
    ));
    for label in ["", " studio", "studio\n"] {
        assert_eq!(
            HostIdentity::new(label.into(), "boot".into()),
            Err(LaunchError::InvalidHostIdentity)
        );
    }
    let mut coordinator = coordinator();
    let now = Instant::now();
    assert!(matches!(
        coordinator.begin_human_operation(host(), now, now),
        Err(LaunchError::InvalidDeadline)
    ));
    assert!(matches!(
        coordinator.begin_human_operation(host(), now + Duration::from_secs(301), now),
        Err(LaunchError::InvalidDeadline)
    ));
}

#[test]
fn cli_script_launcher_only_name_only_and_mismatched_metadata_never_plan() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    let base = installation("/Applications/Grok Bot.app");
    let mut cases = Vec::new();
    let mut case = base.clone();
    case.kind = InstallationKind::CommandLine;
    cases.push(case);
    let mut case = base.clone();
    case.executable.format = ExecutableFormat::Script;
    cases.push(case);
    let mut case = base.clone();
    case.match_basis = InstallationMatch::LauncherOnly;
    cases.push(case);
    let mut case = base.clone();
    case.match_basis = InstallationMatch::NameAndExecutableHint;
    cases.push(case);
    let mut case = base.clone();
    case.bundle_id = Some("com.macpaw.Gemini2".into());
    cases.push(case);
    let mut case = base.clone();
    case.display_name = "Not Grok".into();
    cases.push(case);
    let mut case = base.clone();
    case.executable_path = PathBuf::from("/usr/bin/true");
    cases.push(case);
    let mut case = base.clone();
    case.canonical_path = PathBuf::from("/Applications/../Grok Bot.app");
    cases.push(case);
    let mut case = base.clone();
    case.canonical_path = PathBuf::from("Applications/Grok Bot.app");
    cases.push(case);
    let mut case = base.clone();
    case.executable.mode = 0o120755;
    cases.push(case);
    let mut case = base.clone();
    case.executable.mode = 0o100644;
    cases.push(case);
    let mut case = base.clone();
    case.metadata_fingerprint = "G".repeat(64);
    cases.push(case);
    let mut case = base;
    case.family = ClientFamily::Zed;
    cases.push(case);
    for candidate in cases {
        assert!(matches!(
            coordinator.plan(
                &operation,
                &NativeObservation::new(host(), candidate, now),
                now
            ),
            Err(LaunchError::UnsupportedInstallation)
        ));
    }
    // Invalid observations do not consume the plan capacity.
    assert!(coordinator.plan(&operation, &observation(now), now).is_ok());
}

#[test]
fn planning_rejects_foreign_host_boot_stale_and_future_observations() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    for foreign_host in [
        HostIdentity::new("macbook-fixture".into(), "boot-a".into()).unwrap(),
        HostIdentity::new("studio-fixture".into(), "boot-b".into()).unwrap(),
    ] {
        let candidate = NativeObservation::new(
            foreign_host,
            installation("/Applications/Grok Bot.app"),
            now,
        );
        assert!(matches!(
            coordinator.plan(&operation, &candidate, now),
            Err(LaunchError::HostChanged)
        ));
    }
    assert!(matches!(
        coordinator.plan(&operation, &observation(now), now + Duration::from_secs(11)),
        Err(LaunchError::StaleObservation)
    ));
    assert!(matches!(
        coordinator.plan(&operation, &observation(now + Duration::from_secs(1)), now),
        Err(LaunchError::StaleObservation)
    ));
    assert!(
        coordinator
            .plan(&operation, &observation(now), now + Duration::from_secs(10))
            .is_ok()
    );
}

#[test]
fn superseded_and_cancelled_operations_cannot_dispatch() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let first = operation(&mut coordinator, now);
    let plan = coordinator.plan(&first, &observation(now), now).unwrap();
    let next = operation(&mut coordinator, now);
    let mut launcher = launcher();
    assert_eq!(
        coordinator.execute(&plan, &observation(now), &mut launcher, || now),
        Err(LaunchError::StaleGeneration)
    );
    assert!(plan.target().is_cancelled());
    let next_plan = coordinator.plan(&next, &observation(now), now).unwrap();
    coordinator.cancel(&next).unwrap();
    assert_eq!(
        coordinator.execute(&next_plan, &observation(now), &mut launcher, || now),
        Err(LaunchError::Cancelled)
    );
    assert_eq!(launcher.calls, 0);
}

#[test]
fn exact_deadline_expires_and_consumes_plan_without_executor() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    let plan = coordinator
        .plan(&operation, &observation(now), now)
        .unwrap();
    let mut launcher = launcher();
    let fresh = observation(operation.deadline());
    assert_eq!(
        coordinator.execute(&plan, &fresh, &mut launcher, || operation.deadline()),
        Err(LaunchError::Expired)
    );
    assert_eq!(
        coordinator.execute(&plan, &fresh, &mut launcher, || now),
        Err(LaunchError::AlreadyAttempted)
    );
    assert_eq!(launcher.calls, 0);
}

#[test]
fn duplicate_copy_cannot_replan_after_fingerprint_changes_but_selected_other_copy_can() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    let first = coordinator
        .plan(&operation, &observation(now), now)
        .unwrap();
    let mut updated = installation("/Applications/Grok Bot.app");
    updated.metadata_fingerprint = "c".repeat(64);
    updated.id = "d".repeat(64);
    assert!(matches!(
        coordinator.plan(
            &operation,
            &NativeObservation::new(host(), updated, now),
            now
        ),
        Err(LaunchError::AlreadyPlanned)
    ));
    let selected_copy = NativeObservation::new(
        host(),
        installation("/Users/fixture/Applications/Grok Bot.app"),
        now,
    );
    let second = coordinator.plan(&operation, &selected_copy, now).unwrap();
    assert_ne!(first.id(), second.id());
    let mut launcher = launcher();
    let receipt = coordinator
        .execute(&second, &selected_copy, &mut launcher, || now)
        .unwrap();
    assert_eq!(
        receipt.application_path,
        Path::new("/Users/fixture/Applications/Grok Bot.app")
    );
    assert_eq!(launcher.calls, 1);
}

#[test]
fn bounded_plan_capacity_does_not_replace_other_selection() {
    let now = Instant::now();
    let mut coordinator = LaunchCoordinator::new(1, Duration::from_secs(10)).unwrap();
    let operation = operation(&mut coordinator, now);
    let plan = coordinator
        .plan(&operation, &observation(now), now)
        .unwrap();
    let other = NativeObservation::new(host(), installation("/Applications/Other Grok.app"), now);
    assert!(matches!(
        coordinator.plan(&operation, &other, now),
        Err(LaunchError::Capacity)
    ));
    let mut launcher = launcher();
    assert!(
        coordinator
            .execute(&plan, &observation(now), &mut launcher, || now)
            .is_ok()
    );
}

#[test]
fn same_numeric_generations_from_another_coordinator_grant_nothing() {
    let now = Instant::now();
    let mut first = coordinator();
    let first_operation = operation(&mut first, now);
    let plan = first
        .plan(&first_operation, &observation(now), now)
        .unwrap();
    let mut second = coordinator();
    let _second_operation = operation(&mut second, now);
    assert!(matches!(
        second.plan(&first_operation, &observation(now), now),
        Err(LaunchError::ForeignOperation)
    ));
    let mut launcher = launcher();
    assert_eq!(
        second.execute(&plan, &observation(now), &mut launcher, || now),
        Err(LaunchError::ForeignOperation)
    );
    assert_eq!(launcher.calls, 0);
}

#[test]
fn fresh_observation_must_revalidate_selected_copy_fingerprint_stat_and_host() {
    let now = Instant::now();
    let mut cases = Vec::new();
    let mut changed = observation(now);
    changed.installation.metadata_fingerprint = "c".repeat(64);
    cases.push(changed);
    let mut changed = observation(now);
    changed.installation.executable.inode += 1;
    cases.push(changed);
    let mut changed = observation(now);
    changed.installation.id = "c".repeat(64);
    cases.push(changed);
    let changed = NativeObservation::new(host(), installation("/Applications/Other Grok.app"), now);
    cases.push(changed);
    let mut changed = observation(now);
    changed.host = HostIdentity::new("studio-fixture".into(), "reboot".into()).unwrap();
    cases.push(changed);
    for fresh in cases {
        let mut coordinator = coordinator();
        let operation = operation(&mut coordinator, now);
        let plan = coordinator
            .plan(&operation, &observation(now), now)
            .unwrap();
        let mut launcher = launcher();
        assert!(matches!(
            coordinator.execute(&plan, &fresh, &mut launcher, || now),
            Err(LaunchError::InstallationChanged | LaunchError::HostChanged)
        ));
        assert_eq!(launcher.calls, 0);
    }
}

#[test]
fn stale_dispatch_observation_is_terminal_without_executor() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    let plan = coordinator
        .plan(&operation, &observation(now), now)
        .unwrap();
    let mut launcher = launcher();
    assert_eq!(
        coordinator.execute(&plan, &observation(now), &mut launcher, || now
            + Duration::from_secs(11)),
        Err(LaunchError::StaleObservation)
    );
    assert_eq!(
        coordinator.execute(
            &plan,
            &observation(now + Duration::from_secs(11)),
            &mut launcher,
            || now + Duration::from_secs(11)
        ),
        Err(LaunchError::AlreadyAttempted)
    );
    assert_eq!(launcher.calls, 0);
}

#[test]
fn uncertain_attempt_never_retries_and_does_not_block_another_selected_copy() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    let plan = coordinator
        .plan(&operation, &observation(now), now)
        .unwrap();
    let mut uncertain = FakeLauncher {
        calls: 0,
        callback: |_: &LaunchTarget, _| Err(LaunchFailure::Uncertain("OS completion lost")),
    };
    assert_eq!(
        coordinator.execute(&plan, &observation(now), &mut uncertain, || now),
        Err(LaunchError::Execution(LaunchFailure::Uncertain(
            "OS completion lost"
        )))
    );
    assert_eq!(
        coordinator.execute(&plan, &observation(now), &mut uncertain, || now),
        Err(LaunchError::AlreadyAttempted)
    );
    assert_eq!(uncertain.calls, 1);
    let other = NativeObservation::new(
        host(),
        installation("/Applications/Selected Other Grok.app"),
        now,
    );
    let other_plan = coordinator.plan(&operation, &other, now).unwrap();
    let mut launcher = launcher();
    assert!(
        coordinator
            .execute(&other_plan, &other, &mut launcher, || now)
            .is_ok()
    );
}

#[test]
fn rejected_unavailable_and_access_required_do_not_retry() {
    let now = Instant::now();
    for failure in [
        LaunchFailure::Rejected("cancelled before submission"),
        LaunchFailure::Unavailable("unsupported OS"),
        LaunchFailure::AccessRequired("human access"),
    ] {
        let mut coordinator = coordinator();
        let operation = operation(&mut coordinator, now);
        let plan = coordinator
            .plan(&operation, &observation(now), now)
            .unwrap();
        let mut launcher = FakeLauncher {
            calls: 0,
            callback: |_: &LaunchTarget, _| Err(failure.clone()),
        };
        assert_eq!(
            coordinator.execute(&plan, &observation(now), &mut launcher, || now),
            Err(LaunchError::Execution(failure.clone()))
        );
        assert_eq!(
            coordinator.execute(&plan, &observation(now), &mut launcher, || now),
            Err(LaunchError::AlreadyAttempted)
        );
        assert_eq!(launcher.calls, 1);
    }
}

#[test]
fn receipt_for_another_copy_bundle_or_zero_pid_is_uncertain_without_retry() {
    let now = Instant::now();
    for case in 0..3 {
        let mut coordinator = coordinator();
        let operation = operation(&mut coordinator, now);
        let plan = coordinator
            .plan(&operation, &observation(now), now)
            .unwrap();
        let mut launcher = FakeLauncher {
            calls: 0,
            callback: |target: &LaunchTarget, deadline| {
                let mut receipt = success(target, deadline)?;
                match case {
                    0 => receipt.application_path = PathBuf::from("/Applications/Other Grok.app"),
                    1 => receipt.bundle_id = "different.bundle".into(),
                    _ => receipt.process_id = Some(0),
                }
                Ok(receipt)
            },
        };
        assert!(matches!(
            coordinator.execute(&plan, &observation(now), &mut launcher, || now),
            Err(LaunchError::Execution(LaunchFailure::Uncertain(_)))
        ));
        assert_eq!(
            coordinator.execute(&plan, &observation(now), &mut launcher, || now),
            Err(LaunchError::AlreadyAttempted)
        );
        assert_eq!(launcher.calls, 1);
    }
}

#[test]
fn cancellation_during_os_call_preserves_uncertainty() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    let plan = coordinator
        .plan(&operation, &observation(now), now)
        .unwrap();
    let mut launcher = FakeLauncher {
        calls: 0,
        callback: |target: &LaunchTarget, deadline| {
            operation.cancel();
            assert!(target.is_cancelled());
            success(target, deadline)
        },
    };
    assert!(matches!(
        coordinator.execute(&plan, &observation(now), &mut launcher, || now),
        Err(LaunchError::Execution(LaunchFailure::Uncertain(_)))
    ));
    assert_eq!(launcher.calls, 1);
}

#[test]
fn late_os_completion_is_uncertain_even_when_exact_receipt_arrives() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    let plan = coordinator
        .plan(&operation, &observation(now), now)
        .unwrap();
    let mut launcher = launcher();
    let mut calls = 0;
    let result = coordinator.execute(&plan, &observation(now), &mut launcher, || {
        calls += 1;
        if calls == 1 {
            now
        } else {
            operation.deadline()
        }
    });
    assert!(matches!(
        result,
        Err(LaunchError::Execution(LaunchFailure::Uncertain(_)))
    ));
    assert_eq!(
        coordinator.execute(&plan, &observation(now), &mut launcher, || now),
        Err(LaunchError::AlreadyAttempted)
    );
    assert_eq!(launcher.calls, 1);
}

#[test]
fn queued_submission_deadline_is_shortened_to_observation_freshness() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    let plan = coordinator
        .plan(&operation, &observation(now), now)
        .unwrap();
    let fresh = observation(now + Duration::from_secs(1));
    let expected_deadline = now + Duration::from_secs(11);
    let mut launcher = FakeLauncher {
        calls: 0,
        callback: |target: &LaunchTarget, deadline| {
            assert_eq!(deadline, expected_deadline);
            assert!(deadline < operation.deadline());
            success(target, deadline)
        },
    };
    assert!(
        coordinator
            .execute(&plan, &fresh, &mut launcher, || now
                + Duration::from_secs(2))
            .is_ok()
    );
    assert_eq!(launcher.calls, 1);
}

#[test]
fn observation_at_exact_freshness_deadline_cannot_reach_executor() {
    let now = Instant::now();
    let mut coordinator = coordinator();
    let operation = operation(&mut coordinator, now);
    let plan = coordinator
        .plan(&operation, &observation(now), now)
        .unwrap();
    let mut launcher = launcher();
    assert_eq!(
        coordinator.execute(&plan, &observation(now), &mut launcher, || now
            + Duration::from_secs(10)),
        Err(LaunchError::StaleObservation)
    );
    assert_eq!(launcher.calls, 0);
}

#[test]
fn every_late_executor_error_is_uncertain_and_terminal() {
    let now = Instant::now();
    for failure in [
        LaunchFailure::Rejected("late rejection"),
        LaunchFailure::Unavailable("late unavailable"),
        LaunchFailure::AccessRequired("late access"),
        LaunchFailure::Uncertain("late uncertain"),
    ] {
        let mut coordinator = coordinator();
        let operation = operation(&mut coordinator, now);
        let plan = coordinator
            .plan(&operation, &observation(now), now)
            .unwrap();
        let mut launcher = FakeLauncher {
            calls: 0,
            callback: |_: &LaunchTarget, _| Err(failure.clone()),
        };
        let mut reads = 0;
        let result = coordinator.execute(&plan, &observation(now), &mut launcher, || {
            reads += 1;
            if reads == 1 {
                now
            } else {
                now + Duration::from_secs(10)
            }
        });
        assert!(matches!(
            result,
            Err(LaunchError::Execution(LaunchFailure::Uncertain(_)))
        ));
        assert_eq!(
            coordinator.execute(&plan, &observation(now), &mut launcher, || now),
            Err(LaunchError::AlreadyAttempted)
        );
        assert_eq!(launcher.calls, 1);
    }
}

#[test]
fn cancelled_or_clock_regressed_executor_error_is_uncertain() {
    let now = Instant::now();
    for cancelled in [true, false] {
        let mut coordinator = coordinator();
        let operation = operation(&mut coordinator, now);
        let plan = coordinator
            .plan(&operation, &observation(now), now)
            .unwrap();
        let mut launcher = FakeLauncher {
            calls: 0,
            callback: |_: &LaunchTarget, _| {
                if cancelled {
                    operation.cancel();
                }
                Err(LaunchFailure::Rejected("late rejection"))
            },
        };
        let mut reads = 0;
        let result = coordinator.execute(&plan, &observation(now), &mut launcher, || {
            reads += 1;
            if reads == 1 || cancelled {
                now + Duration::from_secs(1)
            } else {
                now
            }
        });
        assert!(matches!(
            result,
            Err(LaunchError::Execution(LaunchFailure::Uncertain(_)))
        ));
        assert_eq!(launcher.calls, 1);
    }
}
