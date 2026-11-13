// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
use chinwag_fleet::*;
use ed25519_dalek::{Signer, SigningKey};
use std::{collections::BTreeMap, path::PathBuf};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    repo: PathBuf,
    manifest: FleetManifest,
}
impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = root.join("repository");
        std::fs::create_dir(&repo).unwrap();
        let initialized = std::process::Command::new("git")
            .args([
                "-c",
                "init.defaultBranch=fixture",
                "init",
                "--quiet",
                "--template=",
            ])
            .current_dir(&repo)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        assert!(
            initialized.status.success(),
            "{}",
            String::from_utf8_lossy(&initialized.stderr)
        );
        let mut manifest = FleetManifest::starter_profile("solo").unwrap();
        let seat = &mut manifest.seats[0];
        seat.lifecycle = SeatLifecycle::ActiveStanding;
        seat.model.provider = "test-provider".into();
        seat.model.model_id = "test-model".into();
        seat.driver = DriverSpec::CliSubprocess {
            executable: "sh".into(),
            argv_template: vec!["-c".into(), "cat".into()],
            auth_isolation: CredentialIsolation::NoneLocal,
            env_allowlist: vec!["PATH".into()],
            env_overrides: BTreeMap::new(),
            framing: "stdin".into(),
            timeout_secs: 5,
        };
        Self {
            _temp: temp,
            root,
            repo,
            manifest,
        }
    }
    fn request(&self) -> DispatchRequest {
        DispatchRequest {
            seat: "default".into(),
            cwd: self.repo.clone(),
            actor: Some("default#run".into()),
            ..Default::default()
        }
    }
    fn plan(&self) -> ResolvedDispatchPlan {
        resolve_dispatch_plan(&self.manifest, &self.request()).unwrap()
    }
    fn mutate(&mut self) {
        let seat = &mut self.manifest.seats[0];
        seat.write_mode = WriteMode::Isolated;
        seat.allowed_write_roots = vec!["src/**".into()];
        seat.isolation = IsolationSpec::CopyOnWriteDir {
            root: Some(self.root.join("copies")),
        };
        std::fs::create_dir(self.repo.join("src")).unwrap();
        std::fs::write(self.repo.join("src/input.txt"), "source").unwrap();
    }
    fn keys(&mut self) {
        self.manifest.pubkey_map.clear();
        self.manifest.allowed_signers.clear();
        for (index, seat) in self.manifest.seats.iter().enumerate() {
            let key = SigningKey::from_bytes(&[index as u8 + 1; 32]);
            let text = chinwag_claim::encode_hex(key.verifying_key().as_bytes());
            self.manifest
                .pubkey_map
                .insert(seat.id.clone(), text.clone());
            self.manifest.allowed_signers.insert(seat.id.clone(), text);
        }
    }
}

#[test]
fn starter_profiles_validate_offline_and_round_trip() {
    for profile in ["solo", "mesh", "airgapped", "cloud-pool"] {
        let manifest = FleetManifest::starter_profile(profile).unwrap();
        assert_eq!(manifest.policy.failover_policy, FailoverPolicy::Forbid);
        let toml = manifest.to_toml().unwrap();
        let parsed = FleetManifest::from_toml(&toml).unwrap();
        let json = parsed.to_canonical_json().unwrap();
        assert_eq!(
            FleetManifest::from_json(&json).unwrap().digest().unwrap(),
            manifest.digest().unwrap()
        );
    }
}
#[test]
fn arbitrary_identifiers_are_validated() {
    assert!(SeatId::new("research-west_2").is_ok());
    for bad in ["", "../escape", "seat#instance", "white space", "@seat"] {
        assert!(SeatId::new(bad).is_err());
    }
}
#[test]
fn unknown_paused_retired_fail_before_any_child() {
    let mut f = Fixture::new();
    let marker = f.root.join("executed");
    if let DriverSpec::CliSubprocess { argv_template, .. } = &mut f.manifest.seats[0].driver {
        *argv_template = vec!["-c".into(), format!("touch '{}'", marker.display())];
    }
    let mut request = f.request();
    request.seat = "unknown".into();
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::UnknownSeat(_))
    ));
    for lifecycle in [SeatLifecycle::Paused, SeatLifecycle::Retired] {
        f.manifest.seats[0].lifecycle = lifecycle;
        assert!(matches!(
            resolve_dispatch_plan(&f.manifest, &f.request()),
            Err(FleetPolicyError::RetiredOrPausedSeat(_))
        ));
    }
    assert!(!marker.exists());
}
#[test]
fn missing_driver_never_substitutes_another_binary() {
    let mut f = Fixture::new();
    if let DriverSpec::CliSubprocess { executable, .. } = &mut f.manifest.seats[0].driver {
        *executable = f.root.join("absent-driver").to_string_lossy().into_owned();
    }
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &f.request()),
        Err(FleetPolicyError::DriverBinaryMissing(_))
    ));
}
#[test]
fn bare_actor_is_rejected() {
    let f = Fixture::new();
    let mut r = f.request();
    r.actor = Some("default".into());
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &r),
        Err(FleetPolicyError::BareSeatAddressRejected(_))
    ));
}
#[test]
fn oauth_scrubs_credentials_even_from_overrides_and_context() {
    let mut f = Fixture::new();
    if let DriverSpec::CliSubprocess {
        argv_template,
        auth_isolation,
        env_overrides,
        ..
    } = &mut f.manifest.seats[0].driver
    {
        *argv_template=vec!["-c".into(),"printf '%s:%s:%s:%s' \"${ANTHROPIC_BASE_URL-unset}\" \"${ANTHROPIC_AUTH_TOKEN-unset}\" \"${ANTHROPIC_API_KEY-unset}\" \"${CUSTOM_SECRET-unset}\"".into()];
        *auth_isolation = CredentialIsolation::FirstPartyCliOauth {
            scrub_env: vec!["CUSTOM_SECRET".into()],
            preflight_cmd: vec![],
        };
        env_overrides.insert("ANTHROPIC_API_KEY".into(), "must-not-leak".into());
    }
    let context = ExecutionContext {
        env: BTreeMap::from([
            ("ANTHROPIC_BASE_URL".into(), "must-not-leak".into()),
            ("ANTHROPIC_AUTH_TOKEN".into(), "must-not-leak".into()),
            ("CUSTOM_SECRET".into(), "must-not-leak".into()),
        ]),
        ..Default::default()
    };
    let outcome = ProcessExecutionDriver.execute(&f.plan(), &context).unwrap();
    assert_eq!(outcome.stdout, "unset:unset:unset:unset");
}
#[test]
fn subprocess_receives_prompt_model_parameters_and_context() {
    let mut f = Fixture::new();
    f.manifest.seats[0]
        .model
        .params
        .insert("reasoning_effort".into(), serde_json::json!("high"));
    if let DriverSpec::CliSubprocess { argv_template, .. } = &mut f.manifest.seats[0].driver {
        *argv_template = vec![
            "-c".into(),
            "printf '%s:%s:' \"$CHINWAG_ACTOR\" \"$CHINWAG_MODEL_ID\"; cat".into(),
        ];
    }
    let context = ExecutionContext {
        env: BTreeMap::from([("CHINWAG_ACTOR".into(), "default#run".into())]),
        prompt: Some("message".into()),
        ..Default::default()
    };
    let outcome = ProcessExecutionDriver.execute(&f.plan(), &context).unwrap();
    assert!(outcome.success);
    assert_eq!(outcome.stdout, "default#run:test-model:message");
}
#[test]
fn child_exit_is_reported_without_fallback() {
    let mut f = Fixture::new();
    if let DriverSpec::CliSubprocess { argv_template, .. } = &mut f.manifest.seats[0].driver {
        *argv_template = vec!["-c".into(), "exit 7".into()];
    }
    let outcome = ProcessExecutionDriver
        .execute(&f.plan(), &ExecutionContext::default())
        .unwrap();
    assert!(!outcome.success);
    assert_eq!(outcome.exit_code, Some(7));
}
#[test]
fn provider_deny_rule_is_case_insensitive() {
    let mut f = Fixture::new();
    f.manifest.policy.deny_providers = vec!["TEST-PROVIDER".into()];
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &f.request()),
        Err(FleetPolicyError::ProviderDenied(_))
    ));
}
#[test]
fn room_acl_and_seat_patterns_deny_unlisted_rooms() {
    let mut f = Fixture::new();
    f.manifest
        .policy
        .room_acls
        .insert("project-*".into(), vec![SeatId::new("default").unwrap()]);
    f.manifest.seats[0].allowed_rooms = Some(vec!["project-one".into()]);
    let mut request = f.request();
    request.room = Some("project-two".into());
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::RoomAclDenied(_))
    ));
    request.room = Some("project-one".into());
    assert!(resolve_dispatch_plan(&f.manifest, &request).is_ok());
    request.room = None;
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::RoomAclDenied(_))
    ));
}
#[test]
fn restrictive_overlapping_room_acl_wins() {
    let mut f = Fixture::new();
    f.manifest
        .policy
        .room_acls
        .insert("project-*".into(), vec![SeatId::new("default").unwrap()]);
    f.manifest
        .policy
        .room_acls
        .insert("project-secret".into(), vec![]);
    let mut request = f.request();
    request.room = Some("project-secret".into());
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::RoomAclDenied(_))
    ));
}
#[test]
fn http_egress_denies_all_and_prefix_confusion() {
    let mut f = Fixture::new();
    f.manifest.seats[0].driver = DriverSpec::OpenAiCompatibleHttp {
        base_url: "https://api.invalid.evil/v1".into(),
        api_key_env: "TEST_API_KEY".into(),
        wire_mode: "responses".into(),
        stream_mode: "none".into(),
        timeout_secs: 5,
    };
    for policy in [
        EgressPolicy::DenyAll,
        EgressPolicy::AllowList {
            endpoints: vec!["https://api.invalid".into()],
        },
    ] {
        f.manifest.policy.egress_policy = policy;
        assert!(matches!(
            resolve_dispatch_plan(&f.manifest, &f.request()),
            Err(FleetPolicyError::EgressViolation(_))
        ));
    }
}
#[test]
fn denied_and_missing_skills_are_distinct_and_symlinks_fail() {
    let mut f = Fixture::new();
    f.manifest.seats[0].skills.allowed_skills = vec!["approved".into()];
    let mut request = f.request();
    request.requested_skills = vec!["approved".into()];
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::MissingSkill(_))
    ));
    let skill = f.root.join("SKILL.md");
    std::fs::write(&skill, "approved skill").unwrap();
    f.manifest.skills.paths.insert("approved".into(), skill);
    assert!(resolve_dispatch_plan(&f.manifest, &request).is_ok());
    f.manifest.skills.forbidden_skills.push("approved".into());
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::ForbiddenSkill(_))
    ));
}
#[test]
fn key_bijection_rejects_missing_duplicate_and_disagreeing_keys() {
    let mut f = Fixture::new();
    assert!(KeyBijectionValidator::validate(&f.manifest, true).is_err());
    let mut other = f.manifest.seats[0].clone();
    other.id = SeatId::new("second").unwrap();
    f.manifest.seats.push(other);
    f.keys();
    KeyBijectionValidator::validate(&f.manifest, true).unwrap();
    let first = f.manifest.pubkey_map[&SeatId::new("default").unwrap()].clone();
    f.manifest
        .pubkey_map
        .insert(SeatId::new("second").unwrap(), first.clone());
    f.manifest
        .allowed_signers
        .insert(SeatId::new("second").unwrap(), first);
    assert!(matches!(
        KeyBijectionValidator::validate(&f.manifest, true),
        Err(FleetPolicyError::KeyBijectionFailed(_))
    ));
}
#[cfg(unix)]
#[test]
fn private_key_permissions_and_symlinks_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let mut f = Fixture::new();
    f.keys();
    let key = f.root.join("key");
    std::fs::write(&key, "private-key-fixture").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    f.manifest
        .private_key_paths
        .insert(SeatId::new("default").unwrap(), key.clone());
    assert!(KeyBijectionValidator::validate(&f.manifest, true).is_err());
    for mode in [0o4600, 0o2600, 0o1600] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            KeyBijectionValidator::validate(&f.manifest, true),
            Err(FleetPolicyError::KeyBijectionFailed(_))
        ));
    }
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    KeyBijectionValidator::validate(&f.manifest, true).unwrap();
    let link = f.root.join("key-link");
    symlink(&key, &link).unwrap();
    f.manifest
        .private_key_paths
        .insert(SeatId::new("default").unwrap(), link);
    assert!(matches!(
        KeyBijectionValidator::validate(&f.manifest, true),
        Err(FleetPolicyError::KeyBijectionFailed(_))
    ));
}
#[test]
fn repo_holds_block_mutation_but_allow_read_only_and_other_repositories() {
    let mut f = Fixture::new();
    f.manifest.policy.repo_holds.push(RepoHoldRule {
        repo_pattern: "repository".into(),
        active: true,
        reason: "maintenance".into(),
    });
    assert!(resolve_dispatch_plan(&f.manifest, &f.request()).is_ok());
    f.mutate();
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &f.request()),
        Err(FleetPolicyError::RepoHoldActive(_))
    ));
    f.manifest.policy.repo_holds[0].repo_pattern = "different-repository".into();
    assert!(resolve_dispatch_plan(&f.manifest, &f.request()).is_ok());
}
#[test]
fn write_scope_subset_and_traversal_are_fail_closed() {
    let f = Fixture::new();
    let mut request = f.request();
    request.requested_write_globs = vec!["src/**".into()];
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::WriteScopeDenied(_))
    ));
    for path in [
        "../escape",
        "src/../../escape",
        "/absolute",
        "src/*",
        ".git/config",
    ] {
        assert!(authorize_write_roots(&[path.into()], &["src/**".into()]).is_err());
    }
    assert!(authorize_write_roots(&["src/nested/file.rs".into()], &["src/**".into()]).is_ok());
    assert!(authorize_write_roots(&["src-other/file.rs".into()], &["src/**".into()]).is_err());
}
#[test]
fn overlapping_claims_survive_reopen_and_block_before_provisioning() {
    let mut f = Fixture::new();
    f.mutate();
    let mut request = f.request();
    request.requested_write_globs = vec!["src/**".into()];
    let plan = resolve_dispatch_plan(&f.manifest, &request).unwrap();
    let claims = f.root.join("claims");
    let first = prepare_execution_sandbox(&f.manifest, &plan, &claims, "default#run").unwrap();
    assert!(first.isolated_cwd.join("src/input.txt").exists());
    verify_execution_sandbox(&claims, &first).unwrap();
    assert!(matches!(
        prepare_execution_sandbox(&f.manifest, &plan, &claims, "default#peer"),
        Err(FleetPolicyError::OverlappingClaim(_))
    ));
    release_execution_sandbox(&claims, &first, false).unwrap();
    assert!(!first.isolated_cwd.exists());
    assert!(verify_execution_sandbox(&claims, &first).is_err());
    let second = prepare_execution_sandbox(&f.manifest, &plan, &claims, "default#peer").unwrap();
    release_execution_sandbox(&claims, &second, true).unwrap();
    assert!(matches!(
        prepare_execution_sandbox(&f.manifest, &plan, &claims, "default#third"),
        Err(FleetPolicyError::OverlappingClaim(_))
    ));
}
#[test]
fn forged_lease_receipt_is_rejected() {
    let f = Fixture::new();
    let claims = f.root.join("claims");
    let mut lease =
        prepare_execution_sandbox(&f.manifest, &f.plan(), &claims, "default#run").unwrap();
    lease.seat_actor = "default#forged".into();
    assert!(verify_execution_sandbox(&claims, &lease).is_err());
}
#[test]
fn manifest_digest_and_signature_pins_detect_tampering() {
    let mut f = Fixture::new();
    let digest = f.manifest.digest().unwrap();
    let key = SigningKey::from_bytes(&[9; 32]);
    let signature = key.sign(digest.as_bytes());
    f.manifest.pin = Some(ManifestPin {
        digest_sha256: digest,
        signer_public_key: Some(chinwag_claim::encode_hex(key.verifying_key().as_bytes())),
        signature: Some(chinwag_claim::encode_hex(&signature.to_bytes())),
    });
    f.manifest.validate().unwrap();
    f.manifest.seats[0].model.model_id = "tampered".into();
    assert!(f.manifest.validate().is_err());
}
#[test]
fn manifest_paths_are_anchored_to_manifest_parent() {
    let mut f = Fixture::new();
    f.manifest.source_dir = Some(f.root.clone());
    f.manifest
        .skills
        .paths
        .insert("approved".into(), PathBuf::from("skill.md"));
    f.manifest.seats[0]
        .skills
        .allowed_skills
        .push("approved".into());
    std::fs::write(f.root.join("skill.md"), "skill").unwrap();
    let path = f.root.join("fleet.toml");
    std::fs::write(&path, f.manifest.to_toml().unwrap()).unwrap();
    let loaded = FleetManifest::load(&path).unwrap();
    let mut request = f.request();
    request.requested_skills = vec!["approved".into()];
    assert!(resolve_dispatch_plan(&loaded, &request).is_ok());
}
#[test]
fn mesh_selection_is_deterministic_and_missing_nodes_fail_closed() {
    let mut f = Fixture::new();
    f.manifest.seats[0].target_selector = ExecutionTarget::MeshPeerSelector {
        required_labels: BTreeMap::from([("role".into(), "compute".into())]),
        preferred_labels: BTreeMap::new(),
    };
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &f.request()),
        Err(FleetPolicyError::TargetNodeUnavailable(_))
    ));
    for id in ["z", "a"] {
        f.manifest.nodes.push(NodeDescriptor {
            node_id: id.into(),
            labels: BTreeMap::from([("role".into(), "compute".into())]),
            capabilities: NodeCapabilities::default(),
            transport: NodeTransport::Local,
        });
    }
    assert_eq!(f.plan().resolved_node.as_deref(), Some("a"));
    assert!(matches!(
        ProcessExecutionDriver.execute(&f.plan(), &ExecutionContext::default()),
        Err(FleetPolicyError::UnsupportedDriver(_))
    ));
}
#[test]
fn operator_pins_require_qualified_configured_actor() {
    let mut f = Fixture::new();
    f.manifest.policy.operator_signers.push("default".into());
    assert!(matches!(
        f.manifest.validate(),
        Err(FleetPolicyError::BareSeatAddressRejected(_))
    ));
    f.manifest.policy.operator_signers[0] = "default#operator".into();
    f.manifest.validate().unwrap();
}

#[test]
fn plan_policy_mutation_is_rejected_before_sandbox_or_spawn() {
    let f = Fixture::new();
    let mut plan = f.plan();
    if let DriverSpec::CliSubprocess { argv_template, .. } = &mut plan.driver {
        *argv_template = vec![
            "-c".into(),
            format!("touch '{}'", f.root.join("forged-execution").display()),
        ];
    }
    assert!(matches!(
        prepare_execution_sandbox(&f.manifest, &plan, &f.root.join("claims"), "default#run"),
        Err(FleetPolicyError::InvalidManifest(_))
    ));
    assert!(matches!(
        ProcessExecutionDriver.execute(&plan, &ExecutionContext::default()),
        Err(FleetPolicyError::InvalidManifest(_))
    ));
    assert!(!f.root.join("forged-execution").exists());
}
#[test]
fn timeout_returns_real_reaped_terminal_status() {
    let mut f = Fixture::new();
    if let DriverSpec::CliSubprocess {
        argv_template,
        timeout_secs,
        ..
    } = &mut f.manifest.seats[0].driver
    {
        *argv_template = vec!["-c".into(), "sleep 30".into()];
        *timeout_secs = 1;
    }
    let start = std::time::Instant::now();
    let result = ProcessExecutionDriver
        .execute(&f.plan(), &ExecutionContext::default())
        .unwrap();
    assert!(!result.success);
    assert!(result.timed_out);
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    #[cfg(unix)]
    assert_eq!(result.termination_signal, Some(9));
}
#[test]
fn descendants_holding_output_descriptors_do_not_block_terminal_receipt() {
    let mut f = Fixture::new();
    let release = f.root.join("release-descendant");
    let stopped = f.root.join("descendant-stopped");
    if let DriverSpec::CliSubprocess { argv_template, .. } = &mut f.manifest.seats[0].driver {
        *argv_template = vec![
            "-c".into(),
            format!(
                "(remaining=100; while [ ! -e '{}' ] && [ $remaining -gt 0 ]; do remaining=$((remaining-1)); sleep 0.05; done; : > '{}') & printf done",
                release.display(),
                stopped.display()
            ),
        ];
    }
    let result = ProcessExecutionDriver
        .execute(&f.plan(), &ExecutionContext::default())
        .unwrap();
    std::fs::write(release, "release").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !stopped.exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(result.success);
    assert_eq!(result.stdout, "done");
}
#[test]
fn child_output_capture_is_bounded_and_excess_is_terminal_failure() {
    let mut f = Fixture::new();
    if let DriverSpec::CliSubprocess { argv_template, .. } = &mut f.manifest.seats[0].driver {
        *argv_template=vec!["-c".into(),"while :; do printf '01234567890123456789012345678901234567890123456789012345678901234567890123456789'; done".into()];
    }
    let result = ProcessExecutionDriver
        .execute(&f.plan(), &ExecutionContext::default())
        .unwrap();
    assert!(result.output_limit_exceeded);
    assert!(!result.success);
    assert!(result.stdout.len() <= 1024 * 1024);
}
#[test]
fn competing_path_leases_acquire_exactly_once() {
    use chinwag_claim::path_lease::{PathLeaseError, PathLeaseRequest, PathLeaseStore};
    let f = Fixture::new();
    let root = f.root.join("concurrent-leases");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for index in 0..2 {
        let barrier = barrier.clone();
        let root = root.clone();
        let repository = f.repo.clone();
        handles.push(std::thread::spawn(move || {
            let store = PathLeaseStore::open(&root).unwrap();
            barrier.wait();
            store.acquire(&PathLeaseRequest {
                claim_id: format!("claim-{index}"),
                actor: format!("default#peer{index}"),
                repository,
                roots: vec!["src/**".into()],
                metadata: BTreeMap::new(),
            })
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(PathLeaseError::OverlappingClaim(_))))
            .count(),
        1
    );
}
#[test]
fn corrupted_path_lease_state_fails_closed() {
    use chinwag_claim::path_lease::{PathLeaseRequest, PathLeaseStore};
    let f = Fixture::new();
    let root = f.root.join("corrupt-leases");
    let store = PathLeaseStore::open(&root).unwrap();
    let request = PathLeaseRequest {
        claim_id: "claim-one".into(),
        actor: "default#one".into(),
        repository: f.repo.clone(),
        roots: vec!["src/**".into()],
        metadata: BTreeMap::new(),
    };
    let receipt = store.acquire(&request).unwrap();
    std::fs::write(root.join("path-leases.v1.json"), b"truncated").unwrap();
    assert!(store.verify(&receipt).is_err());
    assert!(store.acquire(&request).is_err());
}
#[cfg(unix)]
#[test]
fn symlink_write_roots_fail_before_provisioning() {
    let mut f = Fixture::new();
    f.mutate();
    let external = f.root.join("external");
    std::fs::create_dir(&external).unwrap();
    std::os::unix::fs::symlink(&external, f.repo.join("src/escape")).unwrap();
    let mut request = f.request();
    request.requested_write_globs = vec!["src/escape/**".into()];
    let plan = resolve_dispatch_plan(&f.manifest, &request).unwrap();
    assert!(matches!(
        prepare_execution_sandbox(&f.manifest, &plan, &f.root.join("claims"), "default#run"),
        Err(FleetPolicyError::WriteScopeDenied(_))
    ));
    assert!(!f.root.join("copies").exists());
}
#[test]
fn explicitly_registered_mount_backend_receives_lease_and_clean_release() {
    struct RegisteredMount;
    impl IsolationBackend for RegisteredMount {
        fn prepare(
            &self,
            _workspace: &std::path::Path,
            destination: &std::path::Path,
        ) -> FleetResult<()> {
            std::fs::create_dir(destination)?;
            Ok(())
        }
        fn release(
            &self,
            _workspace: &std::path::Path,
            destination: &std::path::Path,
        ) -> FleetResult<()> {
            std::fs::remove_dir(destination)?;
            Ok(())
        }
    }
    let mut f = Fixture::new();
    f.manifest.seats[0].write_mode = WriteMode::Isolated;
    f.manifest.seats[0].allowed_write_roots = vec!["artifacts/**".into()];
    f.manifest.seats[0].isolation = IsolationSpec::ContainerOrMicroVmMount {
        root: f.root.join("mounts"),
    };
    let mut request = f.request();
    request.requested_write_globs = vec!["artifacts/**".into()];
    let plan = resolve_dispatch_plan(&f.manifest, &request).unwrap();
    let claims = f.root.join("claims");
    let receipt = prepare_execution_sandbox_with_backend(
        &f.manifest,
        &plan,
        &claims,
        "default#run",
        &RegisteredMount,
    )
    .unwrap();
    verify_execution_sandbox(&claims, &receipt).unwrap();
    release_execution_sandbox_with_backend(&claims, &receipt, false, &RegisteredMount).unwrap();
    assert!(!receipt.isolated_cwd.exists());
}

#[test]
fn cwd_changes_require_verified_sandbox_relocation() {
    let f = Fixture::new();
    let mut plan = f.plan();
    plan.cwd = f.root.clone();
    assert!(matches!(
        ProcessExecutionDriver.execute(&plan, &ExecutionContext::default()),
        Err(FleetPolicyError::InvalidManifest(_))
    ));
    let claims = f.root.join("claims");
    let original = f.plan();
    let receipt =
        prepare_execution_sandbox(&f.manifest, &original, &claims, "default#run").unwrap();
    let authorized = original.with_sandbox(&claims, &receipt).unwrap();
    assert!(
        ProcessExecutionDriver
            .execute(&authorized, &ExecutionContext::default())
            .unwrap()
            .success
    );
    release_execution_sandbox(&claims, &receipt, false).unwrap();
    assert!(
        ProcessExecutionDriver
            .execute(&authorized, &ExecutionContext::default())
            .is_err()
    );
}
#[test]
fn named_task_profiles_merge_scope_through_ordinary_policy_gates() {
    let mut f = Fixture::new();
    let mut request = f.request();
    request.task_profile = Some("unknown".into());
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::UnknownTaskProfile(_))
    ));
    f.manifest
        .task_profiles
        .insert("summarize".into(), TaskProfile::default());
    request.task_profile = Some("summarize".into());
    assert!(resolve_dispatch_plan(&f.manifest, &request).is_ok());
    f.manifest
        .task_profiles
        .get_mut("summarize")
        .unwrap()
        .requested_write_globs
        .push("src/**".into());
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::WriteScopeDenied(_))
    ));
    f.manifest
        .task_profiles
        .get_mut("summarize")
        .unwrap()
        .requested_write_globs
        .clear();
    f.manifest
        .task_profiles
        .get_mut("summarize")
        .unwrap()
        .requested_skills
        .push("forbidden".into());
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::ForbiddenSkill(_))
    ));
}

#[test]
fn mutating_nested_cwd_cannot_bypass_repository_scoped_leases() {
    let mut f = Fixture::new();
    f.mutate();
    assert!(f.repo.join(".git").is_dir());
    let mut request = f.request();
    request.cwd = f.repo.join("src");
    request.requested_write_globs = vec!["src/**".into()];
    assert!(matches!(
        resolve_dispatch_plan(&f.manifest, &request),
        Err(FleetPolicyError::WriteScopeDenied(_))
    ));
}

#[cfg(unix)]
#[test]
fn relative_private_key_paths_are_loaded_against_manifest_directory() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::new();
    f.keys();
    let key = f.root.join("relative-key");
    std::fs::write(&key, "private-key-fixture").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    f.manifest.private_key_paths.insert(
        SeatId::new("default").unwrap(),
        PathBuf::from("relative-key"),
    );
    for extension in ["json", "toml"] {
        let path = f.root.join(format!("fleet.{extension}"));
        if extension == "json" {
            std::fs::write(&path, f.manifest.to_canonical_json().unwrap()).unwrap();
        } else {
            std::fs::write(&path, f.manifest.to_toml().unwrap()).unwrap();
        }
        let loaded = FleetManifest::load(&path).unwrap();
        KeyBijectionValidator::validate(&loaded, true).unwrap();
    }
}
#[cfg(unix)]
#[test]
fn credential_files_cannot_override_execution_identity() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::new();
    let credentials = f.root.join("credentials");
    std::fs::write(&credentials, "AUTH_VALUE=forged#actor\n").unwrap();
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).unwrap();
    if let DriverSpec::CliSubprocess { auth_isolation, .. } = &mut f.manifest.seats[0].driver {
        *auth_isolation = CredentialIsolation::SecretEnvFile {
            path: credentials,
            key_map: BTreeMap::from([("AUTH_VALUE".into(), "CHINWAG_ACTOR".into())]),
        };
    }
    let context = ExecutionContext {
        env: BTreeMap::from([("CHINWAG_ACTOR".into(), "default#run".into())]),
        ..Default::default()
    };
    assert!(matches!(
        ProcessExecutionDriver.execute(&f.plan(), &context),
        Err(FleetPolicyError::InvalidManifest(_))
    ));
}

#[test]
fn trusted_context_scrubs_manifest_namespaces_before_reinstalling_bindings() {
    let mut f = Fixture::new();
    if let DriverSpec::CliSubprocess {
        argv_template,
        env_overrides,
        ..
    } = &mut f.manifest.seats[0].driver
    {
        *argv_template=vec!["-c".into(),"printf '%s:%s:%s' \"${GIT_DIR-unset}\" \"${CHINWAG_STORE_ID-unset}\" \"${CHINWAG_ACTOR-unset}\"".into()];
        env_overrides.extend(BTreeMap::from([
            ("GIT_DIR".into(), "untrusted".into()),
            ("CHINWAG_STORE_ID".into(), "untrusted".into()),
        ]));
    }
    let context = ExecutionContext {
        env: BTreeMap::from([
            ("CHINWAG_STORE_ID".into(), "trusted-store".into()),
            ("CHINWAG_ACTOR".into(), "default#run".into()),
        ]),
        scrub_env_prefixes: vec!["GIT_".into(), "CHINWAG_".into()],
        ..Default::default()
    };
    let result = ProcessExecutionDriver.execute(&f.plan(), &context).unwrap();
    assert_eq!(result.stdout, "unset:trusted-store:default#run");
}

#[test]
fn read_only_seats_cannot_provision_mutating_backends_through_repo_holds() {
    let mut f = Fixture::new();
    f.manifest.policy.repo_holds.push(RepoHoldRule {
        repo_pattern: "repository".into(),
        active: true,
        reason: "held".into(),
    });
    for isolation in [
        IsolationSpec::GitWorktree { root: None },
        IsolationSpec::JujutsuWorkspace { root: None },
        IsolationSpec::CopyOnWriteDir { root: None },
        IsolationSpec::ContainerOrMicroVmMount {
            root: f.root.join("mounts"),
        },
        IsolationSpec::ArtifactSubdirOnly {
            root: f.root.join("artifacts"),
        },
    ] {
        f.manifest.seats[0].isolation = isolation;
        assert!(matches!(
            resolve_dispatch_plan(&f.manifest, &f.request()),
            Err(FleetPolicyError::InvalidManifest(_))
        ));
    }
    assert!(!f.root.join("mounts").exists());
    assert!(!f.root.join("artifacts").exists());
}

#[cfg(unix)]
#[test]
fn child_process_group_probe() {
    let Some(path) = std::env::var_os("CHINWAG_TEST_PROCESS_GROUP_RECORD") else {
        return;
    };
    std::fs::write(path, rustix::process::getpgrp().as_raw_pid().to_string()).unwrap();
}

#[cfg(unix)]
#[test]
fn interactive_children_keep_foreground_process_group_and_headless_children_isolate() {
    let mut f = Fixture::new();
    if let DriverSpec::CliSubprocess {
        executable,
        argv_template,
        ..
    } = &mut f.manifest.seats[0].driver
    {
        *executable = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        *argv_template = vec![
            "--exact".into(),
            "child_process_group_probe".into(),
            "--nocapture".into(),
        ];
    }
    let parent_group = rustix::process::getpgrp().as_raw_pid().to_string();
    for interactive in [true, false] {
        let record = f.root.join(if interactive {
            "interactive-group"
        } else {
            "headless-group"
        });
        let context = ExecutionContext {
            env: BTreeMap::from([(
                "CHINWAG_TEST_PROCESS_GROUP_RECORD".into(),
                record.to_string_lossy().into_owned(),
            )]),
            interactive,
            ..Default::default()
        };
        let outcome = ProcessExecutionDriver.execute(&f.plan(), &context).unwrap();
        assert!(outcome.success);
        let child_group = std::fs::read_to_string(record).unwrap();
        if interactive {
            assert_eq!(child_group, parent_group);
        } else {
            assert_ne!(child_group, parent_group);
        }
    }
}
