use super::*;
use crate::{CandidateState, catalogue::InstallationMatch};
use std::os::unix::fs::{PermissionsExt, symlink};
use tempfile::TempDir;

fn scope(directory: &TempDir) -> Scope {
    let apps = directory.path().join("Applications");
    let cli = directory.path().join("bin");
    fs::create_dir_all(&apps).unwrap();
    fs::create_dir_all(&cli).unwrap();
    let apps = fs::canonicalize(apps).unwrap();
    let cli = fs::canonicalize(cli).unwrap();
    Scope {
        apps: vec![apps.clone()],
        cli: vec![cli.clone()],
        public_binary_roots: vec![apps, cli],
        entry_cap: 64,
        app_cap: 16,
        installation_cap: 16,
    }
}

fn binary(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn make_app(
    scope: &Scope,
    file_name: &str,
    name: &str,
    bundle: &str,
    executable_name: &str,
    binary_plist: bool,
) -> PathBuf {
    let path = scope.apps[0].join(file_name);
    fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
    let mut fields = plist::Dictionary::new();
    for (key, value) in [
        ("CFBundleName", name),
        ("CFBundleDisplayName", name),
        ("CFBundleIdentifier", bundle),
        ("CFBundleExecutable", executable_name),
        ("CFBundleShortVersionString", "1.0"),
        ("UncollectedPrivateField", "must-not-be-copied"),
    ] {
        fields.insert(key.into(), plist::Value::String(value.into()));
    }
    let value = plist::Value::Dictionary(fields);
    let mut bytes = Vec::new();
    if binary_plist {
        value.to_writer_binary(&mut bytes).unwrap();
    } else {
        value.to_writer_xml(&mut bytes).unwrap();
    }
    fs::write(path.join("Contents/Info.plist"), bytes).unwrap();
    if plain_component(executable_name) {
        binary(
            &path.join("Contents/MacOS").join(executable_name),
            &[0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0],
        );
    }
    path
}

fn process(path: &Path, role: ProcessRole, family: ClientFamily, pid: u32) -> ClientCandidate {
    let birth = ProcessBirth {
        pid,
        start_seconds: 100,
        start_microseconds: 1,
    };
    ClientCandidate {
        family,
        role,
        state: CandidateState::DetectedUnverified,
        birth,
        parent_pid: 1,
        uid: 501,
        process_group: pid,
        executable: path
            .join("Contents/MacOS/ChatGPT")
            .to_string_lossy()
            .into_owned(),
        outer_application: Some(path.to_string_lossy().into_owned()),
        sampled_parent_birth: None,
        instance_root: if role == ProcessRole::BundledComponent {
            None
        } else {
            Some(birth)
        },
    }
}

fn process_snapshot(candidates: Vec<ClientCandidate>) -> InventorySnapshot {
    InventorySnapshot {
        observed_at_unix_ms: 1000,
        host: HostObservation {
            label: "fixture-host".into(),
            boot_uuid: "fixture-boot".into(),
        },
        uid: 501,
        coverage: Coverage {
            pid_capacity: 4096,
            candidate_capacity: 128,
            sampled_pid_count: 10,
            ..Coverage::default()
        },
        candidates,
        limitations: vec![],
    }
}

#[test]
fn recorded_public_identities_do_not_conflate_chatgpt_grok_cursor_or_gemini2() {
    for (name, id, executable, family) in [
        (
            "ChatGPT",
            "com.openai.codex",
            "ChatGPT",
            ClientFamily::ChatgptDesktop,
        ),
        (
            "Grok Bot",
            "com.anysphere.sand",
            "Grok Bot",
            ClientFamily::GrokBot,
        ),
        (
            "Cursor",
            "com.todesktop.230313mzl4w4u92",
            "Cursor",
            ClientFamily::Cursor,
        ),
        (
            "Gemini",
            "com.google.GeminiMacOS",
            "Gemini",
            ClientFamily::GeminiDesktop,
        ),
    ] {
        assert_eq!(
            app_family(name, id, executable),
            Some((family, InstallationMatch::PublicBundleIdentity))
        );
    }
    assert_eq!(
        app_family("Gemini 2", "com.macpaw.Gemini2", "Gemini 2"),
        None
    );
    assert_eq!(app_family("Gemini", "com.macpaw.Gemini2", "Gemini"), None);
    assert_eq!(
        app_family("Grok Bot", "com.todesktop.230313mzl4w4u92", "Grok Bot"),
        None
    );
    assert_eq!(
        app_family(
            "Claude Code URL Handler",
            "com.anthropic.claude-code-url-handler",
            "claude"
        ),
        Some((ClientFamily::ClaudeCode, InstallationMatch::LauncherOnly))
    );
}

#[test]
fn xml_and_binary_plists_produce_only_bounded_public_metadata() {
    let directory = TempDir::new().unwrap();
    let scope = scope(&directory);
    make_app(
        &scope,
        "ChatGPT.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    make_app(
        &scope,
        "Grok Bot.app",
        "Grok Bot",
        "com.anysphere.sand",
        "Grok Bot",
        true,
    );
    let installed = collect(&scope).unwrap();
    assert_eq!(installed.installations.len(), 2);
    assert!(installed.installations.iter().all(|row| row.id.len() == 64
        && row.metadata_fingerprint.len() == 64
        && row.executable.format == ExecutableFormat::MachO));
    assert!(
        !serde_json::to_string(&installed)
            .unwrap()
            .contains("must-not-be-copied")
    );
    assert_eq!(
        installed.coverage.application_directories[0].entries_examined,
        2
    );
    assert_eq!(installed.coverage.invalid_metadata, 0);
}

#[test]
fn aliases_merge_but_physical_copies_keep_exact_installation_identity() {
    let directory = TempDir::new().unwrap();
    let scope = scope(&directory);
    let original = make_app(
        &scope,
        "ChatGPT.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    let alias = scope.apps[0].join("ChatGPT alias.app");
    symlink(&original, &alias).unwrap();
    let copy = make_app(
        &scope,
        "ChatGPT copy.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    let installed = collect(&scope).unwrap();
    assert_eq!(installed.installations.len(), 2);
    let original_row = installed
        .installations
        .iter()
        .find(|row| row.canonical_path == original)
        .unwrap();
    assert_eq!(original_row.observed_paths.len(), 2);
    assert!(original_row.observed_paths.contains(&alias));
    let copied_row = installed
        .installations
        .iter()
        .find(|row| row.canonical_path == copy)
        .unwrap();
    assert_ne!(original_row.id, copied_row.id);
    assert_eq!(installed.coverage.aliases_merged, 1);
}

#[test]
fn unknown_apps_and_malformed_or_oversized_metadata_are_visible_in_coverage() {
    let directory = TempDir::new().unwrap();
    let scope = scope(&directory);
    make_app(
        &scope,
        "Gemini 2.app",
        "Gemini 2",
        "com.macpaw.Gemini2",
        "Gemini 2",
        false,
    );
    let bad = make_app(
        &scope,
        "Bad.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    fs::write(bad.join("Contents/Info.plist"), b"not a plist").unwrap();
    let huge = make_app(
        &scope,
        "Huge.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    fs::write(
        huge.join("Contents/Info.plist"),
        vec![b' '; MAX_PLIST_BYTES + 1],
    )
    .unwrap();
    let installed = collect(&scope).unwrap();
    assert!(installed.installations.is_empty());
    assert_eq!(installed.coverage.unrecognized_applications, 1);
    assert_eq!(installed.coverage.invalid_metadata, 1);
    assert_eq!(installed.coverage.oversized_plists, 1);
}

#[test]
fn symlink_escapes_symlink_plists_and_executable_traversal_are_rejected() {
    let directory = TempDir::new().unwrap();
    let scope = scope(&directory);
    let private = directory.path().join("private");
    fs::create_dir(&private).unwrap();
    symlink(&private, scope.apps[0].join("Escaped.app")).unwrap();
    let app = make_app(
        &scope,
        "Symlink plist.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    fs::rename(app.join("Contents/Info.plist"), private.join("secret")).unwrap();
    symlink(private.join("secret"), app.join("Contents/Info.plist")).unwrap();
    make_app(
        &scope,
        "Traversal.app",
        "ChatGPT",
        "com.openai.codex",
        "../../secret",
        false,
    );
    let installed = collect(&scope).unwrap();
    assert!(installed.installations.is_empty());
    assert_eq!(installed.coverage.unsafe_paths, 2);
    assert_eq!(installed.coverage.invalid_metadata, 1);
}

#[test]
fn directory_and_installation_caps_and_missing_roots_are_not_absence_proof() {
    let directory = TempDir::new().unwrap();
    let mut scope = scope(&directory);
    make_app(
        &scope,
        "ChatGPT.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    make_app(
        &scope,
        "Grok Bot.app",
        "Grok Bot",
        "com.anysphere.sand",
        "Grok Bot",
        false,
    );
    scope.installation_cap = 1;
    let installed = collect(&scope).unwrap();
    assert_eq!(installed.installations.len(), 1);
    assert!(installed.coverage.installation_cap_reached);
    assert_eq!(installed.coverage.omitted_installations, 1);
    scope.entry_cap = 1;
    scope.apps.push(directory.path().join("missing"));
    let capped = collect(&scope).unwrap();
    assert!(capped.coverage.application_directories[0].entry_cap_reached);
    assert_eq!(
        capped.coverage.application_directories[1].status,
        DirectoryStatus::Missing
    );
    scope.entry_cap = 64;
    scope.app_cap = 1;
    assert!(collect(&scope).unwrap().coverage.application_directories[0].app_cap_reached);
}

#[test]
fn cli_candidates_are_exact_files_and_wrappers_stay_metadata_hints() {
    let directory = TempDir::new().unwrap();
    let mut scope = scope(&directory);
    binary(&scope.cli[0].join("gemini"), b"#!/bin/sh\nexit 99\n");
    binary(&scope.cli[0].join("codex"), &[0xcf, 0xfa, 0xed, 0xfe]);
    let second = directory.path().join("other-bin");
    fs::create_dir(&second).unwrap();
    symlink(scope.cli[0].join("codex"), second.join("codex")).unwrap();
    scope.cli.push(second.clone());
    scope.public_binary_roots.push(second);
    let installed = collect(&scope).unwrap();
    assert_eq!(installed.installations.len(), 2);
    let gemini = installed
        .installations
        .iter()
        .find(|row| row.family == ClientFamily::GeminiCli)
        .unwrap();
    assert_eq!(gemini.executable.format, ExecutableFormat::Script);
    assert_eq!(gemini.match_basis, InstallationMatch::ExactCliFilenameHint);
    assert_eq!(installed.coverage.aliases_merged, 1);
    assert!(
        !installed
            .installations
            .iter()
            .any(|row| row.family == ClientFamily::Continue)
    );
    assert_eq!(installed.coverage.cli_paths_checked, 2 * CLI_NAMES.len());
}

#[test]
fn cli_symlink_outside_public_binary_roots_is_not_opened() {
    let directory = TempDir::new().unwrap();
    let scope = scope(&directory);
    let private = directory.path().join("private-key");
    fs::write(&private, b"not an executable").unwrap();
    symlink(private, scope.cli[0].join("codex")).unwrap();
    let installed = collect(&scope).unwrap();
    assert!(installed.installations.is_empty());
    assert_eq!(installed.coverage.unsafe_paths, 1);
}

#[test]
fn nofollow_applies_to_parent_directories_as_well_as_the_file_leaf() {
    let directory = TempDir::new().unwrap();
    let base = fs::canonicalize(directory.path()).unwrap();
    let target = base.join("actual");
    fs::create_dir(&target).unwrap();
    binary(&target.join("codex"), b"#!/bin/sh\nexit 99\n");
    symlink(&target, base.join("redirect")).unwrap();
    assert!(matches!(
        open_regular(&base.join("redirect/codex")),
        Err(ReadFailure::Unsafe)
    ));
}

#[test]
fn pure_merge_matches_exact_paths_and_never_calls_an_unseen_installation_asleep() {
    let directory = TempDir::new().unwrap();
    let scope = scope(&directory);
    let original = make_app(
        &scope,
        "ChatGPT.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    let copy = make_app(
        &scope,
        "ChatGPT copy.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    let installed = collect(&scope).unwrap();
    let mut observed = process_snapshot(vec![process(
        &original,
        ProcessRole::MainApplication,
        ClientFamily::ChatgptDesktop,
        50,
    )]);
    observed.coverage.pid_capacity_reached = true;
    observed.coverage.permission_denied_processes = 1;
    let merged = merge_installed(&observed, &installed);
    let running = merged
        .installations
        .iter()
        .find(|row| row.installation.canonical_path == original)
        .unwrap();
    assert_eq!(
        running.running_state,
        InstalledRunningState::ObservedRunning
    );
    assert_eq!(running.observed_instances.len(), 1);
    let unseen = merged
        .installations
        .iter()
        .find(|row| row.installation.canonical_path == copy)
        .unwrap();
    assert_eq!(unseen.running_state, InstalledRunningState::NotObserved);
    assert!(unseen.observed_instances.is_empty());
    assert!(merged.process_coverage.pid_capacity_reached);
    assert_eq!(merged.process_coverage.permission_denied_processes, 1);
    assert_eq!(merged.process_observed_at_unix_ms, 1000);
    assert!(merged.unmatched_running.is_empty());
    assert!(!serde_json::to_string(&merged).unwrap().contains("asleep"));
}

#[test]
fn orphan_components_and_unmatched_processes_are_retained_without_new_instances() {
    let directory = TempDir::new().unwrap();
    let scope = scope(&directory);
    let original = make_app(
        &scope,
        "ChatGPT.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    let installed = collect(&scope).unwrap();
    let observed = process_snapshot(vec![
        process(
            &original,
            ProcessRole::BundledComponent,
            ClientFamily::ChatgptDesktop,
            50,
        ),
        process(
            Path::new("/unobserved/Grok Bot.app"),
            ProcessRole::MainApplication,
            ClientFamily::GrokBot,
            60,
        ),
    ]);
    let merged = merge_installed(&observed, &installed);
    assert_eq!(
        merged.installations[0].running_state,
        InstalledRunningState::ComponentsObserved
    );
    assert_eq!(merged.installations[0].observed_component_count, 1);
    assert!(merged.installations[0].observed_instances.is_empty());
    assert_eq!(merged.unmatched_running.len(), 1);
    assert_eq!(merged.unmatched_running[0].family, ClientFamily::GrokBot);
}

#[test]
fn public_metadata_change_replaces_the_observation_fingerprint() {
    let directory = TempDir::new().unwrap();
    let scope = scope(&directory);
    let original = make_app(
        &scope,
        "ChatGPT.app",
        "ChatGPT",
        "com.openai.codex",
        "ChatGPT",
        false,
    );
    let first = collect(&scope).unwrap().installations.remove(0);
    let mut value = plist::Value::from_file(original.join("Contents/Info.plist")).unwrap();
    value.as_dictionary_mut().unwrap().insert(
        "CFBundleShortVersionString".into(),
        plist::Value::String("2.0".into()),
    );
    value
        .to_file_xml(original.join("Contents/Info.plist"))
        .unwrap();
    let second = collect(&scope).unwrap().installations.remove(0);
    assert_ne!(first.metadata_fingerprint, second.metadata_fingerprint);
    assert_ne!(first.id, second.id);
    assert_eq!(second.version.as_deref(), Some("2.0"));
}
