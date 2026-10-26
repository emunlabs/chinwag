//! Owned Rust handoff cases use unique new bare repositories prepared by the once QA operator.
#![cfg(target_os = "macos")]
use chinwag_confirmed_initial_private::{InitializationHandoff, SigningAttempt};
use chinwag_editor_config_private::{Editor, install::configure_initialized};
use chinwag_signing::{InitReceipt, TxState};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn repo(name: &str) -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("CHINWAG_ONBOARDING_QA_REPOSITORIES")
            .expect("new once-operator repository namespace required"),
    );
    let repo = root.join(name);
    assert!(repo.is_absolute() && repo.join(".git").is_dir() && !repo.join(".chinwag").exists());
    repo
}
fn handoff(repo: &Path) -> InitializationHandoff {
    let mut attempt =
        SigningAttempt::start_fresh_private_fixture(repo, "fixture@chinwag.test").unwrap();
    loop {
        match attempt.poll(Instant::now()) {
            InitReceipt::Config { transaction, .. }
                if matches!(transaction.state, TxState::Pending { .. }) =>
            {
                std::thread::sleep(Duration::from_millis(20))
            }
            InitReceipt::Config { transaction, .. }
                if matches!(transaction.state, TxState::ChildUnknown { .. }) =>
            {
                // Keep observing exactly this original child, never kill, drop or retry an unknown child.
                loop {
                    if let Ok(Some(exit)) = attempt.observe_child() {
                        panic!("original unknown Git child later observed: {exit}")
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            InitReceipt::Config { transaction, .. }
                if matches!(transaction.state, TxState::Installed | TxState::Unchanged) =>
            {
                let original = attempt
                    .confirm()
                    .unwrap()
                    .begin_initial()
                    .unwrap()
                    .finish_for_editor()
                    .unwrap();
                let name = repo.file_name().unwrap().to_str().unwrap();
                let path = repo
                    .parent()
                    .unwrap()
                    .join(format!("{name}.initial-store-observation.json"));
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .unwrap();
                writeln!(file, "{}", json!({"case":name,"site_id":original.store_receipt().site_id(),"sha256":original.store_receipt().sha256(),"bytes":original.store_receipt().bytes(),"observation_not_cleanup_authority":true})).unwrap();
                file.sync_all().unwrap();
                return original;
            }
            _ => panic!("terminal initialization refusal: {}", attempt.reason()),
        }
    }
}
fn no_editor(repo: &Path) {
    assert!(!repo.join(".mcp.json").exists());
    assert!(!repo.join(".cursor").exists());
    assert!(!repo.join(".codex").exists());
    assert!(!repo.join(".chinwag/editor-claude-code.pending").exists());
}
fn refused(handoff: &InitializationHandoff) {
    let failure = match configure_initialized(handoff, Editor::ClaudeCode) {
        Ok(_) => panic!("changed original must refuse"),
        Err(failure) => failure,
    };
    assert_eq!(failure.observation()["config_may_have_changed"], false);
    assert_eq!(failure.observation()["outer_guard_created"], false);
}
fn report(repo: &Path, name: &str, result: serde_json::Value) {
    let path = repo
        .parent()
        .unwrap()
        .join(format!("{name}.unit-observation.json"));
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    writeln!(
        output,
        "{}",
        json!({"case":name,"outcome":result,"full_init_complete":false,"hosted_verified":false})
    )
    .unwrap();
    output.sync_all().unwrap();
}
#[test]
fn original_handoff_rejects_foreign_observations_then_completes_one_bound_editor() {
    let repo = repo("handoff-positive");
    let original = handoff(&repo);
    assert_eq!(
        original
            .verify_admitted_directories([(0, 0); 3])
            .unwrap_err(),
        "initial_editor_admission_mismatch"
    );
    no_editor(&repo);
    let editor = configure_initialized(&original, Editor::Cursor)
        .unwrap_or_else(|failure| panic!("{}", failure.reason()));
    assert_eq!(editor.value()["result"], "installed");
    let receipt = original.finish().unwrap();
    assert!(receipt.directly_owned_checked_fds() > 3);
    report(
        &repo,
        "handoff-positive",
        json!({"public_key":receipt.public_key(),"site_id":receipt.store().site_id(),"store_sha256":receipt.store().sha256(),"editor":editor.value(),"checked_initial_fds":receipt.directly_owned_checked_fds()}),
    );
}
#[test]
fn replaced_git_config_inode_with_same_body_refuses_before_editor_mutation() {
    let repo = repo("handoff-config-replaced");
    let original = handoff(&repo);
    let path = repo.join(".git/config");
    let body = fs::read(&path).unwrap();
    let replacement = repo.join(".git/replacement-config");
    fs::write(&replacement, &body).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(replacement, &path).unwrap();
    refused(&original);
    no_editor(&repo);
    assert!(original.finish().is_err());
    report(
        &repo,
        "handoff-config-replaced",
        json!({"original_finish_refused":true,"no_editor_mutation":true,"same_config_body":fs::read(path).unwrap()==body}),
    );
}
#[test]
fn replaced_repository_name_cannot_redirect_the_initializer_to_another_repo() {
    let repo = repo("handoff-repo-replaced");
    let original = handoff(&repo);
    let retained = repo.with_file_name("handoff-repo-replaced-original");
    fs::rename(&repo, &retained).unwrap();
    fs::create_dir(&repo).unwrap();
    fs::set_permissions(&repo, fs::Permissions::from_mode(0o700)).unwrap();
    for child in [".git", ".chinwag"] {
        fs::create_dir(repo.join(child)).unwrap();
        fs::set_permissions(repo.join(child), fs::Permissions::from_mode(0o700)).unwrap();
    }
    refused(&original);
    no_editor(&repo);
    assert!(original.finish().is_err());
    assert!(retained.join(".chinwag/state.crdb").is_file());
    report(
        &repo,
        "handoff-repo-replaced",
        json!({"original_retained_directory":"handoff-repo-replaced-original","foreign_private_directory_empty":fs::read_dir(repo.join(".chinwag")).unwrap().count()==0,"original_finish_refused":true}),
    );
}
#[test]
fn replaced_store_inode_with_identical_bytes_cannot_be_adopted() {
    let repo = repo("handoff-store-replaced");
    let original = handoff(&repo);
    let path = repo.join(".chinwag/state.crdb");
    let body = fs::read(&path).unwrap();
    let replacement = repo.join(".chinwag/replacement-store");
    fs::write(&replacement, &body).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(replacement, &path).unwrap();
    refused(&original);
    no_editor(&repo);
    assert!(original.finish().is_err());
    report(
        &repo,
        "handoff-store-replaced",
        json!({"same_store_body":fs::read(path).unwrap()==body,"original_finish_refused":true,"no_editor_mutation":true}),
    );
}
#[test]
fn changed_original_store_body_refuses_before_editor_mutation() {
    let repo = repo("handoff-store-changed");
    let original = handoff(&repo);
    let path = repo.join(".chinwag/state.crdb");
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.write_all(b"X").unwrap();
    file.sync_all().unwrap();
    drop(file);
    refused(&original);
    no_editor(&repo);
    assert!(original.finish().is_err());
    report(
        &repo,
        "handoff-store-changed",
        json!({"controlled_original_header_first_byte":"X","original_finish_refused":true,"no_editor_mutation":true}),
    );
}
#[test]
fn dropping_the_live_handoff_does_not_create_an_editor_or_completion_receipt() {
    let repo = repo("handoff-dropped");
    let original = handoff(&repo);
    original.verify().unwrap();
    drop(original);
    no_editor(&repo);
    assert!(repo.join(".chinwag/signer").is_file() && repo.join(".chinwag/state.crdb").is_file());
    report(
        &repo,
        "handoff-dropped",
        json!({"no_original_finish_receipt":true,"known_completed_store_and_signing_files_retained":true,"no_editor_mutation":true}),
    );
}
#[test]
fn editor_conflict_retains_partial_outcome_and_still_checks_original_init_release() {
    let repo = repo("handoff-editor-conflict");
    let original = handoff(&repo);
    let path = repo.join(".mcp.json");
    let body = b"{\"mcpServers\":{\"chinwag\":{\"command\":\"/foreign\"}}}\n";
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let editor = match configure_initialized(&original, Editor::ClaudeCode) {
        Ok(_) => panic!("must refuse conflict"),
        Err(error) => error,
    };
    assert_eq!(fs::read(path).unwrap(), body);
    assert!(repo.join(".chinwag/editor-claude-code.pending").is_file());
    let receipt = original.finish().unwrap();
    report(
        &repo,
        "handoff-editor-conflict",
        json!({"public_key":receipt.public_key(),"site_id":receipt.store().site_id(),"store_sha256":receipt.store().sha256(),"editor":editor.observation(),"checked_initial_fds":receipt.directly_owned_checked_fds(),"conflict_bytes_retained":true}),
    );
}
#[test]
fn changed_config_after_completed_editor_prevents_combined_initial_acknowledgement() {
    let repo = repo("handoff-after-editor");
    let original = handoff(&repo);
    let editor = configure_initialized(&original, Editor::ClaudeCode)
        .unwrap_or_else(|failure| panic!("{}", failure.reason()));
    assert_eq!(editor.value()["result"], "installed");
    let path = repo.join(".git/config");
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(b"\n[fixture]\n\tlater = changed\n").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(original.finish().is_err());
    assert!(repo.join(".mcp.json").is_file());
    report(
        &repo,
        "handoff-after-editor",
        json!({"known_completed_editor":editor.value(),"original_finish_refused":true,"no_combined_initialization_receipt":true}),
    );
}
