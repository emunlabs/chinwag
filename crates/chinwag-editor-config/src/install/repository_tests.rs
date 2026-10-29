use super::super::{COMPLETED, Fault, INTENT, LOCK, Prepared};
use super::*;
use std::os::unix::fs::PermissionsExt;
fn repo(name: &str) -> PathBuf {
    // Operator-supplied namespace when set, else a freshly initialized temp repository.
    let repo = chinwag_test_fixtures::initialized_repo("CHINWAG_EDITOR_QA_REPOSITORIES", name);
    assert!(repo.join(".git").is_dir() && repo.join(".chinwag/state.crdb").is_file());
    repo
}
fn open(name: &str, editor: Editor) -> (RepositoryRequest, Launcher, OuterGuard<'_>, Progress) {
    let request = RepositoryRequest::new(&repo(name), editor).unwrap();
    let launcher = Launcher::capture().unwrap();
    let mut progress = Progress::new();
    let guard = OuterGuard::start(&request, &launcher, &mut progress, None).unwrap();
    (request, launcher, guard, progress)
}
fn ready(
    request: &RepositoryRequest,
    launcher: &Launcher,
    guard: &mut OuterGuard,
) -> Box<Prepared> {
    let target = RepositoryTarget::open(request, guard).unwrap().inner;
    let observation = target.inspect().unwrap();
    let args = vec![
        "mcp-serve".to_owned(),
        "--repo".to_owned(),
        request.repo.to_str().unwrap().to_owned(),
    ];
    match target
        .prepare_owned(
            observation,
            Launch {
                command: launcher.command(),
                args: &args,
            },
            Some(guard),
        )
        .unwrap()
    {
        OwnedPreparation::Ready(prepared) => prepared,
        OwnedPreparation::Unchanged { .. } => panic!("fresh fixture unexpectedly unchanged"),
    }
}
fn pending(request: &RepositoryRequest) {
    assert!(
        request
            .repo
            .join(".chinwag")
            .join(layout(request.editor).2)
            .is_file()
    );
    assert!(request.repo.join(".chinwag/state.crdb.lock").is_file());
}
fn empty_body(path: &Path) {
    std::fs::write(path, b"{}").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn normal_observation_stale_preimage_keeps_outer_owner() {
    let (request, launcher, mut guard, _) = open("unit-stale", Editor::ClaudeCode);
    let path = request.repo.join(".mcp.json");
    empty_body(&path);
    let target = RepositoryTarget::open(&request, &mut guard).unwrap().inner;
    let observed = target.inspect().unwrap();
    std::fs::write(&path, b"{\"changed\":true}").unwrap();
    let Err(error) = target.prepare_owned(
        observed,
        Launch {
            command: launcher.command(),
            args: &[],
        },
        Some(&guard),
    ) else {
        panic!("stale observation accepted")
    };
    assert_eq!(error.reason, "stale_preimage");
    assert_eq!(std::fs::read(&path).unwrap(), b"{\"changed\":true}");
    assert!(!request.repo.join(LOCK).exists());
    pending(&request);
}
#[test]
fn normal_original_before_rename_cut_keeps_data_and_all_markers() {
    let (request, launcher, mut guard, _) = open("unit-before-rename", Editor::ClaudeCode);
    let path = request.repo.join(".mcp.json");
    empty_body(&path);
    let prepared = ready(&request, &launcher, &mut guard);
    assert!(matches!(
        (*prepared).commit_with_guard(Fault::BeforeRename, Some(&guard)),
        CommitOutcome::BeforeCommitRefused {
            intent_created_no_cleanup: true,
            ..
        }
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"{}");
    assert!(request.repo.join(LOCK).exists() && request.repo.join(INTENT).exists());
    assert!(!request.repo.join(COMPLETED).exists());
    pending(&request);
}
#[test]
fn normal_original_after_rename_cut_is_unknown_and_keeps_intent() {
    let (request, launcher, mut guard, _) = open("unit-after-rename", Editor::ClaudeCode);
    let path = request.repo.join(".mcp.json");
    empty_body(&path);
    let prepared = ready(&request, &launcher, &mut guard);
    assert!(matches!(
        (*prepared).commit_with_guard(Fault::AfterRename, Some(&guard)),
        CommitOutcome::CommitOutcomeUnknown { .. }
    ));
    assert_ne!(std::fs::read(&path).unwrap(), b"{}");
    assert!(!request.repo.join(LOCK).exists() && request.repo.join(INTENT).exists());
    pending(&request);
}
#[test]
fn normal_changed_outer_literal_cannot_authorize_commit() {
    let (request, launcher, mut guard, _) = open("unit-outer-changed", Editor::ClaudeCode);
    let path = request.repo.join(".mcp.json");
    empty_body(&path);
    let prepared = ready(&request, &launcher, &mut guard);
    let outer = request.repo.join(".chinwag").join(layout(request.editor).2);
    std::fs::write(&outer, b"controlled changed original guard").unwrap();
    assert!(matches!(
        prepared.commit_repository(&guard),
        CommitOutcome::BeforeCommitRefused { .. }
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"{}");
    assert_eq!(
        std::fs::read(&outer).unwrap(),
        b"controlled changed original guard"
    );
    assert!(request.repo.join(LOCK).exists());
    pending(&request);
}
#[test]
fn normal_dropped_live_record_retains_inner_and_outer_guards() {
    let (request, launcher, mut guard, _) = open("unit-record-drop", Editor::ClaudeCode);
    let prepared = ready(&request, &launcher, &mut guard);
    let CommitOutcome::InstalledAndReadBack { completion, .. } = prepared.commit_repository(&guard)
    else {
        panic!("original commit failed")
    };
    drop(completion.record_original(&guard).unwrap());
    assert!(request.repo.join(INTENT).exists() && request.repo.join(COMPLETED).exists());
    pending(&request);
}
#[test]
fn normal_changed_record_refuses_original_cleanup() {
    let (request, launcher, mut guard, _) = open("unit-record-changed", Editor::ClaudeCode);
    let prepared = ready(&request, &launcher, &mut guard);
    let CommitOutcome::InstalledAndReadBack { completion, .. } = prepared.commit_repository(&guard)
    else {
        panic!("original commit failed")
    };
    let record = completion.record_original(&guard).unwrap();
    std::fs::write(
        request.repo.join(COMPLETED),
        b"controlled changed completion",
    )
    .unwrap();
    assert!(record.finish(&guard).is_err());
    assert_eq!(
        std::fs::read(request.repo.join(COMPLETED)).unwrap(),
        b"controlled changed completion"
    );
    assert!(request.repo.join(INTENT).exists());
    pending(&request);
}
#[test]
fn normal_store_changed_after_inner_finish_retains_outer_guard() {
    let (request, launcher, mut guard, mut progress) =
        open("unit-store-changed", Editor::ClaudeCode);
    let prepared = ready(&request, &launcher, &mut guard);
    let CommitOutcome::InstalledAndReadBack { completion, .. } = prepared.commit_repository(&guard)
    else {
        panic!("original commit failed")
    };
    completion
        .record_original(&guard)
        .unwrap()
        .finish(&guard)
        .unwrap();
    let path = request.repo.join(".chinwag/state.crdb");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] = b'X';
    std::fs::write(&path, bytes).unwrap();
    assert!(guard.finish(launcher, &mut progress).is_err());
    assert!(!request.repo.join(INTENT).exists() && !request.repo.join(COMPLETED).exists());
    pending(&request);
}
#[test]
fn normal_new_parent_drop_keeps_original_creation_guard() {
    let (request, _launcher, mut guard, _) = open("unit-parent-drop", Editor::Cursor);
    let target = RepositoryTarget::open(&request, &mut guard).unwrap();
    assert_eq!(guard.parent_creation, "created_0700_and_synced");
    assert_eq!(
        std::fs::metadata(request.repo.join(".cursor"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    drop(target);
    assert!(!request.repo.join(".cursor/mcp.json").exists());
    pending(&request);
}
#[test]
fn normal_fixture_api_cannot_substitute_for_live_repository_guard() {
    let (request, launcher, mut guard, _) = open("unit-policy", Editor::ClaudeCode);
    let target = RepositoryTarget::open(&request, &mut guard).unwrap().inner;
    let observed = target.inspect().unwrap();
    let Err(error) = target.prepare_owned(
        observed,
        Launch {
            command: launcher.command(),
            args: &[],
        },
        None,
    ) else {
        panic!("normal target lost its guard requirement")
    };
    assert_eq!(error.reason, "install_policy_guard_mismatch");
    assert!(!request.repo.join(LOCK).exists());
    pending(&request);
}
#[test]
fn normal_complete_then_new_unchanged_call_preserves_config_inode() {
    let path = repo("unit-unchanged");
    let one = configure(RepositoryRequest::new(&path, Editor::Codex).unwrap()).unwrap();
    assert_eq!(one.value()["result"], "installed");
    let before = std::fs::metadata(path.join(".codex/config.toml")).unwrap();
    use std::os::unix::fs::MetadataExt;
    let bytes = std::fs::read(path.join(".codex/config.toml")).unwrap();
    let two = configure(RepositoryRequest::new(&path, Editor::Codex).unwrap()).unwrap();
    assert_eq!(two.value()["result"], "unchanged");
    let after = std::fs::metadata(path.join(".codex/config.toml")).unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.mode()),
        (after.dev(), after.ino(), after.mode())
    );
    assert_eq!(
        std::fs::read(path.join(".codex/config.toml")).unwrap(),
        bytes
    );
    assert!(
        !path.join(".chinwag/editor-codex.pending").exists()
            && !path.join(".chinwag/state.crdb.lock").exists()
    );
}
#[test]
fn normal_conflicting_document_never_overwrites_existing_entry() {
    let path = repo("unit-conflict");
    let original = b"{\"mcpServers\":{\"chinwag\":{\"command\":\"/different\",\"args\":[]}}}";
    std::fs::write(path.join(".mcp.json"), original).unwrap();
    let failure = match configure(RepositoryRequest::new(&path, Editor::ClaudeCode).unwrap()) {
        Err(f) => f,
        Ok(_) => panic!("conflict overwritten"),
    };
    assert_eq!(failure.reason(), "planner_refused");
    assert_eq!(std::fs::read(path.join(".mcp.json")).unwrap(), original);
    assert!(
        path.join(".chinwag/editor-claude-code.pending").exists()
            && path.join(".chinwag/state.crdb.lock").exists()
    );
    assert!(!path.join(LOCK).exists());
}
#[test]
fn normal_opaque_request_rejects_expansion_parent_and_relative_paths() {
    for value in [
        "relative",
        "/",
        "/owned/../other",
        "/owned/${SECRET}",
        "/owned/line\npath",
        "/owned/zero\0path",
    ] {
        assert!(RepositoryRequest::new(Path::new(value), Editor::ClaudeCode).is_err());
    }
    assert!(RepositoryRequest::new(Path::new("/owned/valid"), Editor::Cursor).is_ok());
}

#[test]
fn normal_gemini_parent_creation_and_unchanged_call_keep_original_inode() {
    let path = repo("unit-gemini-unchanged");
    assert!(!path.join(".gemini").exists());
    let one = configure(RepositoryRequest::new(&path, Editor::Gemini).unwrap()).unwrap();
    assert_eq!(one.value()["result"], "installed");
    assert_eq!(one.value()["target"], ".gemini/settings.json");
    let settings = path.join(".gemini/settings.json");
    let before = std::fs::metadata(&settings).unwrap();
    let bytes = std::fs::read(&settings).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        std::fs::metadata(path.join(".gemini")).unwrap().mode() & 0o7777,
        0o700
    );
    assert_eq!(before.mode() & 0o7777, 0o600);
    let two = configure(RepositoryRequest::new(&path, Editor::Gemini).unwrap()).unwrap();
    assert_eq!(two.value()["result"], "unchanged");
    let after = std::fs::metadata(&settings).unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.mode()),
        (after.dev(), after.ino(), after.mode())
    );
    assert_eq!(std::fs::read(&settings).unwrap(), bytes);
    assert!(!path.join(".chinwag/editor-gemini.pending").exists());
    assert!(!path.join(".chinwag/state.crdb.lock").exists());
}
