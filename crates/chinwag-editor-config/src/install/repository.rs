//! One original repository operation; unresolved artifacts never authorize adoption.
mod launcher;
use super::{
    Anchor, CommitOutcome, DirId, Editor, FileId, Image, Launch, OwnedPreparation, Target,
    checked_close, completion::RecordOutcome, hex,
};
use chinwag_confirmed_initial_private::InitializationHandoff;
use chinwag_snapshot_read_owner_private::{ReadOwner, RepositoryAdmission};
use chinwag_snapshot_session_private::SnapshotSession;
use launcher::Launcher;
use rustix::fs::{AtFlags, fsync, unlinkat};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::Write,
    path::{Component, Path, PathBuf},
};

/// A parsed intention only. It contains no launcher or cleanup authority.
#[derive(Debug, PartialEq, Eq)]
pub struct RepositoryRequest {
    repo: PathBuf,
    editor: Editor,
}
impl RepositoryRequest {
    pub fn new(repo: &Path, editor: Editor) -> Result<Self, &'static str> {
        let text = repo.to_str().ok_or("repository_utf8")?;
        if text.len() > 4096
            || text.contains(['\0', '\r', '\n'])
            || text.contains("${")
            || !repo.is_absolute()
            || repo
                .components()
                .any(|x| !matches!(x, Component::RootDir | Component::Normal(_)))
            || repo.components().count() < 2
        {
            return Err("invalid_repository_path");
        }
        Ok(Self {
            repo: repo.to_owned(),
            editor,
        })
    }
}
/// Observation of this completed original call. No fields can mint an owner.
pub struct ConfigureReceipt {
    value: Value,
}
impl ConfigureReceipt {
    pub fn value(&self) -> &Value {
        &self.value
    }
}
#[derive(Debug)]
pub struct ConfigureFailure {
    reason: &'static str,
    observation: Value,
}
impl ConfigureFailure {
    pub fn reason(&self) -> &'static str {
        self.reason
    }
    pub fn observation(&self) -> &Value {
        &self.observation
    }
}
struct Progress {
    phase: &'static str,
    outer_guard_may_exist: bool,
    outer_guard_created: bool,
    parent_creation: &'static str,
    config_may_have_changed: bool,
    store_validation_started: bool,
    observed_sha256: Option<[u8; 32]>,
    target_mode: u16,
}
impl Progress {
    fn new() -> Self {
        Self {
            phase: "launcher",
            outer_guard_may_exist: false,
            outer_guard_created: false,
            parent_creation: "not_attempted",
            config_may_have_changed: false,
            store_validation_started: false,
            observed_sha256: None,
            target_mode: 0o600,
        }
    }
    fn failure(&self, reason: &'static str) -> ConfigureFailure {
        ConfigureFailure {
            reason,
            observation: json!({
                "format":"chinwag-editor-config-outcome/v1", "result":"unconfirmed",
                "stage":self.phase, "reason":reason, "no_retry_of_uncertain_operation":true,
                "outer_guard_may_exist":self.outer_guard_may_exist,
                "outer_guard_created":self.outer_guard_created, "parent_creation":self.parent_creation,
                "config_may_have_changed":self.config_may_have_changed,
                "store_validation_started":self.store_validation_started,
                "observed_sha256":self.observed_sha256.map(|h|hex(&h)),
                "full_init_complete":false, "hosted_verified":false
            }),
        }
    }
}
fn layout(editor: Editor) -> (Option<&'static str>, &'static str, &'static str) {
    match editor {
        Editor::ClaudeCode => (None, ".mcp.json", "editor-claude-code.pending"),
        Editor::Cursor => (Some(".cursor"), "mcp.json", "editor-cursor.pending"),
        Editor::Codex => (Some(".codex"), "config.toml", "editor-codex.pending"),
    }
}
struct OriginalGuard {
    anchor: Anchor,
    file: File,
    name: &'static str,
    bytes: Vec<u8>,
    id: FileId,
}
impl OriginalGuard {
    fn verify(&self) -> Result<(), &'static str> {
        self.anchor.check()?;
        let image = self
            .anchor
            .read_bounded(self.name, 4096)?
            .ok_or("outer_guard_missing")?;
        if FileId::read(&self.file)? != self.id || image.id != self.id || image.bytes != self.bytes
        {
            return Err("outer_guard_changed");
        }
        self.anchor.check()?;
        Ok(())
    }
    fn close_retaining(self) {
        let _ = checked_close::file(self.file);
        let _ = self.anchor.close_all();
    }
    fn finish(self, progress: &mut Progress) -> Result<usize, &'static str> {
        let verified = self.verify();
        let Self {
            anchor,
            file,
            name,
            bytes,
            id,
        } = self;
        let closed = checked_close::file(file);
        let cleanup = (|| {
            verified?;
            closed?;
            anchor.check()?;
            let image = anchor
                .read_bounded(name, 4096)?
                .ok_or("outer_guard_missing")?;
            if image.id != id || image.bytes != bytes {
                return Err("closed_outer_guard_changed");
            }
            unlinkat(&anchor.fd, name, AtFlags::empty()).map_err(|_| "outer_guard_unlink")?;
            progress.outer_guard_may_exist = false;
            fsync(&anchor.fd).map_err(|_| "outer_guard_unlink_sync")?;
            anchor.check()?;
            anchor.require_absent(name)?;
            Ok(())
        })();
        let directories = anchor.close_all();
        cleanup?;
        directories
    }
}
/// Only the normal constructor makes this live token; present metadata never does.
pub(super) struct OuterGuard<'a> {
    initial: Option<&'a InitializationHandoff>,
    origin: OriginalGuard,
    admission: RepositoryAdmission,
    session: SnapshotSession,
    editor: Editor,
    repo_id: DirId,
    target: Option<(DirId, &'static str)>,
    parent_creation: &'static str,
}
impl<'a> OuterGuard<'a> {
    fn start(
        request: &RepositoryRequest,
        launcher: &Launcher,
        progress: &mut Progress,
        initial: Option<&'a InitializationHandoff>,
    ) -> Result<Self, &'static str> {
        progress.phase = "repository_admission";
        let admission = RepositoryAdmission::open(&request.repo).map_err(|e| e.reason)?;
        if let Some(initial) = initial {
            initial.verify_admitted_directories(
                admission.directory_identities().map_err(|e| e.reason)?,
            )?;
        }
        let anchor = Anchor::open_private(&request.repo)?;
        let repo_id = anchor.repository_identity();
        admission.verify().map_err(|e| e.reason)?;
        anchor.check()?;
        let (_, _, name) = layout(request.editor);
        progress.phase = "outer_guard_inspection";
        progress.outer_guard_may_exist = true;
        anchor.require_absent(name)?;
        progress.outer_guard_may_exist = false;
        let bytes = serde_json::to_vec(&json!({
            "format":"chinwag-original-editor-guard/v1", "target":request.editor.relative_path(),
            "repo_dev":repo_id.dev,"repo_ino":repo_id.ino,
            "launcher_sha256":hex(&launcher.sha256()),
            "pending_is_not_cleanup_authority":true
        }))
        .map_err(|_| "outer_guard_encoding")?;
        if bytes.len() > 4096 {
            return Err("outer_guard_limit");
        }
        progress.phase = "outer_guard_create";
        progress.outer_guard_may_exist = true;
        let mut file = anchor.exclusive(name)?;
        progress.outer_guard_created = true;
        file.write_all(&bytes).map_err(|_| "outer_guard_write")?;
        file.sync_all().map_err(|_| "outer_guard_sync")?;
        let id = anchor.verify(&mut file, name, &bytes)?;
        fsync(&anchor.fd).map_err(|_| "outer_guard_parent_sync")?;
        let origin = OriginalGuard {
            anchor,
            file,
            name,
            bytes,
            id,
        };
        origin.verify()?;
        admission.verify().map_err(|e| e.reason)?;
        progress.phase = "store_validation";
        progress.store_validation_started = true;
        let owner =
            ReadOwner::acquire_existing_private_fixture(&request.repo).map_err(|e| e.reason)?;
        let session = SnapshotSession::from_owner(owner)
            .map_err(|_| "repository_store_validation_unconfirmed")?;
        let guard = Self {
            initial,
            origin,
            admission,
            session,
            editor: request.editor,
            repo_id,
            target: None,
            parent_creation: "not_attempted",
        };
        guard.verify()?;
        Ok(guard)
    }
    fn verify(&self) -> Result<(), &'static str> {
        self.admission.verify().map_err(|e| e.reason)?;
        if let Some(initial) = self.initial {
            initial.verify_admitted_directories(
                self.admission
                    .directory_identities()
                    .map_err(|e| e.reason)?,
            )?;
        }
        self.origin.verify()
    }
    pub(super) fn verify_parent_creation(
        &self,
        parent: DirId,
        name: &str,
    ) -> Result<(), &'static str> {
        self.verify()?;
        if parent != self.repo_id || layout(self.editor).0 != Some(name) {
            return Err("editor_parent_guard_mismatch");
        }
        Ok(())
    }
    pub(super) fn before_parent_create(&mut self) -> Result<(), &'static str> {
        self.verify()?;
        self.parent_creation = "creation_outcome_unconfirmed";
        Ok(())
    }
    pub(super) fn parent_created(&mut self) {
        self.parent_creation = "created_0700_and_synced";
    }
    fn bind_target(&mut self, target: &Target) -> Result<(), &'static str> {
        self.verify()?;
        if target.anchor.repository_identity() != self.repo_id
            || target.editor != self.editor
            || target.name != layout(self.editor).1
        {
            return Err("normal_target_guard_mismatch");
        }
        self.target = Some((target.anchor.identity(), target.name));
        self.verify_target(target)
    }
    pub(super) fn verify_target(&self, target: &Target) -> Result<(), &'static str> {
        self.verify()?;
        if self.target != Some((target.anchor.check()?, target.name))
            || target.anchor.repository_identity() != self.repo_id
            || target.editor != self.editor
        {
            return Err("normal_target_guard_changed");
        }
        Ok(())
    }
    fn finish(self, launcher: Launcher, progress: &mut Progress) -> Result<Value, &'static str> {
        let verified = self.verify();
        let Self {
            origin,
            admission,
            session,
            ..
        } = self;
        progress.phase = "store_launcher_admission_checked_finish";
        // Every independent held resource is attempted, including after a prior failure.
        let store = session
            .finish()
            .map_err(|_| "repository_store_checked_finish");
        let executable = launcher.finish();
        let admission = admission.finish().map_err(|e| e.reason);
        let guarded = origin.verify();
        let failure = verified
            .err()
            .or_else(|| store.as_ref().err().copied())
            .or_else(|| executable.as_ref().err().copied())
            .or_else(|| admission.as_ref().err().copied())
            .or_else(|| guarded.err());
        if let Some(reason) = failure {
            origin.close_retaining();
            return Err(reason);
        }
        let store = store?;
        let (launcher_files, launcher_directories) = executable?;
        let admission_directories = admission?;
        progress.phase = "outer_guard_finalize";
        let outer_directories = origin.finish(progress)?;
        Ok(json!({"store_sha256":hex(&store.file().sha256()),
            "store_owner_checked_fds":store.file().checked_owner_fds(),
            "native_checked_before_file_release":store.owner_verified_after_native_close(),
            "launcher_checked_files":launcher_files,"launcher_checked_directories":launcher_directories,
            "repository_admission_checked_directories":admission_directories,
            "outer_guard_checked_files":1,"outer_guard_checked_directories":outer_directories}))
    }
}
struct RepositoryTarget {
    inner: Target,
}
impl RepositoryTarget {
    fn open(request: &RepositoryRequest, guard: &mut OuterGuard) -> Result<Self, &'static str> {
        guard.verify()?;
        let (child, name, _) = layout(request.editor);
        let anchor = Anchor::open_repository(&request.repo, None)?;
        if anchor.identity() != guard.repo_id {
            return Err("normal_repository_changed");
        }
        let anchor = match child {
            Some(name) => anchor.repository_child(name, guard)?,
            None => anchor,
        };
        let inner = Target {
            anchor,
            editor: request.editor,
            name,
        };
        guard.bind_target(&inner)?;
        Ok(Self { inner })
    }
}
fn unchanged(target: Target, original: Image, guard: &OuterGuard) -> Result<usize, &'static str> {
    let verified = (|| {
        guard.verify_target(&target)?;
        if target.anchor.read(target.name)? != Some(original) {
            return Err("unchanged_target_changed");
        }
        for name in [super::LOCK, super::INTENT, super::COMPLETED] {
            target.anchor.require_absent(name)?;
        }
        guard.verify_target(&target)
    })();
    let closed = target.anchor.close_all();
    verified?;
    closed
}
/// Configure exactly one editor, preserving every other entry and existing mode.
/// A later process can inspect retained artifacts, but cannot adopt this operation.
pub fn configure(request: RepositoryRequest) -> Result<ConfigureReceipt, ConfigureFailure> {
    configure_inner(request, None)
}

/// Configure one editor while borrowing the actual original live initialization owner.
/// The destination comes only from that owner; directory observations never mint it.
pub fn configure_initialized(
    initial: &InitializationHandoff,
    editor: Editor,
) -> Result<ConfigureReceipt, ConfigureFailure> {
    let request = RepositoryRequest::new(initial.repository(), editor)
        .map_err(|reason| Progress::new().failure(reason))?;
    configure_inner(request, Some(initial))
}

fn configure_inner(
    request: RepositoryRequest,
    initial: Option<&InitializationHandoff>,
) -> Result<ConfigureReceipt, ConfigureFailure> {
    let mut progress = Progress::new();
    let outcome = (|| {
        let launcher = Launcher::capture()?;
        let command = launcher.command().to_owned();
        let launcher_sha256 = launcher.sha256();
        let repo = request.repo.to_str().ok_or("repository_utf8")?.to_owned();
        let args = vec!["mcp-serve".to_owned(), "--repo".to_owned(), repo];
        let mut guard = OuterGuard::start(&request, &launcher, &mut progress, initial)?;
        progress.phase = "editor_parent";
        let opened = RepositoryTarget::open(&request, &mut guard);
        progress.parent_creation = guard.parent_creation;
        let target = opened?.inner;
        progress.phase = "inspect";
        let observed = target.inspect().map_err(|e| e.reason)?;
        progress.observed_sha256 = observed.sha256();
        progress.target_mode = observed
            .original
            .as_ref()
            .map_or(0o600, |image| image.id.permissions());
        guard.verify_target(&target)?;
        progress.phase = "prepare";
        let prepared = target
            .prepare_owned(
                observed,
                Launch {
                    command: &command,
                    args: &args,
                },
                Some(&guard),
            )
            .map_err(|e| e.reason)?;
        let (result, sha256, inner) = match prepared {
            OwnedPreparation::Unchanged {
                sha256,
                target,
                original,
            } => {
                progress.phase = "unchanged_checked_finish";
                let directories = unchanged(target, original, &guard)?;
                (
                    "unchanged",
                    sha256,
                    json!({"checked_files":0,"checked_directories":directories}),
                )
            }
            OwnedPreparation::Ready(prepared) => {
                progress.phase = "commit";
                progress.config_may_have_changed = true;
                let completion = match prepared.commit_repository(&guard) {
                    CommitOutcome::InstalledAndReadBack { completion, .. } => completion,
                    CommitOutcome::BeforeCommitRefused { reason, .. } => {
                        progress.config_may_have_changed = false;
                        return Err(reason);
                    }
                    CommitOutcome::CommitOutcomeUnknown { reason, .. } => return Err(reason),
                };
                progress.phase = "original_record";
                let record =
                    completion
                        .record_original(&guard)
                        .map_err(|outcome| match *outcome {
                            RecordOutcome::BeforeRecordRefused { reason, .. }
                            | RecordOutcome::RecordOutcomeUnknown { reason, .. } => reason,
                            RecordOutcome::Recorded { .. } => "unexpected_observational_record",
                        })?;
                progress.phase = "original_inner_checked_finish";
                let finished = record.finish(&guard)?;
                (
                    "installed",
                    finished.evidence().staged_sha256,
                    json!({"record_sha256":hex(&finished.record_sha256()),
                        "checked_files":finished.checked_file_fds(),"checked_directories":finished.checked_directory_fds()}),
                )
            }
        };
        let close_receipts = guard.finish(launcher, &mut progress)?;
        progress.phase = "complete";
        Ok(ConfigureReceipt {
            value: json!({
                "format":"chinwag-editor-config-outcome/v1","result":result,"stage":"complete",
                "target":request.editor.relative_path(),"sha256":hex(&sha256),"mode":progress.target_mode,
                "parent_creation":progress.parent_creation,"launcher_command":command,"launcher_args":args,
                "launcher_sha256":hex(&launcher_sha256),"launcher_binding":"held_current_exe_file_no_crypto_attestation",
                "inner":inner,"checked_completion":close_receipts,"outer_guard_removed":true,
                "full_init_complete":false,"hosted_verified":false,"editor_activation_verified":false
            }),
        })
    })();
    outcome.map_err(|reason| progress.failure(reason))
}

#[cfg(test)]
#[path = "repository_tests.rs"]
mod tests;
