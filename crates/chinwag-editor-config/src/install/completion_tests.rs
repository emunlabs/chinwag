use super::*;
use crate::{
    Editor, Launch,
    install::{
        CommitOutcome, Fault, FixtureTarget, Preparation,
        observer::{self, ArtifactObservation},
    },
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

struct Fixture {
    repo: PathBuf,
    editor: Editor,
}
impl Fixture {
    fn new(label: &str, editor: Editor) -> Self {
        let root = chinwag_test_fixtures::namespace("CHINWAG_PRIVATE_INSTALL_FIXTURES");
        let repo = root.join(format!("completion-{label}"));
        fs::create_dir(&repo).unwrap();
        fs::set_permissions(&repo, fs::Permissions::from_mode(0o700)).unwrap();
        for name in [".cursor", ".codex", ".gemini"] {
            fs::create_dir(repo.join(name)).unwrap();
            fs::set_permissions(repo.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fixture = Self { repo, editor };
        private_file(
            &fixture.path(),
            if matches!(editor, Editor::Codex) {
                b"# preserved\n"
            } else {
                b"{}"
            },
        );
        fixture
    }
    fn path(&self) -> PathBuf {
        self.repo.join(self.editor.relative_path())
    }
    fn parent(&self) -> PathBuf {
        self.path().parent().unwrap().to_owned()
    }
    fn target(&self) -> FixtureTarget {
        FixtureTarget::open(&self.repo, self.editor).unwrap()
    }
    fn record(&self) -> PathBuf {
        self.parent().join(COMPLETED)
    }
    fn ready(&self) -> Box<Prepared> {
        let target = self.target();
        let observation = target.inspect().unwrap();
        match target
            .prepare(
                observation,
                Launch {
                    command: "/fixture/chinwag",
                    args: &[],
                },
            )
            .unwrap()
        {
            Preparation::Ready(prepared) => prepared,
            _ => panic!("Expected staged config"),
        }
    }
    fn complete(&self) -> Box<Completed> {
        match self.ready().commit() {
            CommitOutcome::InstalledAndReadBack {
                evidence,
                completion,
            } => {
                assert_eq!(&evidence, completion.evidence());
                completion
            }
            other => panic!("{other:?}"),
        }
    }
    fn report(&self, outcome: &'static str) {
        println!(
            "COMPLETION {}",
            json!({"fixture":self.repo.file_name().unwrap().to_str().unwrap(),"outcome":outcome,"inventory_sha256":hex(&digest(&serde_json::to_vec(&inventory(&self.repo, false)).unwrap()))})
        );
    }
}
fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn inventory(root: &Path, omit_record: bool) -> Value {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Value>, omit_record: bool) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if omit_record && path.file_name().unwrap() == COMPLETED {
                continue;
            }
            let stat = fs::symlink_metadata(&path).unwrap();
            let mut value = json!({"dev":stat.dev(),"ino":stat.ino(),"uid":stat.uid(),"gid":stat.gid(),"mode":stat.mode(),"nlink":stat.nlink(),"size":stat.len()});
            if stat.is_file() {
                value["sha256"] = json!(hex(&digest(&fs::read(&path).unwrap())));
            } else if stat.file_type().is_symlink() {
                value["symlink"] = json!(fs::read_link(&path).unwrap().to_str().unwrap());
            } else {
                assert!(stat.is_dir());
            }
            // Adding a child changes directory size; compare directory identity and mode.
            if omit_record && stat.is_dir() {
                value.as_object_mut().unwrap().remove("size");
                value.as_object_mut().unwrap().remove("nlink");
            }
            out.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
                value,
            );
            if stat.is_dir() {
                walk(root, &path, out, omit_record);
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result, omit_record);
    json!(result)
}
fn refused_without_write(fixture: &Fixture, completed: Box<Completed>) {
    let before = inventory(&fixture.repo, false);
    assert!(matches!(
        completed.write_record(),
        RecordOutcome::BeforeRecordRefused { .. }
    ));
    assert_eq!(inventory(&fixture.repo, false), before);
    fixture.report("BeforeRecordRefused");
}

#[test]
fn all_four_editor_original_success_tokens_write_literal_bounded_records() {
    for (i, editor) in [
        Editor::ClaudeCode,
        Editor::Cursor,
        Editor::Codex,
        Editor::Gemini,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(&format!("recorded-{i}"), editor);
        let completed = fixture.complete();
        let before = inventory(&fixture.repo, true);
        let evidence = completed.evidence().clone();
        let result = completed.write_record();
        let RecordOutcome::Recorded {
            record_sha256,
            record_dev,
            record_ino,
            ..
        } = result
        else {
            panic!("{result:?}");
        };
        let bytes = fs::read(fixture.record()).unwrap();
        let stat = fs::metadata(fixture.record()).unwrap();
        assert_eq!(record_sha256, digest(&bytes));
        assert_eq!((record_dev as u64, record_ino), (stat.dev(), stat.ino()));
        assert_eq!(stat.mode() & 0o7777, 0o600);
        assert_eq!(stat.nlink(), 1);
        assert!(bytes.len() <= 4096);
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.as_object().unwrap().len(), 9);
        assert_eq!(body["format"], "chinwag-private-config-completed/v1");
        assert_eq!(
            body["target"],
            fixture.path().file_name().unwrap().to_str().unwrap()
        );
        assert_eq!(body["staged_sha256"], hex(&evidence.staged_sha256));
        assert_eq!(
            body["intent_sha256"],
            hex(&digest(&fs::read(fixture.parent().join(INTENT)).unwrap()))
        );
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains(fixture.repo.to_str().unwrap())
        );
        assert_eq!(inventory(&fixture.repo, true), before);
        assert!(fixture.target().inspect().is_err());
        assert!(matches!(
            observer::observe(&fixture.target()),
            ArtifactObservation::ChangedUnrecognizedOrAmbiguous {
                reason: "completion_artifact_present_no_authority"
            }
        ));
        fixture.report("Recorded");
    }
}

#[test]
fn dropping_original_completion_closes_owner_but_retains_intent_without_record() {
    let fixture = Fixture::new("drop", Editor::Cursor);
    let completed = fixture.complete();
    let before = inventory(&fixture.repo, false);
    drop(completed);
    assert_eq!(inventory(&fixture.repo, false), before);
    assert!(!fixture.record().exists());
    assert!(fixture.parent().join(INTENT).is_file() && fixture.target().inspect().is_err());
    fixture.report("DroppedNoRecord");
}

#[test]
fn actual_original_postrename_unknown_has_no_completion_owner_or_record() {
    let fixture = Fixture::new("original-unknown", Editor::ClaudeCode);
    assert!(matches!(
        (*fixture.ready()).commit_inner(Fault::AfterRename),
        CommitOutcome::CommitOutcomeUnknown { .. }
    ));
    assert!(matches!(
        observer::observe(&fixture.target()),
        ArtifactObservation::IntentWithMatchingInstalledBytesAndInode { .. }
    ));
    assert!(!fixture.record().exists() && fixture.parent().join(INTENT).is_file());
    fixture.report("OriginalCommitUnknownNoOwner");
}

#[test]
fn foreign_completed_guards_and_guards_after_inspection_are_never_changed() {
    for kind in 0..3 {
        let fixture = Fixture::new(&format!("foreign-{kind}"), Editor::ClaudeCode);
        let completed = fixture.complete();
        match kind {
            0 => private_file(&fixture.record(), b"foreign guard; keep exactly"),
            1 => symlink("missing-foreign-file", fixture.record()).unwrap(),
            2 => {
                let original = fixture.repo.join("foreign-original");
                private_file(&original, b"foreign hardlinked guard");
                fs::hard_link(original, fixture.record()).unwrap();
            }
            _ => unreachable!(),
        }
        refused_without_write(&fixture, completed);
    }
    for kind in 0..2 {
        let fixture = Fixture::new(&format!("initial-guard-{kind}"), Editor::Cursor);
        let target = fixture.target();
        let observed = target.inspect().unwrap();
        private_file(&fixture.record(), b"preexisting operation");
        let before = inventory(&fixture.repo, false);
        if kind == 0 {
            assert!(target.inspect().is_err());
        } else {
            assert!(
                target
                    .prepare(
                        observed,
                        Launch {
                            command: "/fixture/chinwag",
                            args: &[]
                        }
                    )
                    .is_err()
            );
        }
        assert_eq!(inventory(&fixture.repo, false), before);
        fixture.report("InitialGuardRefused");
    }
}

#[test]
fn changed_installed_bytes_or_same_bytes_on_replacement_inode_refuse_before_record() {
    for kind in 0..2 {
        let fixture = Fixture::new(&format!("changed-target-{kind}"), Editor::Cursor);
        let completed = fixture.complete();
        if kind == 0 {
            fs::write(fixture.path(), b"{\"later\":true}").unwrap();
        } else {
            let bytes = fs::read(fixture.path()).unwrap();
            fs::rename(fixture.path(), fixture.repo.join("retained-target")).unwrap();
            private_file(&fixture.path(), &bytes);
        }
        refused_without_write(&fixture, completed);
        assert!(!fixture.record().exists());
    }
}

#[test]
fn changed_intent_bytes_or_same_bytes_on_replacement_inode_refuse_before_record() {
    for kind in 0..2 {
        let fixture = Fixture::new(&format!("changed-intent-{kind}"), Editor::Codex);
        let completed = fixture.complete();
        let intent = fixture.parent().join(INTENT);
        if kind == 0 {
            fs::write(&intent, b"{\"changed\":true}").unwrap();
        } else {
            let bytes = fs::read(&intent).unwrap();
            fs::rename(&intent, fixture.repo.join("retained-intent")).unwrap();
            private_file(&intent, &bytes);
        }
        refused_without_write(&fixture, completed);
        assert!(!fixture.record().exists());
    }
}

#[test]
fn replaced_parent_and_new_staging_guard_refuse_without_record_or_cleanup() {
    let parent = Fixture::new("parent-replaced", Editor::Codex);
    let completed = parent.complete();
    fs::rename(parent.parent(), parent.repo.join("retained-parent")).unwrap();
    fs::create_dir(parent.parent()).unwrap();
    fs::set_permissions(parent.parent(), fs::Permissions::from_mode(0o700)).unwrap();
    refused_without_write(&parent, completed);
    assert!(!parent.record().exists());
    let lock = Fixture::new("new-lock", Editor::ClaudeCode);
    let completed = lock.complete();
    private_file(&lock.parent().join(LOCK), b"later staging guard");
    refused_without_write(&lock, completed);
    assert!(!lock.record().exists());
}

#[test]
fn after_create_and_after_write_faults_retain_unknown_record_outcomes_without_retry() {
    for (kind, fault) in [RecordFault::AfterCreate, RecordFault::AfterWriteBeforeSync]
        .into_iter()
        .enumerate()
    {
        let fixture = Fixture::new(&format!("record-fault-{kind}"), Editor::ClaudeCode);
        let completed = fixture.complete();
        let before = inventory(&fixture.repo, true);
        assert!(matches!(
            (*completed).write_inner(fault),
            RecordOutcome::RecordOutcomeUnknown { .. }
        ));
        assert_eq!(inventory(&fixture.repo, true), before);
        let bytes = fs::read(fixture.record()).unwrap();
        if kind == 0 {
            assert!(bytes.is_empty());
        } else {
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["format"], "chinwag-private-config-completed/v1");
        }
        assert!(fixture.parent().join(INTENT).is_file() && fixture.target().inspect().is_err());
        assert!(matches!(
            observer::observe(&fixture.target()),
            ArtifactObservation::ChangedUnrecognizedOrAmbiguous { .. }
        ));
        fixture.report("RecordOutcomeUnknown");
    }
}
