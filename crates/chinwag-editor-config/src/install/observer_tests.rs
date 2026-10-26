use super::*;
use crate::{
    Editor, Launch,
    install::{CommitOutcome, Fault, Preparation, Prepared},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

struct Fixture {
    repo: PathBuf,
    editor: Editor,
}
impl Fixture {
    fn new(label: &str, editor: Editor) -> Self {
        let root = std::env::var_os("CHINWAG_PRIVATE_INSTALL_FIXTURES")
            .expect("Explicit new Root fixture namespace required");
        let repo = PathBuf::from(root).join(format!("observer-{label}"));
        fs::create_dir(&repo).unwrap();
        fs::set_permissions(&repo, fs::Permissions::from_mode(0o700)).unwrap();
        for name in [".cursor", ".codex"] {
            fs::create_dir(repo.join(name)).unwrap();
            fs::set_permissions(repo.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { repo, editor }
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
    fn seed(&self) {
        private_file(
            &self.path(),
            if matches!(self.editor, Editor::Codex) {
                b"# kept\n"
            } else {
                b"{}"
            },
        );
    }
    fn ready(&self) -> Box<Prepared> {
        let target = self.target();
        let observed = target.inspect().unwrap();
        match target
            .prepare(
                observed,
                Launch {
                    command: "/fixture/chinwag",
                    args: &[],
                },
            )
            .unwrap()
        {
            Preparation::Ready(prepared) => prepared,
            _ => panic!("Expected new staged config"),
        }
    }
    fn before_rename(&self) {
        assert!(matches!(
            (*self.ready()).commit_inner(Fault::BeforeRename),
            CommitOutcome::BeforeCommitRefused {
                intent_created_no_cleanup: true,
                ..
            }
        ));
    }
    fn installed(&self) {
        assert!(matches!(
            self.ready().commit(),
            CommitOutcome::InstalledAndReadBack { .. }
        ));
    }
    fn intent(&self) -> PathBuf {
        self.parent().join(INTENT)
    }
    fn rewrite_intent(&self, value: &Value) {
        fs::write(self.intent(), serde_json::to_vec(value).unwrap()).unwrap();
    }
    fn intent_json(&self) -> Value {
        serde_json::from_slice(&fs::read(self.intent()).unwrap()).unwrap()
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
fn inventory(root: &Path) -> Value {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Value>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let stat = fs::symlink_metadata(&path).unwrap();
            let mut value = json!({"dev":stat.dev(),"ino":stat.ino(),"uid":stat.uid(),"gid":stat.gid(),"mode":stat.mode(),"nlink":stat.nlink(),"size":stat.len()});
            if stat.is_file() {
                value["sha256"] = json!(super::super::hex(&digest(&fs::read(&path).unwrap())));
            } else if stat.file_type().is_symlink() {
                value["symlink"] = json!(fs::read_link(&path).unwrap().to_str().unwrap());
            } else {
                assert!(stat.is_dir());
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
                walk(root, &path, out);
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    json!(result)
}
fn class(observation: &ArtifactObservation) -> &'static str {
    match observation {
        ArtifactObservation::NoOperationArtifacts { .. } => "NoOperationArtifacts",
        ArtifactObservation::StagingOnly { .. } => "StagingOnly",
        ArtifactObservation::IntentWithOriginalPreimage { .. } => "IntentWithOriginalPreimage",
        ArtifactObservation::IntentWithMatchingInstalledBytesAndInode { .. } => {
            "IntentWithMatchingInstalledBytesAndInode"
        }
        ArtifactObservation::ChangedUnrecognizedOrAmbiguous { .. } => {
            "ChangedUnrecognizedOrAmbiguous"
        }
    }
}
fn checked(fixture: &Fixture, target: &FixtureTarget) -> ArtifactObservation {
    let before = inventory(&fixture.repo);
    let observed = observe(target);
    assert_eq!(observe(target), observed);
    let after = inventory(&fixture.repo);
    assert_eq!(before, after, "Observer changed private artifacts");
    println!(
        "OBSERVER {}",
        json!({"fixture":fixture.repo.file_name().unwrap().to_str().unwrap(),"class":class(&observed),"inventory_sha256":super::super::hex(&digest(&serde_json::to_vec(&after).unwrap())),"two_observations_unchanged":true})
    );
    observed
}
fn expect_ambiguous(fixture: &Fixture) {
    assert!(matches!(
        checked(fixture, &fixture.target()),
        ArtifactObservation::ChangedUnrecognizedOrAmbiguous { .. }
    ));
}

#[test]
fn three_fixed_editors_all_consistent_states_are_readonly_and_guards_remain() {
    for (index, editor) in [Editor::ClaudeCode, Editor::Cursor, Editor::Codex]
        .into_iter()
        .enumerate()
    {
        let original = Fixture::new(&format!("states-{index}"), editor);
        let target = original.target();
        assert_eq!(
            checked(&original, &target),
            ArtifactObservation::NoOperationArtifacts {
                target_sha256: None
            }
        );
        original.seed();
        assert!(matches!(
            checked(&original, &target),
            ArtifactObservation::NoOperationArtifacts {
                target_sha256: Some(_)
            }
        ));
        let prepared = original.ready();
        assert!(matches!(
            checked(&original, &target),
            ArtifactObservation::StagingOnly { .. }
        ));
        assert!(matches!(
            (*prepared).commit_inner(Fault::BeforeRename),
            CommitOutcome::BeforeCommitRefused { .. }
        ));
        assert!(matches!(
            checked(&original, &target),
            ArtifactObservation::IntentWithOriginalPreimage { .. }
        ));
        assert!(target.inspect().is_err());
        let installed = Fixture::new(&format!("installed-{index}"), editor);
        installed.seed();
        installed.installed();
        assert!(matches!(
            checked(&installed, &installed.target()),
            ArtifactObservation::IntentWithMatchingInstalledBytesAndInode { .. }
        ));
        assert!(installed.target().inspect().is_err());
        assert!(original.intent().exists() && installed.intent().exists());
    }
}

#[test]
fn absent_original_and_actual_postrename_unknown_never_become_completed_receipts() {
    let pre = Fixture::new("absent-pre", Editor::ClaudeCode);
    pre.before_rename();
    match checked(&pre, &pre.target()) {
        ArtifactObservation::IntentWithOriginalPreimage { evidence } => {
            assert_eq!(evidence.original_sha256, None)
        }
        other => panic!("{other:?}"),
    }
    let unknown = Fixture::new("absent-unknown", Editor::ClaudeCode);
    assert!(matches!(
        (*unknown.ready()).commit_inner(Fault::AfterRename),
        CommitOutcome::CommitOutcomeUnknown { .. }
    ));
    let observed = checked(&unknown, &unknown.target());
    assert!(matches!(
        observed,
        ArtifactObservation::IntentWithMatchingInstalledBytesAndInode { .. }
    ));
    let completed = Fixture::new("absent-success", Editor::ClaudeCode);
    completed.installed();
    assert_eq!(
        class(&observed),
        class(&checked(&completed, &completed.target()))
    );
    assert!(unknown.target().inspect().is_err() && completed.target().inspect().is_err());
}

#[test]
fn strict_intent_schema_rejects_unknown_duplicate_missing_types_hashes_and_limits() {
    for case in 0..22 {
        let fixture = Fixture::new(&format!("invalid-intent-{case:02}"), Editor::Cursor);
        fixture.seed();
        fixture.before_rename();
        let mut value = fixture.intent_json();
        match case {
            0 => {
                value["extra"] = json!(true);
            }
            1 | 2 => {
                let bytes = fs::read_to_string(fixture.intent()).unwrap();
                let duplicate = if case == 1 { "target" } else { "ta\\u0072get" };
                fs::write(
                    fixture.intent(),
                    format!("{{\"{duplicate}\":\"mcp.json\",{}", &bytes[1..]),
                )
                .unwrap();
                expect_ambiguous(&fixture);
                continue;
            }
            3 => {
                value.as_object_mut().unwrap().remove("original_sha256");
            }
            4 => {
                value["original_sha256"] = json!(false);
            }
            5 => {
                value["staged_sha256"] = json!("A".repeat(64));
            }
            6 => {
                value["staged_sha256"] = json!("f".repeat(63));
            }
            7 => {
                value["staged_ino"] = json!(-1);
            }
            8 => {
                value["parent_dev"] = json!(1.5);
            }
            9 => {
                value["staged_ino"] = json!("18446744073709551616");
            }
            10 => {
                value["format"] = json!("chinwag-private-config-intent/v2");
            }
            11 => {
                value["target"] = json!("../mcp.json");
            }
            12 => {
                value["parent_ino"] = json!(0);
            }
            13 => {
                fs::write(fixture.intent(), vec![b' '; MAX_INTENT + 1]).unwrap();
                expect_ambiguous(&fixture);
                continue;
            }
            14 => {
                let mut bytes = fs::read(fixture.intent()).unwrap();
                bytes.extend_from_slice(b"{}");
                fs::write(fixture.intent(), bytes).unwrap();
                expect_ambiguous(&fixture);
                continue;
            }
            15 => {
                value["parent_dev"] = json!(i64::MAX);
            }
            16 => {
                value["parent_ino"] = json!(u64::MAX);
            }
            17 => {
                value["staged_sha256"] = json!({"nested":"value"});
            }
            18 => {
                value = json!([]);
            }
            19 => {
                fs::write(fixture.intent(), b"{invalid json").unwrap();
                expect_ambiguous(&fixture);
                continue;
            }
            20 => {
                let bytes = format!("{}0{}", "[".repeat(130), "]".repeat(130));
                fs::write(fixture.intent(), bytes).unwrap();
                expect_ambiguous(&fixture);
                continue;
            }
            21 => {
                value["original_sha256"] = json!("F".repeat(64));
            }
            _ => unreachable!(),
        }
        fixture.rewrite_intent(&value);
        expect_ambiguous(&fixture);
    }
}

#[test]
fn changed_or_missing_artifacts_and_same_bytes_on_wrong_inodes_are_ambiguous() {
    for case in 0..6 {
        let fixture = Fixture::new(&format!("mismatch-{case}"), Editor::ClaudeCode);
        fixture.seed();
        if case < 3 {
            fixture.before_rename();
        } else {
            fixture.installed();
        }
        match case {
            0 => fs::write(fixture.path(), b"{\"later\":true}").unwrap(),
            1 => fs::rename(
                fixture.parent().join(LOCK),
                fixture.repo.join("retained-staging"),
            )
            .unwrap(),
            2 => {
                let lock = fixture.parent().join(LOCK);
                let bytes = fs::read(&lock).unwrap();
                fs::rename(&lock, fixture.repo.join("retained-staging")).unwrap();
                private_file(&lock, &bytes);
            }
            3 => {
                let bytes = fs::read(fixture.path()).unwrap();
                fs::rename(fixture.path(), fixture.repo.join("retained-installed")).unwrap();
                private_file(&fixture.path(), &bytes);
            }
            4 => fs::rename(fixture.path(), fixture.repo.join("retained-installed")).unwrap(),
            5 => private_file(&fixture.parent().join(LOCK), b"unrelated staged object"),
            _ => unreachable!(),
        }
        expect_ambiguous(&fixture);
        assert!(fixture.target().inspect().is_err());
    }
}

#[test]
fn symlink_hardlink_and_nonprivate_artifacts_are_observed_without_following_or_writes() {
    for (kind, filename) in [".mcp.json", LOCK, INTENT].into_iter().enumerate() {
        for fault in 0..3 {
            let fixture = Fixture::new(&format!("unsafe-{kind}-{fault}"), Editor::ClaudeCode);
            let other = fixture.repo.join("untouched");
            private_file(&other, b"literal untouched bytes");
            let path = fixture.repo.join(filename);
            match fault {
                0 => symlink(&other, &path).unwrap(),
                1 => fs::hard_link(&other, &path).unwrap(),
                2 => {
                    private_file(&path, b"{}");
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
                _ => unreachable!(),
            }
            expect_ambiguous(&fixture);
            assert_eq!(fs::read(&other).unwrap(), b"literal untouched bytes");
        }
    }
}

#[test]
fn retained_anchor_detects_parent_replacement_without_reading_replacement_artifacts() {
    let fixture = Fixture::new("parent-replaced", Editor::Cursor);
    fixture.seed();
    fixture.before_rename();
    let target = fixture.target();
    fs::rename(fixture.parent(), fixture.repo.join("retained-parent")).unwrap();
    fs::create_dir(fixture.parent()).unwrap();
    fs::set_permissions(fixture.parent(), fs::Permissions::from_mode(0o700)).unwrap();
    private_file(&fixture.path(), b"replacement path; never adopted");
    assert!(matches!(
        checked(&fixture, &target),
        ArtifactObservation::ChangedUnrecognizedOrAmbiguous {
            reason: "directory_identity_changed"
        }
    ));
    assert!(fixture.repo.join("retained-parent").join(INTENT).exists());
}

#[test]
fn changes_between_snapshots_refuse_instead_of_returning_earlier_state() {
    for case in 0..2 {
        let fixture = Fixture::new(&format!("between-{case}"), Editor::ClaudeCode);
        fixture.seed();
        let target = fixture.target();
        let observed = observe_inner(&target, || {
            if case == 0 {
                fs::write(fixture.path(), b"{\"later\":true}").unwrap();
            } else {
                private_file(&fixture.parent().join(LOCK), b"new staging");
            }
        });
        assert!(matches!(
            observed,
            ArtifactObservation::ChangedUnrecognizedOrAmbiguous {
                reason: "observation_changed"
            }
        ));
        let later = checked(&fixture, &target);
        assert_eq!(
            class(&later),
            if case == 0 {
                "NoOperationArtifacts"
            } else {
                "StagingOnly"
            }
        );
    }
}

#[test]
fn unrelated_files_are_preserved_and_fixed_parent_must_preexist_and_be_private() {
    let fixture = Fixture::new("unrelated", Editor::Codex);
    private_file(&fixture.repo.join("unrelated"), b"not a configured target");
    symlink("missing-unrelated", fixture.repo.join("unrelated-link")).unwrap();
    assert!(matches!(
        checked(&fixture, &fixture.target()),
        ArtifactObservation::NoOperationArtifacts { .. }
    ));
    for case in 0..2 {
        let fixture = Fixture::new(&format!("parent-refused-{case}"), Editor::Codex);
        if case == 0 {
            fs::rename(fixture.parent(), fixture.repo.join("retained-empty-parent")).unwrap();
        } else {
            fs::set_permissions(fixture.parent(), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let before = inventory(&fixture.repo);
        assert!(FixtureTarget::open(&fixture.repo, fixture.editor).is_err());
        assert_eq!(inventory(&fixture.repo), before);
    }
}
