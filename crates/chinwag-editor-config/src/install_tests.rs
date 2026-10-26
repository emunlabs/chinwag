use super::*;
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::PathBuf,
};

struct Fixture {
    repo: PathBuf,
    editor: Editor,
}
impl Fixture {
    fn new(label: &str, editor: Editor) -> Self {
        // Required owned operator namespace, never the user's editor configuration.
        let root = std::env::var_os("CHINWAG_PRIVATE_INSTALL_FIXTURES")
            .expect("Root-owned fixture namespace must be supplied explicitly");
        let repo = PathBuf::from(root).join(label);
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
    fn seed(&self, bytes: &[u8]) {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.path())
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }
    fn target(&self) -> FixtureTarget {
        FixtureTarget::open(&self.repo, self.editor).unwrap()
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
            Preparation::Ready(p) => p,
            _ => panic!("Expected staged proposal"),
        }
    }
}
fn private_file(path: &Path, bytes: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

#[test]
fn three_editor_installs_read_back_and_retained_intent_prevents_replay() {
    for (i, editor) in [Editor::ClaudeCode, Editor::Cursor, Editor::Codex]
        .into_iter()
        .enumerate()
    {
        let fixture = Fixture::new(&format!("three-editors-{i}"), editor);
        let original: &[u8] = if matches!(editor, Editor::Codex) {
            b"# keep spelling\nunknown = 'kept'\n"
        } else {
            b"{\"unknown\":\"kept\"}\n"
        };
        fixture.seed(original);
        let result = fixture.ready().commit();
        let CommitOutcome::InstalledAndReadBack { evidence, .. } = result else {
            panic!("{result:?}");
        };
        let actual = fs::read(fixture.path()).unwrap();
        assert_eq!(evidence.original_sha256, Some(digest(original)));
        assert_eq!(evidence.staged_sha256, digest(&actual));
        match editor {
            Editor::Codex => {
                assert!(actual.starts_with(original));
                let doc: toml_edit::DocumentMut =
                    std::str::from_utf8(&actual).unwrap().parse().unwrap();
                assert_eq!(
                    doc["mcp_servers"]["chinwag"]["command"].as_str(),
                    Some("/fixture/chinwag")
                );
                assert_eq!(doc["unknown"].as_str(), Some("kept"));
            }
            _ => {
                let doc: serde_json::Value = serde_json::from_slice(&actual).unwrap();
                assert_eq!(doc["unknown"], "kept");
                assert_eq!(
                    doc["mcpServers"]["chinwag"],
                    serde_json::json!({"type":"stdio","command":"/fixture/chinwag","args":[]})
                );
            }
        }
        assert!(!fixture.parent().join(LOCK).exists());
        let intent: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.parent().join(INTENT)).unwrap()).unwrap();
        assert_eq!(intent["staged_sha256"], hex(&digest(&actual)));
        assert!(
            !serde_json::to_string(&intent)
                .unwrap()
                .contains(fixture.repo.to_str().unwrap())
        );
        assert!(fixture.target().inspect().is_err());
    }
}

#[test]
fn absent_target_install_and_initial_exact_unchanged() {
    let absent = Fixture::new("absent-target", Editor::ClaudeCode);
    assert!(matches!(
        absent.ready().commit(),
        CommitOutcome::InstalledAndReadBack { .. }
    ));
    assert!(fs::read(absent.path()).unwrap().starts_with(b"{"));
    let exact = Fixture::new("initial-exact", Editor::ClaudeCode);
    let original = b" {\"mcpServers\":{\"chinwag\":{\"type\":\"stdio\",\"command\":\"/fixture/chinwag\",\"args\":[]}}}\n";
    exact.seed(original);
    let t = exact.target();
    let o = t.inspect().unwrap();
    assert!(matches!(
        t.prepare(
            o,
            Launch {
                command: "/fixture/chinwag",
                args: &[]
            }
        )
        .unwrap(),
        Preparation::Unchanged { .. }
    ));
    assert_eq!(fs::read(exact.path()).unwrap(), original);
    assert!(!exact.parent().join(LOCK).exists() && !exact.parent().join(INTENT).exists());
}

#[test]
fn stale_observation_and_customized_entry_refuse_before_staging() {
    let stale = Fixture::new("stale-observation", Editor::Cursor);
    stale.seed(b"{}");
    let t = stale.target();
    let o = t.inspect().unwrap();
    fs::write(stale.path(), b"{\"changed\":true}").unwrap();
    assert!(
        t.prepare(
            o,
            Launch {
                command: "/fixture/chinwag",
                args: &[]
            }
        )
        .is_err()
    );
    assert!(!stale.parent().join(LOCK).exists());
    let custom = Fixture::new("custom-entry", Editor::Cursor);
    custom.seed(b"{\"mcpServers\":{\"chinwag\":{\"command\":\"/custom\",\"args\":[]}}}");
    let before = fs::read(custom.path()).unwrap();
    let t = custom.target();
    let o = t.inspect().unwrap();
    assert!(
        t.prepare(
            o,
            Launch {
                command: "/fixture/chinwag",
                args: &[]
            }
        )
        .is_err()
    );
    assert_eq!(fs::read(custom.path()).unwrap(), before);
    assert!(!custom.parent().join(LOCK).exists());
}

#[test]
fn stale_commit_refuses_and_drop_retains_staging() {
    let stale = Fixture::new("stale-commit", Editor::Cursor);
    stale.seed(b"{}");
    let prepared = stale.ready();
    fs::write(stale.path(), b"{\"later\":true}").unwrap();
    assert!(matches!(
        prepared.commit(),
        CommitOutcome::BeforeCommitRefused {
            intent_created_no_cleanup: false,
            ..
        }
    ));
    assert_eq!(fs::read(stale.path()).unwrap(), b"{\"later\":true}");
    assert!(stale.parent().join(LOCK).exists() && !stale.parent().join(INTENT).exists());
    let dropped = Fixture::new("drop-retains", Editor::Cursor);
    dropped.seed(b"{}");
    drop(dropped.ready());
    assert!(dropped.parent().join(LOCK).exists());
    assert!(dropped.target().inspect().is_err());
}

#[test]
fn symlinks_hardlinks_and_nonprivate_modes_are_refused_without_changes() {
    for (i, kind) in ["symlink", "hardlink", "mode"].into_iter().enumerate() {
        let f = Fixture::new(&format!("bad-file-{i}"), Editor::ClaudeCode);
        let other = f.repo.join("other");
        private_file(&other, b"preserve literal bytes");
        match kind {
            "symlink" => symlink(&other, f.path()).unwrap(),
            "hardlink" => fs::hard_link(&other, f.path()).unwrap(),
            _ => {
                f.seed(b"{}");
                fs::set_permissions(f.path(), fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        assert!(f.target().inspect().is_err());
        assert_eq!(fs::read(other).unwrap(), b"preserve literal bytes");
        assert!(!f.parent().join(LOCK).exists());
    }
    let f = Fixture::new("bad-parent-mode", Editor::Cursor);
    fs::set_permissions(f.parent(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(FixtureTarget::open(&f.repo, f.editor).is_err());
}

#[test]
fn occupied_lock_intent_and_foreign_target_token_are_refused() {
    for name in [LOCK, INTENT] {
        let f = Fixture::new(
            if name == LOCK {
                "occupied-lock"
            } else {
                "occupied-intent"
            },
            Editor::Cursor,
        );
        private_file(&f.parent().join(name), b"existing operation; keep exactly");
        assert!(f.target().inspect().is_err());
        assert_eq!(
            fs::read(f.parent().join(name)).unwrap(),
            b"existing operation; keep exactly"
        );
    }
    let a = Fixture::new("binding-a", Editor::ClaudeCode);
    a.seed(b"{}");
    let b = Fixture::new("binding-b", Editor::ClaudeCode);
    b.seed(b"{}");
    let o = a.target().inspect().unwrap();
    assert!(
        b.target()
            .prepare(
                o,
                Launch {
                    command: "/fixture/chinwag",
                    args: &[]
                }
            )
            .is_err()
    );
    assert!(!b.parent().join(LOCK).exists());
}

#[test]
fn replaced_parent_refuses_before_rename_and_preserves_old_staging() {
    let f = Fixture::new("parent-replacement", Editor::Cursor);
    f.seed(b"{}");
    let prepared = f.ready();
    let moved = f.repo.join("moved-parent");
    fs::rename(f.parent(), &moved).unwrap();
    fs::create_dir(f.parent()).unwrap();
    fs::set_permissions(f.parent(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        prepared.commit(),
        CommitOutcome::BeforeCommitRefused {
            intent_created_no_cleanup: false,
            ..
        }
    ));
    assert!(!f.path().exists());
    assert_eq!(fs::read(moved.join("mcp.json")).unwrap(), b"{}");
    assert!(moved.join(LOCK).exists());
    assert!(!f.parent().join(LOCK).exists());
}

#[test]
fn before_and_after_rename_faults_keep_distinct_outcomes_and_intent() {
    for (i, fault) in [Fault::BeforeRename, Fault::AfterRename]
        .into_iter()
        .enumerate()
    {
        let f = Fixture::new(&format!("commit-fault-{i}"), Editor::ClaudeCode);
        f.seed(b"{}");
        let result = (*f.ready()).commit_inner(fault);
        if i == 0 {
            assert!(matches!(
                result,
                CommitOutcome::BeforeCommitRefused {
                    intent_created_no_cleanup: true,
                    ..
                }
            ));
            assert_eq!(fs::read(f.path()).unwrap(), b"{}");
            assert!(f.parent().join(LOCK).exists());
        } else {
            assert!(matches!(result, CommitOutcome::CommitOutcomeUnknown { .. }));
            let actual: serde_json::Value =
                serde_json::from_slice(&fs::read(f.path()).unwrap()).unwrap();
            assert_eq!(
                actual["mcpServers"]["chinwag"]["command"],
                "/fixture/chinwag"
            );
            assert!(!f.parent().join(LOCK).exists());
        }
        assert!(f.parent().join(INTENT).exists());
        assert!(f.target().inspect().is_err());
    }
}
