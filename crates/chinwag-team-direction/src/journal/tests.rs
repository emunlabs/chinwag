use super::*;
use std::{
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
};

fn private_root() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.path().canonicalize().unwrap().join("actions");
    (directory, root)
}
fn parent_id(n: usize) -> String {
    format!("team-{n:064x}")
}
fn uuid(n: usize) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn claude(id: &str, n: usize, text: &str, timing: ClaudeTiming) -> SavedMember {
    let child_id = uuid(n);
    SavedMember {
        id: id.into(),
        label: format!("Work {id}"),
        child_id: Some(child_id.clone()),
        action: Some(match timing {
            ClaudeTiming::Now => ActionLabel::ClaudeNow,
            ClaudeTiming::AfterTools => ActionLabel::ClaudeAfterTools,
            ClaudeTiming::AfterTurn => ActionLabel::ClaudeAfterTurn,
        }),
        excluded: None,
        audit: Some(NativeAudit::Claude {
            captured_sequence: 0,
            operation: chinwag_claude_control::SavedInput {
                schema: "chinwag-claude-input/v1".into(),
                id: child_id,
                text: text.into(),
                session_epoch: uuid(900),
                session_id: uuid(901),
                kind: chinwag_claude_control::ActionKind::Direction,
                timing,
                startup: None,
            },
        }),
    }
}
fn intent(n: usize) -> SavedDirection {
    let text = format!("Explicit team direction {n}");
    let child_id = uuid(n * 4 + 2);
    SavedDirection {
        id: parent_id(n),
        host_instance: format!("host-{:064x}", 1),
        text: text.clone(),
        human_revision: n as u64 + 1,
        selected: vec![
            "claude-review".into(),
            "gemini-research".into(),
            "codex-ui".into(),
        ],
        effective: vec!["claude-review".into(), "gemini-research".into()],
        members: vec![
            claude("claude-review", n * 4 + 1, &text, ClaudeTiming::Now),
            SavedMember {
                id: "gemini-research".into(),
                label: "Research".into(),
                child_id: Some(child_id.clone()),
                action: Some(ActionLabel::GeminiPrompt),
                excluded: None,
                audit: Some(NativeAudit::Gemini {
                    captured_sequence: 0,
                    operation: chinwag_gemini_control::SavedOperation {
                        schema: "chinwag-gemini-operation/v1".into(),
                        id: child_id.clone(),
                        kind: chinwag_gemini_control::ActionKind::Prompt,
                        text,
                        session_epoch: uuid(902),
                        session_id: Some(uuid(903)),
                        prompt_rpc_id: format!("prompt-{child_id}"),
                        prompt_generation: 1,
                        startup: None,
                    },
                }),
            },
            SavedMember {
                id: "codex-ui".into(),
                label: "UI".into(),
                child_id: None,
                action: None,
                excluded: Some(BlockReason::NoActiveTurn),
                audit: None,
            },
        ],
    }
}
fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn save_claim_admission_retirement_preserves_exact_original_intent_and_order() {
    let (_temp, root) = private_root();
    let saved = intent(1);
    let mut journal = Journal::open(&root).unwrap();
    journal.save(saved.clone()).unwrap();
    let path = root.join(filename(&saved.id));
    let initial = fs::read(&path).unwrap();
    let stored = journal.lookup(&saved.id).unwrap().unwrap();
    assert!(stored.claims.is_empty());
    assert!(stored.admissions.is_empty());
    assert!(!stored.retired);
    let claim = journal.claim(&saved.id, "claude-review").unwrap();
    assert_eq!(claim.parent(), saved.id);
    assert_eq!(claim.member(), "claude-review");
    assert!(claim.stored.claims.contains("claude-review"));
    assert!(
        !claim.stored.admissions.contains_key("claude-review"),
        "claim precedes any native/local admission fact"
    );
    let after_claim = fs::read(&path).unwrap();
    assert!(after_claim.starts_with(&initial));
    journal.admission(&claim, LocalAdmission::Queued).unwrap();
    assert!(matches!(
        journal.claim(&saved.id, "claude-review"),
        Err(TeamError::ConsumedRevision)
    ));
    assert!(
        journal.admission(&claim, LocalAdmission::Queued).is_err(),
        "one immutable admission per claim"
    );
    assert!(
        matches!(
            journal.claim(&saved.id, "codex-ui"),
            Err(TeamError::ConsumedRevision)
        ),
        "explicitly excluded member never has a dispatch claim"
    );
    journal.retire(&saved.id).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(journal.claim(&saved.id, "gemini-research").is_err());
    drop(journal);
    let recovered = Journal::open(&root).unwrap();
    let found = recovered.lookup(&saved.id).unwrap().unwrap();
    assert!(found.recovered && found.retired);
    assert_eq!(found.claims, BTreeSet::from(["claude-review".into()]));
    assert_eq!(
        found.admissions.get("claude-review"),
        Some(&LocalAdmission::Queued)
    );
    assert_eq!(
        serde_json::to_value(found.intent).unwrap(),
        serde_json::to_value(saved).unwrap()
    );
    assert_eq!(
        fs::read(path).unwrap(),
        before,
        "recovery is read-only and never invokes children"
    );
}

#[test]
fn claimed_missing_admission_is_preserved_while_unclaimed_members_remain_never_invoked() {
    let (_temp, root) = private_root();
    let saved = intent(2);
    let mut journal = Journal::open(&root).unwrap();
    journal.save(saved.clone()).unwrap();
    let claim = journal.claim(&saved.id, "claude-review").unwrap();
    let path = root.join(filename(&saved.id));
    let before = fs::read(&path).unwrap();
    // The local call may already have happened after this durable claim. A
    // failed admission append must not erase its cached/persisted claim.
    journal.entries.get_mut(&saved.id).unwrap().file = File::open(&path).unwrap();
    assert!(matches!(
        journal.admission(&claim, LocalAdmission::Queued),
        Err(TeamError::Storage)
    ));
    assert!(claim.stored.claims.contains("claude-review"));
    assert_eq!(fs::read(&path).unwrap(), before);
    drop(journal);
    let mut recovered = Journal::open(&root).unwrap();
    let found = recovered.lookup(&saved.id).unwrap().unwrap();
    assert!(found.recovered);
    assert!(found.claims.contains("claude-review"));
    assert!(
        !found.admissions.contains_key("claude-review"),
        "claimed missing child admission stays unknown, not unclaimed"
    );
    assert!(!found.claims.contains("gemini-research"));
    assert!(
        !found.admissions.contains_key("gemini-research"),
        "never claimed means never invoked by this parent"
    );
    assert!(matches!(
        recovered.claim(&saved.id, "claude-review"),
        Err(TeamError::ConsumedRevision)
    ));
    for _ in 0..3 {
        assert_eq!(recovered.receipts().unwrap().len(), 1);
    }
    assert_eq!(
        fs::read(path).unwrap(),
        before,
        "lookup does not replay or manufacture admissions"
    );
}

#[test]
fn duplicate_parent_and_preexisting_canonical_bytes_are_never_overwritten() {
    let (_temp, root) = private_root();
    let mut journal = Journal::open(&root).unwrap();
    let saved = intent(3);
    journal.save(saved.clone()).unwrap();
    let before = fs::read(root.join(filename(&saved.id))).unwrap();
    assert!(matches!(
        journal.save(saved.clone()),
        Err(TeamError::ConsumedRevision)
    ));
    let mut conflict = saved.clone();
    conflict.host_instance = format!("host-{:064x}", 9);
    assert!(matches!(
        journal.save(conflict),
        Err(TeamError::ConsumedRevision)
    ));
    assert_eq!(fs::read(root.join(filename(&saved.id))).unwrap(), before);
    let foreign = intent(4);
    let path = root.join(filename(&foreign.id));
    write_private(&path, b"foreign canonical bytes\n");
    assert!(matches!(journal.save(foreign), Err(TeamError::Storage)));
    assert_eq!(fs::read(path).unwrap(), b"foreign canonical bytes\n");
    assert_eq!(fs::read(root.join(filename(&saved.id))).unwrap(), before);
}

#[test]
fn wrong_claude_timing_or_native_audit_never_creates_a_parent_record() {
    let (_temp, root) = private_root();
    let mut journal = Journal::open(&root).unwrap();
    for (n, change) in ["timing", "text", "child-id", "excluded"]
        .into_iter()
        .enumerate()
    {
        let mut saved = intent(10 + n);
        let member = &mut saved.members[0];
        match change {
            "timing" => member.action = Some(ActionLabel::ClaudeAfterTurn),
            "text" => {
                if let Some(NativeAudit::Claude { operation, .. }) = &mut member.audit {
                    operation.text.push_str(" altered");
                }
            }
            "child-id" => member.child_id = Some(uuid(999)),
            _ => member.excluded = Some(BlockReason::NoSession),
        }
        let id = saved.id.clone();
        assert!(matches!(journal.save(saved), Err(TeamError::InvalidInput)));
        assert!(!root.join(filename(&id)).exists());
    }
    journal.save(intent(20)).unwrap();
    assert_eq!(journal.receipts().unwrap().len(), 1);
}

#[test]
fn full_capacity_preserves_old_claimed_and_unclaimed_rows_without_eviction() {
    let (_temp, root) = private_root();
    let mut journal = Journal::open(&root).unwrap();
    for n in 0..MAX_DIRECTIONS {
        journal.save(intent(n)).unwrap();
    }
    let first = parent_id(0);
    let last = parent_id(MAX_DIRECTIONS - 1);
    journal.claim(&first, "claude-review").unwrap();
    let original_first = fs::read(root.join(filename(&first))).unwrap();
    let original_last = fs::read(root.join(filename(&last))).unwrap();
    assert!(matches!(
        journal.save(intent(MAX_DIRECTIONS)),
        Err(TeamError::Capacity)
    ));
    assert!(!root.join(filename(&parent_id(MAX_DIRECTIONS))).exists());
    drop(journal);
    let recovered = Journal::open(&root).unwrap();
    assert_eq!(recovered.receipts().unwrap().len(), MAX_DIRECTIONS);
    assert!(
        recovered
            .lookup(&first)
            .unwrap()
            .unwrap()
            .claims
            .contains("claude-review")
    );
    assert!(recovered.lookup(&last).unwrap().unwrap().claims.is_empty());
    assert_eq!(
        fs::read(root.join(filename(&first))).unwrap(),
        original_first
    );
    assert_eq!(fs::read(root.join(filename(&last))).unwrap(), original_last);
}

#[test]
fn encoded_byte_bound_is_checked_before_saving_or_claiming_any_member() {
    let (_temp, root) = private_root();
    let mut journal = Journal::open(&root).unwrap();
    journal.save(intent(30)).unwrap();
    let before = fs::read(root.join(filename(&parent_id(30)))).unwrap();
    let text = "\"".repeat(MAX_TEXT_BYTES);
    let mut oversized = intent(31);
    oversized.text = text.clone();
    oversized.members = (0..4)
        .map(|n| claude(&format!("member-{n}"), 200 + n, &text, ClaudeTiming::Now))
        .collect();
    oversized.selected = oversized
        .members
        .iter()
        .map(|member| member.id.clone())
        .collect();
    oversized.effective = oversized.selected.clone();
    assert!(check_intent(&oversized).is_err());
    assert!(journal.save(oversized).is_err());
    assert!(!root.join(filename(&parent_id(31))).exists());
    assert_eq!(
        fs::read(root.join(filename(&parent_id(30)))).unwrap(),
        before
    );
    journal.save(intent(32)).unwrap();
}

#[test]
fn partial_duplicate_or_invalid_order_bytes_are_preserved_and_disable_reopening() {
    for kind in [
        "partial",
        "duplicate",
        "admission-before-claim",
        "too-many-lines",
    ] {
        let (_temp, root) = private_root();
        drop(Journal::open(&root).unwrap());
        let saved = intent(40);
        let mut bytes = encode(&Line::Saved {
            intent: Box::new(saved.clone()),
        })
        .unwrap();
        match kind {
            "partial" => {
                bytes.pop();
            }
            "duplicate" => {
                bytes = format!(
                    "{{\"type\":\"saved\",\"type\":\"saved\",\"intent\":{}}}\n",
                    serde_json::to_string(&saved).unwrap()
                )
                .into_bytes();
            }
            "admission-before-claim" => bytes.extend(
                encode(&Line::Admission {
                    member: "claude-review".into(),
                    result: LocalAdmission::Queued,
                })
                .unwrap(),
            ),
            _ => {
                for _ in 0..MAX_LINES {
                    bytes.extend(encode(&Line::Retired).unwrap());
                }
            }
        }
        let path = root.join(filename(&saved.id));
        write_private(&path, &bytes);
        assert!(Journal::open(&root).is_err(), "reject {kind}");
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn foreign_domains_symlink_records_and_mutated_named_identity_are_not_adopted() {
    let (_temp, root) = private_root();
    drop(Journal::open(&root).unwrap());
    fs::write(root.join(DOMAIN), b"foreign domain\n").unwrap();
    assert!(Journal::open(&root).is_err());
    assert_eq!(fs::read(root.join(DOMAIN)).unwrap(), b"foreign domain\n");
    let (_temp, root) = private_root();
    let mut journal = Journal::open(&root).unwrap();
    journal.save(intent(50)).unwrap();
    let path = root.join(filename(&parent_id(50)));
    let retained = root.with_file_name("original-record");
    fs::rename(&path, &retained).unwrap();
    let original = fs::read(&retained).unwrap();
    write_private(&path, &original);
    assert!(journal.lookup(&parent_id(50)).is_err());
    assert!(journal.claim(&parent_id(50), "claude-review").is_err());
    assert_eq!(fs::read(&retained).unwrap(), original);
    let (_temp, root) = private_root();
    drop(Journal::open(&root).unwrap());
    let outside = root.with_file_name("outside");
    write_private(&outside, b"preserved outside bytes");
    symlink(&outside, root.join(filename(&parent_id(51)))).unwrap();
    assert!(Journal::open(&root).is_err());
    assert_eq!(fs::read(outside).unwrap(), b"preserved outside bytes");
}

#[test]
fn parent_directory_replacement_and_lock_lease_survival_are_checked() {
    let (_temp, root) = private_root();
    let mut journal = Journal::open(&root).unwrap();
    journal.save(intent(60)).unwrap();
    let duplicate = journal.lock.0.try_clone().unwrap();
    assert!(matches!(Journal::open(&root), Err(TeamError::Unavailable)));
    drop(journal);
    drop(Journal::open(&root).unwrap());
    drop(duplicate);
    let mut journal = Journal::open(&root).unwrap();
    let retained = root.with_file_name("retained-actions");
    fs::rename(&root, &retained).unwrap();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(journal.save(intent(61)).is_err());
    assert!(!root.join(filename(&parent_id(61))).exists());
    assert!(retained.join(filename(&parent_id(60))).is_file());
}
