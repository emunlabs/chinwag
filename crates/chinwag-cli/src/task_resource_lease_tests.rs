use super::*;
use crate::task_ref::{GitOid, Sha256Digest, TaskRefV1};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use tempfile::TempDir;

/// Controlled fixture authority only; no production constructor can select it.
pub(crate) struct Fixture {
    pub(crate) root: TempDir,
    pub(crate) root_fd: File,
    pub(crate) common_fd: File,
    pub(crate) gitdir_fd: File,
    pub(crate) store: TempDir,
    pub(crate) store_fd: File,
    pub(crate) clock: Cell<HostClockState>,
    pub(crate) current_bindings: RefCell<BTreeMap<String, QualifiedLeaseBinding>>,
    pub(crate) policy: LeaseStorePolicy,
    scheduler_store: (u64, u64),
    retired: RefCell<BTreeMap<String, RetirementWitness>>,
}

impl Fixture {
    pub(crate) fn new(scheduler_store: (u64, u64)) -> Self {
        let root = TempDir::new().unwrap();
        fs::create_dir(root.path().join("common-git")).unwrap();
        fs::create_dir(root.path().join("worktree-git")).unwrap();
        let root_fd = File::open(root.path()).unwrap();
        let common_fd = File::open(root.path().join("common-git")).unwrap();
        let gitdir_fd = File::open(root.path().join("worktree-git")).unwrap();
        let store = TempDir::new().unwrap();
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store_fd = File::open(store.path()).unwrap();
        let common = identity(&common_fd).unwrap();
        Self {
            root,
            root_fd,
            common_fd,
            gitdir_fd,
            store,
            store_fd,
            clock: Cell::new(HostClockState::Verified { now_unix: 100 }),
            current_bindings: RefCell::new(BTreeMap::new()),
            policy: LeaseStorePolicy {
                repo_id: "repository-fixture".into(),
                common_git_identity: (common.dev, common.ino),
                authority_epoch: 1,
                config_digest: [9; 32],
            },
            scheduler_store,
            retired: RefCell::new(BTreeMap::new()),
        }
    }

    pub(crate) fn authority(&self) -> CurrentLeaseAuthority<'_> {
        CurrentLeaseAuthority {
            profile: Some(ControlledAuthority {
                policy: self.policy.clone(),
                store: identity(&self.store_fd).unwrap(),
                scheduler_store: self.scheduler_store,
                root: &self.root_fd,
                roots: BTreeMap::from([
                    (identity(&self.root_fd).unwrap(), &self.root_fd),
                    (identity(&self.gitdir_fd).unwrap(), &self.gitdir_fd),
                ]),
                gitdir: &self.gitdir_fd,
                common: &self.common_fd,
                target: "refs/heads/integration".into(),
                owner: "RUST#executor".into(),
                clock: &self.clock,
                retired: &self.retired,
                current_bindings: &self.current_bindings,
            }),
        }
    }

    pub(crate) fn open(&self) -> ResourceLeaseStore {
        ResourceLeaseStore::open(&self.store_fd, self.policy.clone()).unwrap()
    }

    pub(crate) fn assignment(&self, id: &str) -> QualifiedLeaseAssignment {
        QualifiedLeaseAssignment::fixture(QualifiedLeaseBinding {
            scheduler_store: self.scheduler_store,
            workspace: "scheduler-fixture".into(),
            repo: "repository-fixture".into(),
            authority_epoch: 1,
            owner: "RUST#executor".into(),
            assignment: id.into(),
            operation: format!("original-{id}"),
            write_scope_claim: format!("write-{id}"),
            original_deadline: 1000,
            assignment_digest: Sha256Digest::of(id.as_bytes()).0,
            task_ref: TaskRefV1 {
                workspace_id: "scheduler-fixture".into(),
                repo_id: "repository-fixture".into(),
                task_source_id: "00000000000000000000000000000001".into(),
                source_generation: 1,
                canonical_task_path: "tasks/fixture.md".into(),
                task_id: format!("task-{id}"),
                task_spec_digest: Sha256Digest::of(id.as_bytes()),
                task_status_rev: 1,
                file_cas_rev: 1,
                baseline_commit: GitOid::from_hex("15ea881e96d43a8ffe87f7e24dd5e9f22311ff31")
                    .unwrap(),
            },
        })
    }

    pub(crate) fn register(&self, assignment: &QualifiedLeaseAssignment) {
        let binding = assignment.binding();
        self.current_bindings
            .borrow_mut()
            .insert(binding.assignment.clone(), binding.clone());
    }

    pub(crate) fn prove_retired(&self, store: &ResourceLeaseStore, id: &str) {
        let row = &store.rows[id];
        self.retired.borrow_mut().insert(
            row.binding.operation.clone(),
            RetirementWitness {
                binding: row.binding.clone(),
                generation: row.generation,
                receipt: format!("quiescent-{id}-{}", row.generation),
                phase_revision: row.phase_revision,
            },
        );
    }

    pub(crate) fn acquire(
        &self,
        store: &mut ResourceLeaseStore,
        assignment: &QualifiedLeaseAssignment,
        request: LeaseRequest,
    ) -> CommittedWriteLease {
        self.register(assignment);
        let prepared = match store
            .prepare(assignment, request, &self.authority())
            .unwrap()
        {
            LeasePreparation::Prepared(prepared) => prepared,
            LeasePreparation::Existing(_) => panic!("fixture expected a new prepared lease"),
        };
        store.commit(prepared, &self.authority()).unwrap()
    }

    pub(crate) fn write(&self, path: &str, bytes: &[u8]) {
        let path = self.root.path().join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }
}

fn file(path: &str) -> ResourceScope {
    ResourceScope::File { path: path.into() }
}
fn request(scopes: Vec<ResourceScope>) -> LeaseRequest {
    LeaseRequest {
        scopes,
        ttl_seconds: 60,
    }
}
fn unknown() -> InvocationOutcome {
    InvocationOutcome::Unknown {
        reason: "fixture-reply-lost".into(),
    }
}

fn stale_retirement_must_not_release_later_effect(late_delivery: bool) {
    let f = Fixture::new((11, 22));
    f.write("x", b"original");
    let a = f.assignment("a");
    let mut store = f.open();
    let cap = f.acquire(&mut store, &a, request(vec![file("x")]));
    f.prove_retired(&store, "a");
    let old = f
        .retired
        .borrow()
        .get(&a.binding().operation)
        .unwrap()
        .clone();
    if late_delivery {
        f.retired.borrow_mut().remove(&a.binding().operation);
    }
    let calls = Cell::new(0);
    store
        .invoke(cap, &a, &f.authority(), |writer| {
            calls.set(calls.get() + 1);
            writer.write_file(0, b"later uncertain effect").unwrap();
            unknown()
        })
        .unwrap();
    assert_eq!(calls.get(), 1);
    if late_delivery {
        f.retired
            .borrow_mut()
            .insert(a.binding().operation.clone(), old);
    }
    assert_eq!(store.status("a"), Some(LeaseStatus::Unknown));
    assert!(
        matches!(
            store.reconcile_original("a", &f.authority()),
            Err(LeaseError::Authority)
        ),
        "a pre-invocation quiescence witness cannot retire later uncertain effects"
    );
    let b = f.assignment("b");
    f.register(&b);
    assert!(matches!(
        store.prepare(&b, request(vec![file("x")]), &f.authority()),
        Err(LeaseError::Conflict)
    ));
    drop(store);
    let mut reopened = f.open();
    assert!(matches!(
        reopened.reconcile_original("a", &f.authority()),
        Err(LeaseError::Authority)
    ));
    f.prove_retired(&reopened, "a");
    assert_eq!(
        reopened.reconcile_original("a", &f.authority()).unwrap(),
        LeaseStatus::Retired
    );
    assert!(matches!(
        reopened
            .prepare(&b, request(vec![file("x")]), &f.authority())
            .unwrap(),
        LeasePreparation::Prepared(_)
    ));
}
#[test]
fn p008_stale_retirement_cached_before_invocation_cannot_release_unknown() {
    stale_retirement_must_not_release_later_effect(false);
}
#[test]
fn p008_stale_retirement_delivered_after_invocation_cannot_release_unknown() {
    stale_retirement_must_not_release_later_effect(true);
}

#[test]
fn p008_stale_retirement_before_checked_write_is_fenced_by_durable_write_phase() {
    let f = Fixture::new((11, 22));
    f.write("x", b"before");
    let a = f.assignment("a");
    let mut store = f.open();
    let cap = f.acquire(&mut store, &a, request(vec![file("x")]));
    store
        .invoke(cap, &a, &f.authority(), |writer| {
            f.prove_retired(writer.store, "a");
            let before = writer.store.rows["a"].phase_revision;
            writer.write_file(0, b"after phase witness").unwrap();
            assert!(writer.store.rows["a"].phase_revision > before);
            assert!(matches!(
                writer.store.reconcile_original("a", &f.authority()),
                Err(LeaseError::Authority)
            ));
            unknown()
        })
        .unwrap();
    assert_eq!(
        fs::read(f.root.path().join("x")).unwrap(),
        b"after phase witness"
    );
    assert!(matches!(
        store.reconcile_original("a", &f.authority()),
        Err(LeaseError::Authority)
    ));
}

#[test]
fn p008_retirement_record_replay_validates_witnessed_predecessor_phase() {
    for forged in [false, true] {
        let f = Fixture::new((11, 22));
        f.write("x", b"before");
        let a = f.assignment("a");
        let mut store = f.open();
        let cap = f.acquire(&mut store, &a, request(vec![file("x")]));
        let stale = store.rows["a"].phase_revision;
        store
            .invoke(cap, &a, &f.authority(), |writer| {
                writer.write_file(0, b"effect").unwrap();
                unknown()
            })
            .unwrap();
        if forged {
            let mut row = store.rows["a"].clone();
            row.status = LeaseStatus::Retired;
            row.retirement = Some("stale-phase-receipt".into());
            row.retirement_phase_revision = Some(stale);
            row.phase_revision = store.next_revision;
            let record = Record {
                revision: store.next_revision,
                data: Data::Lease {
                    row: Box::new(row),
                    observed: 100,
                },
            };
            let bytes = serde_json::to_vec(&record).unwrap();
            drop(store);
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(f.store.path().join("repository-resource-leases-v1.ndjson"))
                .unwrap();
            file.write_all(&bytes).unwrap();
            file.write_all(b"\n").unwrap();
            file.sync_all().unwrap();
            drop(file);
            assert!(matches!(
                ResourceLeaseStore::open(&f.store_fd, f.policy.clone()),
                Err(LeaseError::Authority)
            ));
        } else {
            let predecessor = store.rows["a"].phase_revision;
            f.prove_retired(&store, "a");
            store.reconcile_original("a", &f.authority()).unwrap();
            assert_eq!(store.rows["a"].retirement_phase_revision, Some(predecessor));
            assert!(store.rows["a"].phase_revision > predecessor);
            drop(store);
            assert_eq!(f.open().status("a"), Some(LeaseStatus::Retired));
        }
    }
}

#[test]
fn p008_protected_writer_changes_actual_file_and_keeps_retirement_separate() {
    let f = Fixture::new((7, 9));
    f.write("src/x.rs", b"before");
    let a = f.assignment("a");
    let mut store = f.open();
    let cap = f.acquire(&mut store, &a, request(vec![file("src/x.rs")]));
    let calls = Cell::new(0);
    let result = store
        .invoke(cap, &a, &f.authority(), |writer| {
            calls.set(calls.get() + 1);
            writer.write_file(0, b"after").unwrap();
            InvocationOutcome::ConfirmedRetired {
                original_operation_id: "original-a".into(),
                receipt_id: "executor-result".into(),
            }
        })
        .unwrap();
    assert!(matches!(result, InvocationOutcome::ConfirmedRetired { .. }));
    assert_eq!(calls.get(), 1);
    assert_eq!(fs::read(f.root.path().join("src/x.rs")).unwrap(), b"after");
    assert_eq!(store.status("a"), Some(LeaseStatus::Unknown));
    let b = f.assignment("b");
    f.register(&b);
    assert!(matches!(
        store.prepare(&b, request(vec![file("src/x.rs")]), &f.authority()),
        Err(LeaseError::Conflict)
    ));
    f.prove_retired(&store, "a");
    assert_eq!(
        store.reconcile_original("a", &f.authority()).unwrap(),
        LeaseStatus::Retired
    );
    assert!(matches!(
        store.prepare(&b, request(vec![file("src/x.rs")]), &f.authority()),
        Ok(LeasePreparation::Prepared(_))
    ));
}

#[test]
fn p008_exact_replay_after_ttl_does_not_mint_capability_or_extend_deadline() {
    let f = Fixture::new((7, 9));
    f.write("x", b"x");
    let a = f.assignment("a");
    let mut store = f.open();
    let _cap = f.acquire(&mut store, &a, request(vec![file("x")]));
    let before = store.rows["a"].clone();
    let revision = store.next_revision;
    f.clock.set(HostClockState::Verified { now_unix: 500 });
    assert!(matches!(
        store.prepare(&a, request(vec![file("x")]), &f.authority()),
        Ok(LeasePreparation::Existing(LeaseStatus::Committed))
    ));
    assert_eq!(store.rows["a"], before);
    assert_eq!(store.next_revision, revision);
    let mut changed = request(vec![file("x")]);
    changed.ttl_seconds += 1;
    assert!(matches!(
        store.prepare(&a, changed, &f.authority()),
        Err(LeaseError::ReplayConflict)
    ));
    let mut changed_binding = a.binding().clone();
    changed_binding.assignment_digest[0] ^= 1;
    let changed = QualifiedLeaseAssignment::fixture(changed_binding);
    f.register(&changed);
    assert!(matches!(
        store.prepare(&changed, request(vec![file("x")]), &f.authority()),
        Err(LeaseError::ReplayConflict)
    ));
}

#[test]
fn p008_physical_aliases_and_folded_missing_names_conflict_across_assignments() {
    let f = Fixture::new((7, 9));
    f.write("one", b"x");
    fs::hard_link(f.root.path().join("one"), f.root.path().join("two")).unwrap();
    let mut store = f.open();
    let a = f.assignment("a");
    let _cap = f.acquire(&mut store, &a, request(vec![file("one")]));
    let b = f.assignment("b");
    f.register(&b);
    assert!(matches!(
        store.prepare(&b, request(vec![file("two")]), &f.authority()),
        Err(LeaseError::Conflict)
    ));
    let c = f.assignment("c");
    let _cap = f.acquire(&mut store, &c, request(vec![file("new.rs")]));
    let d = f.assignment("d");
    f.register(&d);
    assert!(matches!(
        store.prepare(&d, request(vec![file("NEW.RS")]), &f.authority()),
        Err(LeaseError::Conflict)
    ));
}

#[test]
fn p008_directory_and_even_disjoint_symbols_need_exclusive_file_ownership() {
    let f = Fixture::new((7, 9));
    f.write("src/nested/x", b"x");
    let mut store = f.open();
    let a = f.assignment("a");
    let _cap = f.acquire(
        &mut store,
        &a,
        request(vec![ResourceScope::Directory { path: "src".into() }]),
    );
    let b = f.assignment("b");
    f.register(&b);
    assert!(matches!(
        store.prepare(&b, request(vec![file("src/nested/new")]), &f.authority()),
        Err(LeaseError::Conflict)
    ));
    f.prove_retired(&store, "a");
    store.reconcile_original("a", &f.authority()).unwrap();
    let _cap = f.acquire(
        &mut store,
        &b,
        request(vec![ResourceScope::Symbol {
            path: "src/nested/x".into(),
            symbol: "first".into(),
        }]),
    );
    let c = f.assignment("c");
    f.register(&c);
    assert!(matches!(
        store.prepare(
            &c,
            request(vec![ResourceScope::Symbol {
                path: "src/nested/x".into(),
                symbol: "other".into()
            }]),
            &f.authority()
        ),
        Err(LeaseError::Conflict)
    ));
    assert!(matches!(
        store.prepare(&c, request(vec![file("src/nested/x")]), &f.authority()),
        Err(LeaseError::Conflict)
    ));
}

#[test]
fn p008_multiscope_conflict_does_not_partially_reserve_free_scope() {
    let f = Fixture::new((7, 9));
    let mut store = f.open();
    let a = f.assignment("a");
    let _cap = f.acquire(&mut store, &a, request(vec![file("occupied")]));
    let b = f.assignment("b");
    f.register(&b);
    let revision = store.next_revision;
    assert!(matches!(
        store.prepare(
            &b,
            request(vec![file("free"), file("occupied")]),
            &f.authority()
        ),
        Err(LeaseError::Conflict)
    ));
    assert_eq!(store.next_revision, revision);
    assert_eq!(store.status("b"), None);
    let c = f.assignment("c");
    let _cap = f.acquire(&mut store, &c, request(vec![file("free")]));
    assert_eq!(store.status("c"), Some(LeaseStatus::Committed));
}

#[test]
fn p008_unknown_survives_reopen_and_ttl_without_replacement_until_quiescent() {
    let f = Fixture::new((7, 9));
    f.write("x", b"x");
    let a = f.assignment("a");
    let mut store = f.open();
    let cap = f.acquire(&mut store, &a, request(vec![file("x")]));
    let calls = Cell::new(0);
    store
        .invoke(cap, &a, &f.authority(), |_| {
            calls.set(calls.get() + 1);
            unknown()
        })
        .unwrap();
    drop(store);
    f.clock.set(HostClockState::Verified { now_unix: 500 });
    let mut store = f.open();
    assert_eq!(store.status("a"), Some(LeaseStatus::Unknown));
    let b = f.assignment("b");
    f.register(&b);
    assert!(matches!(
        store.prepare(&b, request(vec![file("x")]), &f.authority()),
        Err(LeaseError::Conflict)
    ));
    assert!(matches!(
        store.reconcile_original("a", &f.authority()),
        Err(LeaseError::Unknown)
    ));
    assert_eq!(calls.get(), 1);
    f.prove_retired(&store, "a");
    assert_eq!(
        store.reconcile_original("a", &f.authority()).unwrap(),
        LeaseStatus::Retired
    );
    let _cap = f.acquire(&mut store, &b, request(vec![file("x")]));
    assert_eq!(store.status("b"), Some(LeaseStatus::Committed));
}

#[test]
fn p008_expiry_and_stale_current_binding_refuse_before_executor_callback() {
    for mode in ["expiry", "baseline", "owner", "binding"] {
        let f = Fixture::new((7, 9));
        f.write("x", b"original");
        let a = f.assignment("a");
        let mut store = f.open();
        let cap = f.acquire(&mut store, &a, request(vec![file("x")]));
        let mut authority = f.authority();
        match mode {
            "expiry" => f.clock.set(HostClockState::Verified { now_unix: 160 }),
            "baseline" => {
                f.current_bindings
                    .borrow_mut()
                    .get_mut("a")
                    .unwrap()
                    .task_ref
                    .baseline_commit = GitOid::Sha1([8; 20])
            }
            "owner" => authority.profile.as_mut().unwrap().owner = "RUST#other".into(),
            "binding" => {
                f.current_bindings.borrow_mut().remove("a");
            }
            _ => unreachable!(),
        }
        let calls = Cell::new(0);
        assert!(
            store
                .invoke(cap, &a, &authority, |_| {
                    calls.set(calls.get() + 1);
                    unknown()
                })
                .is_err(),
            "{mode}"
        );
        assert_eq!(calls.get(), 0, "{mode}");
        assert_eq!(fs::read(f.root.path().join("x")).unwrap(), b"original");
        assert_eq!(store.status("a"), Some(LeaseStatus::Committed));
    }
}

#[test]
fn p008_wrong_store_capability_and_wrong_retirement_witness_hold() {
    let f = Fixture::new((7, 9));
    let g = Fixture::new((7, 9));
    let a = f.assignment("a");
    let b = g.assignment("a");
    let mut first = f.open();
    let mut second = g.open();
    let cap = f.acquire(&mut first, &a, request(vec![file("x")]));
    let _other = g.acquire(&mut second, &b, request(vec![file("x")]));
    let calls = Cell::new(0);
    assert!(matches!(
        second.invoke(cap, &b, &g.authority(), |_| {
            calls.set(calls.get() + 1);
            unknown()
        }),
        Err(LeaseError::Authority)
    ));
    assert_eq!(calls.get(), 0);
    f.prove_retired(&first, "a");
    f.retired
        .borrow_mut()
        .get_mut("original-a")
        .unwrap()
        .generation += 1;
    assert!(matches!(
        first.reconcile_original("a", &f.authority()),
        Err(LeaseError::Authority)
    ));
    f.prove_retired(&first, "a");
    f.retired
        .borrow_mut()
        .get_mut("original-a")
        .unwrap()
        .binding
        .task_ref
        .baseline_commit = GitOid::Sha1([8; 20]);
    assert!(matches!(
        first.reconcile_original("a", &f.authority()),
        Err(LeaseError::Authority)
    ));
    assert_eq!(first.status("a"), Some(LeaseStatus::Committed));
    f.prove_retired(&first, "a");
    assert_eq!(
        first.reconcile_original("a", &f.authority()).unwrap(),
        LeaseStatus::Retired
    );
}

#[test]
fn p008_checked_write_persists_time_highwater_before_effect_and_reopen() {
    let f = Fixture::new((7, 9));
    f.write("x", b"original");
    let a = f.assignment("a");
    let mut store = f.open();
    let cap = f.acquire(
        &mut store,
        &a,
        LeaseRequest {
            scopes: vec![file("x")],
            ttl_seconds: 120,
        },
    );
    // Remain within the original 120-second TTL while advancing verified time.
    let result = store
        .invoke(cap, &a, &f.authority(), |writer| {
            f.clock.set(HostClockState::Verified { now_unix: 200 });
            writer.write_file(0, b"first").unwrap();
            f.clock.set(HostClockState::Verified { now_unix: 199 });
            assert!(matches!(
                writer.write_file(0, b"second"),
                Err(LeaseError::Clock)
            ));
            assert_eq!(fs::read(f.root.path().join("x")).unwrap(), b"first");
            unknown()
        })
        .unwrap();
    assert!(matches!(result, InvocationOutcome::Unknown { .. }));
    assert_eq!(store.max_time, 200);
    drop(store);
    let mut store = f.open();
    assert_eq!(store.max_time, 200);
    let b = f.assignment("b");
    f.register(&b);
    assert!(matches!(
        store.prepare(&b, request(vec![file("other")]), &f.authority()),
        Err(LeaseError::Clock)
    ));
    assert!(store.status("a").unwrap().held());
}

#[test]
fn p008_ttl_bound_original_deadline_and_invalid_requests_write_nothing() {
    let f = Fixture::new((7, 9));
    let a = f.assignment("a");
    f.register(&a);
    let mut store = f.open();
    let revision = store.next_revision;
    for ttl in [0, 121, u64::MAX] {
        assert!(matches!(
            store.prepare(
                &a,
                LeaseRequest {
                    scopes: vec![file("x")],
                    ttl_seconds: ttl
                },
                &f.authority()
            ),
            Err(LeaseError::Invalid)
        ));
        assert_eq!(store.next_revision, revision);
    }
    assert!(matches!(
        store.prepare(&a, request(vec![file("x"), file("x")]), &f.authority()),
        Err(LeaseError::Invalid)
    ));
    assert!(matches!(
        store.prepare(&a, request(vec![]), &f.authority()),
        Err(LeaseError::Invalid)
    ));
    assert_eq!(store.next_revision, revision);
    let mut binding = a.binding().clone();
    binding.original_deadline = 150;
    let bounded = QualifiedLeaseAssignment::fixture(binding);
    f.register(&bounded);
    let _cap = f.acquire(
        &mut store,
        &bounded,
        LeaseRequest {
            scopes: vec![file("x")],
            ttl_seconds: 120,
        },
    );
    assert_eq!(store.rows["a"].expires, 150);
}

#[test]
fn p008_malformed_or_torn_replay_never_becomes_an_empty_lease_store() {
    for raw in [
        b"{".as_slice(),
        b"{}\n",
        b"{\"revision\":1,\"revision\":1}\n",
        b"[]\n",
    ] {
        let f = Fixture::new((7, 9));
        let path = f.store.path().join("repository-resource-leases-v1.ndjson");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(raw).unwrap();
        file.sync_all().unwrap();
        assert!(ResourceLeaseStore::open(&f.store_fd, f.policy.clone()).is_err());
        assert_eq!(fs::read(&path).unwrap(), raw);
    }
}

#[test]
fn p008_logical_paths_across_worktrees_conflict_only_under_same_target_policy() {
    let f = Fixture::new((7, 9));
    f.write("x", b"first");
    let other = TempDir::new().unwrap();
    fs::write(other.path().join("x"), b"second").unwrap();
    let other_fd = File::open(other.path()).unwrap();
    let a = f.assignment("a");
    let b = f.assignment("b");
    f.register(&b);
    let mut store = f.open();
    let _cap = f.acquire(&mut store, &a, request(vec![file("x")]));
    let mut authority = f.authority();
    let p = authority.profile.as_mut().unwrap();
    p.root = &other_fd;
    p.roots.insert(identity(&other_fd).unwrap(), &other_fd);
    assert!(matches!(
        store.prepare(&b, request(vec![file("x")]), &authority),
        Err(LeaseError::Conflict)
    ));
    authority.profile.as_mut().unwrap().target = "refs/heads/INTEGRATION".into();
    assert!(matches!(
        store.prepare(&b, request(vec![file("x")]), &authority),
        Err(LeaseError::Conflict)
    ));
    authority.profile.as_mut().unwrap().target = "refs/heads/isolated-feature".into();
    assert!(matches!(
        store.prepare(&b, request(vec![file("x")]), &authority),
        Ok(LeasePreparation::Prepared(_))
    ));
}

#[test]
fn p008_git_index_refs_common_and_integration_targets_share_real_domain_keys() {
    for (first, second) in [
        (ResourceScope::GitIndex, ResourceScope::GitIndex),
        (
            ResourceScope::GitRef {
                reference: "refs/heads/integration".into(),
            },
            ResourceScope::IntegrationTarget,
        ),
        (
            ResourceScope::GitRef {
                reference: "refs/heads/feature-a".into(),
            },
            ResourceScope::GitRef {
                reference: "refs/heads/FEATURE-B".into(),
            },
        ),
        (
            ResourceScope::GitRef {
                reference: "refs/heads/main".into(),
            },
            ResourceScope::GitRef {
                reference: "refs/heads/MAIN".into(),
            },
        ),
        (ResourceScope::GitCommonDirectory, ResourceScope::GitIndex),
        (ResourceScope::IntegrationTarget, file("x")),
    ] {
        let f = Fixture::new((7, 9));
        let mut store = f.open();
        let a = f.assignment("a");
        let _cap = f.acquire(&mut store, &a, request(vec![first]));
        let b = f.assignment("b");
        f.register(&b);
        assert!(matches!(
            store.prepare(&b, request(vec![second]), &f.authority()),
            Err(LeaseError::Conflict)
        ));
    }
}

#[test]
fn p008_atomic_file_replacement_keeps_new_inode_alias_held_across_reopen() {
    let f = Fixture::new((7, 9));
    f.write("x", b"original");
    let a = f.assignment("a");
    let mut store = f.open();
    let _cap = f.acquire(&mut store, &a, request(vec![file("x")]));
    f.write("replacement", b"replacement");
    fs::rename(f.root.path().join("replacement"), f.root.path().join("x")).unwrap();
    fs::hard_link(f.root.path().join("x"), f.root.path().join("alias")).unwrap();
    let b = f.assignment("b");
    f.register(&b);
    assert!(matches!(
        store.prepare(&b, request(vec![file("alias")]), &f.authority()),
        Err(LeaseError::Conflict)
    ));
    drop(store);
    let mut store = f.open();
    assert!(matches!(
        store.prepare(&b, request(vec![file("alias")]), &f.authority()),
        Err(LeaseError::Conflict)
    ));
    assert_eq!(store.status("a"), Some(LeaseStatus::Committed));
    assert_eq!(store.status("b"), None);
}

#[test]
fn p008_git_index_hardlink_aliases_and_replacement_aliases_remain_held() {
    let f = Fixture::new((7, 9));
    fs::write(f.root.path().join("worktree-git/index"), b"index-before").unwrap();
    let other_gitdir = TempDir::new().unwrap();
    fs::hard_link(
        f.root.path().join("worktree-git/index"),
        other_gitdir.path().join("index"),
    )
    .unwrap();
    let other_fd = File::open(other_gitdir.path()).unwrap();
    let a = f.assignment("a");
    let b = f.assignment("b");
    f.register(&b);
    let mut store = f.open();
    let _cap = f.acquire(&mut store, &a, request(vec![ResourceScope::GitIndex]));
    let mut other_authority = f.authority();
    let p = other_authority.profile.as_mut().unwrap();
    p.gitdir = &other_fd;
    p.roots.insert(identity(&other_fd).unwrap(), &other_fd);
    assert!(matches!(
        store.prepare(&b, request(vec![ResourceScope::GitIndex]), &other_authority),
        Err(LeaseError::Conflict)
    ));
    fs::write(
        f.root.path().join("worktree-git/replacement"),
        b"index-after",
    )
    .unwrap();
    fs::rename(
        f.root.path().join("worktree-git/replacement"),
        f.root.path().join("worktree-git/index"),
    )
    .unwrap();
    fs::hard_link(
        f.root.path().join("worktree-git/index"),
        f.root.path().join("replacement-alias"),
    )
    .unwrap();
    // The old inode is still held through the other gitdir; the replacement
    // inode is also excluded by refreshing the original reserved index name.
    assert!(matches!(
        store.prepare(&b, request(vec![ResourceScope::GitIndex]), &other_authority),
        Err(LeaseError::Conflict)
    ));
    assert!(matches!(
        store.prepare(&b, request(vec![file("replacement-alias")]), &f.authority()),
        Err(LeaseError::Conflict)
    ));
    assert_eq!(store.status("b"), None);
}
