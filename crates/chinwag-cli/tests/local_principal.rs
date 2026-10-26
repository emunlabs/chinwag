//! Each test consumes one fresh repository supplied by the once-only operator.
#![cfg(target_os = "macos")]
use chinwag_confirmed_initial_private::{
    PrincipalLookup, PrincipalState, ResolvedPrincipal, SigningAttempt,
};
use chinwag_signing::{InitReceipt, TxState};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn repo(name: &str) -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("CHINWAG_PRINCIPAL_QA_REPOSITORIES")
            .expect("fresh once-operator repository namespace required"),
    );
    let repo = root.join(name);
    assert!(repo.is_absolute() && repo.join(".git").is_dir() && !repo.join(".chinwag").exists());
    repo
}
fn config(repo: &Path, extra: &[u8]) {
    let path = repo.join(".git/config");
    let mut out = fs::OpenOptions::new().append(true).open(path).unwrap();
    out.write_all(extra).unwrap();
    out.sync_all().unwrap();
}
fn report(repo: &Path, value: Value) {
    let name = repo.file_name().unwrap().to_str().unwrap();
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(
            repo.parent()
                .unwrap()
                .join(format!("{name}.principal-observation.json")),
        )
        .unwrap();
    writeln!(
        out,
        "{}",
        json!({"case":name,"outcome":value,"Genesis_complete":false})
    )
    .unwrap();
    out.sync_all().unwrap();
}
fn start_lookup(repo: &Path) -> (PrincipalLookup, Option<u32>) {
    let lookup = PrincipalLookup::start(repo).unwrap();
    let pid = match lookup.state() {
        PrincipalState::Pending { pid } => Some(pid),
        _ => None,
    };
    (lookup, pid)
}
fn terminal(mut lookup: PrincipalLookup) -> PrincipalLookup {
    loop {
        match lookup.poll(Instant::now()) {
            PrincipalState::Pending { .. } => std::thread::sleep(Duration::from_millis(5)),
            PrincipalState::Unknown { .. } => {
                let exit = observe_unknown(&mut lookup);
                panic!("original query was unknown, later observed {exit}");
            }
            _ => return lookup,
        }
    }
}
fn observe_unknown(lookup: &mut PrincipalLookup) -> String {
    loop {
        if let Ok(Some(exit)) = lookup.observe_child() {
            return format!("{exit:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn ready(repo: &Path) -> (PrincipalLookup, u32) {
    let (lookup, pid) = start_lookup(repo);
    let lookup = terminal(lookup);
    assert_eq!(lookup.state(), PrincipalState::Ready);
    (lookup, pid.expect("original spawned query"))
}
fn resolved(repo: &Path) -> (ResolvedPrincipal, u32) {
    let (lookup, pid) = ready(repo);
    let value = lookup.resolve().unwrap();
    for suffix in ["pending", "stdout", "stderr"] {
        assert!(
            !repo
                .join(format!(".git/chinwag-principal.{suffix}"))
                .exists()
        );
    }
    (value, pid)
}
fn no_material(repo: &Path) {
    assert!(!repo.join(".chinwag").exists());
}
fn refused(repo: &Path, reason: &'static str) {
    let (lookup, pid) = start_lookup(repo);
    let lookup = terminal(lookup);
    assert_eq!(lookup.state(), PrincipalState::Refused { reason });
    no_material(repo);
    assert!(repo.join(".git/chinwag-principal.pending").is_file());
    report(
        repo,
        json!({"query_pid":pid,"known_refusal":reason,"no_material":true}),
    );
}
fn signing_terminal(mut attempt: SigningAttempt) -> SigningAttempt {
    loop {
        match attempt.poll(Instant::now()) {
            InitReceipt::Config { transaction, .. }
                if matches!(transaction.state, TxState::Pending { .. }) =>
            {
                std::thread::sleep(Duration::from_millis(5))
            }
            InitReceipt::Config { transaction, .. }
                if matches!(transaction.state, TxState::ChildUnknown { .. }) =>
            {
                loop {
                    if let Ok(Some(exit)) = attempt.observe_child() {
                        panic!("original signing unknown, observed {exit}")
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            _ => return attempt,
        }
    }
}
#[test]
fn local_query_transfers_original_preimage_into_confirmed_initial_store() {
    let repo = repo("principal-positive");
    let (resolved, pid) = resolved(&repo);
    assert_eq!(resolved.principal(), "fixture@chinwag.test");
    assert_eq!(resolved.repository(), repo.as_path());
    let attempt = signing_terminal(SigningAttempt::start_discovered(resolved).unwrap());
    let receipt = attempt
        .confirm()
        .unwrap()
        .begin_initial()
        .unwrap()
        .finish()
        .unwrap();
    report(
        &repo,
        json!({"query_pid":pid,"public_key":receipt.public_key(),"site_id":receipt.store().site_id(),"store_sha256":receipt.store().sha256(),"checked_initial_fds":receipt.directly_owned_checked_fds()}),
    );
}
#[test]
fn quoted_case_is_preserved_by_git_without_handwritten_config_parsing() {
    let repo = repo("principal-quoted");
    let path = repo.join(".git/config");
    let bytes = fs::read_to_string(&path).unwrap().replace(
        "fixture@chinwag.test",
        "\"Fixture.Name+tag@chinwag.test\" # literal comment",
    );
    fs::write(path, bytes).unwrap();
    let (value, pid) = resolved(&repo);
    assert_eq!(value.principal(), "Fixture.Name+tag@chinwag.test");
    let closed = value.finish().unwrap();
    no_material(&repo);
    report(
        &repo,
        json!({"query_pid":pid,"principal":"Fixture.Name+tag@chinwag.test","checked_fds":closed,"no_material":true}),
    );
}
#[test]
fn missing_local_email_never_uses_ambient_identity() {
    let repo = repo("principal-missing");
    let path = repo.join(".git/config");
    let bytes = fs::read_to_string(&path)
        .unwrap()
        .replace("\temail = fixture@chinwag.test\n", "");
    fs::write(path, bytes).unwrap();
    refused(&repo, "local_principal_missing");
}
#[test]
fn duplicate_emails_are_refused_without_selecting_the_last_value() {
    let repo = repo("principal-duplicate");
    config(&repo, b"\n[user]\n\temail = second@chinwag.test\n");
    refused(&repo, "local_principal_ambiguous");
}
#[test]
fn invalid_principal_refuses_before_entropy_or_material() {
    let repo = repo("principal-invalid");
    let path = repo.join(".git/config");
    fs::write(
        &path,
        fs::read_to_string(&path)
            .unwrap()
            .replace("fixture@chinwag.test", "not-an-email"),
    )
    .unwrap();
    refused(&repo, "local_principal_invalid");
}
#[test]
fn query_does_not_follow_includes_and_signing_still_refuses_that_profile() {
    let repo = repo("principal-include");
    let include = repo.join("public-include-fixture");
    fs::write(&include, b"[user]\n\temail = included@chinwag.test\n").unwrap();
    config(
        &repo,
        format!("\n[include]\n\tpath = {}\n", include.display()).as_bytes(),
    );
    let before = fs::read(repo.join(".git/config")).unwrap();
    let (resolved, pid) = resolved(&repo);
    assert_eq!(resolved.principal(), "fixture@chinwag.test");
    let attempt = signing_terminal(SigningAttempt::start_discovered(resolved).unwrap());
    assert!(
        !matches!(attempt.receipt(), InitReceipt::Config { transaction, .. }
        if matches!(transaction.state, TxState::Installed | TxState::Unchanged))
    );
    assert_eq!(fs::read(repo.join(".git/config")).unwrap(), before);
    assert!(repo.join(".chinwag/signer").is_file());
    assert!(!repo.join(".chinwag/state.crdb").exists());
    report(
        &repo,
        json!({"query_pid":pid,"partial_material":true,"reason":attempt.reason(),"original_config_unchanged":true,"no_store":true}),
    );
}
#[test]
fn changed_config_after_query_cannot_generate_a_signer() {
    let repo = repo("principal-config-change");
    let (resolved, pid) = resolved(&repo);
    config(&repo, b"\n[core]\n\tcommentChar = !\n");
    assert!(SigningAttempt::start_discovered(resolved).is_err());
    no_material(&repo);
    report(
        &repo,
        json!({"query_pid":pid,"preimage_changed":true,"no_material":true}),
    );
}
#[test]
fn identical_bytes_on_another_config_inode_cannot_recreate_authority() {
    let repo = repo("principal-config-inode");
    let (resolved, pid) = resolved(&repo);
    let config = repo.join(".git/config");
    let old_inode = fs::metadata(&config).unwrap().ino();
    fs::rename(&config, repo.join(".git/original-public-config")).unwrap();
    fs::copy(repo.join(".git/original-public-config"), &config).unwrap();
    assert_ne!(old_inode, fs::metadata(&config).unwrap().ino());
    assert!(SigningAttempt::start_discovered(resolved).is_err());
    no_material(&repo);
    report(
        &repo,
        json!({"query_pid":pid,"same_body_new_inode":true,"no_material":true}),
    );
}
#[test]
fn expired_original_query_cannot_become_ready_after_its_late_exit() {
    let repo = repo("principal-timeout");
    let (mut lookup, pid) = start_lookup(&repo);
    let state = lookup.poll(Instant::now() + Duration::from_secs(10));
    let exit = observe_unknown(&mut lookup);
    assert_eq!(
        state,
        PrincipalState::Unknown {
            pid: pid.unwrap(),
            reason: "principal_query_timeout"
        }
    );
    assert_eq!(exit, "Code(0)");
    assert_eq!(lookup.poll(Instant::now()), state);
    let failure = match lookup.resolve() {
        Ok(_) => panic!("unknown must never resolve"),
        Err(error) => error,
    };
    let original = failure.into_original();
    assert_eq!(original.state(), state);
    no_material(&repo);
    for suffix in ["pending", "stdout", "stderr"] {
        assert!(
            repo.join(format!(".git/chinwag-principal.{suffix}"))
                .is_file()
        );
    }
    report(
        &repo,
        json!({"query_pid":pid,"original_observed_exit":exit,"late_exit_never_grants_ready":true,"no_material":true}),
    );
}
#[test]
fn dropped_terminal_lookup_does_not_grant_adoption_or_unlock() {
    let repo = repo("principal-dropped");
    let (lookup, pid) = ready(&repo);
    drop(lookup);
    let before = fs::read(repo.join(".git/chinwag-principal.pending")).unwrap();
    let (second, second_pid) = start_lookup(&repo);
    assert_eq!(second_pid, None);
    assert_eq!(
        second.state(),
        PrincipalState::Refused {
            reason: "query_file_exclusive_create"
        }
    );
    assert_eq!(
        fs::read(repo.join(".git/chinwag-principal.pending")).unwrap(),
        before
    );
    no_material(&repo);
    report(
        &repo,
        json!({"query_pid":pid,"second_query_pid":second_pid,"no_adoption_or_cleanup":true,"no_material":true}),
    );
}
#[test]
fn changed_guard_prevents_any_query_file_release() {
    let repo = repo("principal-guard-change");
    let (lookup, pid) = ready(&repo);
    let pending = repo.join(".git/chinwag-principal.pending");
    fs::write(&pending, b"controlled replacement guard body").unwrap();
    assert!(lookup.resolve().is_err());
    assert_eq!(
        fs::read(&pending).unwrap(),
        b"controlled replacement guard body"
    );
    for suffix in ["stdout", "stderr"] {
        assert!(
            repo.join(format!(".git/chinwag-principal.{suffix}"))
                .is_file()
        );
    }
    no_material(&repo);
    report(
        &repo,
        json!({"query_pid":pid,"guard_changed":true,"all_query_names_retained":true,"no_material":true}),
    );
}
#[test]
fn occupied_query_namespace_never_spawns_a_child() {
    let repo = repo("principal-occupied");
    let guard = repo.join(".git/chinwag-principal.pending");
    fs::write(&guard, b"literal prior occupied namespace").unwrap();
    fs::set_permissions(&guard, fs::Permissions::from_mode(0o600)).unwrap();
    let (lookup, pid) = start_lookup(&repo);
    assert_eq!(pid, None);
    assert_eq!(
        lookup.state(),
        PrincipalState::Refused {
            reason: "query_file_exclusive_create"
        }
    );
    for suffix in ["stdout", "stderr"] {
        assert!(
            !repo
                .join(format!(".git/chinwag-principal.{suffix}"))
                .exists()
        );
    }
    assert_eq!(
        fs::read(guard).unwrap(),
        b"literal prior occupied namespace"
    );
    no_material(&repo);
    report(
        &repo,
        json!({"query_pid":pid,"occupied_guard_unchanged":true,"no_material":true}),
    );
}
#[test]
fn hardlinked_config_refuses_before_a_query_guard_or_child() {
    let repo = repo("principal-hardlink");
    fs::hard_link(
        repo.join(".git/config"),
        repo.join("public-config-hardlink"),
    )
    .unwrap();
    assert!(PrincipalLookup::start(&repo).is_err());
    assert!(!repo.join(".git/chinwag-principal.pending").exists());
    no_material(&repo);
    report(
        &repo,
        json!({"query_pid":null,"hardlinked_config_refused":true,"no_material":true}),
    );
}
