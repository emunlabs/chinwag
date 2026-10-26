#![forbid(unsafe_code)]
use chinwag_confirmed_initial_private::{ConfirmedSigning, IntegrationFailure, SigningAttempt};
use chinwag_signing::{InitReceipt, PrivateDirectory, TxState};
use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::{
    NativeCounts, SnapshotSession, native_counts_for_private_probe,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    error::Error,
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const PRINCIPAL: &str = "fixture@chinwag.test";
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn native(opens: u64, checked_closes: u64) {
    assert_eq!(
        native_counts_for_private_probe(),
        NativeCounts {
            opens,
            checked_closes
        }
    );
}
fn public_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}
#[derive(Debug, PartialEq, Eq)]
struct KeyMetadata {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
fn key_metadata(path: &Path) -> Result<KeyMetadata> {
    let s = std::fs::symlink_metadata(path)?;
    assert!(s.is_file() && s.mode() & 0o7777 == 0o600 && s.nlink() == 1);
    Ok(KeyMetadata {
        dev: s.dev(),
        ino: s.ino(),
        uid: s.uid(),
        gid: s.gid(),
        mode: s.mode(),
        nlink: s.nlink(),
        size: s.len(),
        mtime: s.mtime(),
        mtime_nsec: s.mtime_nsec(),
        ctime: s.ctime(),
        ctime_nsec: s.ctime_nsec(),
    })
}
fn record_pid(receipt: InitReceipt, seen: &mut BTreeSet<u32>) {
    if let InitReceipt::Config { transaction, .. } = receipt
        && let TxState::Pending { pid } = transaction.state
        && seen.insert(pid)
    {
        println!("HANDOFF_ORIGINAL_GIT_PENDING pid={pid}");
    }
}
fn confirmed(repo: &Path, pending_roundtrip: bool) -> Result<ConfirmedSigning> {
    let mut attempt = SigningAttempt::start_fresh_private_fixture(repo, PRINCIPAL)?;
    let mut seen = BTreeSet::new();
    record_pid(attempt.receipt(), &mut seen);
    if pending_roundtrip {
        let original_pid = match attempt.receipt() {
            InitReceipt::Config { transaction, .. } => match transaction.state {
                TxState::Pending { pid } => pid,
                _ => return Err("Expected actual initial pending coordinator".into()),
            },
            _ => return Err("Expected original config coordinator".into()),
        };
        attempt = match attempt.confirm() {
            Err(failure) => {
                assert_eq!(failure.reason(), "original_child_pending");
                match failure.receipt() {
                    InitReceipt::Config { transaction, .. } => {
                        assert_eq!(transaction.state, TxState::Pending { pid: original_pid })
                    }
                    _ => return Err("Pending confirmation lost original coordinator".into()),
                }
                native(0, 0);
                assert!(!repo.join(".chinwag/state.crdb").exists());
                println!(
                    "HANDOFF_PENDING_CONFIRMATION_RETAINED original_pid={original_pid} native_opens=0 no_DB=true same_original=true"
                );
                failure.into_original()
            }
            Ok(_) => return Err("Pending original falsely confirmed".into()),
        };
    }
    loop {
        let receipt = attempt.receipt();
        record_pid(receipt, &mut seen);
        match receipt {
            InitReceipt::Config { transaction, .. } => match transaction.state {
                TxState::Pending { .. } => {
                    attempt.poll(Instant::now());
                    std::thread::sleep(Duration::from_millis(5));
                }
                TxState::Installed | TxState::Unchanged => break,
                TxState::ChildUnknown { pid } => {
                    println!(
                        "HANDOFF_UNKNOWN_ORIGINAL_RETAINED pid={pid} no_confirmation_or_retry=true"
                    );
                    // The bounded outer operator may yield uncertain; this same
                    // process retains and observes the original child, no signals.
                    loop {
                        if let Some(exit) = attempt.observe_child()? {
                            println!("HANDOFF_UNKNOWN_ORIGINAL_OBSERVED pid={pid} exit={exit}");
                            return Err("Original unknown observed; no handoff or replay".into());
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                state => return Err(format!("Original signing did not confirm: {state:?}").into()),
            },
            _ => return Err("Original signing material did not confirm".into()),
        }
    }
    let token = attempt.confirm()?;
    native(0, 0);
    assert!(!repo.join(".chinwag/state.crdb").exists());
    assert_eq!(token.public_key(), token.proof().public);
    assert_eq!(token.proof().namespace, "git");
    assert_eq!(token.proof().challenge, "chinwag-signing-selftest-v1");
    assert_eq!(
        hash(&std::fs::read(repo.join(".git/config"))?),
        token.config_sha256()
    );
    public_new(
        &repo.join("fixture-proof.sig"),
        token.proof().armored.as_bytes(),
    )?;
    public_new(
        &repo.join("fixture-challenge.txt"),
        token.proof().challenge.as_bytes(),
    )?;
    public_new(
        &repo.join("fixture-allowed-verifier.txt"),
        format!(
            "{PRINCIPAL} namespaces=\"git\" {}\n",
            token.proof().public_openssh
        )
        .as_bytes(),
    )?;
    let directory_meta = std::fs::symlink_metadata(repo.join(".chinwag"))?;
    let directory = PrivateDirectory::open(&repo.join(".chinwag"))?;
    let device = i32::try_from(directory_meta.dev())?;
    assert!(directory.matches_directory_identity(device, directory_meta.ino())?);
    assert!(!directory.matches_directory_identity(device, directory_meta.ino().wrapping_add(1))?);
    drop(directory);
    println!(
        "HANDOFF_DIRECTORY_IDENTITY_OBSERVATION same=true wrong_inode=false raw_descriptor_exposed=false"
    );
    let metadata = key_metadata(&repo.join(".chinwag/signer"))?;
    public_new(
        &repo.join("fixture-key-metadata.txt"),
        format!("{metadata:?}\n").as_bytes(),
    )?;
    println!(
        "HANDOFF_ORIGINAL_SIGNING_CONFIRMED pid={} state={:?} public={} config_sha256={} git_children={} native_opens=0",
        std::process::id(),
        token.config_state(),
        hex(&token.public_key()),
        hex(&token.config_sha256()),
        seen.len()
    );
    Ok(token)
}
fn expected_failure<T>(
    result: std::result::Result<T, IntegrationFailure>,
    completed: bool,
) -> Result<IntegrationFailure> {
    match result {
        Err(error) => {
            assert_eq!(error.original_store_callee_completed, completed);
            Ok(error)
        }
        Ok(_) => Err("Expected no integrated completion receipt".into()),
    }
}
fn positive(repo: &Path, unchanged: bool) -> Result<()> {
    let original_modes = [repo, &repo.join(".git"), &repo.join(".git/config")]
        .map(|path| std::fs::symlink_metadata(path).map(|m| m.mode() & 0o7777))
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()?;
    let token = confirmed(repo, !unchanged)?;
    assert_eq!(
        token.config_state(),
        if unchanged {
            TxState::Unchanged
        } else {
            TxState::Installed
        }
    );
    let pin = token.public_key();
    let config = std::fs::read(repo.join(".git/config"))?;
    let allowed = std::fs::read(repo.join(".chinwag/allowed_signers"))?;
    let key = key_metadata(&repo.join(".chinwag/signer"))?;
    let receipt = token.begin_initial()?.finish()?;
    native(1, 1);
    assert_eq!(receipt.public_key(), pin);
    assert_eq!(receipt.proof().public, pin);
    assert_eq!(receipt.config_sha256(), hash(&config));
    assert_eq!(
        receipt.config_state(),
        if unchanged {
            TxState::Unchanged
        } else {
            TxState::Installed
        }
    );
    assert_eq!(std::fs::read(repo.join(".git/config"))?, config);
    assert_eq!(
        std::fs::read(repo.join(".chinwag/allowed_signers"))?,
        allowed
    );
    assert_eq!(key_metadata(&repo.join(".chinwag/signer"))?, key);
    let owner = ReadOwner::acquire_existing_private_fixture(repo).map_err(|e| e.reason)?;
    let session = SnapshotSession::from_owner(owner)?;
    assert_eq!(session.site_id()?, receipt.store().site_id());
    assert_eq!(session.schema_objects()?.len(), 78);
    let context = session.context("absent-in-fresh-handoff")?;
    assert!(context.thread.is_empty() && context.messages.is_empty() && context.pins.is_empty());
    let read = session.finish()?;
    assert_eq!(read.file().sha256(), receipt.store().sha256());
    assert_eq!(read.file().bytes(), receipt.store().bytes());
    assert!(read.owner_verified_after_native_close());
    assert!(!repo.join(".chinwag/state.crdb.lock").exists());
    native(3, 3);
    let final_modes = [repo, &repo.join(".git"), &repo.join(".git/config")]
        .map(|path| std::fs::symlink_metadata(path).map(|m| m.mode() & 0o7777))
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(original_modes, final_modes);
    for (path, expected) in [
        (".chinwag", 0o700),
        (".chinwag/signer", 0o600),
        (".chinwag/allowed_signers", 0o600),
        (".chinwag/state.crdb", 0o600),
    ] {
        assert_eq!(
            std::fs::symlink_metadata(repo.join(path))?.mode() & 0o7777,
            expected
        );
    }
    println!(
        "POLICY_MODES_PRESERVED repo={:o} git={:o} config={:o} private_leaf=700 private_files=600",
        final_modes[0], final_modes[1], final_modes[2]
    );
    println!(
        "HANDOFF_POSITIVE pid={} state={:?} public={} config_sha256={} site={} store_sha256={} bytes={} wrapper_checked_fds={} create_checked_fds={} read_checked_fds={} native_opens=3 native_checked_closes=3 full_init_complete=false",
        std::process::id(),
        receipt.config_state(),
        hex(&pin),
        hex(&receipt.config_sha256()),
        hex(&receipt.store().site_id()),
        hex(&receipt.store().sha256()),
        receipt.store().bytes(),
        receipt.directly_owned_checked_fds(),
        receipt.store().checked_owner_fds(),
        read.file().checked_owner_fds()
    );
    Ok(())
}
fn controlled(repo: &Path, mode: &str) -> Result<()> {
    let token = confirmed(repo, false)?;
    let config = std::fs::read(repo.join(".git/config"))?;
    let allowed = std::fs::read(repo.join(".chinwag/allowed_signers"))?;
    let key = key_metadata(&repo.join(".chinwag/signer"))?;
    let error = match mode {
        "config-change" => {
            OpenOptions::new()
                .append(true)
                .open(repo.join(".git/config"))?
                .write_all(b"\n# controlled fixture mutation\n")?;
            let error = expected_failure(token.begin_initial(), false)?;
            native(0, 0);
            error
        }
        "key-change" => {
            OpenOptions::new()
                .append(true)
                .open(repo.join(".chinwag/signer"))?
                .write_all(b"\n")?;
            let error = expected_failure(token.begin_initial(), false)?;
            native(0, 0);
            error
        }
        "private-replace" => {
            std::fs::rename(repo.join(".chinwag"), repo.join("fixture-retained-private"))?;
            std::fs::create_dir(repo.join(".chinwag"))?;
            let error = expected_failure(token.begin_initial(), false)?;
            native(0, 0);
            assert_eq!(
                key_metadata(&repo.join("fixture-retained-private/signer"))?,
                key
            );
            assert_eq!(
                std::fs::read(repo.join("fixture-retained-private/allowed_signers"))?,
                allowed
            );
            error
        }
        "existing-target" => {
            public_new(&repo.join(".chinwag/state.crdb"), &[])?;
            let error = expected_failure(token.begin_initial(), false)?;
            native(1, 1);
            error
        }
        "allowed-after-begin" => {
            let owner = token.begin_initial()?;
            std::fs::write(
                repo.join(".chinwag/allowed_signers"),
                b"controlled-public-fixture-mutation\n",
            )?;
            let error = expected_failure(owner.finish(), false)?;
            native(1, 1);
            error
        }
        "post-store-cut" => {
            let owner = token.begin_initial()?;
            let error = expected_failure(owner.refuse_after_store_for_private_probe(), true)?;
            assert_eq!(
                error.reason,
                "controlled_after_store_callee_before_handoff_receipt"
            );
            native(1, 1);
            error
        }
        _ => return Err("Unknown controlled handoff case".into()),
    };
    let target = repo.join(".chinwag/state.crdb");
    let marker = repo.join(".chinwag/state.crdb.lock");
    if matches!(mode, "config-change" | "key-change" | "private-replace") {
        assert!(!target.exists() && !marker.exists());
    }
    if mode == "existing-target" {
        assert_eq!(std::fs::metadata(&target)?.len(), 0);
        assert!(!marker.exists());
    }
    if mode == "allowed-after-begin" {
        assert_eq!(std::fs::metadata(&target)?.len(), 0);
        assert!(marker.exists());
    }
    if mode == "post-store-cut" {
        assert_eq!(std::fs::metadata(&target)?.len(), 245760);
        assert!(!marker.exists());
    }
    if mode != "config-change" {
        assert_eq!(std::fs::read(repo.join(".git/config"))?, config);
    }
    if !matches!(mode, "key-change" | "private-replace") {
        assert_eq!(key_metadata(&repo.join(".chinwag/signer"))?, key);
    }
    if !matches!(mode, "private-replace" | "allowed-after-begin") {
        assert_eq!(
            std::fs::read(repo.join(".chinwag/allowed_signers"))?,
            allowed
        );
    }
    println!(
        "HANDOFF_EXPECTED_REFUSAL pid={} mode={mode} reason={} native_opens={} native_checked_closes={} original_store_callee_completed={} integrated_receipt=false real_OS_fault_injection=false",
        std::process::id(),
        error.reason,
        native_counts_for_private_probe().opens,
        native_counts_for_private_probe().checked_closes,
        error.original_store_callee_completed
    );
    Ok(())
}
fn invalid_principal(repo: &Path) -> Result<()> {
    let config = std::fs::read(repo.join(".git/config"))?;
    let attempt = SigningAttempt::start_fresh_private_fixture(repo, "invalid-principal")?;
    assert!(matches!(attempt.receipt(), InitReceipt::Refused { .. }));
    match attempt.confirm() {
        Err(failure) => {
            assert_eq!(failure.reason(), "original_material_not_confirmed");
            assert!(matches!(failure.receipt(), InitReceipt::Refused { .. }));
            let original = failure.into_original();
            assert!(matches!(original.receipt(), InitReceipt::Refused { .. }));
            drop(original);
        }
        Ok(_) => return Err("Invalid principal falsely confirmed".into()),
    }
    native(0, 0);
    assert!(!repo.join(".chinwag").exists());
    assert_eq!(std::fs::read(repo.join(".git/config"))?, config);
    println!(
        "HANDOFF_INVALID_PRINCIPAL pid={} original_attempt_retained=true private_directory_absent=true native_opens=0 native_checked_closes=0 integrated_receipt=false",
        std::process::id()
    );
    Ok(())
}
fn mode_change(repo: &Path, relative: &str, mode: u32) -> Result<()> {
    std::fs::set_permissions(repo.join(relative), std::fs::Permissions::from_mode(mode))?;
    Ok(())
}
fn policy_preflight(repo: &Path) -> Result<()> {
    let config = std::fs::read(repo.join(".git/config"))?;
    match SigningAttempt::start_fresh_private_fixture(repo, PRINCIPAL) {
        Err(error) => println!(
            "POLICY_PREFLIGHT_REFUSAL reason={} native_opens=0 signing_not_started=true",
            error.0
        ),
        Ok(_) => return Err("Unsafe preflight created signing attempt".into()),
    }
    assert_eq!(std::fs::read(repo.join(".git/config"))?, config);
    assert!(!repo.join(".chinwag/signer").exists());
    assert!(!repo.join(".chinwag/state.crdb").exists());
    native(0, 0);
    Ok(())
}
fn policy_late(repo: &Path, mode: &str) -> Result<()> {
    let token = confirmed(repo, false)?;
    let config = std::fs::read(repo.join(".git/config"))?;
    let is_after_begin = matches!(mode, "late-create-marker" | "late-create-data");
    let error = if is_after_begin {
        let owner = token.begin_initial()?;
        let path = if mode == "late-create-marker" {
            ".chinwag/state.crdb.lock"
        } else {
            ".chinwag/state.crdb"
        };
        mode_change(repo, path, 0o644)?;
        expected_failure(owner.finish(), false)?
    } else {
        let (path, bits) = match mode {
            "late-private" => (".chinwag", 0o755),
            "late-key" => (".chinwag/signer", 0o644),
            "late-allowed" => (".chinwag/allowed_signers", 0o644),
            "late-repo" => (".", 0o770),
            "late-git" => (".git", 0o775),
            "late-config" => (".git/config", 0o644),
            _ => return Err("Unknown late policy fixture".into()),
        };
        mode_change(repo, path, bits)?;
        expected_failure(token.begin_initial(), false)?
    };
    let count = u64::from(is_after_begin);
    native(count, count);
    assert_eq!(std::fs::read(repo.join(".git/config"))?, config);
    if is_after_begin {
        assert_eq!(
            std::fs::metadata(repo.join(".chinwag/state.crdb"))?.len(),
            0
        );
        assert!(repo.join(".chinwag/state.crdb.lock").exists());
    } else {
        assert!(!repo.join(".chinwag/state.crdb").exists());
        assert!(!repo.join(".chinwag/state.crdb.lock").exists());
    }
    println!(
        "POLICY_LATE_REFUSAL mode={mode} reason={} native_opens={count} native_checked_closes={count} empty_target_marker_retained={is_after_begin} integrated_receipt=false",
        error.reason
    );
    Ok(())
}
fn policy_read_refusal(repo: &Path) -> Result<()> {
    match ReadOwner::acquire_existing_private_fixture(repo) {
        Err(error) => println!(
            "POLICY_READ_REFUSAL reason={} native_opens=0 private_mode_not_relaxed=true",
            error.reason
        ),
        Ok(_) => return Err("Unsafe read policy falsely accepted".into()),
    }
    native(0, 0);
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = if let [_, mode, path] = args.as_slice() {
        let repo = Path::new(path);
        match mode.to_str() {
            Some("installed") => positive(repo, false),
            Some("unchanged") => positive(repo, true),
            Some("invalid-principal") => invalid_principal(repo),
            Some("policy-preflight") => policy_preflight(repo),
            Some("policy-read-refusal") => policy_read_refusal(repo),
            Some(mode) if mode.starts_with("late-") => policy_late(repo, mode),
            Some(mode) => controlled(repo, mode),
            None => Err("Private handoff fixture mode required".into()),
        }
    } else {
        Err("Private handoff fixture arguments required".into())
    };
    if let Err(error) = result {
        eprintln!("PRIVATE_HANDOFF_ERROR: {error}");
        std::process::exit(1);
    }
}
