//! Private release consumer; execute only under a separately reviewed one-shot operator.
use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::{
    self as session, SnapshotSession, Value,
    replacement::{
        Completion, Cut, PinRequest, PreparedOutcome, SeedThread, WriteOwner, WriteSession,
    },
};
use serde_json::{Value as Json, json};
use std::{
    cell::Cell,
    error::Error,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn emit(value: Json) -> Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn report(result: &Completion) -> Json {
    let o = result.observation();
    json!({"kind":o.kind(),"outcome":o.outcome(),"is_error":result.is_error(),
        "written":matches!(result,Completion::Written(_)),"site":hex(&o.site_id()),
        "old_sha256":hex(&o.old_sha256()),"new_sha256":hex(&o.new_sha256()),"bytes":o.bytes(),
        "old_db_version":o.old_db_version(),"new_db_version":o.new_db_version(),
        "generation":o.generation().map(|g|hex(&g)),"request_digest":hex(&o.request_digest()),
        "checked_owner_fds":o.checked_owner_fds(),"replacement_identities":o.replacement_identities(),"native_opens":o.native_before_file_release().opens,
        "native_checked_closes":o.native_before_file_release().checked_closes,"response":result.response()})
}
fn initial(repo: &Path) -> Result<()> {
    let receipt = session::initial_create::fresh_empty_store_image_for_private_fixture()?
        .begin_private_fixture(repo)?
        .finish()?;
    assert_eq!(receipt.bytes(), 245_760);
    Ok(())
}
fn open(repo: &Path) -> Result<WriteSession> {
    Ok(WriteSession::from_owner(
        WriteOwner::acquire_existing_private_fixture(repo)?,
    )?)
}
fn seed(repo: &Path) -> Result<Completion> {
    let request = SeedThread::try_new(
        "thread-a".into(),
        "private-repo".into(),
        "refs/heads/private".into(),
        "Private fixture".into(),
        1,
        1,
    )?;
    Ok(open(repo)?
        .prepare_seed_thread_for_private_probe(request)?
        .commit(false)?)
}
fn prepared(repo: &Path, id: &str, thread: &str, body: &str) -> Result<PreparedOutcome> {
    let request = PinRequest::try_new(
        id.into(),
        thread.into(),
        "src/private.rs".into(),
        "symbol-a".into(),
        "source-a".into(),
        body.into(),
        2,
    )?;
    Ok(open(repo)?.prepare_pin(request, || false)?)
}
fn check_completion(repo: &Path, result: &Completion, written: bool, error: bool) {
    assert_eq!(matches!(result, Completion::Written(_)), written);
    assert_eq!(result.is_error(), error);
    let o = result.observation();
    assert_eq!(
        o.native_before_file_release().opens,
        o.native_before_file_release().checked_closes
    );
    assert_eq!(
        o.checked_owner_fds(),
        repo.components().count() + if written { 5 } else { 3 }
    );
    if written {
        let ids = o
            .replacement_identities()
            .expect("actual original identity snapshots");
        assert_eq!(ids["old_linked"]["inode"], ids["old_detached"]["inode"]);
        assert_eq!(ids["old_linked"]["nlink"], 1);
        assert_eq!(ids["old_detached"]["nlink"], 0);
        assert_eq!(ids["old_linked"]["mtime"], ids["old_detached"]["mtime"]);
        assert_eq!(ids["staged"]["inode"], ids["renamed_target"]["inode"]);
        assert_eq!(ids["staged"]["mtime"], ids["renamed_target"]["mtime"]);
        assert_eq!(ids["renamed_target"]["nlink"], 1);
        assert_ne!(ids["old_linked"]["inode"], ids["renamed_target"]["inode"]);
        assert_eq!(ids["old_bytes_verified_unchanged"], true);
        assert!(o.new_db_version() > o.old_db_version());
        assert_ne!(o.old_sha256(), o.new_sha256());
    } else {
        assert_eq!(o.old_db_version(), o.new_db_version());
        assert_eq!(o.old_sha256(), o.new_sha256());
    }
}
fn read(repo: &Path, expected_pins: usize) -> Result<Json> {
    let session = SnapshotSession::from_owner(
        ReadOwner::acquire_existing_private_fixture(repo)
            .map_err(|e| format!("read acquire: {}", e.reason))?,
    )?;
    let site = session.site_id()?;
    let context = session.context("thread-a")?;
    assert_eq!(context.thread.len(), 1);
    assert_eq!(context.pins.len(), expected_pins);
    if expected_pins >= 1 {
        let row = context
            .pins
            .iter()
            .find(|r| matches!(r.first(),Some(Value::Text(id)) if id=="pin-a"))
            .ok_or("missing pin-a")?;
        assert_eq!(row[5], Value::Text("λ\0private-a".into()));
    }
    let receipt = session.finish()?;
    assert!(receipt.owner_verified_after_native_close());
    assert_eq!(
        receipt.file().checked_owner_fds(),
        repo.components().count() + 3
    );
    Ok(
        json!({"site":hex(&site),"pins":expected_pins,"sha256":hex(&receipt.file().sha256()),
        "checked_owner_fds":receipt.file().checked_owner_fds(),"native_checked_close_before_release":true}),
    )
}
fn positive(repo: &Path) -> Result<Json> {
    initial(repo)?;
    let seed = seed(repo)?;
    check_completion(repo, &seed, true, false);
    let first = prepared(repo, "pin-a", "thread-a", "λ\0private-a")?.commit(false)?;
    check_completion(repo, &first, true, false);
    let second = prepared(repo, "pin-b", "thread-a", "private-b")?.commit(false)?;
    check_completion(repo, &second, true, false);
    assert_eq!(
        first.observation().site_id(),
        second.observation().site_id()
    );
    assert_eq!(
        first.observation().new_sha256(),
        second.observation().old_sha256()
    );
    assert_eq!(
        first.observation().new_db_version(),
        second.observation().old_db_version()
    );
    let original = fs::read(repo.join(".chinwag/state.crdb"))?;
    let matched = prepared(repo, "pin-a", "thread-a", "λ\0private-a")?.commit(false)?;
    check_completion(repo, &matched, false, false);
    assert_eq!(matched.response()["replayed"], true);
    let conflict = prepared(repo, "pin-a", "thread-a", "different")?.commit(false)?;
    check_completion(repo, &conflict, false, true);
    let unknown = prepared(repo, "pin-new", "unknown-thread", "body")?.commit(false)?;
    check_completion(repo, &unknown, false, true);
    let count = Cell::new(0);
    let request = PinRequest::try_new(
        "pin-cancel".into(),
        "thread-a".into(),
        "x".into(),
        "s".into(),
        "c".into(),
        "body".into(),
        2,
    )?;
    let cancelled = open(repo)?
        .prepare_pin(request, || {
            let c = count.get();
            count.set(c + 1);
            c > 0
        })?
        .commit(false)?;
    check_completion(repo, &cancelled, false, true);
    let discarded = prepared(repo, "pin-discard", "thread-a", "body")?.commit(true)?;
    check_completion(repo, &discarded, false, true);
    let overbound = prepared(repo, "pin-big", "thread-a", &"\0".repeat(16_000))?.commit(false)?;
    check_completion(repo, &overbound, false, true);
    assert_eq!(fs::read(repo.join(".chinwag/state.crdb"))?, original);
    // Both mutual-exclusion directions using original owners in this process.
    let owner = ReadOwner::acquire_existing_private_fixture(repo)
        .map_err(|e| format!("read lock: {}", e.reason))?;
    assert!(WriteOwner::acquire_existing_private_fixture(repo).is_err());
    owner
        .finish_read()
        .map_err(|e| format!("read release: {}", e.reason))?;
    let owner = WriteOwner::acquire_existing_private_fixture(repo)?;
    assert!(ReadOwner::acquire_existing_private_fixture(repo).is_err());
    let no_write = WriteSession::from_owner(owner)?
        .prepare_pin(
            PinRequest::try_new(
                "pin-a".into(),
                "thread-a".into(),
                "src/private.rs".into(),
                "symbol-a".into(),
                "source-a".into(),
                "λ\0private-a".into(),
                2,
            )?,
            || false,
        )?
        .commit(false)?;
    check_completion(repo, &no_write, false, false);
    Ok(
        json!({"seed":report(&seed),"first":report(&first),"second":report(&second),
        "matched":report(&matched),"conflict":report(&conflict),"unknown":report(&unknown),
        "cancelled":report(&cancelled),"discarded":report(&discarded),"overbound":report(&overbound),
        "same_process_both_exclusions":true,"readback":read(repo,2)?}),
    )
}
fn cut(name: &str) -> Result<Cut> {
    Ok(match name {
        "native" => Cut::AfterNativeClose,
        "next-create" => Cut::AfterNextCreate,
        "next-write" => Cut::AfterNextWrite,
        "next-sync" => Cut::AfterNextSync,
        "intent" => Cut::AfterIntent,
        "rename" => Cut::AfterRename,
        "postcheck" => Cut::AfterPostcheck,
        "data-close" => Cut::AfterDataCloses,
        "intent-unlink" => Cut::AfterIntentUnlink,
        "intent-sync" => Cut::AfterIntentSync,
        "lock-close" => Cut::AfterLockClose,
        "lock-unlink" => Cut::AfterLockUnlink,
        "release-sync" => Cut::AfterReleaseSync,
        _ => return Err("unknown controlled cut".into()),
    })
}
fn failure(result: std::result::Result<Completion, session::replacement::Failure>) -> Result<Json> {
    let error = match result {
        Err(e) => e,
        Ok(_) => return Err("expected original refusal, got completion".into()),
    };
    Ok(
        json!({"no_completion":true,"reason":error.reason,"marker_created_no_retry":error.marker_created_no_retry,
        "staging_attempted_no_retry":error.staging_attempted_no_retry,"rename_attempted_no_retry":error.rename_attempted_no_retry}),
    )
}
fn hook(repo: PathBuf, kind: &str) -> Result<(Cut, Box<dyn FnOnce()>)> {
    let leaf = repo.join(".chinwag");
    let selected: (Cut, Box<dyn FnOnce()>) = match kind {
        "next" => (
            Cut::AfterNextSync,
            Box::new(move || {
                fs::OpenOptions::new()
                    .append(true)
                    .open(leaf.join("state.crdb.next"))
                    .expect("fixture next")
                    .write_all(b"x")
                    .expect("fixture append");
            }),
        ),
        "intent" => (
            Cut::AfterIntent,
            Box::new(move || {
                fs::write(leaf.join("state.crdb.intent"), b"foreign").expect("fixture intent");
            }),
        ),
        "lock" => (
            Cut::AfterNextSync,
            Box::new(move || {
                fs::write(leaf.join("state.crdb.lock"), b"foreign").expect("fixture lock");
            }),
        ),
        "source" => (
            Cut::AfterNextSync,
            Box::new(move || {
                let path = leaf.join("state.crdb");
                let mut bytes = fs::read(&path).expect("fixture source");
                bytes[100] ^= 1;
                fs::write(path, bytes).expect("fixture mutation");
            }),
        ),
        "source-mode" => (
            Cut::AfterNextSync,
            Box::new(move || {
                fs::set_permissions(leaf.join("state.crdb"), fs::Permissions::from_mode(0o644))
                    .expect("fixture mode");
            }),
        ),
        "next-name" => (
            Cut::AfterIntent,
            Box::new(move || {
                fs::rename(leaf.join("state.crdb.next"), leaf.join("held-next-renamed"))
                    .expect("fixture rename");
                fs::write(leaf.join("state.crdb.next"), b"foreign").expect("fixture substitute");
            }),
        ),
        "new-target" => (
            Cut::AfterRename,
            Box::new(move || {
                let path = leaf.join("state.crdb");
                let mut bytes = fs::read(&path).expect("fixture target");
                bytes[100] ^= 1;
                fs::write(path, bytes).expect("fixture target mutation");
            }),
        ),
        _ => return Err("unknown private fixture hook".into()),
    };
    Ok(selected)
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("expected exact case and absolute private fixture repo".into());
    }
    let case = &args[0];
    let repo = PathBuf::from(&args[1]);
    if !repo.is_absolute() {
        return Err("absolute private fixture required".into());
    }
    let result = if case == "positive" {
        positive(&repo)?
    } else if case == "base" {
        initial(&repo)?;
        report(&seed(&repo)?)
    } else if case == "pin" {
        report(&prepared(&repo, "pin-a", "thread-a", "λ\0private-a")?.commit(false)?)
    } else if case == "read" {
        read(&repo, 1)?
    } else if let Some(point) = case.strip_prefix("cut:") {
        initial(&repo)?;
        let _seed = seed(&repo)?;
        failure(
            prepared(&repo, "pin-a", "thread-a", "λ\0private-a")?
                .commit_with_controlled_cut_for_private_probe(cut(point)?),
        )?
    } else if let Some(kind) = case.strip_prefix("hook:") {
        initial(&repo)?;
        let _seed = seed(&repo)?;
        let prepared = prepared(&repo, "pin-a", "thread-a", "λ\0private-a")?;
        let (point, hook) = hook(repo.clone(), kind)?;
        failure(prepared.commit_with_hook_for_private_probe(point, hook))?
    } else if case == "output-loss" {
        initial(&repo)?;
        let _seed = seed(&repo)?;
        report(&prepared(&repo, "pin-a", "thread-a", "λ\0private-a")?.commit(false)?)
    } else if case == "hold-read" {
        let session = SnapshotSession::from_owner(
            ReadOwner::acquire_existing_private_fixture(&repo)
                .map_err(|e| format!("read acquire: {}", e.reason))?,
        )?;
        emit(json!({"ready":"read_owner_held"}))?;
        std::thread::sleep(Duration::from_secs(3));
        let receipt = session.finish()?;
        json!({"read_owner_finished":true,"sha256":hex(&receipt.file().sha256())})
    } else if case == "hold-write" {
        let prepared = prepared(&repo, "pin-a", "thread-a", "λ\0private-a")?;
        emit(json!({"ready":"prepared_writer_held_native_closed"}))?;
        std::thread::sleep(Duration::from_secs(3));
        report(&prepared.commit(false)?)
    } else if let Some(kind) = case.strip_prefix("drop:") {
        if !["owner", "session", "prepared"].contains(&kind) {
            return Err("unknown drop case".into());
        }
        initial(&repo)?;
        let _seed = seed(&repo)?;
        let before_image = fs::read(repo.join(".chinwag/state.crdb"))?;
        let before_counts = session::native_counts_for_private_probe();
        match kind {
            "owner" => drop(WriteOwner::acquire_existing_private_fixture(&repo)?),
            "session" => drop(open(&repo)?),
            "prepared" => drop(prepared(&repo, "pin-a", "thread-a", "λ\0private-a")?),
            _ => unreachable!(),
        }
        let after = session::native_counts_for_private_probe();
        let expected_opens = if kind == "owner" { 0 } else { 2 };
        let expected_closes = match kind {
            "owner" => 0,
            "session" => 1,
            _ => 2,
        };
        assert_eq!(after.opens - before_counts.opens, expected_opens);
        assert_eq!(
            after.checked_closes - before_counts.checked_closes,
            expected_closes
        );
        assert!(repo.join(".chinwag/state.crdb.lock").exists());
        assert_eq!(fs::read(repo.join(".chinwag/state.crdb"))?, before_image);
        json!({"dropped_original":kind,"no_completion":true,"source_unchanged":true,
            "native_opens_delta":expected_opens,"native_checked_closes_delta":expected_closes})
    } else if case == "expect-session-refusal" {
        let owner = WriteOwner::acquire_existing_private_fixture(&repo)?;
        match WriteSession::from_owner(owner) {
            Err(e) => {
                json!({"session_refused":true,"reason":e.reason,"marker_created_no_retry":e.marker_created_no_retry,
                "native_opens":session::native_counts_for_private_probe().opens,
                "native_checked_closes":session::native_counts_for_private_probe().checked_closes})
            }
            Ok(_) => return Err("unexpected session acceptance".into()),
        }
    } else if case == "expect-initial-refusal" {
        let image = session::initial_create::fresh_empty_store_image_for_private_fixture()?;
        match image.begin_private_fixture(&repo) {
            Err(e) => {
                json!({"initial_refused":true,"reason":e.reason,"marker_created_no_retry":e.marker_created_no_retry,
                "target_created_no_retry":e.target_created_no_retry,
                "native_opens":session::native_counts_for_private_probe().opens,
                "native_checked_closes":session::native_counts_for_private_probe().checked_closes})
            }
            Ok(_) => return Err("unexpected initializer acceptance".into()),
        }
    } else if case == "expect-write-refusal" {
        match WriteOwner::acquire_existing_private_fixture(&repo) {
            Err(e) => {
                json!({"acquire_refused":true,"reason":e.reason,"marker_created_no_retry":e.marker_created_no_retry,"native_opens":session::native_counts_for_private_probe().opens})
            }
            Ok(_) => return Err("unexpected write acquisition".into()),
        }
    } else if case == "expect-read-refusal" {
        match ReadOwner::acquire_existing_private_fixture(&repo) {
            Err(e) => {
                json!({"acquire_refused":true,"reason":e.reason,"marker_created_no_retry":e.marker_created_no_retry,"native_opens":session::native_counts_for_private_probe().opens})
            }
            Ok(_) => return Err("unexpected read acquisition".into()),
        }
    } else {
        return Err("unknown private probe case".into());
    };
    emit(result)
}
fn main() {
    if let Err(error) = run() {
        eprintln!("private_writer_probe: {error}");
        std::process::exit(1);
    }
}
