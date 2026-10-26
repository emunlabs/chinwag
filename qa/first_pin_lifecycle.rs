//! Root-only external lifecycle consumer, normal feature API, no SQL or fixture seeding.
#![forbid(unsafe_code)]
use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::{
    SnapshotSession, native_counts_for_private_probe,
    replacement::{Completion, PinRequest, ThreadStart, WriteOwner, WriteSession},
};
use serde_json::{Value, json};
use std::{cell::Cell, error::Error, io::Write, path::Path};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn report(c: &Completion) -> Value {
    let o = c.observation();
    json!({"written":matches!(c, Completion::Written(_)),"is_error":c.is_error(),"outcome":o.outcome(),"old_sha256":hex(&o.old_sha256()),"new_sha256":hex(&o.new_sha256()),"old_version":o.old_db_version(),"new_version":o.new_db_version(),"request_digest":hex(&o.request_digest()),"native_opens":o.native_before_file_release().opens,"native_checked_closes":o.native_before_file_release().checked_closes,"checked_owner_fds":o.checked_owner_fds(),"response":c.response()})
}
fn check(c: &Completion, written: bool, error: bool) {
    assert_eq!(matches!(c, Completion::Written(_)), written);
    assert_eq!(c.is_error(), error);
    let o = c.observation();
    assert_eq!(
        o.native_before_file_release().opens,
        o.native_before_file_release().checked_closes
    );
    if written {
        assert!(o.new_db_version() > o.old_db_version());
        assert_ne!(o.old_sha256(), o.new_sha256());
    } else {
        assert_eq!(o.new_db_version(), o.old_db_version());
        assert_eq!(o.old_sha256(), o.new_sha256());
    }
}
fn request(wide: bool) -> Result<PinRequest> {
    Ok(PinRequest::try_new(
        "first-pin".into(),
        "thread-a".into(),
        "src/private.rs".into(),
        "caller-symbol".into(),
        "caller-source".into(),
        "Private lifecycle decision λ\0".into(),
        7,
    )?
    .with_new_thread(ThreadStart::try_new(
        "caller-repo".into(),
        "refs/heads/main".into(),
        if wide {
            "\0".repeat(20000)
        } else {
            "Private first decision".into()
        },
    )?))
}
fn open(repo: &Path) -> Result<WriteSession> {
    Ok(WriteSession::from_owner(
        WriteOwner::acquire_existing_private_fixture(repo)?,
    )?)
}
fn view(repo: &Path) -> Result<Value> {
    let s = SnapshotSession::from_owner(
        ReadOwner::acquire_existing_private_fixture(repo)
            .map_err(|e| format!("read acquire: {}", e.reason))?,
    )?;
    let c = s.context("thread-a")?;
    let counts = json!({"threads":c.thread.len(),"pins":c.pins.len(),"messages":c.messages.len()});
    let r = s.finish()?;
    assert!(r.owner_verified_after_native_close());
    assert_eq!(
        r.native_before_file_release().opens,
        r.native_before_file_release().checked_closes
    );
    Ok(counts)
}
fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let [case, path] = args.as_slice() else {
        return Err("exact case and absolute owned repository required".into());
    };
    let repo = Path::new(path);
    if !repo.is_absolute() {
        return Err("absolute repository required".into());
    }
    let calls = Cell::new(0_u32);
    let original = match case.as_str() {
        "cancel-at-entry" => {
            let c = open(repo)?
                .prepare_pin(request(false)?, || {
                    calls.set(calls.get() + 1);
                    true
                })?
                .commit(false)?;
            assert_eq!(calls.get(), 1);
            c
        }
        "cancel-after-decision-before-COMMIT" => {
            let c = open(repo)?
                .prepare_pin(request(false)?, || {
                    calls.set(calls.get() + 1);
                    calls.get() == 2
                })?
                .commit(false)?;
            assert_eq!(calls.get(), 2);
            c
        }
        "discard-before-staging" => {
            let prepared = open(repo)?.prepare_pin(request(false)?, || false)?;
            let n = native_counts_for_private_probe();
            assert_eq!(n.opens, n.checked_closes);
            prepared.commit(true)?
        }
        "full-response-limit" => open(repo)?
            .prepare_pin(request(true)?, || false)?
            .commit(false)?,
        "positive" | "output-loss" => open(repo)?
            .prepare_pin(request(false)?, || false)?
            .commit(false)?,
        _ => return Err("unknown exact lifecycle case".into()),
    };
    let wrote = matches!(case.as_str(), "positive" | "output-loss");
    check(&original, wrote, !wrote);
    if !wrote {
        assert_eq!(
            original.observation().outcome(),
            if case == "full-response-limit" {
                "response_limit"
            } else {
                "cancelled_before_staging"
            }
        );
    }
    let retry = if case == "positive" {
        let c = open(repo)?
            .prepare_pin(request(false)?, || false)?
            .commit(false)?;
        check(&c, false, false);
        assert_eq!(c.response(), &{
            let mut r = original.response().clone();
            r["replayed"] = Value::Bool(true);
            r
        });
        Some(report(&c))
    } else {
        None
    };
    let current = view(repo)?;
    assert_eq!(
        current,
        json!({"threads":usize::from(wrote),"pins":usize::from(wrote),"messages":0})
    );
    let data = json!({"case":case,"callback_calls":calls.get(),"original":report(&original),"retry":retry,"current_owned_read":current,"normal_feature_API_no_SQL_or_seed":true});
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &data)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("first_pin_lifecycle_probe: {e}");
        std::process::exit(1);
    }
}
