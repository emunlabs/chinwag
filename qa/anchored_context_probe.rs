//! Standalone private release consumer. Requires a separate final BEFORE QA scope.
use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::{
    self as session, SnapshotSession, ThreadContext, Value,
    replacement::{
        Completion, HandoffRequest, PinRequest, SeedMessage, SeedThread, WriteOwner, WriteSession,
    },
};
use serde_json::{Value as Json, json};
use std::{
    cell::Cell,
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn emit(value: Json) -> Result<()> {
    let mut w = std::io::stdout().lock();
    serde_json::to_writer(&mut w, &value)?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
}
fn report(c: &Completion) -> Json {
    let o = c.observation();
    json!({"written":matches!(c,Completion::Written(_)),"is_error":c.is_error(),"outcome":o.outcome(),"old_sha256":hex(&o.old_sha256()),"new_sha256":hex(&o.new_sha256()),"site":hex(&o.site_id()),"old_db_version":o.old_db_version(),"new_db_version":o.new_db_version(),"native_opens":o.native_before_file_release().opens,"native_checked_closes":o.native_before_file_release().checked_closes,"response":c.response()})
}
fn check(c: &Completion, dirty: bool, error: bool) {
    assert_eq!(matches!(c, Completion::Written(_)), dirty);
    assert_eq!(c.is_error(), error);
    let o = c.observation();
    assert_eq!(
        o.native_before_file_release().opens,
        o.native_before_file_release().checked_closes
    );
    if dirty {
        assert!(o.new_db_version() > o.old_db_version());
        assert_ne!(o.old_sha256(), o.new_sha256());
    } else {
        assert_eq!(o.old_db_version(), o.new_db_version());
        assert_eq!(o.old_sha256(), o.new_sha256());
    }
}
fn open(repo: &Path) -> Result<WriteSession> {
    Ok(WriteSession::from_owner(
        WriteOwner::acquire_existing_private_fixture(repo)?,
    )?)
}
fn seed_message(
    repo: &Path,
    id: &str,
    thread: &str,
    author: &str,
    role: &str,
    body: &str,
    time: i64,
) -> Result<Completion> {
    Ok(open(repo)?
        .prepare_seed_message_for_private_probe(SeedMessage::try_new(
            id.into(),
            thread.into(),
            author.into(),
            role.into(),
            body.into(),
            time,
        )?)?
        .commit(false)?)
}
fn pin(repo: &Path, id: &str, body: &str) -> Result<Completion> {
    Ok(open(repo)?
        .prepare_pin(
            PinRequest::try_new(
                id.into(),
                "thread-a".into(),
                "src/private.rs".into(),
                "symbol".into(),
                "private-source".into(),
                body.into(),
                2,
            )?,
            || false,
        )?
        .commit(false)?)
}
fn request(id: &str, thread: &str, note: &str) -> Result<HandoffRequest> {
    Ok(HandoffRequest::try_new(
        id.into(),
        thread.into(),
        "caller supplied label".into(),
        note.into(),
        3,
    )?)
}
fn handoff(repo: &Path, id: &str, thread: &str, note: &str) -> Result<Completion> {
    Ok(open(repo)?
        .prepare_handoff(request(id, thread, note)?, || false)?
        .commit(false)?)
}
fn context(repo: &Path) -> Result<ThreadContext> {
    let s = SnapshotSession::from_owner(
        ReadOwner::acquire_existing_private_fixture(repo).map_err(|e| e.reason)?,
    )?;
    let data = s.context("thread-a")?;
    s.finish()?;
    Ok(data)
}
fn message_body(repo: &Path, id: &str) -> Result<String> {
    let c = context(repo)?;
    let row = c
        .messages
        .iter()
        .find(|r| matches!(r.first(),Some(Value::Text(value)) if value==id))
        .ok_or("expected message")?;
    match &row[4] {
        Value::Text(body) => Ok(body.clone()),
        _ => Err("message text type".into()),
    }
}
fn base(repo: &Path) -> Result<Json> {
    session::initial_create::fresh_empty_store_image_for_private_fixture()?
        .begin_private_fixture(repo)?
        .finish()?;
    let thread = open(repo)?
        .prepare_seed_thread_for_private_probe(SeedThread::try_new(
            "thread-a".into(),
            "private-repo".into(),
            "refs/heads/private".into(),
            "Private fixture".into(),
            1,
            1,
        )?)?
        .commit(false)?;
    check(&thread, true, false);
    let message = seed_message(
        repo,
        "ordinary-a",
        "thread-a",
        "unverified-caller",
        "user",
        "hello λ\0private",
        1,
    )?;
    check(&message, true, false);
    let pin = pin(repo, "pin-a", "pin λ\0private")?;
    check(&pin, true, false);
    Ok(json!({"thread":report(&thread),"message":report(&message),"pin":report(&pin)}))
}
fn positive(repo: &Path) -> Result<Json> {
    let base = base(repo)?;
    let first = handoff(repo, "offer-a", "thread-a", "note λ\0one")?;
    check(&first, true, false);
    let original = first.response()["offer"].clone();
    assert_eq!(
        original["snapshot"]["messages"]
            .as_array()
            .ok_or("messages")?
            .len(),
        1
    );
    assert_eq!(
        original["snapshot"]["pins"].as_array().ok_or("pins")?.len(),
        1
    );
    assert_eq!(first.response()["delivery"], "not_attempted");
    assert_eq!(first.response()["author_authentication"], "none");
    assert_eq!(first.response()["authority"], "context_only_no_grants");
    let later_pin = pin(repo, "pin-b", "second pin")?;
    check(&later_pin, true, false);
    let later_message = seed_message(
        repo,
        "ordinary-b",
        "thread-a",
        "unverified-caller",
        "assistant",
        "later",
        4,
    )?;
    check(&later_message, true, false);
    let second = handoff(repo, "offer-b", "thread-a", "second note")?;
    check(&second, true, false);
    let next = &second.response()["offer"]["snapshot"];
    assert_eq!(next["messages"].as_array().ok_or("messages")?.len(), 2);
    assert_eq!(next["pins"].as_array().ok_or("pins")?.len(), 2);
    assert!(
        next["messages"]
            .as_array()
            .ok_or("messages")?
            .iter()
            .all(|m| m["role"] != "local_context_offer_v1")
    );
    let frozen_image = fs::read(repo.join(".chinwag/state.crdb"))?;
    let replay = handoff(repo, "offer-a", "thread-a", "note λ\0one")?;
    check(&replay, false, false);
    assert_eq!(replay.response()["offer"], original);
    assert_eq!(replay.response()["replayed"], true);
    let conflict = handoff(repo, "offer-a", "thread-a", "different")?;
    check(&conflict, false, true);
    let unknown = handoff(repo, "unknown", "missing-thread", "")?;
    check(&unknown, false, true);
    let calls = Cell::new(0);
    let cancelled = open(repo)?
        .prepare_handoff(request("cancelled", "thread-a", "")?, || {
            let c = calls.get();
            calls.set(c + 1);
            c > 0
        })?
        .commit(false)?;
    check(&cancelled, false, true);
    let discarded = open(repo)?
        .prepare_handoff(request("discarded", "thread-a", "")?, || false)?
        .commit(true)?;
    check(&discarded, false, true);
    let limit = handoff(repo, "stored-limit", "thread-a", &"\0".repeat(6_000))?;
    check(&limit, false, true);
    assert_eq!(fs::read(repo.join(".chinwag/state.crdb"))?, frozen_image);
    let too_long_id = "x".repeat(129);
    for bad in ["", "space id", "../file", too_long_id.as_str()] {
        assert!(
            HandoffRequest::try_new(
                bad.into(),
                "thread-a".into(),
                "target".into(),
                "note".into(),
                1
            )
            .is_err()
        );
    }
    assert!(
        HandoffRequest::try_new(
            "valid".into(),
            "thread-a".into(),
            "target".into(),
            "".into(),
            -1
        )
        .is_err()
    );
    let current = context(repo)?;
    assert_eq!(current.messages.len(), 4);
    assert_eq!(current.pins.len(), 2);
    Ok(
        json!({"base":base,"first":report(&first),"later_pin":report(&later_pin),"later_message":report(&later_message),"second":report(&second),"replay":report(&replay),"conflict":report(&conflict),"unknown":report(&unknown),"cancelled":report(&cancelled),"discarded":report(&discarded),"stored_limit":report(&limit),"flat_local_offers_only_no_network":true,"owned_readback_messages":4,"owned_readback_pins":2}),
    )
}
fn refusal(repo: &Path, kind: &str) -> Result<Json> {
    let _base = base(repo)?;
    if kind == "snapshot-limit" {
        let seeded = seed_message(
            repo,
            "big-context",
            "thread-a",
            "caller",
            "user",
            &"z".repeat(24_576),
            1,
        )?;
        check(&seeded, true, false);
    } else {
        let (thread, author, role, body, time) = match kind {
            "malformed-envelope" => (
                "thread-a",
                "",
                "local_context_offer_v1",
                "{broken".to_string(),
                3,
            ),
            "forged-author" => (
                "thread-a",
                "forged-author",
                "local_context_offer_v1",
                "{}".to_string(),
                3,
            ),
            "wrong-thread" => (
                "other-thread",
                "",
                "local_context_offer_v1",
                "{}".to_string(),
                3,
            ),
            "wrong-role" => ("thread-a", "", "ordinary", "{}".to_string(), 3),
            "wrong-time" => (
                "thread-a",
                "",
                "local_context_offer_v1",
                "{}".to_string(),
                4,
            ),
            "noncanonical" => {
                let _source = handoff(repo, "source-offer", "thread-a", "")?;
                let body = message_body(repo, "chinwag:local-handoff:v1:source-offer")?;
                assert_eq!(body.matches("\"id\":\"source-offer\"").count(), 1);
                let body = body.replace("\"id\":\"source-offer\"", "\"id\":\"refused\"") + " ";
                ("thread-a", "", "local_context_offer_v1", body, 3)
            }
            _ => return Err("unknown refusal case".into()),
        };
        let seeded = seed_message(
            repo,
            "chinwag:local-handoff:v1:refused",
            thread,
            author,
            role,
            &body,
            time,
        )?;
        check(&seeded, true, false);
    }
    let before = fs::read(repo.join(".chinwag/state.crdb"))?;
    let result = handoff(repo, "refused", "thread-a", "")?;
    check(&result, false, true);
    assert_eq!(fs::read(repo.join(".chinwag/state.crdb"))?, before);
    Ok(json!({"case":kind,"original_domain_refused_no_write":true,"result":report(&result)}))
}
fn replay_after_large_context(repo: &Path) -> Result<Json> {
    let _base = base(repo)?;
    let first = handoff(repo, "frozen", "thread-a", "original")?;
    check(&first, true, false);
    let original = first.response()["offer"].clone();
    let changed = seed_message(
        repo,
        "later-large",
        "thread-a",
        "caller",
        "user",
        &"z".repeat(24_576),
        4,
    )?;
    check(&changed, true, false);
    let image = fs::read(repo.join(".chinwag/state.crdb"))?;
    let replay = handoff(repo, "frozen", "thread-a", "original")?;
    check(&replay, false, false);
    assert_eq!(replay.response()["offer"], original);
    let new_offer = handoff(repo, "new-over-limit", "thread-a", "original")?;
    check(&new_offer, false, true);
    assert_eq!(fs::read(repo.join(".chinwag/state.crdb"))?, image);
    Ok(
        json!({"first":report(&first),"later_large":report(&changed),"replay":report(&replay),"new_offer_refused":report(&new_offer),"identity_lookup_precedes_current_overbudget_snapshot":true}),
    )
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [case, path] = args.as_slice() else {
        return Err("exact case and absolute private repository required".into());
    };
    let repo = PathBuf::from(path);
    if !repo.is_absolute() {
        return Err("absolute repository required".into());
    }
    let value = if case == "replay-large-context" {
        replay_after_large_context(&repo)?
    } else if case == "base" {
        base(&repo)?
    } else if case == "positive" {
        positive(&repo)?
    } else if let Some(kind) = case.strip_prefix("refusal:") {
        refusal(&repo, kind)?
    } else if case == "output-loss" {
        let _ = base(&repo)?;
        report(&handoff(&repo, "offer-a", "thread-a", "closed output")?)
    } else {
        return Err("unknown exact probe case".into());
    };
    emit(value)
}
fn main() {
    if let Err(error) = run() {
        eprintln!("private_anchored_context_probe: {error}");
        std::process::exit(1);
    }
}
