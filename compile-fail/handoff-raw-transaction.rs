use chinwag_snapshot_session_private::replacement::WriteSession;
fn no_raw_transaction(s: WriteSession) {
    let _ = s.transaction("INSERT INTO messages VALUES('forged')");
}
fn main() {}
