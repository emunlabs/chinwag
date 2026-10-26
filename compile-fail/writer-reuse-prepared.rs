use chinwag_snapshot_session_private::replacement::PreparedOutcome;
fn inspect(w: PreparedOutcome) {
    let _ = w.commit(false);
    let _ = w.commit(false);
}
fn main() {}
