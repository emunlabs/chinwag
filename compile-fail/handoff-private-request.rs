use chinwag_snapshot_session_private::replacement::HandoffRequest;
fn no_private_request(r: HandoffRequest) {
    let _ = r.record;
}
fn main() {}
