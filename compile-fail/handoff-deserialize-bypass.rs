use chinwag_snapshot_session_private::replacement::HandoffRequest;
fn main() {
    let _: HandoffRequest = serde_json::from_str("{}").unwrap();
}
