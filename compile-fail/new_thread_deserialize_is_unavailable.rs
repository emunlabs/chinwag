use chinwag_snapshot_session_private::replacement::ThreadStart;
fn main() {
    let _: ThreadStart =
        serde_json::from_str(r#"{"repo_id":"r","branch_ref":"HEAD","title":"decision"}"#).unwrap();
}
