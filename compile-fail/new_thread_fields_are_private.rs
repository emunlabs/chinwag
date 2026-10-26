use chinwag_snapshot_session_private::replacement::ThreadStart;
fn main() {
    let _ = ThreadStart {
        repo_id: "r".into(),
        branch_ref: "HEAD".into(),
        title: "decision".into(),
    };
}
