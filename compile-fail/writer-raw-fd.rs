use chinwag_snapshot_session_private::replacement::WriteOwner;
use std::os::fd::AsFd;
fn inspect(w: WriteOwner) {
    let _ = w.as_fd();
}
fn main() {}
