//! Read-only external release QA driver; never initializes or signs.
#![forbid(unsafe_code)]
use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::SnapshotSession;
use std::{error::Error, path::Path};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    let [_, repo] = args.as_slice() else {
        return Err("Private read-only QA fixture argument required".into());
    };
    let owner = ReadOwner::acquire_existing_private_fixture(Path::new(repo))
        .map_err(|error| error.reason)?;
    let session = SnapshotSession::from_owner(owner)?;
    let site = session.site_id()?;
    let objects = session.schema_objects()?.len();
    if objects != 78 {
        return Err("Unexpected schema object count".into());
    }
    let context = session.context("absent-in-fresh-CLI-QA")?;
    if !context.thread.is_empty() || !context.messages.is_empty() || !context.pins.is_empty() {
        return Err("Fresh CLI fixture context is not empty".into());
    }
    let receipt = session.finish()?;
    if !receipt.owner_verified_after_native_close() {
        return Err("Native owner close not confirmed".into());
    }
    println!(
        "CLI_SNAPSHOT_READ site={} schema_objects={objects} sha256={} bytes={} checked_owner_fds={} native_close_before_file_release=true",
        hex(&site),
        hex(&receipt.file().sha256()),
        receipt.file().bytes(),
        receipt.file().checked_owner_fds()
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("PRIVATE_CLI_READ_QA_ERROR: {error}");
        std::process::exit(1);
    }
}
