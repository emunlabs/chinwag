//! Callable private repository context server with original per-request owners.
#![forbid(unsafe_code)]
#[cfg(feature = "private-http-probe")]
mod http_lifetime;
#[cfg(all(test, feature = "private-http-probe"))]
mod http_probe;
#[cfg(all(test, feature = "private-http-probe"))]
mod http_tests;
mod owner;
#[cfg(feature = "private-http-probe")]
pub mod repository_http;
mod wire;

use owner::{ContextServer, Owner};
use rmcp::{ServiceExt, transport::async_rw::AsyncRwTransport};
use std::{error::Error, path::PathBuf};

/// Blocks the calling thread until stdio ends and the original operations finish and the worker joins.
///
/// The supplied existing initialized repository and directories must remain exclusively owned
/// private fixtures. This does not adopt a user repository. Call outside Tokio;
/// the async server lifetime is deliberately private to this blocking entrypoint.
pub fn run_private_repository_stdio(path: PathBuf) -> Result<(), Box<dyn Error>> {
    run(path, false)
}

/// Serve an existing initialized local repository under held directory admission.
/// Requires an owned .git directory, private .chinwag and valid owned store.
/// No signing keys or Git config are read; this is local filesystem admission.
pub fn run_repository_stdio(path: PathBuf) -> Result<(), Box<dyn Error>> {
    run(path, true)
}

fn run(path: PathBuf, require_repository: bool) -> Result<(), Box<dyn Error>> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err("Private fixture stdio entrypoint must run outside a Tokio runtime".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve(path, require_repository))
}

async fn serve(path: PathBuf, require_repository: bool) -> Result<(), Box<dyn Error>> {
    let (server, owner): (ContextServer, Owner) = Owner::start(path, require_repository).await?;
    let transport = AsyncRwTransport::new(
        tokio::io::stdin(),
        wire::BoundedWriter::new(tokio::io::stdout()),
    )
    .with_max_line_length(wire::MAX_INPUT_BYTES);
    let outcome = async {
        server.serve(transport).await?.waiting().await?;
        Ok::<(), Box<dyn Error>>(())
    }
    .await;
    // EOF or transport failure both close the owned original operation and join.
    // A detached worker or Drop is not an explicit close receipt.
    let closed = owner.shutdown().await;
    closed?;
    outcome
}

#[cfg(feature = "private-loopback")]
pub mod loopback_listener;
#[cfg(all(test, feature = "private-loopback"))]
mod loopback_tests;
