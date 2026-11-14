//! Callable private repository and blind-org MCP server with original per-request owners.
#![forbid(unsafe_code)]
#[cfg(feature = "private-http-probe")]
mod http_lifetime;
#[cfg(all(test, feature = "private-http-probe"))]
mod http_probe;
#[cfg(all(test, feature = "private-http-probe"))]
mod http_tests;
mod owner;
pub mod profile;
#[cfg(test)]
mod profile_tests;
#[cfg(feature = "private-http-probe")]
pub mod repository_http;
mod wire;

pub use profile::{
    McpProfile, ProfileToolDescriptor, ToolAnnotationSpec, catalog_for_profile,
    rmcp_tools_for_profile,
};

use owner::{ContextServer, Owner};
use rmcp::{ServiceExt, transport::async_rw::AsyncRwTransport};
use serde_json::{Value, json};
use std::{error::Error, path::PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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

/// Serve the stateless `--profile blind-org` MCP surface over stdio with zero repository or filesystem access.
pub fn run_blind_org_stdio() -> Result<(), Box<dyn Error>> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err("Blind-org stdio entrypoint must run outside a Tokio runtime".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve_blind_org())
}

/// Dispatch stdio MCP execution according to an explicit `McpProfile`.
pub fn run_stdio_with_profile(
    profile: McpProfile,
    repository: Option<PathBuf>,
    require_repository: bool,
) -> Result<(), Box<dyn Error>> {
    match profile {
        McpProfile::BlindOrg => {
            if repository.is_some() {
                return Err("blind-org profile refuses local repository paths".into());
            }
            run_blind_org_stdio()
        }
        McpProfile::LocalRepository => {
            let path = repository
                .ok_or("local-repository profile requires an absolute repository path")?;
            run(path, require_repository)
        }
    }
}

/// Execute a live JSON-RPC 2.0 `initialize` + `tools/list` round-trip over an in-memory duplex
/// transport against `ContextServer` for `profile`, returning the wire `result` object (`{"tools":[...]}`).
pub async fn live_tools_list_wire_json_async(profile: McpProfile) -> Result<Value, Box<dyn Error>> {
    let server = ContextServer::new_catalog_only(profile)?;
    let (client_stream, server_stream) = tokio::io::duplex(65_536);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let transport = AsyncRwTransport::new(server_read, wire::BoundedWriter::new(server_write))
        .with_max_line_length(wire::MAX_INPUT_BYTES);

    let server_task = tokio::spawn(async move {
        let running = server.serve(transport).await.map_err(|e| e.to_string())?;
        running.waiting().await.map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    });

    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let mut lines = BufReader::new(client_read).lines();

    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "chinwag-drift-gate", "version": "1.0.0" }
        }
    });
    client_write
        .write_all(format!("{init_req}\n").as_bytes())
        .await?;
    client_write.flush().await?;
    let init_line = lines
        .next_line()
        .await?
        .ok_or("MCP server closed before initialize response")?;
    let init_resp: Value = serde_json::from_str(&init_line)?;
    if init_resp.get("error").is_some() {
        return Err(format!("MCP initialize failed: {init_resp}").into());
    }

    let initialized_note = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    client_write
        .write_all(format!("{initialized_note}\n").as_bytes())
        .await?;

    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    client_write
        .write_all(format!("{list_req}\n").as_bytes())
        .await?;
    client_write.flush().await?;

    let list_line = lines
        .next_line()
        .await?
        .ok_or("MCP server closed before tools/list response")?;
    let list_resp: Value = serde_json::from_str(&list_line)?;
    if let Some(err) = list_resp.get("error") {
        return Err(format!("MCP tools/list failed: {err}").into());
    }
    let result = list_resp
        .get("result")
        .cloned()
        .ok_or("MCP tools/list missing result object")?;

    client_write.shutdown().await?;
    drop(lines);
    drop(client_write);
    server_task
        .await
        .map_err(|e| format!("MCP server join error: {e}"))?
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    Ok(result)
}

/// Blocking wrapper around [`live_tools_list_wire_json_async`] for cross-crate drift verification.
pub fn live_tools_list_wire_json(profile: McpProfile) -> Result<Value, Box<dyn Error>> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err("live_tools_list_wire_json must run outside an active Tokio runtime".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(live_tools_list_wire_json_async(profile))
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

async fn serve_blind_org() -> Result<(), Box<dyn Error>> {
    let server = ContextServer::new_blind_org()?;
    let transport = AsyncRwTransport::new(
        tokio::io::stdin(),
        wire::BoundedWriter::new(tokio::io::stdout()),
    )
    .with_max_line_length(wire::MAX_INPUT_BYTES);
    server.serve(transport).await?.waiting().await?;
    Ok(())
}

#[cfg(feature = "private-loopback")]
pub mod loopback_listener;
#[cfg(all(test, feature = "private-loopback"))]
mod loopback_tests;
