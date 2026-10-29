//! An unregistered five-tool surface over existing operator-created servers.
//! This router neither opens nor compares their scopes. The operator chooses
//! each scope and must not also serve the inner VerifyServer on this session.

use super::EditServer;
use crate::{mcp::VerifyServer, send_owner::mcp::SendServer};
use rmcp::{
    RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ErrorData, Implementation,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    },
    service::RequestContext,
};
use serde_json::json;

const EDIT_NAMES: [&str; 3] = ["claim_task", "read_file", "write_file"];
const CARGO: &str = "run_cargo_test";
const SEND: &str = "send_git_bundle_over_iroh";

/// Routing only: child clones retain their existing shared state and scopes.
/// There is no aggregate shutdown or claim that all admission closes at once.
/// Retain the EditState handle and a SendServer clone; stop serving, fully poll
/// send shutdown, then shut down the claim before dropping the runtime.
/// Cancelling that send shutdown can still detach its running worker.
#[derive(Clone)]
pub struct FiveToolServer {
    edit: EditServer,
    verify: VerifyServer,
    send: SendServer,
    definitions: Vec<Tool>,
}

impl FiveToolServer {
    /// Consume already constructed servers without starting any cold job.
    /// No shared-workspace check or new permission is implied by composition.
    pub fn new(
        edit: EditServer,
        verify: VerifyServer,
        send: SendServer,
    ) -> Result<Self, &'static str> {
        let mut definitions = Vec::with_capacity(5);
        for name in EDIT_NAMES {
            definitions.push(edit.get_tool(name).ok_or("five_tool_definition")?);
        }
        definitions.push(verify.get_tool(CARGO).ok_or("five_tool_definition")?);
        definitions.push(send.get_tool(SEND).ok_or("five_tool_definition")?);
        Ok(Self {
            edit,
            verify,
            send,
            definitions,
        })
    }
}

impl ServerHandler for FiveToolServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("chinwag-seed-five-tool", "0.0.1"))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.definitions.clone()))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.definitions
            .iter()
            .find(|tool| tool.name == name)
            .cloned()
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        match request.name.as_ref() {
            "claim_task" | "read_file" | "write_file" => {
                self.edit.call_tool(request, context).await
            }
            CARGO => self.verify.call_tool(request, context).await,
            SEND => self.send.call_tool(request, context).await,
            _ => Ok(CallToolResult::structured_error(json!({"error":"unknown_tool"})).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EditRequest, read_source};
    use super::*;
    use crate::{
        send_owner::{Error, LocalNote, SendOwner},
        workspace::Workspace,
    };
    use chinwag_swarm::room::CLAIM_FILE;
    use rig_core::tool::DynamicTool;
    use rig_rmcp::McpConnection;
    use rmcp::{ServiceExt, model::ClientConfig};
    use std::{
        fs,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    #[tokio::test]
    async fn exact_five_routes_preserve_scopes_and_existing_owner_lifecycle() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let edit_root = tempfile::tempdir().unwrap();
            let source = edit_root.path().join(CLAIM_FILE);
            fs::create_dir_all(source.parent().unwrap()).unwrap();
            fs::write(&source, b"edit-only original\n").unwrap();
            let workspace = Arc::new(Workspace::open(edit_root.path()).unwrap());
            let edits = Arc::new(AtomicUsize::new(0));
            let observed_edits = edits.clone();
            // Test-only handler: no real claim service, witness or network.
            let edit = EditServer::from_handler(Arc::new(move |request| {
                let workspace = workspace.clone();
                let edits = edits.clone();
                Box::pin(async move {
                    edits.fetch_add(1, Ordering::SeqCst);
                    match request {
                        EditRequest::Claim => Ok(json!({"fixture":"claim_refused_no_grant"})),
                        EditRequest::Read(path) => read_source(&workspace, &path),
                        EditRequest::Write { .. } => Err("write_grant_unavailable"),
                    }
                })
            }))
            .unwrap();

            let cargo_root = tempfile::tempdir().unwrap();
            let root = cargo_root.path();
            for name in ["src", "target", "cache"] {
                fs::create_dir(root.join(name)).unwrap();
            }
            fs::write(root.join("README.md"), b"verify-only read scope\n").unwrap();
            fs::write(root.join("Cargo.toml"), "[package]\nname='five-tool-fixture'\nversion='0.0.0'\nedition='2024'\n").unwrap();
            fs::write(root.join("Cargo.lock"), "version = 4\n\n[[package]]\nname=\"five-tool-fixture\"\nversion=\"0.0.0\"\n").unwrap();
            let cargo_source = b"#[test] fn actual_assertion() { assert_eq!(6 * 7, 42); }\n";
            fs::write(root.join("src/lib.rs"), cargo_source).unwrap();
            let rustc = chinwag_test_fixtures::rustc();
            let verify = VerifyServer::open(
                root,
                vec!["README.md".into()],
                rustc.parent().unwrap(),
                &root.join("cache"),
                &root.join("target"),
            )
            .unwrap();
            let sends = Arc::new(AtomicUsize::new(0));
            let observed_sends = sends.clone();
            // Test-only synthetic job, not an exporter, blob, or peer delivery.
            let send = SendServer::new(SendOwner::from_job(async move {
                sends.fetch_add(1, Ordering::SeqCst);
                LocalNote::PublishedLocal
            }))
            .unwrap();
            let mut expected = EDIT_NAMES
                .iter()
                .map(|name| edit.get_tool(name).unwrap())
                .collect::<Vec<_>>();
            expected.push(verify.get_tool(CARGO).unwrap());
            expected.push(send.get_tool(SEND).unwrap());
            assert_ne!(
                serde_json::to_value(edit.get_tool("read_file")).unwrap(),
                serde_json::to_value(verify.get_tool("read_file")).unwrap()
            );
            let server = FiveToolServer::new(edit, verify, send.clone()).unwrap();
            let retained = server.clone();
            assert_eq!(observed_edits.load(Ordering::SeqCst), 0);
            assert_eq!(observed_sends.load(Ordering::SeqCst), 0);
            assert!(server.get_tool("shutdown").is_none());
            for definition in &expected {
                assert_eq!(
                    serde_json::to_value(server.get_tool(&definition.name)).unwrap(),
                    serde_json::to_value(Some(definition)).unwrap()
                );
            }
            let (client_io, server_io) = tokio::io::duplex(32768);
            let task = tokio::spawn(async move {
                server.serve(tokio::io::split(server_io)).await.unwrap().waiting().await.unwrap();
            });
            let client = McpConnection::new(ClientConfig::default().serve(tokio::io::split(client_io)).await.unwrap());
            let listed = client.peer().list_all_tools().await.unwrap();
            assert_eq!(serde_json::to_value(&listed).unwrap(), serde_json::to_value(&expected).unwrap());
            assert_eq!(listed.iter().map(|tool| tool.name.as_ref()).collect::<Vec<_>>(),
                vec!["claim_task", "read_file", "write_file", CARGO, SEND]);
            // Raw MCP calls bypass client-side schema guards. Every invalid
            // call must be refused by the actual child without a side effect.
            for (name, args) in [
                ("claim_task", json!({"nonce":"replacement"})),
                ("read_file", json!({"path":"README.md"})),
                ("read_file", json!({"path":CLAIM_FILE,"extra":true})),
                ("write_file", json!({"path":"README.md","expected":{"state":"absent"},"content":"no"})),
                (CARGO, json!({"command":"sh"})),
                (SEND, json!({"scope":"replacement"})),
                ("shutdown", json!({})),
            ] {
                let request = serde_json::from_value(json!({"name":name,"arguments":args})).unwrap();
                let result = client.peer().call_tool(request).await.unwrap();
                assert_eq!(result.is_error, Some(true), "{name}");
                if name == "shutdown" {
                    assert_eq!(result.structured_content, Some(json!({"error":"unknown_tool"})));
                }
            }
            assert_eq!(observed_edits.load(Ordering::SeqCst), 0);
            assert_eq!(observed_sends.load(Ordering::SeqCst), 0);
            assert_eq!(fs::read_dir(root.join("target")).unwrap().count(), 0);
            let mut dynamic = Vec::new();
            for tool in client.tools().await.unwrap() {
                dynamic.push(DynamicTool::try_from(tool).unwrap());
            }
            let get = |name| dynamic.iter().find(|tool| tool.name() == name).unwrap();
            let read = get("read_file").run(json!({"path":CLAIM_FILE})).await.unwrap();
            assert_eq!(read.as_json().unwrap()["content"], "edit-only original\n");
            let claim = get("claim_task").run(json!({})).await.unwrap();
            assert_eq!(claim.as_json(), Some(&json!({"fixture":"claim_refused_no_grant"})));
            let write = get("write_file").run(json!({"path":CLAIM_FILE,"expected":{"state":"absent"},"content":"no"})).await.unwrap_err();
            assert_eq!(write.model_output().as_json(), Some(&json!({"error":"write_grant_unavailable"})));
            let cargo = get(CARGO).run(json!({})).await.unwrap();
            let report = cargo.as_json().unwrap();
            assert_eq!(report["passed"], true);
            assert_eq!(report["check"]["success"], true);
            assert_eq!(report["test"]["success"], true);
            assert!(report["test"]["stdout"].as_str().unwrap().contains("1 passed"));
            let local = json!({"local_status":"published_local","authority":"local_only"});
            for _ in 0..2 {
                assert_eq!(get(SEND).run(json!({})).await.unwrap().as_json(), Some(&local));
            }
            assert_eq!(observed_edits.load(Ordering::SeqCst), 3);
            assert_eq!(observed_sends.load(Ordering::SeqCst), 1);
            assert_eq!(fs::read(&source).unwrap(), b"edit-only original\n");
            assert_eq!(fs::read(root.join("src/lib.rs")).unwrap(), cargo_source);
            assert_eq!(fs::read(root.join("README.md")).unwrap(), b"verify-only read scope\n");
            client.close().await;
            task.await.unwrap();
            assert_eq!(send.shutdown().await.unwrap(), Some(LocalNote::PublishedLocal));
            assert_eq!(send.shutdown().await.unwrap_err(), Error::Unavailable);
            // The retained composite still shares the now closed send state.
            let (client_io, server_io) = tokio::io::duplex(32768);
            let task = tokio::spawn(async move {
                retained.serve(tokio::io::split(server_io)).await.unwrap().waiting().await.unwrap();
            });
            let client = McpConnection::new(ClientConfig::default().serve(tokio::io::split(client_io)).await.unwrap());
            let result = client.peer().call_tool(serde_json::from_value(json!({"name":SEND,"arguments":{}})).unwrap()).await.unwrap();
            assert_eq!(result.is_error, Some(true));
            assert_eq!(result.structured_content, Some(json!({"error":"send_unavailable_no_retry"})));
            assert_eq!(observed_sends.load(Ordering::SeqCst), 1);
            client.close().await;
            task.await.unwrap();
            println!("five_tool_fixture exact5=true raw_refusals=true edit_read_only_route=true actual_cargo_pass=true synthetic_send_once=true shared_closed_send=true no_socket=true");
        })
        .await
        .unwrap();
    }
}
