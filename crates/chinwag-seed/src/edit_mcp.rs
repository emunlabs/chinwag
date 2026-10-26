//! Explicit operator-selected claim/read/write mode, confined to one source path.
//! A single mutex covers the owned claim service and workspace. File publication
//! blocks that runtime and does not promise an atomic remote lease transaction.

pub mod five_tool;

use crate::{
    workspace::{ExpectedContent, MAX_FILE_BYTES, Workspace},
    write_gate::WritePermit,
};
use chinwag_swarm::room::{CLAIM_FILE, ClaimService, LeaseError};
use rig_core::{
    message::ToolName,
    tool::{DynamicTool, ToolExecutionError, ToolOutput},
};
use rmcp::{
    RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ErrorData, Implementation,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
        ToolAnnotations,
    },
    service::RequestContext,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{future::Future, path::Path, pin::Pin, sync::Arc};
use tokio::sync::Mutex;

pub struct EditState {
    claim: ClaimService,
    workspace: Workspace,
}

impl EditState {
    pub fn new(claim: ClaimService, workspace: Workspace) -> Self {
        Self { claim, workspace }
    }

    pub async fn shutdown(&mut self) {
        self.claim.shutdown().await;
    }

    pub(crate) async fn prepare_bundle_peer(
        &mut self,
    ) -> Result<(), chinwag_swarm::room::PeerError> {
        self.claim.prepare_peer_transport().await
    }

    pub(crate) fn bundle_peer(
        &self,
    ) -> Result<&chinwag_swarm::transport::DataPlane, chinwag_swarm::room::PeerError> {
        self.claim.peer_plane()
    }

    /// Passive bounded cache data, never a lease, freshness, or peer permit.
    pub(crate) fn bundle_peer_ips(&self) -> Option<chinwag_swarm::transport::BoundedIps> {
        self.claim.cached_peer_ips()
    }

    async fn execute(&mut self, request: EditRequest) -> Result<Value, &'static str> {
        match request {
            EditRequest::Claim => {
                serde_json::to_value(self.claim.claim_task().await.map_err(|_| "claim_error")?)
                    .map_err(|_| "claim_error")
            }
            EditRequest::Read(path) => read_source(&self.workspace, &path),
            EditRequest::Write {
                path,
                expected,
                content,
            } => {
                let path_ref = Path::new(&path);
                let witness = self
                    .claim
                    .authorize_local_write(path_ref)
                    .map_err(grant_error)?;
                let replaced = self
                    .workspace
                    .replace_if(
                        WritePermit::from_witness(witness),
                        path_ref,
                        expected,
                        content.as_bytes(),
                    )
                    .map_err(|error| match error {
                        crate::workspace::Error::Permit => "write_expired",
                        crate::workspace::Error::Preimage => "write_preimage",
                        crate::workspace::Error::Size => "write_size",
                        _ => "write_filesystem",
                    })?;
                Ok(json!({"path":path,"bytes":replaced.len,
                    "sha256":hex(&replaced.postimage_sha256),"publication":"renamed"}))
            }
        }
    }
}

fn grant_error(error: LeaseError) -> &'static str {
    match error {
        LeaseError::Expired => "write_expired",
        LeaseError::Path => "write_path",
        LeaseError::Unavailable | LeaseError::Session => "write_grant_unavailable",
    }
}

fn read_source(workspace: &Workspace, path: &str) -> Result<Value, &'static str> {
    let bytes = workspace
        .read_optional(Path::new(path))
        .map_err(|_| "read_filesystem")?
        .ok_or("read_absent")?;
    let sha256 = hex(&Sha256::digest(&bytes));
    let content = String::from_utf8(bytes).map_err(|_| "read_encoding")?;
    Ok(json!({"path":path,"content":content,"sha256":sha256}))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    path: String,
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
enum ExpectedArgs {
    Absent {},
    Sha256 { value: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    path: String,
    expected: ExpectedArgs,
    content: String,
}

enum EditRequest {
    Claim,
    Read(String),
    Write {
        path: String,
        expected: ExpectedContent,
        content: String,
    },
}

fn parse_request(name: &str, value: Value) -> Result<EditRequest, &'static str> {
    match name {
        "claim_task" => {
            let _: ClaimArgs = serde_json::from_value(value).map_err(|_| "claim_args")?;
            Ok(EditRequest::Claim)
        }
        "read_file" => {
            let args: ReadArgs = serde_json::from_value(value).map_err(|_| "read_args")?;
            if args.path != CLAIM_FILE {
                return Err("read_path");
            }
            Ok(EditRequest::Read(args.path))
        }
        "write_file" => {
            let args: WriteArgs = serde_json::from_value(value).map_err(|_| "write_args")?;
            if args.path != CLAIM_FILE {
                return Err("write_path");
            }
            if args.content.len() > MAX_FILE_BYTES {
                return Err("write_size");
            }
            let expected = match args.expected {
                ExpectedArgs::Absent {} => ExpectedContent::Absent,
                ExpectedArgs::Sha256 { value } => {
                    if value.len() != 64
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        return Err("write_hash");
                    }
                    let mut digest = [0; 32];
                    for (i, byte) in digest.iter_mut().enumerate() {
                        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)
                            .map_err(|_| "write_hash")?;
                    }
                    ExpectedContent::Sha256(digest)
                }
            };
            Ok(EditRequest::Write {
                path: args.path,
                expected,
                content: args.content,
            })
        }
        _ => Err("unknown_tool"),
    }
}

type HandlerFuture = Pin<Box<dyn Future<Output = Result<Value, &'static str>> + Send>>;
type Handler = Arc<dyn Fn(EditRequest) -> HandlerFuture + Send + Sync>;

#[derive(Clone)]
pub struct EditServer {
    tools: Vec<DynamicTool>,
    definitions: Vec<Tool>,
}

impl EditServer {
    pub fn new(state: Arc<Mutex<EditState>>) -> Result<Self, &'static str> {
        Self::from_handler(Arc::new(move |request| {
            let state = state.clone();
            Box::pin(async move { state.lock().await.execute(request).await })
        }))
    }

    // Private adapter seam; production captures only the one owned EditState.
    fn from_handler(handler: Handler) -> Result<Self, &'static str> {
        let path = json!({"type":"string","enum":[CLAIM_FILE]});
        let expected = json!({"oneOf":[
            {"type":"object","properties":{"state":{"const":"absent"}},"required":["state"],"additionalProperties":false},
            {"type":"object","properties":{"state":{"const":"sha256"},"value":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["state","value"],"additionalProperties":false}
        ]});
        let schemas = [
            (
                "claim_task",
                json!({"type":"object","properties":{},"additionalProperties":false}),
                "Submit the operator's original fixed claim once or read its stored outcome; no automatic retry.",
            ),
            (
                "read_file",
                json!({"type":"object","properties":{"path":path},"required":["path"],"additionalProperties":false}),
                "Read the one operator-scoped UTF-8 source file and its SHA-256.",
            ),
            (
                "write_file",
                json!({"type":"object","properties":{"path":path,"expected":expected,"content":{"type":"string","maxLength":MAX_FILE_BYTES}},"required":["path","expected","content"],"additionalProperties":false}),
                "Replace that source file only with this process's unexpired claim witness and matching preimage. Success means local rename, not a durable save or remote transaction.",
            ),
        ];
        let mut tools = Vec::new();
        let mut definitions = Vec::new();
        for (name, schema, description) in schemas {
            let handler = handler.clone();
            tools.push(DynamicTool::new(
                ToolName::new(name).map_err(|_| "edit_definition")?,
                description,
                schema.clone(),
                move |arguments| {
                    let handler = handler.clone();
                    Box::pin(async move {
                        let request = parse_request(name, arguments)
                            .map_err(ToolExecutionError::invalid_args)?;
                        let value = handler(request)
                            .await
                            .map_err(ToolExecutionError::refused)?;
                        Ok(ToolOutput::json(value))
                    })
                },
            ));
            definitions.push(
                Tool::new(
                    name,
                    description,
                    Arc::new(schema.as_object().ok_or("edit_schema")?.clone()),
                )
                .with_annotations(
                    ToolAnnotations::new()
                        .read_only(name == "read_file")
                        .destructive(name != "read_file")
                        .idempotent(name == "read_file")
                        .open_world(name == "claim_task"),
                ),
            );
        }
        Ok(Self { tools, definitions })
    }
}

impl ServerHandler for EditServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("chinwag-seed-edit", "0.0.1"))
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
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let Some(index) = self
            .definitions
            .iter()
            .position(|tool| tool.name == request.name)
        else {
            return Ok(CallToolResult::structured_error(json!({"error":"unknown_tool"})).into());
        };
        let result = match self.tools[index]
            .run(Value::Object(request.arguments.unwrap_or_default()))
            .await
        {
            Ok(output) => match output.as_json() {
                Some(value) => CallToolResult::structured(value.clone()),
                None => CallToolResult::structured_error(json!({"error":"edit_output"})),
            },
            Err(error) => CallToolResult::structured_error(json!({"error":error.to_string()})),
        };
        Ok(result.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rig_rmcp::McpConnection;
    use rmcp::{ServiceExt, model::ClientConfig};
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[tokio::test]
    async fn actual_adapter_lists_three_and_rejects_configuration_before_handler() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join(CLAIM_FILE);
            fs::create_dir_all(source.parent().unwrap()).unwrap(); fs::write(&source,b"original\n").unwrap();
            let workspace = Arc::new(Workspace::open(root.path()).unwrap());
            let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
            let server = EditServer::from_handler(Arc::new(move |request| {
                let workspace=workspace.clone(); let calls=calls.clone();
                Box::pin(async move { calls.fetch_add(1,Ordering::SeqCst); match request {
                    EditRequest::Read(path)=>read_source(&workspace,&path),
                    EditRequest::Claim=>Ok(json!({"outcome":"refused","status":403,"code":"claim_policy","cf_ray":"fixture-TEST"})),
                    EditRequest::Write {..}=>Err("write_grant_unavailable"),
                }})
            })).unwrap();
            assert!(server.get_tool("run_cargo_test").is_none());
            // Run the SERVER's DynamicTool directly as well as the real transport,
            // so client-side JSON-schema validation cannot hide a missing guard.
            for args in [
                json!({"path":CLAIM_FILE,"expected":{"state":"absent"},"content":"x","key":"no"}),
                json!({"path":".git/config","expected":{"state":"absent"},"content":"x"}),
                json!({"path":CLAIM_FILE,"expected":{"state":"absent","value":"extra"},"content":"x"}),
                json!({"path":CLAIM_FILE,"expected":{"state":"sha256","value":"A".repeat(64)},"content":"x"}),
                json!({"path":CLAIM_FILE,"expected":{"state":"sha256","value":"0".repeat(63)},"content":"x"}),
                json!({"path":CLAIM_FILE,"expected":{"state":"absent"},"content":"é".repeat(MAX_FILE_BYTES/2+1)}),
            ] { assert!(server.tools[2].run(args).await.is_err()); }
            assert!(server.tools[0].run(json!({"nonce":"new"})).await.is_err());
            assert!(server.tools[1].run(json!({"path":"./crates/chinwag-seed/src/main.rs"})).await.is_err());
            assert_eq!(observed.load(Ordering::SeqCst),0);
            let (client_io, server_io)=tokio::io::duplex(32768);
            let task=tokio::spawn(async move {server.serve(tokio::io::split(server_io)).await.unwrap().waiting().await.unwrap();});
            let client=McpConnection::new(ClientConfig::default().serve(tokio::io::split(client_io)).await.unwrap());
            let tools=client.tools().await.unwrap(); assert_eq!(tools.len(),3);
            let mut dynamic=Vec::new();for tool in tools {dynamic.push(DynamicTool::try_from(tool).unwrap());}
            let read=dynamic.iter().find(|tool| tool.name()=="read_file").unwrap();
            let result=read.run(json!({"path":CLAIM_FILE})).await.unwrap();
            assert_eq!(result.as_json().unwrap()["content"],"original\n");
            let write=dynamic.iter().find(|tool| tool.name()=="write_file").unwrap();
            assert!(write.run(json!({"path":CLAIM_FILE,"expected":{"state":"sha256","value":hex(&Sha256::digest(b"original\n"))},"content":"changed"})).await.is_err());
            assert_eq!(fs::read(&source).unwrap(),b"original\n");assert_eq!(fs::read_dir(source.parent().unwrap()).unwrap().count(),1);
            assert_eq!(observed.load(Ordering::SeqCst),2);
            client.close().await;task.await.unwrap();
        }).await.unwrap();
    }

    #[test]
    fn read_absence_is_distinct_from_existing_empty_utf8_source() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(CLAIM_FILE);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        assert_eq!(
            read_source(&workspace, CLAIM_FILE).unwrap_err(),
            "read_absent"
        );
        fs::write(path, []).unwrap();
        assert_eq!(read_source(&workspace, CLAIM_FILE).unwrap()["content"], "");
    }
}
