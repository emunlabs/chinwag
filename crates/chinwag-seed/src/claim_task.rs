//! An explicitly selected, one-tool claim MCP mode. No file writes or replay.
use chinwag_swarm::room::{ClaimService, ClaimTaskError, ClaimTaskReport};
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
use std::{future::Future, sync::Arc};
use tokio::sync::Mutex;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimArgs {}

#[derive(Clone)]
pub struct ClaimServer {
    tool: DynamicTool,
    definition: Tool,
}
impl ClaimServer {
    pub fn new(service: Arc<Mutex<ClaimService>>) -> Result<Self, &'static str> {
        Self::from_handler(move || {
            let service = service.clone();
            async move { service.lock().await.claim_task().await }
        })
    }
    // Adapter seam only. Production always captures the one owned service;
    // tests exercise Rig/rmcp dispatch separately from real HTTPS core tests.
    fn from_handler<F, Fut>(handler: F) -> Result<Self, &'static str>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ClaimTaskReport, ClaimTaskError>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let schema = json!({"type":"object","properties":{},"additionalProperties":false});
        let tool = DynamicTool::new(
            ToolName::new("claim_task").map_err(|_| "claim tool definition")?,
            "Submit the operator's one PR-01 claim once, or read its stored outcome. Unresolved originals are not retried. Reports grant no write authority.",
            schema.clone(),
            move |arguments| {
                let handler = handler.clone();
                Box::pin(async move {
                    let _: ClaimArgs = serde_json::from_value(arguments).map_err(|_| {
                        ToolExecutionError::invalid_args("expected an empty object")
                    })?;
                    let report = handler()
                        .await
                        .map_err(|error| ToolExecutionError::refused(error.to_string()))?;
                    let value = serde_json::to_value(report).map_err(|_| {
                        ToolExecutionError::refused("claim report serialization failed")
                    })?;
                    Ok(ToolOutput::json(value))
                })
            },
        );
        let definition = Tool::new("claim_task",
            "Claim the fixed operator PR-01 slot or read its outcome. May create a signed network request; no write permit and no automatic retry.",
            Arc::new(schema.as_object().ok_or("claim tool schema")?.clone()))
            .with_annotations(ToolAnnotations::new().read_only(false).destructive(true).idempotent(false).open_world(true));
        Ok(Self { tool, definition })
    }
}
impl ServerHandler for ClaimServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("chinwag-seed-claim", "0.0.1"))
    }
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(vec![
            self.definition.clone(),
        ]))
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        (name == "claim_task").then(|| self.definition.clone())
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name != "claim_task" {
            return Ok(CallToolResult::structured_error(json!({"error":"unknown tool"})).into());
        }
        let result = match self
            .tool
            .run(Value::Object(request.arguments.unwrap_or_default()))
            .await
        {
            Ok(output) => match output.as_json() {
                Some(value) => CallToolResult::structured(value.clone()),
                None => CallToolResult::structured_error(json!({"error":"invalid claim output"})),
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
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[tokio::test]
    async fn rig_claim_adapter_lists_one_tool_and_refuses_model_configuration_before_handler() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
            let server = ClaimServer::from_handler(move || {
                let calls = calls.clone();
                async move { calls.fetch_add(1, Ordering::SeqCst); Ok(ClaimTaskReport::Refused {
                    status:403, code:"claim_policy".into(), cf_ray:"adapter-TEST".into(),
                }) }
            }).unwrap();
            assert!(server.get_tool("read_file").is_none());
            assert!(server.get_tool("run_cargo_test").is_none());
            let (client_io, server_io) = tokio::io::duplex(32768);
            let task = tokio::spawn(async move {
                let running = server.serve(tokio::io::split(server_io)).await.unwrap();
                running.waiting().await.unwrap();
            });
            let client = McpConnection::new(ClientConfig::default().serve(tokio::io::split(client_io)).await.unwrap());
            let mut tools = client.tools().await.unwrap();assert_eq!(tools.len(),1);
            let claim: DynamicTool = tools.pop().unwrap().try_into().unwrap();
            for args in [json!({"origin":"https://example.invalid/"}),json!({"nonce":"new"}),json!({"session":"x"}),
                json!({"key_path":"/"}),json!({"pr_id":"PR-02","files":[]}),json!({"journal":"/tmp"})] {
                assert!(claim.run(args).await.is_err());
            }
            assert_eq!(observed.load(Ordering::SeqCst),0);
            let result = claim.run(json!({})).await.unwrap();
            assert_eq!(result.as_json().unwrap(), &json!({"outcome":"refused","status":403,"code":"claim_policy","cf_ray":"adapter-TEST"}));
            assert_eq!(observed.load(Ordering::SeqCst),1);
            client.close().await;task.await.unwrap();
        }).await.unwrap();
    }
}
