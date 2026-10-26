//! The fixed-argument send tool, without a CLI mode or native registration.
//! The operator constructs one cold owner and retains a server clone through
//! shutdown. Request futures hold observers only. Shutdown closes admission
//! before draining that owner; cancelling shutdown can detach its worker, so
//! the service must poll shutdown to completion before dropping its runtime.

use super::{Error, LocalNote, SendOwner};
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
use std::sync::{Arc, Mutex};

const NAME: &str = "send_git_bundle_over_iroh";
type OwnerSlot = Arc<Mutex<Option<SendOwner>>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {}

/// Clones share the same owner and irreversible closed state. The model gets
/// only `{}`; it cannot construct an exporter, callback, scope, or shutdown.
#[derive(Clone)]
pub struct SendServer {
    owner: OwnerSlot,
    tool: DynamicTool,
    definition: Tool,
}

impl SendServer {
    /// Accept one operator-created owner, without starting its cold job.
    pub fn new(owner: SendOwner) -> Result<Self, &'static str> {
        let owner = Arc::new(Mutex::new(Some(owner)));
        let state = owner.clone();
        let schema = json!({"type":"object","properties":{},"additionalProperties":false});
        let description = "Start or observe the single operator-pinned send attempt. The first call starts the cold job; later calls observe it. No arguments, retry or recovery. A local report is not independent delivery, Cargo, model review or seal acceptance.";
        let tool = DynamicTool::new(
            ToolName::new(NAME).map_err(|_| "send_definition")?,
            description,
            schema.clone(),
            move |arguments| {
                let state = state.clone();
                Box::pin(async move {
                    if !arguments.is_object() {
                        return Err(ToolExecutionError::invalid_args("send_args"));
                    }
                    let _: Args = serde_json::from_value(arguments)
                        .map_err(|_| ToolExecutionError::invalid_args("send_args"))?;
                    let waiter = {
                        let slot = state.lock().map_err(|_| refused(Error::Unknown))?;
                        slot.as_ref()
                            .ok_or_else(|| refused(Error::Unavailable))?
                            .attach()
                            .map_err(refused)?
                    };
                    match waiter.wait().await.map_err(refused)? {
                        LocalNote::PublishedLocal => Ok(ToolOutput::json(json!({
                            "local_status":"published_local", "authority":"local_only"
                        }))),
                        LocalNote::FailedLocal => {
                            Err(ToolExecutionError::refused("send_failed_local_no_retry"))
                        }
                    }
                })
            },
        );
        let definition = Tool::new(
            NAME,
            description,
            Arc::new(schema.as_object().ok_or("send_schema")?.clone()),
        )
        .with_annotations(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(true)
                .idempotent(false)
                .open_world(true),
        );
        Ok(Self {
            owner,
            tool,
            definition,
        })
    }

    /// Close admission for every clone and await the existing owner. A cold
    /// owner starts nothing. A second shutdown refuses, never reports success
    /// for a drain it did not observe. No model tool exposes this method.
    pub async fn shutdown(&self) -> Result<Option<LocalNote>, Error> {
        let owner = {
            self.owner
                .lock()
                .map_err(|_| Error::Unknown)?
                .take()
                .ok_or(Error::Unavailable)?
        };
        owner.finish().await
    }
}

fn refused(error: Error) -> ToolExecutionError {
    ToolExecutionError::refused(match error {
        Error::Unavailable => "send_unavailable_no_retry",
        Error::Unknown => "send_unknown_no_retry",
    })
}

impl ServerHandler for SendServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("chinwag-seed-send", "0.0.1"))
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
        (name == NAME).then(|| self.definition.clone())
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name != NAME {
            return Ok(CallToolResult::structured_error(json!({"error":"unknown_tool"})).into());
        }
        let result = match self
            .tool
            .run(Value::Object(request.arguments.unwrap_or_default()))
            .await
        {
            Ok(output) => match output.as_json() {
                Some(value) => CallToolResult::structured(value.clone()),
                None => CallToolResult::structured_error(json!({"error":"send_output"})),
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
    use tokio::sync::oneshot;

    struct TagGuard(Arc<AtomicUsize>);

    impl Drop for TagGuard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn rejects_model_configuration_before_job_and_cold_shutdown_closes_all_clones() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let server = SendServer::new(SendOwner::from_job(async move {
            count.fetch_add(1, Ordering::SeqCst);
            LocalNote::PublishedLocal
        }))
        .unwrap();
        let clone = server.clone();
        assert!(server.get_tool(NAME).is_some());
        for name in [
            "shutdown",
            "claim_task",
            "read_file",
            "send_git_bundle_over_turn",
        ] {
            assert!(server.get_tool(name).is_none());
        }
        for args in [
            Value::Null,
            json!([]),
            json!({"path":"candidate.bundle"}),
            json!({"room":"new-room"}),
            json!({"run":"new-run"}),
            json!({"retry":true}),
            json!({"key":"other"}),
        ] {
            assert!(server.tool.run(args).await.is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(server.shutdown().await.unwrap(), None);
        assert!(clone.tool.run(json!({})).await.is_err());
        assert_eq!(clone.shutdown().await, Err(Error::Unavailable));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancelled_direct_call_leaves_worker_owned_for_real_mcp_observer() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let drops = Arc::new(AtomicUsize::new(0));
            let resource = drops.clone();
            let (started, observed) = oneshot::channel();
            let (release, gate) = oneshot::channel();
            let server = SendServer::new(SendOwner::from_job(async move {
                count.fetch_add(1, Ordering::SeqCst);
                let _guard = TagGuard(resource);
                started.send(()).unwrap();
                gate.await.unwrap();
                LocalNote::PublishedLocal
            }))
            .unwrap();
            let first = server.tool.clone();
            let pending = tokio::spawn(async move { first.run(json!({})).await });
            observed.await.unwrap();
            pending.abort();
            assert!(pending.await.unwrap_err().is_cancelled());
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            let handler = server.clone();
            let (client_io, server_io) = tokio::io::duplex(32768);
            let task = tokio::spawn(async move {
                handler
                    .serve(tokio::io::split(server_io))
                    .await
                    .unwrap()
                    .waiting()
                    .await
                    .unwrap();
            });
            let client = McpConnection::new(
                ClientConfig::default()
                    .serve(tokio::io::split(client_io))
                    .await
                    .unwrap(),
            );
            let tools = client.tools().await.unwrap();
            assert_eq!(tools.len(), 1);
            let tool = DynamicTool::try_from(tools.into_iter().next().unwrap()).unwrap();
            assert_eq!(tool.name(), NAME);
            release.send(()).unwrap();
            for _ in 0..2 {
                let output = tool.run(json!({})).await.unwrap();
                assert_eq!(
                    output.as_json().unwrap(),
                    &json!({
                        "local_status":"published_local", "authority":"local_only"
                    })
                );
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                server.shutdown().await.unwrap(),
                Some(LocalNote::PublishedLocal)
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(tool.run(json!({})).await.is_err());
            client.close().await;
            task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shutdown_closes_admission_before_waiting_for_existing_worker() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let (started, observed) = oneshot::channel();
            let (release, gate) = oneshot::channel();
            let server = SendServer::new(SendOwner::from_job(async move {
                count.fetch_add(1, Ordering::SeqCst);
                started.send(()).unwrap();
                gate.await.unwrap();
                LocalNote::PublishedLocal
            }))
            .unwrap();
            let tool = server.tool.clone();
            let request = tokio::spawn(async move { tool.run(json!({})).await });
            observed.await.unwrap();
            let close = server.clone();
            let drain = tokio::spawn(async move { close.shutdown().await });
            while server.owner.lock().unwrap().is_some() {
                tokio::task::yield_now().await;
            }
            assert!(!drain.is_finished());
            assert!(server.tool.run(json!({})).await.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            release.send(()).unwrap();
            request.await.unwrap().unwrap();
            assert_eq!(
                drain.await.unwrap().unwrap(),
                Some(LocalNote::PublishedLocal)
            );
            assert_eq!(server.shutdown().await, Err(Error::Unavailable));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn local_failure_stays_cached_and_is_a_tool_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let server = SendServer::new(SendOwner::from_job(async move {
            count.fetch_add(1, Ordering::SeqCst);
            LocalNote::FailedLocal
        }))
        .unwrap();
        for _ in 0..2 {
            let error = server.tool.run(json!({})).await.unwrap_err();
            assert!(error.to_string().contains("send_failed_local_no_retry"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            server.shutdown().await.unwrap(),
            Some(LocalNote::FailedLocal)
        );
    }

    #[tokio::test]
    async fn worker_panic_remains_unknown_without_reexecution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let server = SendServer::new(SendOwner::from_job(async move {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("intentional send MCP worker fault");
            }
            LocalNote::PublishedLocal
        }))
        .unwrap();
        for _ in 0..2 {
            let error = server.tool.run(json!({})).await.unwrap_err();
            assert!(error.to_string().contains("send_unknown_no_retry"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(server.shutdown().await, Err(Error::Unknown));
        assert!(server.tool.run(json!({})).await.is_err());
    }
}
