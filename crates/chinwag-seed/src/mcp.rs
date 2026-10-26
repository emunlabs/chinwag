//! Separate operator-selected MCP modes for source reads and Cargo checks.
//! The read-only mode stays one tool. Cargo execution requires its own explicit
//! mode and fixed operator paths; it controls process lifetime, not OS access.
//! Claims, writes and bundle review remain unadvertised.

use crate::workspace::Workspace;
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
use std::{collections::BTreeSet, path::Path, sync::Arc};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Workspace(#[from] crate::workspace::Error),
    #[error("the read tool needs a nonempty explicit path allowlist")]
    Allowlist,
    #[error("the native read tool definition is invalid")]
    Definition,
    #[error(transparent)]
    Cargo(#[from] crate::cargo::Error),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    path: String,
}

#[derive(Clone)]
pub struct ReadServer {
    tool: DynamicTool,
    definition: Tool,
}

impl ReadServer {
    /// The operator supplies exact model-readable paths. Other files in the
    /// workspace, including ignored credentials, do not enter this allowlist.
    pub fn open(root: &Path, allowed: Vec<String>) -> Result<Self, Error> {
        if allowed.is_empty()
            || allowed.len() > 256
            || allowed
                .iter()
                .any(|name| name.is_empty() || name.len() > 4096)
        {
            return Err(Error::Allowlist);
        }
        let workspace = Arc::new(Workspace::open(root)?);
        let allowed = Arc::new(allowed.into_iter().collect::<BTreeSet<_>>());
        let schema = json!({
            "type":"object", "properties":{"path":{"type":"string","minLength":1,"maxLength":4096}},
            "required":["path"], "additionalProperties":false
        });
        let tool = DynamicTool::new(
            ToolName::new("read_file").map_err(|_| Error::Definition)?,
            "Read one exact operator-allowlisted UTF-8 source file; returns its SHA-256.",
            schema.clone(),
            move |arguments| {
                let workspace = workspace.clone();
                let allowed = allowed.clone();
                Box::pin(async move {
                    let args: ReadArgs = serde_json::from_value(arguments)
                        .map_err(|_| ToolExecutionError::invalid_args("expected only path"))?;
                    if !allowed.contains(&args.path) {
                        return Err(ToolExecutionError::refused(
                            "path is outside the read allowlist",
                        ));
                    }
                    let bytes = workspace
                        .read(Path::new(&args.path))
                        .map_err(|error| ToolExecutionError::refused(error.to_string()))?;
                    let digest = Sha256::digest(&bytes);
                    let content = String::from_utf8(bytes).map_err(|_| {
                        ToolExecutionError::invalid_args("source file is not UTF-8")
                    })?;
                    let sha256: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
                    Ok(ToolOutput::json(
                        json!({"path":args.path,"content":content,"sha256":sha256}),
                    ))
                })
            },
        );
        let definition = Tool::new(
            "read_file",
            "Read one exact operator-allowlisted source file through the Rig tool boundary.",
            Arc::new(schema.as_object().ok_or(Error::Definition)?.clone()),
        )
        .with_raw_output_schema(Arc::new(
            json!({"type":"object","properties":{
                "path":{"type":"string"},"content":{"type":"string"},
                "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}
            },"required":["path","content","sha256"],"additionalProperties":false})
            .as_object()
            .ok_or(Error::Definition)?
            .clone(),
        ))
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        );
        Ok(Self { tool, definition })
    }
}

impl ServerHandler for ReadServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("chinwag-seed-read", "0.0.1"))
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
        (name == "read_file").then(|| self.definition.clone())
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name != "read_file" {
            return Ok(CallToolResult::structured_error(json!({"error":"unknown tool"})).into());
        }
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let result = match self.tool.run(arguments).await {
            Ok(output) => match output.as_json() {
                Some(value) => CallToolResult::structured(value.clone()),
                None => CallToolResult::structured_error(json!({"error":"invalid tool output"})),
            },
            Err(error) => CallToolResult::structured_error(json!({"error":error.to_string()})),
        };
        Ok(result.into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoArgs {}

/// A separate opt-in server. It never changes the default read-only server.
#[derive(Clone)]
pub struct VerifyServer {
    read: ReadServer,
    cargo: DynamicTool,
    definition: Tool,
}

impl VerifyServer {
    /// Only the operator selects these paths. Cargo can execute workspace build
    /// scripts and tests; neither the tool nor its annotations promise a sandbox.
    pub fn open(
        root: &Path,
        allowed: Vec<String>,
        toolchain: &Path,
        cache: &Path,
        target: &Path,
    ) -> Result<Self, Error> {
        let read = ReadServer::open(root, allowed)?;
        let verifier = crate::cargo::CargoVerifier::new(root, toolchain, cache, target)?;
        let schema = json!({"type":"object","properties":{},"additionalProperties":false});
        let description = "Run fixed offline locked Cargo check then test in the operator workspace. No arguments. May execute build scripts/tests with local process permissions; not an OS sandbox.";
        let cargo = DynamicTool::new(
            ToolName::new("run_cargo_test").map_err(|_| Error::Definition)?,
            description,
            schema.clone(),
            move |arguments| {
                let verifier = verifier.clone();
                Box::pin(async move {
                    let _: CargoArgs = serde_json::from_value(arguments).map_err(|_| {
                        ToolExecutionError::invalid_args("expected an empty object")
                    })?;
                    let report = verifier
                        .verify()
                        .await
                        .map_err(|error| ToolExecutionError::refused(error.to_string()))?;
                    let passed = report.passed();
                    let command = |r: crate::cargo::CommandReport| {
                        json!({
                            "success":r.success,"exit_code":r.exit_code,
                            "stdout":String::from_utf8_lossy(&r.stdout),
                            "stderr":String::from_utf8_lossy(&r.stderr),
                            "output_encoding":"utf-8-lossy",
                            "elapsed_ms":r.elapsed_ms
                        })
                    };
                    Ok(ToolOutput::json(json!({
                        "passed":passed,"check":command(report.check),
                        "test":report.test.map(command)
                    })))
                })
            },
        );
        let definition = Tool::new(
            "run_cargo_test",
            description,
            Arc::new(schema.as_object().ok_or(Error::Definition)?.clone()),
        )
        .with_annotations(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(true)
                .idempotent(false)
                .open_world(true),
        );
        Ok(Self {
            read,
            cargo,
            definition,
        })
    }
}

impl ServerHandler for VerifyServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("chinwag-seed-verify", "0.0.1"))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(vec![
            self.read.definition.clone(),
            self.definition.clone(),
        ]))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        match name {
            "read_file" => Some(self.read.definition.clone()),
            "run_cargo_test" => Some(self.definition.clone()),
            _ => None,
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name == "read_file" {
            return self.read.call_tool(request, context).await;
        }
        if request.name != "run_cargo_test" {
            return Ok(CallToolResult::structured_error(json!({"error":"unknown tool"})).into());
        }
        let result = match self
            .cargo
            .run(Value::Object(request.arguments.unwrap_or_default()))
            .await
        {
            Ok(output) => match output.as_json() {
                Some(value) => CallToolResult::structured(value.clone()),
                None => CallToolResult::structured_error(json!({"error":"invalid tool output"})),
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
    use std::{fs, time::Duration};

    #[tokio::test]
    async fn rig_mcp_round_trip_reads_exact_allowlisted_bytes_and_refuses_other_paths() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let directory = tempfile::tempdir().unwrap();
            fs::write(directory.path().join("README.md"), b"pair-owned source\n").unwrap();
            fs::write(directory.path().join("unlisted.txt"), b"not model-readable").unwrap();
            let server = ReadServer::open(directory.path(), vec!["README.md".into()]).unwrap();
            let (client_io, server_io) = tokio::io::duplex(32_768);
            let server_task = tokio::spawn(async move {
                let running = server.serve(tokio::io::split(server_io)).await.unwrap();
                running.waiting().await.unwrap();
            });
            let client = McpConnection::new(
                ClientConfig::default()
                    .serve(tokio::io::split(client_io))
                    .await
                    .unwrap(),
            );
            let mut tools = client.tools().await.unwrap();
            assert_eq!(tools.len(), 1);
            let read: DynamicTool = tools.pop().unwrap().try_into().unwrap();
            let output = read.run(json!({"path":"README.md"})).await.unwrap();
            let value = output.as_json().unwrap();
            assert_eq!(value["content"], "pair-owned source\n");
            assert_eq!(
                value["sha256"],
                format!("{:x}", Sha256::digest(b"pair-owned source\n"))
            );
            for args in [
                json!({"path":"unlisted.txt"}),
                json!({"path":"../README.md"}),
                json!({"path":".Git/config"}),
                json!({"path":"README.md","extra":true}),
            ] {
                assert!(read.run(args).await.is_err());
            }
            client.close().await;
            server_task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn opt_in_cargo_mcp_runs_real_fixed_checks_and_refuses_model_configuration() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path();
            for name in ["src", "target", "cache"] {
                fs::create_dir(root.join(name)).unwrap();
            }
            fs::write(
                root.join("Cargo.toml"),
                "[package]\nname='mcp-cargo-fixture'\nversion='0.0.0'\nedition='2024'\n",
            )
            .unwrap();
            fs::write(
                root.join("Cargo.lock"),
                "version = 4\n\n[[package]]\nname=\"mcp-cargo-fixture\"\nversion=\"0.0.0\"\n",
            )
            .unwrap();
            let source = root.join("src/lib.rs");
            fs::write(
                &source,
                "#[test] fn real_assertion() { assert_eq!(6 * 7, 42); }\n",
            )
            .unwrap();
            let rustc = std::path::PathBuf::from(
                std::env::var_os("RUSTC").expect("test needs declared RUSTC"),
            );
            let server = VerifyServer::open(
                root,
                vec!["src/lib.rs".into()],
                rustc.parent().unwrap(),
                &root.join("cache"),
                &root.join("target"),
            )
            .unwrap();
            let (client_io, server_io) = tokio::io::duplex(32_768);
            let server_task = tokio::spawn(async move {
                let running = server.serve(tokio::io::split(server_io)).await.unwrap();
                running.waiting().await.unwrap();
            });
            let client = McpConnection::new(
                ClientConfig::default()
                    .serve(tokio::io::split(client_io))
                    .await
                    .unwrap(),
            );
            let tools = client.tools().await.unwrap();
            assert_eq!(tools.len(), 2);
            let cargo: DynamicTool = tools
                .into_iter()
                .find(|t| t.name() == "run_cargo_test")
                .unwrap()
                .try_into()
                .unwrap();
            let original = fs::read(&source).unwrap();
            for args in [
                json!({"command":"sh"}),
                json!({"workspace":"/"}),
                json!({"args":["--release"]}),
            ] {
                assert!(cargo.run(args).await.is_err());
                assert_eq!(fs::read(&source).unwrap(), original);
            }
            let output = cargo.run(json!({})).await.unwrap();
            let value = output.as_json().unwrap();
            assert_eq!(value["passed"], true);
            assert_eq!(value["check"]["success"], true);
            assert_eq!(value["test"]["success"], true);
            assert!(
                value["test"]["stdout"]
                    .as_str()
                    .unwrap()
                    .contains("1 passed")
            );
            fs::write(
                &source,
                "#[test] fn real_failure() { assert_eq!(6 * 7, 41); }\n",
            )
            .unwrap();
            let output = cargo.run(json!({})).await.unwrap();
            let value = output.as_json().unwrap();
            assert_eq!(value["passed"], false);
            assert_eq!(value["check"]["success"], true);
            assert_eq!(value["test"]["success"], false);
            assert!(
                value["test"]["stdout"]
                    .as_str()
                    .unwrap()
                    .contains("1 failed")
            );
            client.close().await;
            server_task.await.unwrap();
        })
        .await
        .unwrap();
    }
}
