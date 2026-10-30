//! Explicit SDK subprocess check; does not configure or invoke an AI client.
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::async_rw::AsyncRwTransport};
use serde_json::json;
use std::{process::Stdio, time::Duration};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 || !std::path::Path::new(&args[0]).is_absolute() {
        return Err("use ABSOLUTE_MCP_BINARY EXPLICIT_LOOPBACK_BUS_URL '#room'".into());
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut child = tokio::process::Command::new(&args[0])
            .args([
                "--bus-url",
                &args[1],
                "--allow-room",
                &args[2],
                "--lease-seconds",
                "60",
            ])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let pid = child.id();
        let transport = AsyncRwTransport::new(
            child.stdout.take().ok_or("stdout missing")?,
            child.stdin.take().ok_or("stdin missing")?,
        )
        .with_max_line_length(512 * 1024);
        let client = ().serve(transport).await?;
        let protocol = client
            .peer_info()
            .ok_or("missing initialized server")?
            .protocol_version
            .to_string();
        let tools = client.list_tools(None).await?;
        if tools.tools.len() != 1 || tools.tools[0].name != "chinwag_inbox_read" {
            return Err("unexpected tool catalogue".into());
        }
        let result = client
            .call_tool(
                CallToolRequestParams::new("chinwag_inbox_read").with_arguments(
                    json!({"limit":5})
                        .as_object()
                        .ok_or("arguments missing")?
                        .clone(),
                ),
            )
            .await?;
        if result.is_error == Some(true) {
            return Err("inbox read failed; no retry".into());
        }
        let value = result
            .structured_content
            .ok_or("structured inbox missing")?;
        if value["room"] != args[2]
            || value["authority"] != "owner_local_stdio_unattributed"
            || value["connector_signature_verification"] != false
            || value["grok_delivery_proven"] != false
        {
            return Err("inbox authority or source claims invalid".into());
        }
        let records = value["messages"].as_array().ok_or("messages missing")?;
        let ids: Vec<_> = records
            .iter()
            .map(|message| message["id"].clone())
            .collect();
        let summary = json!({"protocol":protocol,"child_pid":pid,"tool":"chinwag_inbox_read",
            "source":value["source"],"authority":value["authority"],"room":value["room"],
            "completeness":value["completeness"],"returned_count":value["returned_count"],
            "omitted_for_byte_limit":value["omitted_for_byte_limit"],"message_ids":ids,
            "connector_signature_verification":false,"grok_delivery_proven":false,
            "AI_client_configured":false,"model_invoked":false,"published":false});
        client.cancel().await?;
        let status = tokio::time::timeout(Duration::from_secs(3), child.wait()).await??;
        if !status.success() {
            return Err("owned MCP child did not exit successfully".into());
        }
        println!("{}", serde_json::to_string(&summary)?);
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}
