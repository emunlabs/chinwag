#![forbid(unsafe_code)]

use crate::{
    McpProfile, catalog_for_profile, live_tools_list_wire_json, live_tools_list_wire_json_async,
    owner::ContextServer, wire,
};
use rmcp::{ServiceExt, transport::async_rw::AsyncRwTransport};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const FORBIDDEN_BLIND_TOKENS: &[&str] = &[
    "read_thread",
    "pin_context",
    "handoff",
    "file_path",
    "source_commit",
    "lease",
    "patch",
    "diff",
    "worktree",
];

#[test]
fn every_profile_tool_declares_all_four_explicit_annotations_on_the_wire() {
    for profile in McpProfile::ALL {
        let catalog = catalog_for_profile(profile);
        assert!(!catalog.is_empty());

        let wire_result = live_tools_list_wire_json(profile).expect("live tools/list");
        let wire_tools = wire_result["tools"]
            .as_array()
            .expect("tools array on wire");
        assert_eq!(wire_tools.len(), catalog.len());

        for (expected, wire_tool) in catalog.iter().zip(wire_tools.iter()) {
            assert_eq!(wire_tool["name"], expected.name);
            assert_eq!(wire_tool["description"], expected.description);
            assert_eq!(wire_tool["inputSchema"], expected.input_schema);

            let ann = wire_tool["annotations"]
                .as_object()
                .expect("explicit annotations object required on wire");
            assert_eq!(
                ann.get("readOnlyHint").and_then(Value::as_bool),
                Some(expected.annotations.read_only_hint),
                "missing or mismatched readOnlyHint on {}",
                expected.name
            );
            assert_eq!(
                ann.get("destructiveHint").and_then(Value::as_bool),
                Some(expected.annotations.destructive_hint),
                "missing or mismatched destructiveHint on {}",
                expected.name
            );
            assert_eq!(
                ann.get("idempotentHint").and_then(Value::as_bool),
                Some(expected.annotations.idempotent_hint),
                "missing or mismatched idempotentHint on {}",
                expected.name
            );
            assert_eq!(
                ann.get("openWorldHint").and_then(Value::as_bool),
                Some(expected.annotations.open_world_hint),
                "missing or mismatched openWorldHint on {}",
                expected.name
            );
            assert!(
                !expected.justification.trim().is_empty(),
                "tool {} must carry reviewer justification",
                expected.name
            );
        }
    }
}

#[test]
fn blind_org_profile_exposes_zero_source_file_or_lease_tools() {
    let wire_result =
        live_tools_list_wire_json(McpProfile::BlindOrg).expect("blind-org tools/list");
    let serialized = serde_json::to_string(&wire_result).expect("serialize tools/list");
    let lowered = serialized.to_ascii_lowercase();
    for forbidden in FORBIDDEN_BLIND_TOKENS {
        assert!(
            !lowered.contains(forbidden),
            "blind-org tools/list leaked forbidden token `{forbidden}`: {serialized}"
        );
    }

    let tools = wire_result["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "chinwag_org_status",
            "chinwag_run_status",
            "chinwag_board_status",
            "chinwag_credit_ledger",
            "chinwag_docs_search",
            "chinwag_docs_get",
        ]
    );
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], json!(true));
        assert_eq!(tool["annotations"]["destructiveHint"], json!(false));
        assert_eq!(tool["annotations"]["idempotentHint"], json!(true));
        assert_eq!(tool["annotations"]["openWorldHint"], json!(false));
    }
}

#[tokio::test]
async fn blind_org_executes_blind_queries_and_refuses_local_tools_and_interpolation() {
    let list = live_tools_list_wire_json_async(McpProfile::BlindOrg)
        .await
        .expect("async tools/list");
    assert_eq!(list["tools"].as_array().unwrap().len(), 6);

    let server = ContextServer::new_blind_org().expect("blind-org server");
    let (client_stream, server_stream) = tokio::io::duplex(65_536);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let transport = AsyncRwTransport::new(server_read, wire::BoundedWriter::new(server_write))
        .with_max_line_length(wire::MAX_INPUT_BYTES);
    let server_task = tokio::spawn(async move {
        server
            .serve(transport)
            .await
            .expect("serve")
            .waiting()
            .await
            .expect("wait");
    });

    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let mut lines = BufReader::new(client_read).lines();

    let send_recv = |req: Value| {
        let mut writer = &mut client_write;
        let _ = &mut writer;
        req
    };
    let _ = send_recv;

    // 1. Initialize
    client_write
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"}}}\n",
        )
        .await
        .unwrap();
    client_write.flush().await.unwrap();
    let _init: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    client_write
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();

    // 2. Valid blind-org tool call: chinwag_org_status
    let org_call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "chinwag_org_status",
            "arguments": { "org_id": "org_acme_prod" }
        }
    });
    client_write
        .write_all(format!("{org_call}\n").as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();
    let org_resp: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert!(
        org_resp.get("error").is_none(),
        "unexpected error: {org_resp}"
    );
    assert_eq!(
        org_resp["result"]["structuredContent"]["source_bytes"],
        json!(0)
    );
    assert_eq!(
        org_resp["result"]["structuredContent"]["compliance_note"],
        json!("Emun Labs is pursuing SOC 2.")
    );

    // 3. Valid blind-org docs search & get
    let docs_call = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "chinwag_docs_get",
            "arguments": { "slug": "security/blind-boundary" }
        }
    });
    client_write
        .write_all(format!("{docs_call}\n").as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();
    let docs_resp: Value =
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(
        docs_resp["result"]["structuredContent"]["document"]["found"],
        json!(true)
    );

    // 4. Local repository tool MUST fail closed on blind-org
    let forbidden_call = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "chinwag_read_thread",
            "arguments": { "thread_id": "t-1" }
        }
    });
    client_write
        .write_all(format!("{forbidden_call}\n").as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();
    let forbidden_resp: Value =
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert!(
        forbidden_resp.get("error").is_some(),
        "local tool must fail closed in blind-org: {forbidden_resp}"
    );

    // 5. Env-interpolation / path-traversal injection MUST fail closed
    let traversal_call = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "chinwag_docs_get",
            "arguments": { "slug": "../etc/passwd" }
        }
    });
    client_write
        .write_all(format!("{traversal_call}\n").as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();
    let traversal_resp: Value =
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert!(traversal_resp.get("error").is_some());

    let interp_call = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "chinwag_docs_search",
            "arguments": { "query": "${OPENAI_API_KEY}" }
        }
    });
    client_write
        .write_all(format!("{interp_call}\n").as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();
    let interp_resp: Value =
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert!(interp_resp.get("error").is_some());

    client_write.shutdown().await.unwrap();
    drop(lines);
    drop(client_write);
    server_task.await.unwrap();
}
