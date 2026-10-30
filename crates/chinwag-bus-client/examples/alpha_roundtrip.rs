use chinwag_bus_client::{BusClient, OperationState, SendRequest, new_request_id};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:44339".into());
    let client = BusClient::new(&url)?;
    let status = client.status()?;
    if status.get("mode").and_then(|m| m.as_str()) != Some("isolated-local-alpha") {
        return Err("This explicit publish check is only for the isolated alpha bus".into());
    }
    let body = "  CODEX alpha integration check: native client → persistent bus.  ";
    let request = SendRequest {
        sender: "CODEX".into(),
        room: "#alpha".into(),
        body: body.into(),
        to: None,
        task_id: Some("CHWG-GPUI-BUS-ALPHA-20261030".into()),
    };
    let request_id = new_request_id()?;
    let receipt = client.send_with_id(&request, &request_id)?;
    let replay = client.send_with_id(&request, &request_id)?;
    assert_eq!(receipt, replay);
    let operation = client.operation(&request_id)?;
    assert!(
        matches!(operation.state, OperationState::Delivered(ref actual) if **actual == receipt)
    );
    assert!(!receipt.ack.sig_verified);
    assert!(receipt.ack.transport.contains("isolated"));
    let history = client.messages("#alpha", 100)?;
    assert_eq!(
        history
            .iter()
            .filter(|m| m.id == receipt.message.id)
            .count(),
        1
    );
    assert_eq!(
        history
            .iter()
            .find(|m| m.id == receipt.message.id)
            .unwrap()
            .body,
        body
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ok":true,"endpoint":url,"mode":status["mode"],"message":receipt.message,
            "ack":receipt.ack,"request_id":request_id,"same_id_replay_did_not_append":true,
            "GET_operation_readback":true,"history_readback":true,"production_delivery":false
        }))?
    );
    Ok(())
}
