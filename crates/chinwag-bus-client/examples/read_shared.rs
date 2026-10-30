use chinwag_bus_client::BusClient;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "http://127.0.0.1:44341";
    let client = BusClient::new(url)?;
    let status = client.status()?;
    assert!(matches!(
        status["mode"].as_str(),
        Some("fleet-ledger-read-only" | "fleet-signed-ui")
    ));
    if status["send_allowed"] == true {
        assert_eq!(status["allowed_senders"], serde_json::json!(["Brian"]));
    }
    let messages = client.messages("#mgmt", 10)?;
    assert!(
        messages
            .iter()
            .all(|m| m.room == "#mgmt" && !m.sig_verified)
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ok":true,"endpoint":url,"mode":status["mode"],"this_operation_read_only":true,
            "selected_room":"#mgmt","returned_messages":messages.len(),
            "observed":messages.iter().map(|m|serde_json::json!({"id":m.id,"seq":m.seq,"room":m.room,"sender":m.sender,"body_bytes":m.body.len(),"sig_verified":m.sig_verified})).collect::<Vec<_>>(),
            "coverage":status["diagnostics"],"signing_or_publish_invoked":false
        }))?
    );
    Ok(())
}
