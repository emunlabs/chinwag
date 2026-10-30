//! Explicit read-only check of the configured runtime host's client inventory.
use chinwag_bus_client::BusClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let endpoint = arguments
        .next()
        .ok_or("usage: client_inventory http://127.0.0.1:PORT")?;
    if arguments.next().is_some() {
        return Err("client_inventory accepts one explicit loopback endpoint".into());
    }
    let inventory = BusClient::new(&endpoint)?.clients()?;
    println!("{}", serde_json::to_string_pretty(&inventory)?);
    Ok(())
}
