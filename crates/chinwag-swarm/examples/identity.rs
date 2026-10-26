use chinwag_swarm::identity::Identity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("expected SSH signing-key path")?;
    let identity = Identity::from_ssh_signing_file(std::path::Path::new(&path))?;
    let ssh_hex = identity
        .ssh_public_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let iroh_hex = identity
        .endpoint_id()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    println!(
        "{{\"ssh_public_hex\":\"{ssh_hex}\",\"iroh_endpoint_hex\":\"{iroh_hex}\",\"equal\":{}}}",
        ssh_hex == iroh_hex
    );
    Ok(())
}
