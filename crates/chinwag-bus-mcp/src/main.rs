use chinwag_bus_mcp::{LaunchConfig, serve_stdio};
use chinwag_connector_registry::NativeRoom;
use std::time::Duration;

const USAGE: &str = "use --bus-url http://127.0.0.1:PORT --allow-room '#mgmt' [--lease-seconds 900]; only a fixed native-bus read grant is supported";

fn parse(args: Vec<String>) -> Result<LaunchConfig, &'static str> {
    if args.is_empty() || !args.len().is_multiple_of(2) {
        return Err(USAGE);
    }
    let mut endpoint = None;
    let mut room = None;
    let mut lease = None;
    for pair in args.chunks_exact(2) {
        match pair[0].as_str() {
            "--bus-url" if endpoint.is_none() => endpoint = Some(pair[1].clone()),
            "--allow-room" if room.is_none() => {
                room = Some(NativeRoom::try_from(pair[1].as_str()).map_err(|_| USAGE)?);
            }
            "--lease-seconds" if lease.is_none() => {
                let seconds = pair[1].parse::<u64>().map_err(|_| USAGE)?;
                if !(1..=3600).contains(&seconds) {
                    return Err(USAGE);
                }
                lease = Some(Duration::from_secs(seconds));
            }
            _ => return Err(USAGE),
        }
    }
    Ok(LaunchConfig {
        endpoint: endpoint.ok_or(USAGE)?,
        room: room.ok_or(USAGE)?,
        lease: lease.unwrap_or(Duration::from_secs(900)),
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = match parse(std::env::args().skip(1).collect()) {
        Ok(config) => config,
        Err(reason) => {
            eprintln!("chinwag-bus-mcp: {reason}");
            std::process::exit(2);
        }
    };
    if serve_stdio(config).await.is_err() {
        eprintln!("chinwag-bus-mcp: read-only connector stopped with an error");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn owner_must_name_both_route_and_exact_native_room() {
        for bad in [
            vec![],
            args(&["--bus-url", "http://127.0.0.1:44342"]),
            args(&["--allow-room", "#mgmt"]),
            args(&[
                "--bus-url",
                "http://127.0.0.1:1",
                "--allow-room",
                "GROK-MGMT",
            ]),
        ] {
            assert!(parse(bad).is_err());
        }
        let config = parse(args(&[
            "--bus-url",
            "http://127.0.0.1:44342",
            "--allow-room",
            "#mgmt",
        ]))
        .unwrap();
        assert_eq!(config.room, NativeRoom::Mgmt);
        assert_eq!(config.lease, Duration::from_secs(900));
    }

    #[test]
    fn unknown_duplicate_and_excessive_grants_are_rejected() {
        for extra in [
            ["--sender", "Brian"],
            ["--allow-room", "#eng"],
            ["--lease-seconds", "0"],
            ["--lease-seconds", "3601"],
        ] {
            let mut input = args(&["--bus-url", "http://127.0.0.1:1", "--allow-room", "#mgmt"]);
            input.extend(args(&extra));
            assert!(parse(input).is_err());
        }
    }
}
