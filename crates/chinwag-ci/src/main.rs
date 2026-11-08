// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

fn main() {
    #[cfg(unix)]
    {
        let args: Vec<_> = std::env::args_os().collect();
        let result = match args.as_slice() {
            [_, action, config, public] if action == "owner-init" => {
                chinwag_ci::owner_cli::initialize(config.as_ref(), public.as_ref())
            }
            [_, action, config, public] if action == "owner-verify" => {
                chinwag_ci::owner_cli::verify(config.as_ref(), public.as_ref())
            }
            _ => {
                eprintln!(
                    "usage: chinwag-ci owner-init|owner-verify ABS_PUBLIC_CONFIG_JSON ABS_PUBLIC_ENROLLMENT_JSON"
                );
                std::process::exit(2);
            }
        };
        match result {
            Ok(public) => match serde_json::to_string(&public) {
                Ok(json) => println!("{json}"),
                Err(_) => std::process::exit(1),
            },
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(unix))]
    {
        eprintln!("CI owner custody requires the supported Unix private filesystem adapter");
        std::process::exit(2);
    }
}
