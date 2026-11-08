// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#[cfg(unix)]
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result: Result<(), ()> = match args.as_slice() {
        [_, action, config, public] if action == "owner-init" || action == "owner-verify" => {
            let result = if action == "owner-init" {
                chinwag_ci::owner_cli::initialize(config.as_ref(), public.as_ref())
            } else {
                chinwag_ci::owner_cli::verify(config.as_ref(), public.as_ref())
            };
            let owner_result = result.map_err(|_| ()).and_then(|v| {
                serde_json::to_string(&v)
                    .map(|j| println!("{j}"))
                    .map_err(|_| ())
            });
            if owner_result.is_err() {
                eprintln!("CI_OWNER_ENROLLMENT_HELD_PRESERVE_ORIGINAL");
                std::process::exit(1)
            }
            owner_result
        }
        [_, action, config] if action == "serve-root" => {
            chinwag_ci::owner_supervisor::run(
                chinwag_ci::owner_supervisor::OwnerKind::Root,
                config.as_ref(),
            )
            .await
        }
        [_, action, config] if action == "serve-studio" => {
            chinwag_ci::owner_supervisor::run(
                chinwag_ci::owner_supervisor::OwnerKind::Studio,
                config.as_ref(),
            )
            .await
        }
        [_, action, config] if action == "__ci-owned-root" => {
            chinwag_ci::runtime::serve_root(config.as_ref())
                .await
                .map_err(|_| ())
        }
        [_, action, config] if action == "__ci-owned-studio" => {
            chinwag_ci::runtime::serve_studio(config.as_ref())
                .await
                .map_err(|_| ())
        }
        [_, action, config, public, spec, output] if action == "policy-sign" => {
            chinwag_ci::runtime::sign_policy(
                config.as_ref(),
                public.as_ref(),
                spec.as_ref(),
                output.as_ref(),
            )
            .map_err(|_| ())
        }
        [_, action, config] if action == "runner" => {
            match chinwag_ci::runner::run(config.as_ref()).await {
                Ok((observation, green)) => {
                    match serde_json::to_string(&observation) {
                        Ok(j) => println!("{j}"),
                        Err(_) => std::process::exit(2),
                    }
                    std::process::exit(if green { 0 } else { 1 });
                }
                Err(_) => Err(()),
            }
        }
        _ => {
            eprintln!(
                "usage: chinwag-ci owner-init|owner-verify CONFIG PUBLIC; policy-sign CONFIG PUBLIC SPEC OUTPUT; serve-root|serve-studio|runner CONFIG"
            );
            std::process::exit(2)
        }
    };
    if result.is_err() {
        eprintln!("CI_OPERATION_HELD_PRESERVE_ORIGINAL_NO_RETRY");
        std::process::exit(2)
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("CI runtime requires the supported Unix filesystem adapter");
    std::process::exit(2)
}
