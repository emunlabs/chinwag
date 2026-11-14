// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

#[cfg(unix)]
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if matches!(args.as_slice(), [_, flag] if flag == "--version" || flag == "-V") {
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        if writeln!(
            out,
            "{} {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )
        .is_err()
            || out.flush().is_err()
        {
            eprintln!("CI_VERSION_STDOUT_WRITE_FAILED");
            std::process::exit(1);
        }
        return;
    }
    if let Some(code) = chinwag_ci::unified_gates::dispatch_unified_subcommand(&args) {
        std::process::exit(i32::from(code));
    }
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        eprintln!("CI_RUNTIME_INIT_FAILED");
        std::process::exit(2);
    };
    rt.block_on(async_main(args));
}

#[cfg(unix)]
async fn async_main(args: Vec<std::ffi::OsString>) {
    let mut result: Result<(), ()> = match args.as_slice() {
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
            owner_result(
                chinwag_ci::owner_supervisor::run(
                    chinwag_ci::owner_supervisor::OwnerKind::Root,
                    config.as_ref(),
                )
                .await,
            )
            .await
        }
        [_, action, config] if action == "agent-init" => {
            idle_result(chinwag_ci::idle_agent::enroll(config.as_ref()).await).await
        }
        [_, action, socket, scope] if action == "agent-read" => match scope.to_str() {
            Some(scope) => chinwag_ci::agent_read::read_capture(socket.as_ref(), scope)
                .await
                .map_err(|_| ()),
            None => Err(()),
        },
        [_, action, config] if action == "serve-studio" => {
            owner_result(
                chinwag_ci::owner_supervisor::run(
                    chinwag_ci::owner_supervisor::OwnerKind::Studio,
                    config.as_ref(),
                )
                .await,
            )
            .await
        }
        [_, action, config] if action == "__ci-owned-root" => {
            runtime_result(chinwag_ci::runtime::serve_root(config.as_ref()).await).await
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
                Err(error) => {
                    eprintln!("{error}");
                    runtime_result(Err(error.into_runtime())).await
                }
            }
        }
        _ => {
            eprintln!(
                "usage: chinwag-ci --version|-V; owner-init|owner-verify CONFIG PUBLIC; policy-sign CONFIG PUBLIC SPEC OUTPUT; serve-root|serve-studio|runner|agent-init CONFIG; agent-read PIPE_DIRECTORY SCOPE_SHA256"
            );
            std::process::exit(2)
        }
    };
    // Also retain abandoned awaiter results from this owner process. No
    // background reaper, replacement process or numeric-PID signalling.
    loop {
        let retained = chinwag_ci::agent_process::retained_originals();
        if retained.is_empty() {
            break;
        }
        result = Err(());
        for original in retained {
            original.retain_until_retired().await;
        }
    }
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

#[cfg(unix)]
async fn idle_result(r: Result<(), chinwag_ci::idle_agent::IdleAgentError>) -> Result<(), ()> {
    match r {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Some(h) = e.into_held() {
                h.retain_until_retired().await;
            }
            Err(())
        }
    }
}
#[cfg(unix)]
async fn runtime_result(r: Result<(), chinwag_ci::runtime::RuntimeError>) -> Result<(), ()> {
    match r {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Some(h) = e.into_held() {
                h.retain_until_retired().await;
            }
            Err(())
        }
    }
}
#[cfg(unix)]
async fn owner_result(
    r: Result<(), chinwag_ci::owner_supervisor::OwnerSupervisorError>,
) -> Result<(), ()> {
    match r {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Some(h) = e.into_held() {
                h.retain_until_retired().await;
            }
            Err(())
        }
    }
}
