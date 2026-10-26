#![forbid(unsafe_code)]

mod stage1;
mod stage1_build;

use chinwag_seed::vault::{Binding, MAX_CAPSULE_BYTES, Slot, open};
use std::{env, fs::File, io::Read, process::ExitCode};
use zeroize::Zeroizing;

fn read_bounded(path: &str, limit: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input exceeds its size limit".into());
    }
    Ok(bytes)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.as_slice() == ["--version"] {
        println!(
            "chinwag-seed {} (uncommitted candidate)",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    if let [command, recipe] = args.as_slice()
        && command == "stage1-build-exec"
    {
        let never = stage1_build::build_and_replace(std::path::Path::new(recipe))?;
        match never {}
    }
    if let [
        command,
        workspace,
        expected_sha256,
        separator,
        target_args @ ..,
    ] = args.as_slice()
        && command == "stage1-exec"
        && separator == "--"
    {
        // This branch runs before constructing any runtime or owned worker.
        let never = stage1::replace(
            std::path::Path::new(workspace),
            expected_sha256,
            target_args,
        )?;
        match never {}
    }
    if let [command, root, allowed @ ..] = args.as_slice()
        && command == "serve-read-mcp"
    {
        use rmcp::ServiceExt;
        let server =
            chinwag_seed::mcp::ReadServer::open(std::path::Path::new(root), allowed.to_vec())?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                server
                    .serve((tokio::io::stdin(), tokio::io::stdout()))
                    .await?
                    .waiting()
                    .await?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })?;
        return Ok(());
    }
    if let [command, root, toolchain, cache, target, allowed @ ..] = args.as_slice()
        && command == "serve-verify-mcp"
    {
        use rmcp::ServiceExt;
        use std::path::Path;
        let server = chinwag_seed::mcp::VerifyServer::open(
            Path::new(root),
            allowed.to_vec(),
            Path::new(toolchain),
            Path::new(cache),
            Path::new(target),
        )?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                server
                    .serve((tokio::io::stdin(), tokio::io::stdout()))
                    .await?
                    .waiting()
                    .await?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })?;
        return Ok(());
    }
    if let [command, key, journal, lan] = args.as_slice()
        && command == "serve-claim-mcp"
    {
        use chinwag_swarm::room::{ClaimOperatorConfig, ClaimService};
        use rmcp::ServiceExt;
        use std::sync::Arc;
        use tokio::sync::Mutex;
        let config = ClaimOperatorConfig {
            key_path: key.into(),
            journal_directory: journal.into(),
            lan_ipv4: lan.parse()?,
            policy: Arc::new(chinwag_swarm::relay_policy::RelayPolicy::Disabled),
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let service = Arc::new(Mutex::new(ClaimService::open(config)?));
                let server = chinwag_seed::claim_task::ClaimServer::new(service.clone())?;
                let result = async {
                    server
                        .serve((tokio::io::stdin(), tokio::io::stdout()))
                        .await?
                        .waiting()
                        .await?;
                    Ok::<(), Box<dyn std::error::Error>>(())
                }
                .await;
                service.lock().await.shutdown().await;
                result
            })?;
        return Ok(());
    }
    if let [command, key, journal, lan, root] = args.as_slice()
        && command == "serve-edit-mcp"
    {
        use chinwag_swarm::room::{ClaimOperatorConfig, ClaimService};
        use rmcp::ServiceExt;
        use std::{path::Path, sync::Arc};
        use tokio::sync::Mutex;
        let config = ClaimOperatorConfig {
            key_path: key.into(),
            journal_directory: journal.into(),
            lan_ipv4: lan.parse()?,
            policy: Arc::new(chinwag_swarm::relay_policy::RelayPolicy::Disabled),
        };
        let workspace = chinwag_seed::workspace::Workspace::open(Path::new(root))?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let state = Arc::new(Mutex::new(chinwag_seed::edit_mcp::EditState::new(
                    ClaimService::open(config)?,
                    workspace,
                )));
                let server = chinwag_seed::edit_mcp::EditServer::new(state.clone())?;
                let result = async {
                    server
                        .serve((tokio::io::stdin(), tokio::io::stdout()))
                        .await?
                        .waiting()
                        .await?;
                    Ok::<(), Box<dyn std::error::Error>>(())
                }
                .await;
                state.lock().await.shutdown().await;
                result
            })?;
        return Ok(());
    }
    if let [command, config] = args.as_slice()
        && command == "serve-five-mcp"
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(chinwag_seed::five_host::serve(std::path::Path::new(config)))?;
        return Ok(());
    }
    if let [command, config] = args.as_slice()
        && command == "receive-one-bundle"
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(chinwag_seed::receiver_driver::receive(
                std::path::Path::new(config),
            ))?;
        return Ok(());
    }
    if let [command, guard, prepared] = args.as_slice()
        && command == "publish-receive-finish"
    {
        chinwag_seed::receiver_driver::publish_finish(
            std::path::Path::new(guard),
            std::path::Path::new(prepared),
        )?;
        return Ok(());
    }
    if let [command, oid, slot, key_file, capsule_file] = args.as_slice()
        && command == "inspect-file"
    {
        let slot = match slot.as_str() {
            "demo" => Slot::Demo,
            "org" => Slot::Organization,
            _ => return Err("slot must be demo or org".into()),
        };
        let key = Zeroizing::new(read_bounded(key_file, 32)?);
        let key: &[u8; 32] = key.as_slice().try_into()?;
        let capsule = read_bounded(capsule_file, MAX_CAPSULE_BYTES)?;
        let plaintext = open(&Binding::public_chinwag(oid)?, slot, key, &capsule)?;
        use std::io::Write;
        std::io::stdout().lock().write_all(&plaintext)?;
        return Ok(());
    }
    Err("usage: chinwag-seed --version | stage1-build-exec <operator-recipe.json> | stage1-exec <absolute-workspace> <expected-sha256> -- [chinwag-args...] | serve-read-mcp <workspace> <allowed-path>... | serve-verify-mcp <workspace> <toolchain-bin> <cargo-cache> <workspace-target> <allowed-path>... | serve-claim-mcp <own-key-path> <private-journal-directory> <lan-ipv4> | serve-edit-mcp <own-key-path> <new-private-journal-directory> <lan-ipv4> <workspace> | serve-five-mcp <private-operator-config.json> | receive-one-bundle <private-operator-config.json> | publish-receive-finish <private-guard-dir> <prepared-control-file> | inspect-file <source-oid> <demo|org> <raw-32-byte-key-file> <capsule-file>".into())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chinwag-seed: {error}");
            ExitCode::FAILURE
        }
    }
}
