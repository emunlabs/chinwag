//! Explicit operator-only host for the five existing tools. Config validation
//! opens no room and starts no export. The host drains its send owner before
//! claim shutdown, including on construction or serving errors. Process death
//! cannot promise cleanup; private paths do not sandbox Cargo build scripts.

use crate::{
    bundle::GitCandidate,
    bundle_export::ExportOperatorConfig,
    bundle_io::{
        bounded_read, canonical, private_directory, private_empty_directory, private_file,
    },
    bundle_wire::run_id,
    edit_mcp::{EditServer, EditState, five_tool::FiveToolServer},
    mcp::VerifyServer,
    send_owner::{SendOwner, mcp::SendServer},
    workspace::Workspace,
};
use chinwag_swarm::{
    lan::LanInterfaces,
    room::{CLAIM_FILE, ClaimOperatorConfig, ClaimService},
};
use iroh::EndpointId;
use rmcp::ServiceExt;
use serde::Deserialize;
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

const CONFIG_LIMIT: usize = 16 * 1024;
const BUILDER: &str = "df7676a8680f06f1cddb51a793be9a07a0d022638cb25ebe681dd42328867931";
const ARCHITECT: &str = "63e44fbb5054e0730793b2be61daf203b912c7cc5777f86ebbfe5f73b096c3d0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("five-tool operator configuration rejected")]
    Configuration,
    #[error("five-tool workspace unavailable")]
    Workspace,
    #[error("five-tool Cargo scope unavailable")]
    Cargo,
    #[error("five-tool claim service unavailable")]
    Claim,
    #[error("five-tool identity pins do not match the owned claim service")]
    Pins,
    #[error("five-tool construction failed")]
    Construction,
    #[error("five-tool MCP serving failed")]
    Serve,
    #[error("five-tool send drain failed; preserve the original attempt")]
    SendDrain,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    relay: crate::relay_config::RelaySelection,
    workspace: PathBuf,
    key: PathBuf,
    journal: PathBuf,
    lan_ipv4: Ipv4Addr,
    toolchain: PathBuf,
    cache: PathBuf,
    target: PathBuf,
    export: PathBuf,
    staging: PathBuf,
    empty_templates: PathBuf,
    builder_signers: PathBuf,
    run: String,
    oid: String,
    tree: String,
    trace_directory: PathBuf,
    builder: String,
    peer: String,
}

struct Selected {
    claim: ClaimOperatorConfig,
    export: ExportOperatorConfig,
    toolchain: PathBuf,
    cache: PathBuf,
    target: PathBuf,
    run: String,
    peer: EndpointId,
    trace_directory: PathBuf,
}

fn select(path: &Path) -> Result<Selected, Error> {
    let config_path = canonical(path).map_err(|_| Error::Configuration)?;
    let bytes = bounded_read(
        &mut private_file(&config_path).map_err(|_| Error::Configuration)?,
        CONFIG_LIMIT,
    )
    .map_err(|_| Error::Configuration)?;
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| Error::Configuration)?;
    if config.schema != "chinwag-five-tool-host/v3"
        || config.builder != BUILDER
        || config.peer != ARCHITECT
    {
        return Err(Error::Configuration);
    }
    let policy = config.relay.resolve().map_err(|_| Error::Configuration)?;
    run_id(&config.run).map_err(|_| Error::Configuration)?;
    let builder: EndpointId = config.builder.parse().map_err(|_| Error::Configuration)?;
    let peer: EndpointId = config.peer.parse().map_err(|_| Error::Configuration)?;
    if builder == peer {
        return Err(Error::Configuration);
    }
    let candidate = GitCandidate::new(&config.oid, &config.tree, *builder.as_bytes())
        .map_err(|_| Error::Configuration)?;
    LanInterfaces::new(vec![config.lan_ipv4]).map_err(|_| Error::Configuration)?;
    for path in [
        &config.workspace,
        &config.key,
        &config.journal,
        &config.toolchain,
        &config.cache,
        &config.target,
        &config.export,
        &config.staging,
        &config.empty_templates,
        &config.trace_directory,
        &config.builder_signers,
    ] {
        canonical(path).map_err(|_| Error::Configuration)?;
    }
    let scopes = [
        &config.workspace,
        &config.journal,
        &config.export,
        &config.staging,
        &config.empty_templates,
        &config.trace_directory,
        &config.cache,
    ];
    for (index, scope) in scopes.iter().enumerate() {
        for other in &scopes[index + 1..] {
            if scope.starts_with(other) || other.starts_with(scope) {
                return Err(Error::Configuration);
            }
        }
        for protected in [
            &config_path,
            &config.key,
            &config.builder_signers,
            &config.toolchain,
        ] {
            if protected.starts_with(scope) {
                return Err(Error::Configuration);
            }
        }
    }
    if !config.target.starts_with(config.workspace.join("target"))
        || !config.toolchain.is_dir()
        || !config.cache.is_dir()
        || !config.target.is_dir()
        || !config.key.is_file()
        || !config.builder_signers.is_file()
    {
        return Err(Error::Configuration);
    }
    for directory in [&config.workspace, &config.journal] {
        private_directory(directory).map_err(|_| Error::Configuration)?;
    }
    for directory in [
        &config.export,
        &config.staging,
        &config.empty_templates,
        &config.trace_directory,
    ] {
        private_empty_directory(directory).map_err(|_| Error::Configuration)?;
    }
    Ok(Selected {
        claim: ClaimOperatorConfig {
            key_path: config.key,
            journal_directory: config.journal,
            lan_ipv4: config.lan_ipv4,
            policy,
        },
        export: ExportOperatorConfig {
            source: config.workspace,
            export: config.export,
            staging: config.staging,
            empty_templates: config.empty_templates,
            builder_signers: config.builder_signers,
            candidate,
        },
        toolchain: config.toolchain,
        cache: config.cache,
        target: config.target,
        run: config.run,
        peer,
        trace_directory: config.trace_directory,
    })
}

/// Serve only an explicit private config. Call inside the current-thread
/// runtime and retain that runtime until this future completes. Aborting this
/// future or killing the process cannot guarantee the normal shutdown path.
pub async fn serve(path: &Path) -> Result<(), Error> {
    let selected = select(path)?;
    let workspace = Workspace::open(&selected.export.source).map_err(|_| Error::Workspace)?;
    let verify = VerifyServer::open(
        &selected.export.source,
        vec![CLAIM_FILE.into()],
        &selected.toolchain,
        &selected.cache,
        &selected.target,
    )
    .map_err(|_| Error::Cargo)?;
    let claim = ClaimService::open(selected.claim).map_err(|_| Error::Claim)?;
    let pins_match = claim.matches_bundle_pins(selected.export.candidate.builder(), selected.peer);
    let state = Arc::new(Mutex::new(EditState::new(claim, workspace)));
    let mut retained_send: Option<SendServer> = None;
    let primary = async {
        if !pins_match {
            return Err(Error::Pins);
        }
        let edit = EditServer::new(state.clone()).map_err(|_| Error::Construction)?;
        let owner = SendOwner::open_peer(
            selected.export,
            state.clone(),
            selected.run,
            selected.peer,
            selected.trace_directory,
        )
        .map_err(|_| Error::Construction)?;
        let send = SendServer::new(owner).map_err(|_| Error::Construction)?;
        retained_send = Some(send.clone());
        let server = FiveToolServer::new(edit, verify, send).map_err(|_| Error::Construction)?;
        server
            .serve((tokio::io::stdin(), tokio::io::stdout()))
            .await
            .map_err(|_| Error::Serve)?
            .waiting()
            .await
            .map_err(|_| Error::Serve)?;
        Ok(())
    }
    .await;
    // Do not hold the edit mutex while the send worker may still need it.
    // No timeout: cancelling a drain can detach the existing worker.
    let drain = match retained_send {
        Some(send) => send
            .shutdown()
            .await
            .map(|_| ())
            .map_err(|_| Error::SendDrain),
        None => Ok(()),
    };
    state.lock().await.shutdown().await;
    if primary.is_err() && drain.is_err() {
        eprintln!("chinwag-seed: five-tool send drain also failed; preserve the original attempt");
    }
    primary.and(drain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        path: PathBuf,
        json: Value,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            for name in [
                "workspace",
                "journal",
                "toolchain",
                "cache",
                "export",
                "staging",
                "templates",
                "trace",
            ] {
                fs::create_dir(root.join(name)).unwrap();
                fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
            }
            fs::create_dir(root.join("workspace/target")).unwrap();
            fs::create_dir(root.join("workspace/target/proof")).unwrap();
            // Intentionally invalid keys: config parsing must not load keys.
            fs::write(root.join("key"), b"not an OpenSSH key").unwrap();
            fs::write(root.join("signers"), b"not an allowed-signers file").unwrap();
            let path = root.join("host.json");
            let json = json!({
                "schema":"chinwag-five-tool-host/v3", "relay":{"mode":"disabled"}, "workspace":root.join("workspace"),
                "key":root.join("key"), "journal":root.join("journal"), "lan_ipv4":"192.0.2.10",
                "toolchain":root.join("toolchain"), "cache":root.join("cache"),
                "target":root.join("workspace/target/proof"), "export":root.join("export"),
                "staging":root.join("staging"), "empty_templates":root.join("templates"),
                "trace_directory":root.join("trace"),
                "builder_signers":root.join("signers"), "run":"11".repeat(32),
                "oid":"22".repeat(20), "tree":"33".repeat(20), "builder":BUILDER, "peer":ARCHITECT,
            });
            Self {
                _temp: temp,
                root,
                path,
                json,
            }
        }
        fn write(&self, json: &Value) {
            fs::write(&self.path, serde_json::to_vec(json).unwrap()).unwrap();
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fn assert_no_start(&self) {
            for name in ["journal", "export", "staging", "templates", "trace"] {
                assert!(fs::read_dir(self.root.join(name)).unwrap().next().is_none());
            }
            assert_eq!(
                fs::read(self.root.join("key")).unwrap(),
                b"not an OpenSSH key"
            );
        }
    }

    #[test]
    fn config_selects_one_root_and_pins_without_loading_key_or_starting_work() {
        let f = Fixture::new();
        f.write(&f.json);
        let selected = select(&f.path).unwrap();
        assert_eq!(selected.export.source, f.root.join("workspace"));
        assert_eq!(
            selected.export.candidate.builder(),
            *BUILDER.parse::<EndpointId>().unwrap().as_bytes()
        );
        assert_eq!(selected.peer, ARCHITECT.parse::<EndpointId>().unwrap());
        f.assert_no_start();
        println!(
            "five_host_config fixed_root_pins=true invalid_key_not_loaded=true no_export_or_claim_started=true validator_only=true"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_refuses_invalid_cargo_then_invalid_key_before_serving_or_export() {
        let f = Fixture::new();
        f.write(&f.json);
        assert!(matches!(serve(&f.path).await, Err(Error::Cargo)));
        f.assert_no_start();
        let chain = PathBuf::from(std::env::var_os("RUSTC").unwrap());
        let mut configured = f.json.clone();
        configured["toolchain"] = json!(chain.parent().unwrap().canonicalize().unwrap());
        f.write(&configured);
        assert!(matches!(serve(&f.path).await, Err(Error::Claim)));
        f.assert_no_start();
        println!(
            "five_host_startup real_serve_called=true cargo_refusal_before_key=true invalid_key_refused=true journal_export_untouched=true no_owned_identity_or_room=true"
        );
    }

    #[test]
    fn config_refuses_unknown_duplicate_schema_run_and_identity_changes() {
        let f = Fixture::new();
        for (key, value) in [
            ("extra", json!(true)),
            ("schema", json!("chinwag-five-tool-host/v1")),
            ("run", json!("AA".repeat(32))),
            ("builder", json!(ARCHITECT)),
            ("peer", json!(BUILDER)),
            ("oid", json!("bad")),
            ("lan_ipv4", json!("0.0.0.0")),
        ] {
            let mut changed = f.json.clone();
            changed[key] = value;
            f.write(&changed);
            assert!(select(&f.path).is_err(), "{key}");
        }
        f.write(&f.json);
        let original = fs::read_to_string(&f.path).unwrap();
        fs::write(
            &f.path,
            original.replacen('{', "{\"schema\":\"chinwag-five-tool-host/v3\",", 1),
        )
        .unwrap();
        assert!(select(&f.path).is_err());
        f.assert_no_start();
    }

    #[test]
    fn config_file_refuses_symlink_hardlink_permissions_and_oversize() {
        let f = Fixture::new();
        f.write(&f.json);
        let alias = f.root.join("alias");
        symlink(&f.path, &alias).unwrap();
        assert!(select(&alias).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&f.path, &alias).unwrap();
        assert!(select(&f.path).is_err());
        fs::remove_file(&alias).unwrap();
        fs::set_permissions(&f.path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(select(&f.path).is_err());
        fs::set_permissions(&f.path, fs::Permissions::from_mode(0o600)).unwrap();
        f.write(&f.json);
        let mut valid_padded = fs::read(&f.path).unwrap();
        assert!(valid_padded.len() < CONFIG_LIMIT);
        valid_padded.resize(CONFIG_LIMIT, b' ');
        fs::write(&f.path, &valid_padded).unwrap();
        assert!(select(&f.path).is_ok());
        valid_padded.push(b' ');
        // Still valid JSON: only the byte limit can reject this added space.
        assert!(serde_json::from_slice::<Config>(&valid_padded).is_ok());
        fs::write(&f.path, &valid_padded).unwrap();
        assert!(select(&f.path).is_err());
        f.assert_no_start();
    }

    #[test]
    fn config_refuses_overlaps_protected_files_and_noncanonical_scopes() {
        let f = Fixture::new();
        for (key, path) in [
            ("journal", f.root.join("workspace")),
            ("export", f.root.clone()),
            ("cache", f.root.join("workspace/target")),
            ("target", f.root.join("cache")),
            ("trace_directory", f.root.join("journal")),
            ("trace_directory", f.root.join("workspace/target")),
            ("key", f.root.join("workspace/secret")),
            ("workspace", PathBuf::from("workspace")),
        ] {
            if key == "key" {
                fs::write(&path, b"dummy").unwrap();
            }
            let mut changed = f.json.clone();
            changed[key] = json!(path);
            f.write(&changed);
            assert!(select(&f.path).is_err(), "{key}");
        }
        symlink(f.root.join("workspace"), f.root.join("workspace-link")).unwrap();
        let mut changed = f.json.clone();
        changed["workspace"] = json!(f.root.join("workspace-link"));
        f.write(&changed);
        assert!(select(&f.path).is_err());
        f.write(&f.json);
        let inside = f.root.join("workspace/host.json");
        fs::rename(&f.path, &inside).unwrap();
        assert!(select(&inside).is_err());
        f.assert_no_start();
        println!(
            "five_host_config private_bounded_file=true overlaps_refused=true no_service_constructed=true no_network_proof=true"
        );
    }
    #[test]
    fn trace_scope_requires_new_schema_private_empty_and_disjoint_path_without_start() {
        let f = Fixture::new();
        let mut old = f.json.clone();
        old["schema"] = json!("chinwag-five-tool-host/v1");
        old.as_object_mut().unwrap().remove("trace_directory");
        f.write(&old);
        assert!(select(&f.path).is_err());
        for scope in [
            f.root.join("workspace"),
            f.root.join("cache"),
            f.root.join("journal"),
        ] {
            let mut value = f.json.clone();
            value["trace_directory"] = json!(scope);
            f.write(&value);
            assert!(select(&f.path).is_err());
        }
        let trace = f.root.join("trace");
        fs::write(trace.join("keep"), b"original").unwrap();
        f.write(&f.json);
        assert!(select(&f.path).is_err());
        assert_eq!(fs::read(trace.join("keep")).unwrap(), b"original");
        assert!(!trace.join("events.jsonl").exists());
        fs::remove_file(trace.join("keep")).unwrap();
        fs::set_permissions(&trace, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(select(&f.path).is_err());
        fs::set_permissions(&trace, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(select(&f.path).is_ok());
        f.assert_no_start();
    }
}
