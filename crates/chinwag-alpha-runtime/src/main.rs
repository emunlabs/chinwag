use chinwag_alpha_runtime::{
    Result, RuntimeConfig, RuntimeError, RuntimeMode, launcher, server, signed::CliSignedSender,
};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

#[tokio::main]
async fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()).await {
        eprintln!("chinwag-alpha-runtime: {error}");
        std::process::exit(1);
    }
}

async fn run(args: Vec<String>) -> Result<()> {
    let Some((command, rest)) = args.split_first() else {
        return Err(RuntimeError::Invalid(
            "use launch, serve-local, serve-shared or discover-clients".into(),
        ));
    };
    if command == "launch" {
        return launcher::run(rest);
    }
    if command == "discover-clients" {
        if !rest.is_empty() {
            return Err(RuntimeError::Invalid(
                "discover-clients accepts no arguments; it observes only this host's current user"
                    .into(),
            ));
        }
        let snapshot = chinwag_client_discovery::snapshot()
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        println!(
            "{}",
            serde_json::to_string(&snapshot)
                .map_err(|error| RuntimeError::Invalid(error.to_string()))?
        );
        return Ok(());
    }
    let allowed: &[&str] = match command.as_str() {
        "serve-local" => &["--data-dir", "--port"],
        "serve-shared" => &[
            "--ledger",
            "--port",
            "--signed-cli",
            "--repo",
            "--send-journal",
        ],
        _ => return Err(RuntimeError::Invalid("unknown runtime command".into())),
    };
    let mut options = HashMap::new();
    if !rest.len().is_multiple_of(2) {
        return Err(RuntimeError::Invalid("each option requires a value".into()));
    }
    for pair in rest.chunks_exact(2) {
        if !allowed.contains(&pair[0].as_str())
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(RuntimeError::Invalid(format!(
                "unknown or repeated option: {}",
                pair[0]
            )));
        }
    }
    let required = |name: &str| -> Result<PathBuf> {
        let path = PathBuf::from(
            options
                .get(name)
                .ok_or_else(|| RuntimeError::Invalid(format!("{name} is required")))?,
        );
        if !path.is_absolute() {
            return Err(RuntimeError::Invalid(format!("{name} must be absolute")));
        }
        Ok(path)
    };
    let port = options
        .get("--port")
        .copied()
        .unwrap_or(if command == "serve-local" {
            "44339"
        } else {
            "44341"
        })
        .parse::<u16>()
        .map_err(|_| RuntimeError::Invalid("port must be an integer in 0..65535".into()))?;
    let mode = if command == "serve-local" {
        RuntimeMode::Isolated {
            data_dir: required("--data-dir")?,
        }
    } else {
        let signed_sender = match (options.get("--signed-cli"), options.get("--repo")) {
            (None, None) => {
                if options.contains_key("--send-journal") {
                    return Err(RuntimeError::Invalid(
                        "--send-journal requires --signed-cli and --repo".into(),
                    ));
                }
                None
            }
            (Some(_), Some(_)) => {
                verify_signer_ledger(&required("--ledger")?, &required("--repo")?)?;
                Some(Arc::new(CliSignedSender::new(
                    required("--signed-cli")?,
                    required("--repo")?,
                )?)
                    as Arc<dyn chinwag_alpha_runtime::SignedSender>)
            }
            _ => {
                return Err(RuntimeError::Invalid(
                    "--signed-cli and --repo must be supplied together".into(),
                ));
            }
        };
        let journal_dir = if signed_sender.is_some() {
            Some(required("--send-journal")?)
        } else {
            None
        };
        RuntimeMode::Shared {
            ledger: required("--ledger")?,
            signed_sender,
            journal_dir,
        }
    };
    server::serve(RuntimeConfig {
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        mode,
    })
    .await
}

fn verify_signer_ledger(ledger: &std::path::Path, repo: &std::path::Path) -> Result<()> {
    if !std::fs::symlink_metadata(ledger)?.file_type().is_file()
        || std::fs::canonicalize(ledger)?
            != std::fs::canonicalize(repo.join(".chinwag/bus/messages.jsonl"))?
    {
        return Err(RuntimeError::Invalid(
            "signed mode must read the same repository ledger that it publishes to".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn launcher_under_async_dispatch_returns_a_normal_missing_binary_error() {
        let root = tempfile::tempdir().unwrap();
        let error = run(vec![
            "launch".into(),
            "--state-dir".into(),
            root.path().join("state").display().to_string(),
            "--desktop".into(),
            root.path().join("absent-desktop").display().to_string(),
            "--bus-url".into(),
            "http://127.0.0.1:1".into(),
        ])
        .await
        .unwrap_err();
        assert!(
            matches!(error, RuntimeError::Io(ref cause) if cause.kind() == std::io::ErrorKind::NotFound)
        );
        assert!(!root.path().join("state/local-bus-process.json").exists());
        assert!(!root.path().join("state/Chinwag Alpha.app").exists());
    }

    #[test]
    fn signed_timeline_cannot_point_at_a_different_bus() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(repo.join(".chinwag/bus")).unwrap();
        let own = repo.join(".chinwag/bus/messages.jsonl");
        std::fs::write(&own, b"").unwrap();
        let other = root.path().join("other.jsonl");
        std::fs::write(&other, b"").unwrap();
        assert!(verify_signer_ledger(&own, &repo).is_ok());
        assert!(verify_signer_ledger(&other, &repo).is_err());
        let alias = root.path().join("alias.jsonl");
        std::os::unix::fs::symlink(&own, &alias).unwrap();
        assert!(verify_signer_ledger(&alias, &repo).is_err());
    }
}
