#[cfg(target_os = "macos")]
use chinwag_alpha_runtime::onboarding::OnboardingService;
use chinwag_alpha_runtime::{
    Result, RuntimeConfig, RuntimeError, RuntimeMode, launcher, server, signed::CliSignedSender,
};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

mod export_cli;

fn main() {
    if let Err(error) = dispatch(std::env::args().skip(1).collect()) {
        eprintln!("chinwag-alpha-runtime: {error}");
        std::process::exit(1);
    }
}

fn dispatch(mut args: Vec<String>) -> Result<()> {
    if args
        .first()
        .is_some_and(|command| command == "export-connector")
    {
        return export_cli::run(&args[1..]);
    }
    let native_main_loop = take_native_main_loop(&mut args)?;
    let journal = onboarding_journal(&args, native_main_loop)?;
    cursor_mcp_options(&args, native_main_loop, journal.as_deref())?;
    vscode_mcp_options(&args, native_main_loop, journal.as_deref())?;
    http_mcp_capability_file(&args)?;
    if native_main_loop {
        #[cfg(target_os = "macos")]
        {
            return chinwag_native_launch::main_loop::run_main_loop_host(move || {
                run_async(args, true)
            })
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        }
        #[cfg(not(target_os = "macos"))]
        return Err(RuntimeError::Unavailable(
            "native main-loop hosting requires macOS".into(),
        ));
    }
    run_async(args, false)
}

fn run_async(args: Vec<String>, native_main_loop: bool) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(args, native_main_loop))
}

/// Native main-loop ownership is opt-in and changes no launch permissions.
/// Validate before initializing any runtime mode, storage or signer adapter.
fn take_native_main_loop(args: &mut Vec<String>) -> Result<bool> {
    let flags: Vec<_> = args
        .iter()
        .enumerate()
        .filter(|(_, value)| value.as_str() == "--native-main-loop")
        .map(|(index, _)| index)
        .collect();
    let Some(&index) = flags.first() else {
        return Ok(false);
    };
    if flags.len() != 1
        || !matches!(
            args.first().map(String::as_str),
            Some("serve-local" | "serve-shared")
        )
    {
        return Err(RuntimeError::Invalid(
            "--native-main-loop is accepted once with serve-local or serve-shared".into(),
        ));
    }
    args.remove(index);
    Ok(true)
}

fn onboarding_journal(args: &[String], native_main_loop: bool) -> Result<Option<PathBuf>> {
    let positions: Vec<_> = args
        .iter()
        .enumerate()
        .filter(|(_, value)| value.as_str() == "--onboarding-journal")
        .map(|(index, _)| index)
        .collect();
    let Some(&index) = positions.first() else {
        return Ok(None);
    };
    if positions.len() != 1
        || !native_main_loop
        || !matches!(
            args.first().map(String::as_str),
            Some("serve-local" | "serve-shared")
        )
    {
        return Err(RuntimeError::Invalid("--onboarding-journal requires one explicit --native-main-loop with serve-local or serve-shared".into()));
    }
    let path = args
        .get(index + 1)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            RuntimeError::Invalid("--onboarding-journal requires an absolute directory".into())
        })?;
    Ok(Some(path))
}

#[derive(Debug, PartialEq, Eq)]
struct McpOptions {
    binary: PathBuf,
    journal: PathBuf,
}

// Validate explicit opt-ins before initializing any bus mode, storage or signer.
fn cursor_mcp_options(
    args: &[String],
    native_main_loop: bool,
    opening_journal: Option<&std::path::Path>,
) -> Result<Option<McpOptions>> {
    mcp_setup_options(args, native_main_loop, opening_journal, "cursor", "Cursor")
}

fn vscode_mcp_options(
    args: &[String],
    native_main_loop: bool,
    opening_journal: Option<&std::path::Path>,
) -> Result<Option<McpOptions>> {
    let options = mcp_setup_options(args, native_main_loop, opening_journal, "vscode", "VS Code")?;
    let cursor = cursor_mcp_options(args, native_main_loop, opening_journal)?;
    if options
        .as_ref()
        .zip(cursor.as_ref())
        .is_some_and(|(left, right)| left.journal == right.journal)
    {
        return Err(RuntimeError::Invalid(
            "Cursor and VS Code setup require distinct journals".into(),
        ));
    }
    Ok(options)
}

fn mcp_setup_options(
    args: &[String],
    native_main_loop: bool,
    opening_journal: Option<&std::path::Path>,
    kind: &str,
    label: &str,
) -> Result<Option<McpOptions>> {
    let find = |flag: &str| -> Result<Option<PathBuf>> {
        let positions: Vec<_> = args
            .iter()
            .enumerate()
            .filter(|(_, value)| value.as_str() == flag)
            .map(|(i, _)| i)
            .collect();
        if positions.len() > 1 {
            return Err(RuntimeError::Invalid(format!(
                "{label} setup options must be unique"
            )));
        }
        positions
            .first()
            .map(|i| {
                args.get(i + 1)
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .ok_or_else(|| {
                        RuntimeError::Invalid(format!(
                            "{label} setup requires absolute binary and journal paths"
                        ))
                    })
            })
            .transpose()
    };
    let binary = find(&format!("--{kind}-mcp-binary"))?;
    let journal = find(&format!("--{kind}-mcp-journal"))?;
    match (binary, journal) {
        (None, None) => Ok(None),
        (Some(binary), Some(journal))
            if native_main_loop
                && opening_journal.is_some()
                && matches!(
                    args.first().map(String::as_str),
                    Some("serve-local" | "serve-shared")
                )
                && opening_journal != Some(journal.as_path()) =>
        {
            Ok(Some(McpOptions { binary, journal }))
        }
        _ => Err(RuntimeError::Invalid(format!(
            "{label} setup requires --native-main-loop, --onboarding-journal and paired --{kind}-mcp-binary/--{kind}-mcp-journal with a distinct journal"
        ))),
    }
}

/// Issuing a new owner capability is separate from native app setup. Validate
/// the explicit read-only opt-in before runtime, storage or signer startup.
fn http_mcp_capability_file(args: &[String]) -> Result<Option<PathBuf>> {
    let positions = args
        .iter()
        .enumerate()
        .filter(|(_, value)| value.as_str() == "--mcp-http-capability-file")
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let Some(&position) = positions.first() else {
        return Ok(None);
    };
    if positions.len() != 1
        || args.first().map(String::as_str) != Some("serve-shared")
        || args
            .iter()
            .any(|value| matches!(value.as_str(), "--signed-cli" | "--repo" | "--send-journal"))
    {
        return Err(RuntimeError::Invalid(
            "HTTP MCP requires one explicit capability output with a read-only shared runtime"
                .into(),
        ));
    }
    let file = args
        .get(position + 1)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            RuntimeError::Invalid("HTTP MCP capability output must be an absolute new path".into())
        })?;
    chinwag_alpha_runtime::mcp::validate_capability_path(&file).map_err(|_| {
        RuntimeError::Invalid(
            "HTTP MCP capability output must be a normalized absolute new path".into(),
        )
    })?;
    if args
        .windows(2)
        .any(|pair| pair[0] == "--port" && pair[1].parse::<u16>().ok() == Some(0))
    {
        return Err(RuntimeError::Invalid(
            "HTTP MCP requires a fixed nonzero runtime port".into(),
        ));
    }
    Ok(Some(file))
}

async fn run(args: Vec<String>, native_main_loop: bool) -> Result<()> {
    let onboarding_journal = onboarding_journal(&args, native_main_loop)?;
    let cursor_mcp = cursor_mcp_options(&args, native_main_loop, onboarding_journal.as_deref())?;
    let vscode_mcp = vscode_mcp_options(&args, native_main_loop, onboarding_journal.as_deref())?;
    let http_mcp_file = http_mcp_capability_file(&args)?;
    let Some((command, rest)) = args.split_first() else {
        return Err(RuntimeError::Invalid(
            "use launch, serve-local, serve-shared, discover-clients or export-connector".into(),
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
        "serve-local" => &[
            "--data-dir",
            "--port",
            "--onboarding-journal",
            "--cursor-mcp-binary",
            "--cursor-mcp-journal",
            "--vscode-mcp-binary",
            "--vscode-mcp-journal",
        ],
        "serve-shared" => &[
            "--ledger",
            "--port",
            "--signed-cli",
            "--repo",
            "--send-journal",
            "--onboarding-journal",
            "--cursor-mcp-binary",
            "--cursor-mcp-journal",
            "--vscode-mcp-binary",
            "--vscode-mcp-journal",
            "--mcp-http-capability-file",
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
    let config = RuntimeConfig {
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        mode,
    };
    let mut opening_service = None;
    if let Some(path) = onboarding_journal {
        #[cfg(target_os = "macos")]
        {
            match tokio::task::spawn_blocking(move || OnboardingService::new_native(&path)).await {
                Ok(Ok(service)) => {
                    opening_service = Some(Arc::new(service));
                }
                Ok(Err(_)) | Err(_) => {
                    eprintln!(
                        "chinwag-alpha-runtime: native opening initialization unavailable; bus service continues with opening disabled; no recovery was attempted"
                    );
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = path;
            return Err(RuntimeError::Unavailable(
                "native onboarding requires macOS".into(),
            ));
        }
    }
    let mut cursor_service = None;
    let mut vscode_service = None;
    for (is_vscode, label, options) in
        [(false, "Cursor", cursor_mcp), (true, "VS Code", vscode_mcp)]
    {
        if let Some(options) = options {
            #[cfg(target_os = "macos")]
            {
                let endpoint = format!("http://127.0.0.1:{port}");
                if port != 0 {
                    match tokio::task::spawn_blocking(move || {
                        if is_vscode {
                            OnboardingService::new_vscode_mcp_native(
                                &options.journal,
                                &options.binary,
                                endpoint,
                            )
                        } else {
                            OnboardingService::new_cursor_mcp_native(
                                &options.journal,
                                &options.binary,
                                endpoint,
                            )
                        }
                    })
                    .await
                    {
                        Ok(Ok(service)) => {
                            if is_vscode {
                                vscode_service = Some(Arc::new(service));
                            } else {
                                cursor_service = Some(Arc::new(service));
                            }
                        }
                        Ok(Err(_)) | Err(_) => eprintln!(
                            "chinwag-alpha-runtime: {label} setup initialization unavailable; bus and ordinary opening continue; no recovery was attempted"
                        ),
                    }
                } else {
                    eprintln!(
                        "chinwag-alpha-runtime: {label} setup requires a fixed nonzero runtime port; setup disabled"
                    );
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (is_vscode, label, options);
            }
        }
    }
    if let Some(file) = http_mcp_file {
        server::serve_with_http_mcp(
            config,
            opening_service,
            cursor_service,
            vscode_service,
            file,
        )
        .await
    } else {
        server::serve_with_native_actions(config, opening_service, cursor_service, vscode_service)
            .await
    }
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

    #[test]
    fn http_mcp_is_explicit_read_only_owner_output_before_initialization() {
        let args = |parts: &[&str]| {
            parts
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        assert!(
            http_mcp_capability_file(&args(&["serve-shared"]))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            http_mcp_capability_file(&args(&[
                "serve-shared",
                "--mcp-http-capability-file",
                "/owned/new-capability.json"
            ]))
            .unwrap(),
            Some(PathBuf::from("/owned/new-capability.json")),
        );
        for malformed in [
            "/owned/../new.json".to_owned(),
            "/owned/./new.json".to_owned(),
            "/owned//new.json".to_owned(),
            "/owned/new.json/".to_owned(),
            "/owned/new\n.json".to_owned(),
            format!("/owned/{}", "a".repeat(241)),
            format!("/{}/new.json", "a/".repeat(2050)),
        ] {
            assert!(
                http_mcp_capability_file(&args(&[
                    "serve-shared",
                    "--mcp-http-capability-file",
                    &malformed,
                ]))
                .is_err(),
                "malformed path must reject before runtime initialization"
            );
        }
        for command in [
            "serve-local",
            "launch",
            "discover-clients",
            "export-connector",
        ] {
            assert!(
                http_mcp_capability_file(&args(&[
                    command,
                    "--mcp-http-capability-file",
                    "/owned/new.json"
                ]))
                .is_err()
            );
        }
        for parts in [
            vec!["serve-shared", "--mcp-http-capability-file"],
            vec!["serve-shared", "--mcp-http-capability-file", "relative"],
            vec![
                "serve-shared",
                "--mcp-http-capability-file",
                "/owned/new.json",
                "--mcp-http-capability-file",
                "/owned/another.json",
            ],
            vec![
                "serve-shared",
                "--mcp-http-capability-file",
                "/owned/new.json",
                "--signed-cli",
                "/must/not/run",
            ],
            vec![
                "serve-shared",
                "--mcp-http-capability-file",
                "/owned/new.json",
                "--repo",
                "/must/not/read",
            ],
            vec![
                "serve-shared",
                "--mcp-http-capability-file",
                "/owned/new.json",
                "--send-journal",
                "/must/not/create",
            ],
            vec![
                "serve-shared",
                "--mcp-http-capability-file",
                "/owned/new.json",
                "--port",
                "00",
            ],
        ] {
            assert!(http_mcp_capability_file(&args(&parts)).is_err());
        }
    }

    #[test]
    fn cursor_setup_is_a_paired_distinct_owner_opt_in_before_dispatch() {
        let values = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let valid = values(&[
            "serve-shared",
            "--cursor-mcp-binary",
            "/fixture/mcp",
            "--cursor-mcp-journal",
            "/fixture/cursor",
        ]);
        let ordinary = std::path::Path::new("/fixture/ordinary");
        assert_eq!(
            cursor_mcp_options(&valid, true, Some(ordinary)).unwrap(),
            Some(McpOptions {
                binary: "/fixture/mcp".into(),
                journal: "/fixture/cursor".into(),
            })
        );
        assert!(cursor_mcp_options(&valid, false, Some(ordinary)).is_err());
        assert!(cursor_mcp_options(&valid, true, None).is_err());
        assert!(
            cursor_mcp_options(&valid, true, Some(std::path::Path::new("/fixture/cursor")))
                .is_err()
        );
        for bad in [
            values(&["serve-shared", "--cursor-mcp-binary", "/fixture/mcp"]),
            values(&["serve-shared", "--cursor-mcp-journal", "/fixture/cursor"]),
            values(&[
                "serve-shared",
                "--cursor-mcp-binary",
                "relative",
                "--cursor-mcp-journal",
                "/fixture/cursor",
            ]),
            values(&[
                "launch",
                "--cursor-mcp-binary",
                "/fixture/mcp",
                "--cursor-mcp-journal",
                "/fixture/cursor",
            ]),
            values(&[
                "discover-clients",
                "--cursor-mcp-binary",
                "/fixture/mcp",
                "--cursor-mcp-journal",
                "/fixture/cursor",
            ]),
            values(&[
                "serve-local",
                "--cursor-mcp-binary",
                "/fixture/mcp",
                "--cursor-mcp-binary",
                "/fixture/mcp",
                "--cursor-mcp-journal",
                "/fixture/cursor",
            ]),
        ] {
            assert!(cursor_mcp_options(&bad, true, Some(ordinary)).is_err());
        }
        assert!(
            cursor_mcp_options(&values(&["serve-shared"]), false, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn native_main_loop_flag_is_explicit_and_preserves_server_arguments() {
        let mut default = vec![
            "serve-shared".into(),
            "--ledger".into(),
            "/fixture/ledger".into(),
        ];
        let original = default.clone();
        assert!(!take_native_main_loop(&mut default).unwrap());
        assert_eq!(default, original);
        for command in ["serve-local", "serve-shared"] {
            let mut args = vec![
                command.into(),
                "--native-main-loop".into(),
                "--port".into(),
                "44343".into(),
            ];
            assert!(take_native_main_loop(&mut args).unwrap());
            assert_eq!(args, [command, "--port", "44343"]);
        }
    }

    #[test]
    fn invalid_native_host_flags_reject_without_touching_existing_dispatch() {
        for input in [
            vec!["launch", "--native-main-loop"],
            vec!["discover-clients", "--native-main-loop"],
            vec!["--native-main-loop"],
            vec!["serve-shared", "--native-main-loop", "--native-main-loop"],
        ] {
            let mut args: Vec<String> = input.iter().map(|value| (*value).into()).collect();
            let original = args.clone();
            assert!(take_native_main_loop(&mut args).is_err());
            assert_eq!(args, original);
        }
    }

    #[test]
    fn onboarding_journal_requires_explicit_native_host_and_absolute_scope() {
        let ordinary = vec![
            "serve-local".into(),
            "--data-dir".into(),
            "/fixture/state".into(),
        ];
        assert_eq!(onboarding_journal(&ordinary, false).unwrap(), None);
        let opted_in = vec![
            "serve-local".into(),
            "--onboarding-journal".into(),
            "/fixture/open-journal".into(),
        ];
        assert!(onboarding_journal(&opted_in, false).is_err());
        assert_eq!(
            onboarding_journal(&opted_in, true).unwrap(),
            Some(PathBuf::from("/fixture/open-journal"))
        );
        for input in [
            vec!["launch", "--onboarding-journal", "/fixture/journal"],
            vec![
                "discover-clients",
                "--onboarding-journal",
                "/fixture/journal",
            ],
            vec!["serve-local", "--onboarding-journal"],
            vec!["serve-local", "--onboarding-journal", "relative"],
            vec![
                "serve-local",
                "--onboarding-journal",
                "/fixture/journal",
                "--onboarding-journal",
                "/fixture/other",
            ],
        ] {
            let args: Vec<String> = input.into_iter().map(str::to_owned).collect();
            assert!(onboarding_journal(&args, true).is_err());
        }
    }

    #[tokio::test]
    async fn invalid_onboarding_optin_rejects_before_any_storage_or_signer_validation() {
        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("new-opening-journal");
        let error = run(
            vec![
                "serve-shared".into(),
                "--ledger".into(),
                "/missing-ledger".into(),
                "--repo".into(),
                "/missing-repo".into(),
                "--signed-cli".into(),
                "/missing-signer".into(),
                "--onboarding-journal".into(),
                journal.display().to_string(),
            ],
            false,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, RuntimeError::Invalid(ref detail) if detail.contains("--native-main-loop"))
        );
        assert!(!journal.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
    #[tokio::test]
    async fn launcher_under_async_dispatch_returns_a_normal_missing_binary_error() {
        let root = tempfile::tempdir().unwrap();
        let error = run(
            vec![
                "launch".into(),
                "--state-dir".into(),
                root.path().join("state").display().to_string(),
                "--desktop".into(),
                root.path().join("absent-desktop").display().to_string(),
                "--bus-url".into(),
                "http://127.0.0.1:1".into(),
            ],
            false,
        )
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

    #[test]
    fn vscode_setup_requires_its_own_paired_owner_opt_in() {
        let values = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let ordinary = std::path::Path::new("/fixture/open");
        let valid = values(&[
            "serve-shared",
            "--vscode-mcp-binary",
            "/fixture/mcp",
            "--vscode-mcp-journal",
            "/fixture/vscode",
        ]);
        assert_eq!(
            vscode_mcp_options(&valid, true, Some(ordinary)).unwrap(),
            Some(McpOptions {
                binary: "/fixture/mcp".into(),
                journal: "/fixture/vscode".into()
            })
        );
        assert!(vscode_mcp_options(&valid, false, Some(ordinary)).is_err());
        assert!(vscode_mcp_options(&valid, true, None).is_err());
        assert!(
            vscode_mcp_options(&valid, true, Some(std::path::Path::new("/fixture/vscode")))
                .is_err()
        );
        for invalid in [
            values(&["serve-local", "--vscode-mcp-binary", "/fixture/mcp"]),
            values(&["serve-local", "--vscode-mcp-journal", "/fixture/vscode"]),
            values(&[
                "serve-shared",
                "--vscode-mcp-binary",
                "relative",
                "--vscode-mcp-journal",
                "/fixture/vscode",
            ]),
            values(&[
                "launch",
                "--vscode-mcp-binary",
                "/fixture/mcp",
                "--vscode-mcp-journal",
                "/fixture/vscode",
            ]),
            values(&[
                "serve-local",
                "--vscode-mcp-binary",
                "/fixture/mcp",
                "--vscode-mcp-binary",
                "/fixture/mcp",
                "--vscode-mcp-journal",
                "/fixture/vscode",
            ]),
            values(&[
                "serve-shared",
                "--vscode-mcp-binary",
                "/fixture/mcp",
                "--vscode-mcp-journal",
                "/fixture/setup",
                "--cursor-mcp-binary",
                "/fixture/mcp",
                "--cursor-mcp-journal",
                "/fixture/setup",
            ]),
        ] {
            assert!(vscode_mcp_options(&invalid, true, Some(ordinary)).is_err());
        }
        assert!(
            vscode_mcp_options(&values(&["serve-shared"]), false, None)
                .unwrap()
                .is_none()
        );
        let paired = values(&[
            "serve-shared",
            "--vscode-mcp-binary",
            "/fixture/mcp",
            "--vscode-mcp-journal",
            "/fixture/vscode",
            "--cursor-mcp-binary",
            "/fixture/mcp",
            "--cursor-mcp-journal",
            "/fixture/cursor",
        ]);
        assert!(
            vscode_mcp_options(&paired, true, Some(ordinary))
                .unwrap()
                .is_some()
        );
    }
}
