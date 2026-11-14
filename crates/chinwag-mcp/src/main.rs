//! Thin CLI driver for the callable Rust MCP server (`local-repository` & `blind-org`).
#![forbid(unsafe_code)]
use chinwag_mcp_private_anchored::{
    McpProfile, run_private_repository_stdio, run_stdio_with_profile,
};
use std::{error::Error, ffi::OsString, path::PathBuf, str::FromStr};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match parse_cli_args(&args)? {
        CliAction::LegacyPrivateRepository(path) => run_private_repository_stdio(path),
        CliAction::Profiled {
            profile,
            repository,
        } => run_stdio_with_profile(profile, repository, false),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CliAction {
    LegacyPrivateRepository(PathBuf),
    Profiled {
        profile: McpProfile,
        repository: Option<PathBuf>,
    },
}

fn parse_cli_args(args: &[OsString]) -> Result<CliAction, Box<dyn Error>> {
    if args.is_empty() {
        return Err(
            "Expected `serve-private-repository <path> [--profile local-repository]` or `[serve-blind-org] --profile blind-org`"
                .into(),
        );
    }

    if args.len() == 2 && args[0] == "serve-private-repository" {
        return Ok(CliAction::LegacyPrivateRepository(PathBuf::from(&args[1])));
    }

    let mut profile: Option<McpProfile> = None;
    let mut repository: Option<PathBuf> = None;
    let mut subcommand: Option<String> = None;

    let mut idx = 0;
    while idx < args.len() {
        let token = args[idx].to_str().ok_or("CLI flag must be valid UTF-8")?;
        match token {
            "--profile" => {
                let raw = args
                    .get(idx + 1)
                    .ok_or("Missing value after --profile")?
                    .to_str()
                    .ok_or("--profile value must be valid UTF-8")?;
                profile = Some(McpProfile::from_str(raw)?);
                idx += 2;
            }
            arg if arg.starts_with("--profile=") => {
                let raw = &arg["--profile=".len()..];
                profile = Some(McpProfile::from_str(raw)?);
                idx += 1;
            }
            "serve-private-repository" if subcommand.is_none() => {
                subcommand = Some("serve-private-repository".into());
                let repo = args
                    .get(idx + 1)
                    .ok_or("Missing repository path after serve-private-repository")?;
                repository = Some(PathBuf::from(repo));
                idx += 2;
            }
            "serve-blind-org" if subcommand.is_none() => {
                subcommand = Some("serve-blind-org".into());
                idx += 1;
            }
            other => {
                return Err(format!("Unexpected MCP CLI argument: {other}").into());
            }
        }
    }

    let resolved_profile = match (subcommand.as_deref(), profile) {
        (Some("serve-blind-org"), None | Some(McpProfile::BlindOrg)) => McpProfile::BlindOrg,
        (Some("serve-blind-org"), Some(McpProfile::LocalRepository)) => {
            return Err(
                "serve-blind-org cannot be combined with --profile local-repository".into(),
            );
        }
        (Some("serve-private-repository"), None | Some(McpProfile::LocalRepository)) => {
            McpProfile::LocalRepository
        }
        (Some("serve-private-repository"), Some(McpProfile::BlindOrg)) => {
            return Err("blind-org profile refuses local repository paths".into());
        }
        (None, Some(explicit)) => explicit,
        (None, None) => {
            return Err("Missing MCP subcommand or --profile flag".into());
        }
        _ => return Err("Unsupported MCP CLI invocation".into()),
    };

    Ok(CliAction::Profiled {
        profile: resolved_profile,
        repository,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_legacy_and_profiled_invocations() {
        assert_eq!(
            parse_cli_args(&os(&["serve-private-repository", "/tmp/repo"])).unwrap(),
            CliAction::LegacyPrivateRepository(PathBuf::from("/tmp/repo"))
        );
        assert_eq!(
            parse_cli_args(&os(&[
                "serve-private-repository",
                "/tmp/repo",
                "--profile",
                "local-repository"
            ]))
            .unwrap(),
            CliAction::Profiled {
                profile: McpProfile::LocalRepository,
                repository: Some(PathBuf::from("/tmp/repo")),
            }
        );
        assert_eq!(
            parse_cli_args(&os(&["--profile", "blind-org"])).unwrap(),
            CliAction::Profiled {
                profile: McpProfile::BlindOrg,
                repository: None,
            }
        );
        assert_eq!(
            parse_cli_args(&os(&["serve-blind-org"])).unwrap(),
            CliAction::Profiled {
                profile: McpProfile::BlindOrg,
                repository: None,
            }
        );
        assert!(
            parse_cli_args(&os(&[
                "serve-private-repository",
                "/tmp/repo",
                "--profile=blind-org"
            ]))
            .is_err()
        );
    }
}
