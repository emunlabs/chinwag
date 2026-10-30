use chinwag_codex_steer::{Result, RuntimePolicyDeclaration, SteerError, WorkConfig};
use std::{ffi::OsString, path::PathBuf};

/// No default listener, home-directory search or process launch. These are
/// declarations from the human's explicit native invocation, not task text.
pub(crate) fn parse(args: Vec<OsString>) -> Result<Option<WorkConfig>> {
    if args.first().is_none_or(|arg| arg != "codex-work") {
        return Ok(None);
    }
    let (mut socket, mut cwd, mut journal) = (None, None, None);
    let (mut dedicated, mut explicit_login) = (false, false);
    let mut index = 1;
    while index < args.len() {
        match args[index].to_str() {
            Some("--dedicated-runtime") if !dedicated => {
                dedicated = true;
                index += 1;
            }
            Some("--explicit-login-policy") if !explicit_login => {
                explicit_login = true;
                index += 1;
            }
            Some(flag @ ("--owner-socket" | "--workdir" | "--journal")) => {
                let value = args.get(index + 1).ok_or(SteerError::InvalidInput)?;
                if value.to_str().is_some_and(|v| v.starts_with("--")) {
                    return Err(SteerError::InvalidInput);
                }
                let slot = match flag {
                    "--owner-socket" => &mut socket,
                    "--workdir" => &mut cwd,
                    _ => &mut journal,
                };
                if slot.is_some() {
                    return Err(SteerError::InvalidInput);
                }
                *slot = Some(PathBuf::from(value));
                index += 2;
            }
            _ => return Err(SteerError::InvalidInput),
        }
    }
    if !dedicated || !explicit_login {
        return Err(SteerError::PermissionDenied);
    }
    Ok(Some(WorkConfig::new(
        &socket.ok_or(SteerError::InvalidInput)?,
        &cwd.ok_or(SteerError::InvalidInput)?,
        &journal.ok_or(SteerError::InvalidInput)?,
        RuntimePolicyDeclaration::DedicatedRuntimeWithExplicitLogin,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(extra: &[&str]) -> Vec<OsString> {
        [
            "codex-work",
            "--owner-socket",
            "/owner/listener.sock",
            "--workdir",
            "/owner/project",
            "--journal",
            "/owner/work-journal",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(Into::into)
        .collect()
    }
    #[test]
    fn requires_explicit_runtime_and_policy_declarations() {
        assert!(matches!(
            parse(args(&[])),
            Err(SteerError::PermissionDenied)
        ));
        assert!(
            parse(args(&["--dedicated-runtime", "--explicit-login-policy"]))
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn no_default_discovery_or_model_command_options() {
        assert!(parse(vec![]).unwrap().is_none());
        assert!(
            parse(vec!["--old-workbench-setting".into()])
                .unwrap()
                .is_none()
        );
        for flag in [
            "--model",
            "--resume",
            "--command",
            "--daemon-shutdown",
            "--env",
        ] {
            assert!(
                parse(args(&[
                    "--dedicated-runtime",
                    "--explicit-login-policy",
                    flag,
                    "arbitrary"
                ]))
                .is_err()
            );
        }
    }
    #[test]
    fn duplicate_and_relative_paths_fail_before_service_creation() {
        assert!(
            parse(args(&[
                "--dedicated-runtime",
                "--explicit-login-policy",
                "--journal",
                "/other"
            ]))
            .is_err()
        );
        let mut values = args(&["--dedicated-runtime", "--explicit-login-policy"]);
        values[2] = "relative.sock".into();
        assert!(parse(values).is_err());
    }
}
