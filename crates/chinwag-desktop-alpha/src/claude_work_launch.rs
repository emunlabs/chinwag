use chinwag_claude_control::{ClaudeError, Result, StartupPolicyDeclaration, WorkConfig};
use std::{ffi::OsString, path::PathBuf};

/// Parse only a human's explicit native invocation. No discovery, environment
/// fallback, binary execution or service mounting occurs here.
pub(crate) fn parse(args: Vec<OsString>) -> Result<Option<WorkConfig>> {
    if args.first().is_none_or(|arg| arg != "claude-work") {
        return Ok(None);
    }
    let (mut binary, mut digest, mut workdir, mut journal) = (None, None, None, None);
    let mut policy = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].to_str() {
            Some("--managed-policy-prose-only") if !policy => {
                policy = true;
                index += 1;
            }
            Some(flag @ ("--claude-binary" | "--claude-sha256" | "--workdir" | "--journal")) => {
                let value = args.get(index + 1).ok_or(ClaudeError::InvalidInput)?;
                if value.to_str().is_some_and(|value| value.starts_with("--")) {
                    return Err(ClaudeError::InvalidInput);
                }
                if flag == "--claude-sha256" {
                    if digest.is_some() {
                        return Err(ClaudeError::InvalidInput);
                    }
                    digest = Some(value.to_str().ok_or(ClaudeError::InvalidInput)?.to_owned());
                } else {
                    let slot = match flag {
                        "--claude-binary" => &mut binary,
                        "--workdir" => &mut workdir,
                        _ => &mut journal,
                    };
                    if slot.is_some() {
                        return Err(ClaudeError::InvalidInput);
                    }
                    *slot = Some(PathBuf::from(value));
                }
                index += 2;
            }
            _ => return Err(ClaudeError::InvalidInput),
        }
    }
    if !policy {
        return Err(ClaudeError::PermissionDenied);
    }
    Ok(Some(WorkConfig::new(
        &binary.ok_or(ClaudeError::InvalidInput)?,
        &digest.ok_or(ClaudeError::InvalidInput)?,
        &workdir.ok_or(ClaudeError::InvalidInput)?,
        &journal.ok_or(ClaudeError::InvalidInput)?,
        StartupPolicyDeclaration::ManagedPolicyProseOnly,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<OsString> {
        [
            "claude-work",
            "--claude-binary",
            "/owner/bin/claude",
            "--claude-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--workdir",
            "/owner/work",
            "--journal",
            "/owner/claude-journal",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(Into::into)
        .collect()
    }

    #[test]
    fn mode_is_explicit_and_requires_the_managed_policy_declaration() {
        assert!(parse(Vec::new()).unwrap().is_none());
        assert!(parse(vec!["codex-work".into()]).unwrap().is_none());
        assert!(matches!(
            parse(args(&[])),
            Err(ClaudeError::PermissionDenied)
        ));
        assert!(
            parse(args(&["--managed-policy-prose-only"]))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn rejects_duplicates_missing_values_and_unrequested_control_options() {
        for extra in [
            vec!["--managed-policy-prose-only", "--managed-policy-prose-only"],
            vec!["--managed-policy-prose-only", "--journal", "/other"],
            vec!["--managed-policy-prose-only", "--claude-sha256"],
            vec!["--managed-policy-prose-only", "--workdir", "--journal"],
        ] {
            assert!(parse(args(&extra)).is_err());
        }
        for flag in [
            "--model",
            "--env",
            "--command",
            "--resume",
            "--continue",
            "--bare",
            "--dangerously-skip-permissions",
            "--settings",
            "--mcp-config",
            "--args",
        ] {
            assert!(parse(args(&["--managed-policy-prose-only", flag, "value"])).is_err());
        }
    }

    #[test]
    fn requires_exact_digest_and_normalized_absolute_paths() {
        for (index, value) in [
            (2, "relative/claude"),
            (2, "/owner/./claude"),
            (4, "not-a-sha256"),
            (
                4,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            (6, "relative-work"),
            (8, "/owner/../claude-journal"),
        ] {
            let mut values = args(&["--managed-policy-prose-only"]);
            values[index] = value.into();
            assert!(parse(values).is_err(), "must reject {value}");
        }
    }
}
