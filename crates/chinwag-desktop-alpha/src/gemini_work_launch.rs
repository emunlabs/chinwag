use chinwag_gemini_control::{GeminiError, Result, StartupPolicyDeclaration, WorkConfig};
use std::{ffi::OsString, path::PathBuf};

/// Only an explicit, fixed native invocation selects this owned-work mode.
/// Parsing never discovers or starts a process or changes configuration.
pub(crate) fn parse(args: Vec<OsString>) -> Result<Option<WorkConfig>> {
    if args.first().is_none_or(|arg| arg != "gemini-work") {
        return Ok(None);
    }
    let (mut binary, mut digest, mut workdir, mut journal) = (None, None, None, None);
    let mut consent = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].to_str() {
            Some("--configured-runtime-effects") if !consent => {
                consent = true;
                index += 1;
            }
            Some(flag @ ("--gemini-binary" | "--gemini-sha256" | "--workdir" | "--journal")) => {
                let value = args.get(index + 1).ok_or(GeminiError::InvalidInput)?;
                if value.to_str().is_some_and(|value| value.starts_with("--")) {
                    return Err(GeminiError::InvalidInput);
                }
                if flag == "--gemini-sha256" {
                    if digest.is_some() {
                        return Err(GeminiError::InvalidInput);
                    }
                    digest = Some(value.to_str().ok_or(GeminiError::InvalidInput)?.to_owned());
                } else {
                    let slot = match flag {
                        "--gemini-binary" => &mut binary,
                        "--workdir" => &mut workdir,
                        _ => &mut journal,
                    };
                    if slot.is_some() {
                        return Err(GeminiError::InvalidInput);
                    }
                    *slot = Some(PathBuf::from(value));
                }
                index += 2;
            }
            _ => return Err(GeminiError::InvalidInput),
        }
    }
    if !consent {
        return Err(GeminiError::PermissionDenied);
    }
    Ok(Some(WorkConfig::new(
        &binary.ok_or(GeminiError::InvalidInput)?,
        &digest.ok_or(GeminiError::InvalidInput)?,
        &workdir.ok_or(GeminiError::InvalidInput)?,
        &journal.ok_or(GeminiError::InvalidInput)?,
        StartupPolicyDeclaration::ConfiguredRuntimeEffectsManualModeExtensionsDisabled,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<OsString> {
        [
            "gemini-work",
            "--gemini-binary",
            "/owner/bin/gemini",
            "--gemini-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--workdir",
            "/owner/work",
            "--journal",
            "/owner/gemini-journal",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(Into::into)
        .collect()
    }

    #[test]
    fn explicit_mode_requires_configured_runtime_effects_consent() {
        assert!(parse(Vec::new()).unwrap().is_none());
        assert!(parse(vec!["claude-work".into()]).unwrap().is_none());
        assert!(matches!(
            parse(args(&[])),
            Err(GeminiError::PermissionDenied)
        ));
        assert!(
            parse(args(&["--configured-runtime-effects"]))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn rejects_duplicate_missing_and_unrequested_launch_options() {
        for extra in [
            vec![
                "--configured-runtime-effects",
                "--configured-runtime-effects",
            ],
            vec!["--configured-runtime-effects", "--journal", "/other"],
            vec!["--configured-runtime-effects", "--gemini-sha256"],
            vec!["--configured-runtime-effects", "--workdir", "--journal"],
        ] {
            assert!(parse(args(&extra)).is_err());
        }
        for flag in [
            "--model",
            "--env",
            "--command",
            "--resume",
            "--session-id",
            "--settings",
            "--home",
            "--mcp-config",
            "--args",
            "--yolo",
            "--approval-mode",
            "--extensions",
        ] {
            assert!(parse(args(&["--configured-runtime-effects", flag, "value"])).is_err());
        }
    }

    #[test]
    fn rejects_non_normal_paths_and_noncanonical_digest() {
        for (index, value) in [
            (2, "relative/gemini"),
            (2, "/owner/./gemini"),
            (4, "not-a-sha256"),
            (
                4,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            (6, "relative-work"),
            (8, "/owner/../journal"),
        ] {
            let mut values = args(&["--configured-runtime-effects"]);
            values[index] = value.into();
            assert!(parse(values).is_err(), "must reject {value}");
        }
    }
}
