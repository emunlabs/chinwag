use std::{
    ffi::OsString,
    fmt,
    path::{Component, Path, PathBuf},
};

/// Explicit owner declarations only. Parsing performs no IO, construction,
/// environment fallback, native work or provider configuration changes.
pub(crate) struct TeamLaunch {
    pub(crate) config: PathBuf,
    pub(crate) state_root: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LaunchError;
impl fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("use team-work --config ABSOLUTE_FILE --state-root ABSOLUTE_DIRECTORY")
    }
}

pub(crate) fn parse(args: Vec<OsString>) -> Result<Option<TeamLaunch>, LaunchError> {
    if args.first().is_none_or(|arg| arg != "team-work") {
        return Ok(None);
    }
    let (mut config, mut state_root) = (None, None);
    let mut index = 1;
    while index < args.len() {
        let slot = match args[index].to_str() {
            Some("--config") => &mut config,
            Some("--state-root") => &mut state_root,
            _ => return Err(LaunchError),
        };
        let value = args.get(index + 1).ok_or(LaunchError)?;
        let path = PathBuf::from(value);
        if slot.is_some()
            || value.to_str().is_some_and(|text| text.starts_with("--"))
            || !valid_path(&path)
        {
            return Err(LaunchError);
        }
        *slot = Some(path);
        index += 2;
    }
    let config = config.ok_or(LaunchError)?;
    let state_root = state_root.ok_or(LaunchError)?;
    if config == state_root {
        return Err(LaunchError);
    }
    Ok(Some(TeamLaunch { config, state_root }))
}

fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 4096
        && path
            .to_str()
            .is_some_and(|text| !text.chars().any(char::is_control))
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
        && path.file_name().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(extra: &[&str]) -> Vec<OsString> {
        [
            "team-work",
            "--config",
            "/owner/team.json",
            "--state-root",
            "/owner/team-state",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(Into::into)
        .collect()
    }
    #[test]
    fn entry_is_explicit_and_requires_both_owned_paths() {
        assert!(parse(Vec::new()).unwrap().is_none());
        assert!(parse(vec!["codex-work".into()]).unwrap().is_none());
        let declaration = parse(args(&[])).unwrap().unwrap();
        assert_eq!(declaration.config, Path::new("/owner/team.json"));
        assert_eq!(declaration.state_root, Path::new("/owner/team-state"));
        for arguments in [
            vec!["team-work".into()],
            vec![
                "team-work".into(),
                "--config".into(),
                "/owner/team.json".into(),
            ],
        ] {
            assert!(parse(arguments).is_err());
        }
    }
    #[test]
    fn rejects_duplicates_missing_values_and_unrequested_runtime_options() {
        for extra in [
            vec!["--config", "/other"],
            vec!["--state-root", "/other"],
            vec!["--config"],
            vec!["--state-root", "--config"],
        ] {
            assert!(parse(args(&extra)).is_err());
        }
        for flag in [
            "--command",
            "--env",
            "--model",
            "--provider",
            "--session-id",
            "--owner-socket",
            "--binary",
            "--start",
            "--send",
            "--resume",
            "--url",
        ] {
            assert!(parse(args(&[flag, "value"])).is_err());
        }
    }
    #[test]
    fn paths_are_normalized_absolute_and_distinct_without_touching_files() {
        for (index, invalid) in [
            (2, "relative.json"),
            (2, "/owner/./team.json"),
            (2, "/owner//team.json"),
            (4, "/owner/../state"),
            (4, "/"),
            (4, "/owner/team.json"),
        ] {
            let mut arguments = args(&[]);
            arguments[index] = invalid.into();
            assert!(parse(arguments).is_err(), "reject {invalid}");
        }
    }
    #[test]
    #[cfg(unix)]
    fn non_utf8_declarations_are_rejected() {
        use std::os::unix::ffi::OsStringExt as _;
        let mut arguments = args(&[]);
        arguments[2] = OsString::from_vec(b"/owner/\xff.json".to_vec());
        assert!(parse(arguments).is_err());
    }
}
