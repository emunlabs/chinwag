//! Explicit owner export. Runs before runtime, storage, signer or native setup.

use chinwag_alpha_runtime::{
    Result, RuntimeError,
    connector_export::{ConnectorExport, ExportFormat},
};
use std::{collections::HashMap, path::Path};

pub(super) fn run(args: &[String]) -> Result<()> {
    let mut options = HashMap::new();
    if !args.len().is_multiple_of(2) {
        return Err(RuntimeError::Invalid(
            "each export option requires a value".into(),
        ));
    }
    for pair in args.chunks_exact(2) {
        if !["--format", "--mcp-binary", "--bus-url", "--output"].contains(&pair[0].as_str())
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(RuntimeError::Invalid(
                "unknown or repeated export option".into(),
            ));
        }
    }
    let required = |name: &str| -> Result<&str> {
        options.get(name).copied().ok_or_else(|| {
            RuntimeError::Invalid(format!("{name} is required for connector export"))
        })
    };
    let format = match required("--format")? {
        "claude-mcpb" => ExportFormat::ClaudeMcpb,
        "antigravity-plugin" => ExportFormat::AntigravityPlugin,
        _ => {
            return Err(RuntimeError::Invalid(
                "unsupported connector export format".into(),
            ));
        }
    };
    let binary = Path::new(required("--mcp-binary")?);
    let output = Path::new(required("--output")?);
    if !binary.is_absolute() || !output.is_absolute() {
        return Err(RuntimeError::Invalid(
            "export paths must be absolute".into(),
        ));
    }
    let export = ConnectorExport::new(format, binary, required("--bus-url")?)
        .map_err(|error| RuntimeError::Invalid(error.to_string()))?;
    let receipt = export
        .export_new(output)
        .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|_| {
            RuntimeError::Unavailable(
                "export completed but its receipt could not be serialized".into(),
            )
        })?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    #[cfg(target_os = "macos")]
    fn explicit_cli_exports_both_formats_without_a_runtime_or_client() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let binary = root.join("mcp");
        fs::write(&binary, [0xcf, 0xfa, 0xed, 0xfe, 1, 2, 3, 4]).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        for (format, name) in [
            ("claude-mcpb", "inbox.mcpb"),
            ("antigravity-plugin", "plugin"),
        ] {
            let output = root.join(name);
            let args = [
                "--format",
                format,
                "--mcp-binary",
                binary.to_str().unwrap(),
                "--bus-url",
                "http://127.0.0.1:9",
                "--output",
                output.to_str().unwrap(),
            ]
            .map(str::to_owned);
            run(&args).unwrap();
            assert!(output.exists());
            assert!(run(&args).is_err(), "existing output must be preserved");
        }
        assert!(root.join("plugin/plugin.json").is_file());
        assert!(root.join("plugin/mcp.json").is_file());
        assert!(!root.join("ledger").exists());
    }

    #[test]
    fn cli_rejects_implicit_authority_and_repeated_options() {
        for args in [
            vec!["--format", "claude-mcpb", "--native-main-loop", "true"],
            vec!["--format", "claude-mcpb", "--format", "antigravity-plugin"],
            vec!["--format", "claude-mcpb", "--signed-cli", "/never/execute"],
            vec!["--format", "claude-mcpb", "--room", "#eng"],
            vec!["--format", "claude-mcpb", "--lease-seconds", "9000"],
            vec!["--format", "claude-mcpb", "--output"],
            vec!["--format", "unknown"],
        ] {
            assert!(run(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
        }
    }
}
