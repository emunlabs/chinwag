//! CLI entrypoint for `chinwag-plugin-pack` (`build` and `verify`).
#![forbid(unsafe_code)]

use chinwag_plugin_pack::{
    compiler::build_deterministic_release,
    manifest::{LoadedCanonicalBundle, read_regular_file_no_symlink},
    verification::{NativeValidatorMode, verify_release_dir},
};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

fn main() -> ExitCode {
    match run() {
        Ok(json_output) => {
            println!("{json_output}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("chinwag-plugin-pack error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = parse_args(&args)?;
    match parsed {
        CliCommand::Build {
            manifest,
            out,
            signing_seed_file,
            verify,
            native_mode,
        } => {
            let summary = build_deterministic_release(
                &manifest,
                &out,
                signing_seed_file.as_deref(),
                verify,
                native_mode,
            )
            .map_err(|e| e.to_string())?;
            serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())
        }
        CliCommand::Verify {
            manifest,
            out,
            expected_pubkey_hex,
            verifying_key_file,
            native_mode,
        } => {
            let expected_pk = resolve_expected_pubkey(
                expected_pubkey_hex.as_deref(),
                verifying_key_file.as_deref(),
            )?;
            let bundle = LoadedCanonicalBundle::load(&manifest).map_err(|e| e.to_string())?;
            let report = verify_release_dir(&out, &bundle, expected_pk.as_ref(), native_mode)
                .map_err(|e| e.to_string())?;
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CliCommand {
    Build {
        manifest: PathBuf,
        out: PathBuf,
        signing_seed_file: Option<PathBuf>,
        verify: bool,
        native_mode: NativeValidatorMode,
    },
    Verify {
        manifest: PathBuf,
        out: PathBuf,
        expected_pubkey_hex: Option<String>,
        verifying_key_file: Option<PathBuf>,
        native_mode: NativeValidatorMode,
    },
}

fn resolve_expected_pubkey(
    pubkey_hex: Option<&str>,
    key_file: Option<&Path>,
) -> Result<Option<[u8; 32]>, String> {
    if pubkey_hex.is_some() && key_file.is_some() {
        return Err("Pass at most one of `--expected-pubkey-hex` or `--verifying-key-file`".into());
    }
    if let Some(hex_str) = pubkey_hex {
        return decode_pubkey_32_hex(hex_str.trim()).map(Some);
    }
    if let Some(path) = key_file {
        let bytes = read_regular_file_no_symlink(path).map_err(|e| e.to_string())?;
        if bytes.len() == 32 {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes);
            return Ok(Some(pk));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "verifying key file must be 32 raw bytes or 64 hex chars".to_owned())?;
        return decode_pubkey_32_hex(text.trim()).map(Some);
    }
    Ok(None)
}

fn decode_pubkey_32_hex(trimmed: &str) -> Result<[u8; 32], String> {
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected verifying public key to be 64 hexadecimal characters".into());
    }
    let decoded = hex::decode(trimmed).map_err(|e| format!("invalid verifying key hex: {e}"))?;
    decoded
        .try_into()
        .map_err(|_| "expected 32-byte Ed25519 verifying key".to_owned())
}

fn parse_args(args: &[String]) -> Result<CliCommand, String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err(
            "Usage: chinwag-plugin-pack <build|verify> [--manifest <path>] [--out <dir>] [--verify]"
                .into(),
        );
    };
    let mut manifest = PathBuf::from("plugins/canonical/chinwag-plugin.toml");
    let mut out: Option<PathBuf> = None;
    let mut signing_seed_file: Option<PathBuf> = None;
    let mut expected_pubkey_hex: Option<String> = None;
    let mut verifying_key_file: Option<PathBuf> = None;
    let mut verify = false;
    let mut native_mode = NativeValidatorMode::Auto;

    let mut i = 1usize;
    while i < args.len() {
        let arg = args[i].as_str();
        let flag_name = arg.split('=').next().unwrap_or(arg);
        // Never allow raw private keys, seeds, or bearer secrets on command-line argv (`ROG-580`).
        if matches!(
            flag_name,
            "--signing-key"
                | "--private-key"
                | "--seed"
                | "--signing-seed"
                | "--secret"
                | "--token"
        ) {
            return Err(
                "Refusing secret material on command-line argv; pass --signing-seed-file <path>"
                    .into(),
            );
        }
        match arg {
            "--manifest" => {
                let v = args.get(i + 1).ok_or("Missing value for --manifest")?;
                manifest = PathBuf::from(v);
                i += 2;
            }
            "--out" => {
                let v = args.get(i + 1).ok_or("Missing value for --out")?;
                out = Some(PathBuf::from(v));
                i += 2;
            }
            "--signing-seed-file" => {
                let v = args
                    .get(i + 1)
                    .ok_or("Missing value for --signing-seed-file")?;
                signing_seed_file = Some(PathBuf::from(v));
                i += 2;
            }
            "--expected-pubkey-hex" => {
                let v = args
                    .get(i + 1)
                    .ok_or("Missing value for --expected-pubkey-hex")?;
                expected_pubkey_hex = Some(v.clone());
                i += 2;
            }
            "--verifying-key-file" => {
                let v = args
                    .get(i + 1)
                    .ok_or("Missing value for --verifying-key-file")?;
                verifying_key_file = Some(PathBuf::from(v));
                i += 2;
            }
            "--verify" => {
                verify = true;
                i += 1;
            }
            "--require-native-validators" => {
                native_mode = NativeValidatorMode::RequireAll;
                i += 1;
            }
            "--skip-native-validators" => {
                native_mode = NativeValidatorMode::Skip;
                i += 1;
            }
            _ => {
                // Never echo any `=<value>` payload into error logs or stderr (`ROG-580`).
                return Err(format!("Unknown argument `{flag_name}`"));
            }
        }
    }

    match sub {
        "build" => {
            if expected_pubkey_hex.is_some() || verifying_key_file.is_some() {
                return Err(
                    "`--expected-pubkey-hex` / `--verifying-key-file` are only valid on `verify`"
                        .into(),
                );
            }
            Ok(CliCommand::Build {
                manifest,
                out: out.unwrap_or_else(|| PathBuf::from("dist/plugins")),
                signing_seed_file,
                verify,
                native_mode,
            })
        }
        "verify" => {
            if signing_seed_file.is_some() {
                return Err("`--signing-seed-file` is only valid on `build`".into());
            }
            let out = out.ok_or("`verify` subcommand requires `--out <dir>`")?;
            Ok(CliCommand::Verify {
                manifest,
                out,
                expected_pubkey_hex,
                verifying_key_file,
                native_mode,
            })
        }
        other => {
            let sub_only = other.split('=').next().unwrap_or(other);
            Err(format!(
                "Unknown subcommand `{sub_only}` (expected `build` or `verify`)"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_rejects_inline_argv_secrets_and_parses_build_verify() {
        let ok = parse_args(&[
            "build".into(),
            "--manifest".into(),
            "plugins/canonical/chinwag-plugin.toml".into(),
            "--out".into(),
            "/tmp/out".into(),
            "--verify".into(),
        ])
        .unwrap();
        assert_eq!(
            ok,
            CliCommand::Build {
                manifest: PathBuf::from("plugins/canonical/chinwag-plugin.toml"),
                out: PathBuf::from("/tmp/out"),
                signing_seed_file: None,
                verify: true,
                native_mode: NativeValidatorMode::Auto,
            }
        );

        let verify_ok = parse_args(&[
            "verify".into(),
            "--out".into(),
            "/tmp/out".into(),
            "--expected-pubkey-hex".into(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
        ])
        .unwrap();
        assert_eq!(
            verify_ok,
            CliCommand::Verify {
                manifest: PathBuf::from("plugins/canonical/chinwag-plugin.toml"),
                out: PathBuf::from("/tmp/out"),
                expected_pubkey_hex: Some(
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into()
                ),
                verifying_key_file: None,
                native_mode: NativeValidatorMode::Auto,
            }
        );

        for bad in ["--signing-key", "--private-key", "--seed", "--signing-seed"] {
            let err =
                parse_args(&["build".into(), bad.into(), "deadbeefsecret".into()]).unwrap_err();
            assert!(!err.contains("deadbeefsecret"));

            let eq_err =
                parse_args(&["build".into(), format!("{bad}=deadbeefsecret")]).unwrap_err();
            assert!(!eq_err.contains("deadbeefsecret"));
        }

        let unk_err =
            parse_args(&["build".into(), "--mystery-flag=topsecretvalue".into()]).unwrap_err();
        assert!(!unk_err.contains("topsecretvalue"));
    }
}
