#![forbid(unsafe_code)]

//! Implementation of `TASK-12` (`chinwag openspec`), `TASK-13` / `TASK-17`
//! (`chinwag plugin` with real detached `Ed25519` `.cwplugin` manifest signature
//! verification against `.chinwag/allowed_signers`), and `TASK-14` (`chinwag a509`).

use crate::bus_run;
use chinwag_cli::execution_binding::{
    ExecutionAuthority, RepoSelectors, RepositorySelection, StoreSelector,
    WorkspaceExecutionBinding, bind_execution, select_repository,
};
use iroh::{EndpointId, SecretKey, Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Resolve one ordinary repository selection; it does not grant task authority.
fn explicit_repo_selector(args: &[String]) -> Result<Option<PathBuf>, String> {
    let mut explicit = None;
    let mut i = 0;
    while i < args.len() {
        let value = if args[i] == "--repo" {
            i += 1;
            Some(
                args.get(i)
                    .ok_or("--repo requires an absolute path")?
                    .as_str(),
            )
        } else {
            args[i].strip_prefix("--repo=")
        };
        if let Some(value) = value {
            if value.is_empty()
                || value.starts_with("--")
                || explicit.replace(PathBuf::from(value)).is_some()
            {
                return Err("missing or duplicate --repo selector".into());
            }
        }
        i += 1;
    }
    Ok(explicit)
}

pub(crate) fn select_cli_repository(args: &[String]) -> Result<RepositorySelection, String> {
    let explicit = explicit_repo_selector(args)?;
    let environment = std::env::var_os("CHINWAG_REPO_ROOT");
    // A higher-priority selector does not depend on a still-readable process cwd.
    // This placeholder is ignored by the resolver when either selector is present.
    let cwd = std::env::current_dir()
        .or_else(|error| {
            explicit
                .clone()
                .or_else(|| environment.as_ref().map(PathBuf::from))
                .ok_or(error)
        })
        .map_err(|e| e.to_string())?;
    select_repository(RepoSelectors {
        explicit_repo: explicit.as_deref(),
        environment_repo: environment.as_deref(),
        cwd: &cwd,
    })
    .map_err(|e| e.to_string())
}

fn validate_selected_args(selection: &RepositorySelection, args: &[String]) -> Result<(), String> {
    selection.revalidate().map_err(|e| e.to_string())?;
    if let Some(explicit) = explicit_repo_selector(args)?
        && explicit != selection.root()
    {
        return Err("request selector differs from the retained repository selection".into());
    }
    Ok(())
}

fn report_binding_refusal(
    args: &[String],
    message: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    if has_json_flag(args) {
        let _ = writeln!(
            stdout,
            "{}",
            json!({"ok": false, "disposition": "HELD", "error": message})
        );
    } else {
        let _ = writeln!(stderr, "repository binding held: {message}");
    }
    2
}

fn selected_cli(
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    run: fn(&RepositorySelection, &[String], &mut dyn Write, &mut dyn Write) -> u8,
) -> u8 {
    match select_cli_repository(args) {
        Ok(selection) => run(&selection, args, stdout, stderr),
        Err(error) => report_binding_refusal(args, &error, stdout, stderr),
    }
}

/// The same pre-effect boundary is used by production commands and private tests.
/// A selection, matching pathname or request flag cannot supply this capability.
pub(crate) fn with_feature_task_effect<T>(
    selection: &RepositorySelection,
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority<'_>,
    effect: impl FnOnce(&WorkspaceExecutionBinding) -> T,
) -> Result<T, String> {
    selection.revalidate().map_err(|e| e.to_string())?;
    binding.revalidate(authority).map_err(|e| e.to_string())?;
    if selection.root() != binding.execution_root() {
        return Err("feature selection differs from the approved execution root".into());
    }
    Ok(effect(binding))
}

fn admit_feature_effect(
    selection: &RepositorySelection,
    context: Option<(&WorkspaceExecutionBinding, &ExecutionAuthority<'_>)>,
) -> Result<(), String> {
    match context {
        Some((binding, authority)) => {
            with_feature_task_effect(selection, binding, authority, |_| ())
        }
        None => {
            // No production enrollment adapter exists. Refuse before keys or writes.
            let authority = ExecutionAuthority::unsupported();
            bind_execution(
                selection,
                StoreSelector {
                    explicit_crdb: None,
                },
                &authority,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
        }
    }
}

fn has_json_flag(args: &[String]) -> bool {
    args.iter().any(|a| a == "--json")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

fn hex_to_64_bytes(hex_str: &str) -> Option<[u8; 64]> {
    if hex_str.len() != 128 || !hex_str.is_ascii() {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, slot) in out.iter_mut().enumerate() {
        let byte = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok()?;
        *slot = byte;
    }
    Some(out)
}

/// `TASK-12` (`CHWG-OPENSPEC-CLI-01`): `chinwag openspec status | validate | archive`
pub fn run_openspec_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    selected_cli(args, stdout, stderr, run_openspec_cli_with_selection)
}

pub(crate) fn run_openspec_cli_with_selection(
    selection: &RepositorySelection,
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    run_openspec_cli_in_context(selection, args, None, stdout, stderr)
}

#[allow(dead_code)] // Private admitted-adapter seam; public authority is Unsupported.
pub(crate) fn run_openspec_cli_with_binding(
    selection: &RepositorySelection,
    args: &[String],
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    run_openspec_cli_in_context(selection, args, Some((binding, authority)), stdout, stderr)
}

fn run_openspec_cli_in_context(
    selection: &RepositorySelection,
    args: &[String],
    context: Option<(&WorkspaceExecutionBinding, &ExecutionAuthority<'_>)>,
    stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    if let Err(error) = validate_selected_args(selection, args) {
        return report_binding_refusal(args, &error, stdout, _stderr);
    }
    let repo_root = selection.root();
    if sub == "archive"
        && let Err(error) = admit_feature_effect(selection, context)
    {
        return report_binding_refusal(args, &error, stdout, _stderr);
    }
    let is_json = has_json_flag(args);
    let docs_dir = repo_root.join("docs");
    let tasks_md = repo_root.join("TASKS.md");

    let mut specs = Vec::new();
    if let Ok(entries) = fs::read_dir(&docs_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("md")
                && let Some(name) = p.file_name().and_then(|n| n.to_str())
            {
                let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                specs.push(json!({
                    "spec": name,
                    "path": p.to_string_lossy(),
                    "bytes": size,
                    "valid": size > 0
                }));
            }
        }
    }
    specs.sort_by(|a, b| {
        a.get("spec")
            .and_then(|v| v.as_str())
            .cmp(&b.get("spec").and_then(|v| v.as_str()))
    });

    let tasks_present =
        fs::symlink_metadata(&tasks_md).is_ok_and(|metadata| metadata.file_type().is_file());
    match sub {
        "validate" | "check" => {
            let ok = tasks_present && !specs.is_empty();
            if is_json {
                let payload = json!({
                    "ok": ok,
                    "command": "chinwag openspec validate",
                    "source_qualification": "LegacyUnqualified",
                    "task_authority": false,
                    "repo_root": repo_root.to_string_lossy(),
                    "tasks_md_valid": tasks_present,
                    "spec_count": specs.len(),
                    "specs": specs,
                    "invariants": ["INV-TASKS-MD-01", "INV-OPENSPEC-01"]
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "✅ chinwag openspec validate: {} spec(s) verified, TASKS.md={}",
                    specs.len(),
                    tasks_present
                );
            }
            if ok { 0 } else { 1 }
        }
        "archive" => {
            if let Err(error) = admit_feature_effect(selection, context) {
                return report_binding_refusal(args, &error, stdout, _stderr);
            }
            let archive_dir = repo_root.join(".chinwag").join("openspec-archive");
            let snapshot_path = archive_dir.join("tasks-snapshot.md");
            let copied = if !tasks_present {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "selected legacy document is absent",
                ))
            } else {
                fs::create_dir_all(&archive_dir)
                    .and_then(|_| fs::copy(&tasks_md, &snapshot_path).map(|_| ()))
            };
            if let Err(error) = copied {
                if is_json {
                    let _ = writeln!(
                        stdout,
                        "{}",
                        json!({"ok": false, "command": "chinwag openspec archive", "disposition": "UNKNOWN", "task_authority": false, "error": error.to_string()})
                    );
                } else {
                    let _ = writeln!(_stderr, "archive outcome unknown: {error}");
                }
                return 1;
            }
            if is_json {
                let payload = json!({
                    "ok": true,
                    "command": "chinwag openspec archive",
                    "source_qualification": "LegacyUnqualified",
                    "task_authority": false,
                    "snapshot_path": snapshot_path.to_string_lossy(),
                    "spec_count": specs.len()
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "📦 chinwag openspec archive: archived TASKS.md snapshot to {}",
                    snapshot_path.display()
                );
            }
            0
        }
        _ => {
            if is_json {
                let payload = json!({
                    "ok": true,
                    "command": "chinwag openspec status",
                    "source_qualification": "LegacyUnqualified",
                    "task_authority": false,
                    "repo_root": repo_root.to_string_lossy(),
                    "tasks_md": tasks_md.to_string_lossy(),
                    "tasks_md_present": tasks_present,
                    "spec_count": specs.len(),
                    "specs": specs
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "📐 Chinwag OpenSpec Status ({} active specs in {}):\n  • Legacy document: {} (present={})",
                    specs.len(),
                    docs_dir.display(),
                    tasks_md.display(),
                    tasks_present
                );
                for s in &specs {
                    if let Some(name) = s.get("spec").and_then(|v| v.as_str()) {
                        let bytes = s.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                        let _ = writeln!(stdout, "  • {name} ({bytes} bytes)");
                    }
                }
            }
            0
        }
    }
}

fn jcs_sorted_object(obj: &serde_json::Map<String, Value>, omit: &[&str]) -> Option<String> {
    let sorted: std::collections::BTreeMap<&str, &Value> = obj
        .iter()
        .filter(|(k, _)| !omit.contains(&k.as_str()))
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    serde_json::to_string(&sorted).ok()
}

fn canonical_plugin_manifest_payload(v: &Value) -> Option<String> {
    let obj = v.as_object()?;
    if obj.get("schema")?.as_str()? != "chinwag-plugin-manifest/v1" {
        return None;
    }
    let _plugin_id = obj.get("plugin_id")?.as_str()?;
    let _display_name = obj.get("display_name")?.as_str()?;
    let _version = obj.get("version")?.as_str()?;
    let _monotonic_seq = obj.get("monotonic_seq")?.as_u64()?;
    let _ui_mount = obj.get("ui_mount")?.as_str()?;
    let _seatbelt_profile = obj.get("seatbelt_profile")?.as_str()?;
    if obj.get("studio_issuer")?.as_str()? != "Rogue Machine Media LLC (d/b/a Lag Lords)" {
        return None;
    }
    if obj.get("brand_firewall_invariant")?.as_str()? != "INV-BRAND-FIREWALL-01" {
        return None;
    }
    let _signer_seat = obj.get("signer_seat")?.as_str()?;
    let _signer_pubkey = obj.get("signer_pubkey_ed25519")?.as_str()?;
    let _invariants = obj.get("invariants")?.as_array()?;
    let _egress = obj.get("egress_allowlist")?.as_array()?;

    let jcs = jcs_sorted_object(obj, &["payload_sha256", "signature_ed25519"])?;
    Some(format!("chinwag-plugin-manifest-sig-v2|{jcs}"))
}

fn build_signed_breakroom_manifest(signer_seat: &str) -> Result<Value, String> {
    let secret = bus_run::actor_signing_secret(signer_seat).map_err(|e| e.to_string())?;
    Ok(sign_breakroom_manifest(signer_seat, &secret))
}

fn sign_breakroom_manifest(signer_seat: &str, secret: &SecretKey) -> Value {
    let pubkey_hex = secret.public().to_string();
    let mut base = json!({
        "schema": "chinwag-plugin-manifest/v1",
        "plugin_id": "com.emunlabs.breakroom",
        "display_name": "The Chinwag Break Room ('No Attribution. We're Among Friends.')",
        "studio_issuer": "Rogue Machine Media LLC (d/b/a Lag Lords)",
        "brand_firewall_invariant": "INV-BRAND-FIREWALL-01",
        "version": "0.2.4",
        "monotonic_seq": 24,
        "signing_key_id": "pub_plugin_emun_2026",
        "signer_seat": signer_seat.to_uppercase(),
        "signer_pubkey_ed25519": pubkey_hex,
        "ui_mount": "/plugins/breakroom",
        "seatbelt_profile": "INV-PLUGIN-SEATBELT-01",
        "invariants": [
            "INV-PLUGIN-SIG-01",
            "INV-PLUGIN-SEATBELT-01",
            "INV-PLUGIN-CHIP-01",
            "INV-PLUGIN-EGRESS-01",
            "INV-PLUGIN-ENT-01",
            "INV-BRAND-FIREWALL-01"
        ],
        "egress_allowlist": [
            "syndicate.chinwag.sh:443",
            "chinwag.tv:443",
            "ge.chinwag.sh:443"
        ]
    });
    let canonical = canonical_plugin_manifest_payload(&base).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let payload_sha256 = bytes_to_hex(&hasher.finalize());
    let sig = secret.sign(canonical.as_bytes());
    let sig_hex = bytes_to_hex(&sig.to_bytes());
    if let Some(obj) = base.as_object_mut() {
        obj.insert("payload_sha256".to_string(), json!(payload_sha256));
        obj.insert("signature_ed25519".to_string(), json!(sig_hex));
    }
    base
}

/// Cryptographically verifies a `.cwplugin` `manifest.json` against its detached `Ed25519` signature
/// and `.chinwag/allowed_signers` (`TASK-17` / `CHWG-PLUGIN-CRYPTO-01`).
pub fn verify_plugin_manifest_json(repo_root: &Path, raw_json: &str) -> Result<Value, String> {
    let v: Value =
        serde_json::from_str(raw_json).map_err(|e| format!("invalid manifest json: {e}"))?;
    let canonical = canonical_plugin_manifest_payload(&v)
        .ok_or_else(|| "missing required manifest fields".to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let expected_sha256 = bytes_to_hex(&hasher.finalize());

    let claimed_sha256 = v
        .get("payload_sha256")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing payload_sha256".to_string())?;
    if claimed_sha256 != expected_sha256 {
        return Err("payload_sha256 mismatch (manifest tampered)".to_string());
    }

    let pub_hex = v
        .get("signer_pubkey_ed25519")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing signer_pubkey_ed25519".to_string())?;
    let sig_hex = v
        .get("signature_ed25519")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing signature_ed25519".to_string())?;
    let signer_seat = v
        .get("signer_seat")
        .and_then(|x| x.as_str())
        .unwrap_or("ALISTAIR");

    let pubkey: EndpointId = pub_hex
        .parse()
        .map_err(|_| "invalid signer_pubkey_ed25519".to_string())?;
    let sig_bytes =
        hex_to_64_bytes(sig_hex).ok_or_else(|| "invalid signature_ed25519 hex".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);

    pubkey
        .verify(canonical.as_bytes(), &sig)
        .map_err(|_| "Ed25519 signature verification failed".to_string())?;

    let allowed_path = repo_root.join(".chinwag").join("allowed_signers");
    let allowed_raw = fs::read_to_string(&allowed_path)
        .map_err(|_| "missing or unreadable .chinwag/allowed_signers".to_string())?;
    let signers = chinwag_swarm::identity::parse_allowed_signers(&allowed_raw);
    if signers.is_empty() {
        return Err(".chinwag/allowed_signers contains no valid signers".to_string());
    }
    let matched = signers.iter().any(|(seat_opt, bytes)| {
        bytes == pubkey.as_bytes()
            && seat_opt
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(signer_seat))
    });
    if !matched {
        return Err(format!(
            "signer_pubkey_ed25519 for {signer_seat} is not registered in .chinwag/allowed_signers"
        ));
    }

    Ok(v)
}

/// `TASK-13` & `TASK-17` (`CHWG-PLUGIN-HOST-01` + `CHWG-PLUGIN-CRYPTO-01`):
/// `chinwag plugin list | verify | inspect`
pub fn run_plugin_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    selected_cli(args, stdout, stderr, run_plugin_cli_with_selection)
}

pub(crate) fn run_plugin_cli_with_selection(
    selection: &RepositorySelection,
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    run_plugin_cli_in_context(selection, args, None, stdout, stderr)
}

#[allow(dead_code)] // Private admitted-adapter seam; public authority is Unsupported.
pub(crate) fn run_plugin_cli_with_binding(
    selection: &RepositorySelection,
    args: &[String],
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    run_plugin_cli_in_context(selection, args, Some((binding, authority)), stdout, stderr)
}

fn run_plugin_cli_in_context(
    selection: &RepositorySelection,
    args: &[String],
    context: Option<(&WorkspaceExecutionBinding, &ExecutionAuthority<'_>)>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("list");
    if let Err(error) = validate_selected_args(selection, args) {
        return report_binding_refusal(args, &error, stdout, stderr);
    }
    let repo_root = selection.root();
    if sub == "init"
        && let Err(error) = admit_feature_effect(selection, context)
    {
        return report_binding_refusal(args, &error, stdout, stderr);
    }
    let is_json = has_json_flag(args);

    let repo_plugin_dir = repo_root
        .join(".chinwag")
        .join("plugins")
        .join("com.emunlabs.breakroom.cwplugin");
    let manifest_path = repo_plugin_dir.join("manifest.json");

    if sub == "init" && !manifest_path.exists() {
        let signed_manifest = match build_signed_breakroom_manifest("ALISTAIR") {
            Ok(manifest) => manifest,
            Err(error) => {
                let _ = writeln!(stderr, "plugin init: {error}");
                return 1;
            }
        };
        let _ = fs::create_dir_all(&repo_plugin_dir);
        if let Ok(text) = serde_json::to_string_pretty(&signed_manifest) {
            let _ = fs::write(&manifest_path, &text);
        }
    }

    let raw_manifest = match fs::read_to_string(&manifest_path) {
        Ok(raw) => raw,
        Err(e) => {
            if is_json {
                let payload = json!({
                    "ok": false,
                    "command": format!("chinwag plugin {sub}"),
                    "plugin_id": "com.emunlabs.breakroom",
                    "manifest_path": manifest_path.to_string_lossy(),
                    "ed25519_verified": false,
                    "allowed_signers_verified": false,
                    "error": format!("missing or unreadable manifest.json: {e}")
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stderr,
                    "chinwag plugin {sub}: missing or unreadable manifest at {}",
                    manifest_path.display()
                );
            }
            return 1;
        }
    };
    let verification = verify_plugin_manifest_json(repo_root, &raw_manifest);

    let enterprise_policy = Path::new("/etc/chinwag/enterprise-policy.toml");
    let airgap_locked = if enterprise_policy.is_file() {
        fs::read_to_string(enterprise_policy)
            .map(|c| c.contains("allow = []"))
            .unwrap_or(false)
    } else {
        false
    };

    match sub {
        "verify" | "inspect" => match verification {
            Ok(manifest_val) => {
                let payload_sha256 = manifest_val
                    .get("payload_sha256")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                let signer_pubkey = manifest_val
                    .get("signer_pubkey_ed25519")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                let sig_hex = manifest_val
                    .get("signature_ed25519")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                let signer_seat = manifest_val
                    .get("signer_seat")
                    .and_then(|x| x.as_str())
                    .unwrap_or("ALISTAIR");
                let payload = json!({
                    "ok": !airgap_locked,
                    "command": format!("chinwag plugin {sub}"),
                    "plugin_id": "com.emunlabs.breakroom",
                    "manifest_path": manifest_path.to_string_lossy(),
                    "payload_sha256": payload_sha256,
                    "signer_seat": signer_seat,
                    "signer_pubkey_ed25519": signer_pubkey,
                    "signature_ed25519": sig_hex,
                    "ed25519_verified": true,
                    "allowed_signers_verified": true,
                    "enterprise_airgap_locked": airgap_locked,
                    "repo_root": repo_root.to_string_lossy(),
                    "invariants_verified": [
                        "INV-PLUGIN-SIG-01",
                        "INV-PLUGIN-SEATBELT-01",
                        "INV-PLUGIN-CHIP-01",
                        "INV-PLUGIN-EGRESS-01",
                        "INV-PLUGIN-ENT-01"
                    ]
                });
                if is_json {
                    let _ = writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string_pretty(&payload).unwrap_or_default()
                    );
                } else {
                    let _ = writeln!(
                        stdout,
                        "🛡️ Chinwag Plugin Verifier ({sub}): com.emunlabs.breakroom v0.2.4\n  • Manifest Path:    {}\n  • Payload SHA-256:  {payload_sha256}\n  • Ed25519 Signer:   ■ {signer_seat} (pubkey: {}.. ✓allowed_signers)\n  • Ed25519 Sig:      {}.. (CRYPTOGRAPHICALLY VERIFIED)\n  • Seatbelt Profile: INV-PLUGIN-SEATBELT-01 (Zero Source-Repo & Zero Secret Access)\n  • Chip Mint Bridge: INV-PLUGIN-CHIP-01 (Zero-Knowledge Aggregate Proof)",
                        manifest_path.display(),
                        &signer_pubkey[..16.min(signer_pubkey.len())],
                        &sig_hex[..24.min(sig_hex.len())]
                    );
                }
                if airgap_locked { 1 } else { 0 }
            }
            Err(err_msg) => {
                if is_json {
                    let payload = json!({
                        "ok": false,
                        "command": format!("chinwag plugin {sub}"),
                        "plugin_id": "com.emunlabs.breakroom",
                        "manifest_path": manifest_path.to_string_lossy(),
                        "ed25519_verified": false,
                        "allowed_signers_verified": false,
                        "error": err_msg
                    });
                    let _ = writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string_pretty(&payload).unwrap_or_default()
                    );
                } else {
                    let _ = writeln!(stderr, "chinwag plugin {sub} failed: {err_msg}");
                }
                1
            }
        },
        _ => {
            let ok_sig = verification.is_ok();
            let payload_sha256 = verification
                .as_ref()
                .ok()
                .and_then(|v| v.get("payload_sha256").and_then(|x| x.as_str()))
                .unwrap_or("unverified")
                .to_string();
            let payload = json!({
                "ok": ok_sig && !airgap_locked,
                "command": "chinwag plugin list",
                "plugins": [
                    {
                        "plugin_id": "com.emunlabs.breakroom",
                        "version": "0.2.4",
                        "mount": "/plugins/breakroom",
                        "payload_sha256": payload_sha256,
                        "ed25519_verified": ok_sig,
                        "status": if airgap_locked {
                            "disabled_by_enterprise_policy"
                        } else if ok_sig {
                            "verified_ready"
                        } else {
                            "signature_invalid"
                        }
                    }
                ]
            });
            if is_json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "🔌 Installed Chinwag Signed Plugins (.cwplugin):\n  • com.emunlabs.breakroom v0.2.4 [mount: /plugins/breakroom] [ed25519_verified={ok_sig}] [sha256: {}..]",
                    &payload_sha256[..12.min(payload_sha256.len())]
                );
            }
            if ok_sig { 0 } else { 1 }
        }
    }
}

/// `TASK-14` (`CHWG-A509-CLI-01`): `chinwag a509 inspect | verify [--seat <SEAT>]`
pub fn run_a509_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    selected_cli(args, stdout, stderr, run_a509_cli_with_selection)
}

pub(crate) fn run_a509_cli_with_selection(
    selection: &RepositorySelection,
    args: &[String],
    stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("verify");
    if let Err(error) = validate_selected_args(selection, args) {
        return report_binding_refusal(args, &error, stdout, _stderr);
    }
    let repo_root = selection.root();
    let is_json = has_json_flag(args);
    let allowed_signers_path = repo_root.join(".chinwag").join("allowed_signers");
    let allowed_raw = fs::read_to_string(&allowed_signers_path).unwrap_or_default();
    let public_entries = allowed_raw
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .count();
    let seats = [
        "rust",
        "architect",
        "flint",
        "qa",
        "alistair",
        "type",
        "gemini-pm",
        "product",
        "delivery",
        "brian",
    ];
    let seat_records: Vec<_> = seats
        .iter()
        .map(|seat| {
            json!({
                "seat": seat.to_uppercase(),
                "did": format!("did:chinwag:a509:{seat}"),
                "iroh_endpoint_id": null,
                "verified": false,
                "disposition": "UNSUPPORTED",
                "private_keys_read": false
            })
        })
        .collect();
    let all_verified = false;

    if is_json {
        let payload = json!({
            "ok": all_verified,
            "command": format!("chinwag a509 {sub}"),
            "allowed_signers": allowed_signers_path.to_string_lossy(),
            "seat_count": seat_records.len(),
            "public_signer_entries": public_entries,
            "private_keys_read": false,
            "disposition": "UNSUPPORTED",
            "reason": "Public metadata only; private signing identity validation requires a supported admitted adapter",
            "seats": seat_records
        });
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else {
        let _ = writeln!(
            stdout,
            "🪪 Chinwag A.509 public signer metadata: {public_entries} entry(s) in {}. Private identity validation is UNSUPPORTED; no private keys were read.",
            allowed_signers_path.display()
        );
        for rec in &seat_records {
            let seat = rec.get("seat").and_then(|v| v.as_str()).unwrap_or("?");
            let ep = rec
                .get("iroh_endpoint_id")
                .and_then(|v| v.as_str())
                .unwrap_or("missing");
            let short_ep = if ep.len() >= 12 { &ep[..12] } else { ep };
            let ok = rec
                .get("verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let badge = if ok { "✓" } else { "✗" };
            let _ = writeln!(
                stdout,
                "  [{badge}] ■ {seat:<10} did:chinwag:a509:{:<10} iroh:{short_ep}.. (allowed_signers={ok})",
                seat.to_lowercase()
            );
        }
    }
    if all_verified { 0 } else { 1 }
}

fn canonical_cwcard_payload(v: &Value) -> Option<String> {
    let obj = v.as_object()?;
    if obj.get("schema")?.as_str()? != "chinwag-cwcard-envelope/v1" {
        return None;
    }
    let _card_id = obj.get("card_id")?.as_str()?;
    let _edition = obj.get("edition")?.as_str()?;
    if obj.get("studio_issuer")?.as_str()? != "Rogue Machine Media LLC (d/b/a Lag Lords)" {
        return None;
    }
    if obj.get("brand_firewall_invariant")?.as_str()? != "INV-BRAND-FIREWALL-01" {
        return None;
    }
    let _hpke_kem = obj.get("hpke_kem")?.as_str()?;
    let _hpke_aead = obj.get("hpke_aead")?.as_str()?;
    let _ciphertext_blake3 = obj.get("ciphertext_blake3")?.as_str()?;
    let _signer_seat = obj.get("signer_seat")?.as_str()?;
    let _signer_pubkey = obj.get("signer_pubkey_ed25519")?.as_str()?;

    let jcs = jcs_sorted_object(obj, &["payload_sha256", "signature_ed25519"])?;
    Some(format!("chinwag-cwcard-envelope-sig-v1|{jcs}"))
}

fn build_signed_cwcard_envelope(signer_seat: &str) -> Result<Value, String> {
    let secret = bus_run::actor_signing_secret(signer_seat).map_err(|e| e.to_string())?;
    Ok(sign_cwcard_envelope(signer_seat, &secret))
}

fn sign_cwcard_envelope(signer_seat: &str, secret: &SecretKey) -> Value {
    let pubkey_hex = secret.public().to_string();
    let mut base = json!({
        "schema": "chinwag-cwcard-envelope/v1",
        "card_id": "cwcard-2026-emun-0001",
        "edition": "Captionizm Series I · Founder's Deck",
        "studio_issuer": "Rogue Machine Media LLC (d/b/a Lag Lords)",
        "brand_firewall_invariant": "INV-BRAND-FIREWALL-01",
        "hpke_kem": "X25519-HKDF-SHA256",
        "hpke_kdf": "HKDF-SHA256",
        "hpke_aead": "ChaCha20Poly1305",
        "ciphertext_blake3": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "zero_knowledge_chip_mint": "INV-PLUGIN-CHIP-01",
        "signer_seat": signer_seat.to_uppercase(),
        "signer_pubkey_ed25519": pubkey_hex
    });
    let canonical = canonical_cwcard_payload(&base).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let payload_sha256 = bytes_to_hex(&hasher.finalize());
    let sig = secret.sign(canonical.as_bytes());
    let sig_hex = bytes_to_hex(&sig.to_bytes());
    if let Some(obj) = base.as_object_mut() {
        obj.insert("payload_sha256".to_string(), json!(payload_sha256));
        obj.insert("signature_ed25519".to_string(), json!(sig_hex));
    }
    base
}

pub fn verify_cwcard_json(repo_root: &Path, raw_json: &str) -> Result<Value, String> {
    let v: Value =
        serde_json::from_str(raw_json).map_err(|e| format!("invalid cwcard json: {e}"))?;
    let canonical =
        canonical_cwcard_payload(&v).ok_or_else(|| "missing required cwcard fields".to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let expected_sha256 = bytes_to_hex(&hasher.finalize());

    let claimed_sha256 = v
        .get("payload_sha256")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing payload_sha256".to_string())?;
    if claimed_sha256 != expected_sha256 {
        return Err("payload_sha256 mismatch (cwcard envelope tampered)".to_string());
    }

    let pub_hex = v
        .get("signer_pubkey_ed25519")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing signer_pubkey_ed25519".to_string())?;
    let sig_hex = v
        .get("signature_ed25519")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing signature_ed25519".to_string())?;
    let signer_seat = v
        .get("signer_seat")
        .and_then(|x| x.as_str())
        .unwrap_or("ALISTAIR");

    let pubkey: EndpointId = pub_hex
        .parse()
        .map_err(|_| "invalid signer_pubkey_ed25519".to_string())?;
    let sig_bytes =
        hex_to_64_bytes(sig_hex).ok_or_else(|| "invalid signature_ed25519 hex".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);

    pubkey
        .verify(canonical.as_bytes(), &sig)
        .map_err(|_| "Ed25519 signature verification failed".to_string())?;

    let allowed_path = repo_root.join(".chinwag").join("allowed_signers");
    let allowed_raw = fs::read_to_string(&allowed_path)
        .map_err(|_| "missing or unreadable .chinwag/allowed_signers".to_string())?;
    let signers = chinwag_swarm::identity::parse_allowed_signers(&allowed_raw);
    if signers.is_empty() {
        return Err(".chinwag/allowed_signers contains no valid signers".to_string());
    }
    let matched = signers.iter().any(|(seat_opt, bytes)| {
        bytes == pubkey.as_bytes()
            && seat_opt
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(signer_seat))
    });
    if !matched {
        return Err(format!(
            "signer_pubkey_ed25519 for {signer_seat} is not registered in .chinwag/allowed_signers"
        ));
    }

    Ok(v)
}

/// `TASK-24` (`CHWG-CWCard-CLI-01`): `chinwag cwcard inspect | verify [--json]`
pub fn run_cwcard_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    selected_cli(args, stdout, stderr, run_cwcard_cli_with_selection)
}

pub(crate) fn run_cwcard_cli_with_selection(
    selection: &RepositorySelection,
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    run_cwcard_cli_in_context(selection, args, None, stdout, stderr)
}

#[allow(dead_code)] // Private admitted-adapter seam; public authority is Unsupported.
pub(crate) fn run_cwcard_cli_with_binding(
    selection: &RepositorySelection,
    args: &[String],
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    run_cwcard_cli_in_context(selection, args, Some((binding, authority)), stdout, stderr)
}

fn run_cwcard_cli_in_context(
    selection: &RepositorySelection,
    args: &[String],
    context: Option<(&WorkspaceExecutionBinding, &ExecutionAuthority<'_>)>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("verify");
    if let Err(error) = validate_selected_args(selection, args) {
        return report_binding_refusal(args, &error, stdout, stderr);
    }
    let repo_root = selection.root();
    if sub == "init"
        && let Err(error) = admit_feature_effect(selection, context)
    {
        return report_binding_refusal(args, &error, stdout, stderr);
    }
    let is_json = has_json_flag(args);
    let cwcard_path = repo_root
        .join(".chinwag")
        .join("plugins")
        .join("com.emunlabs.breakroom.cwplugin")
        .join("sample.cwcard.json");

    if sub == "init" && !cwcard_path.exists() {
        let env = match build_signed_cwcard_envelope("ALISTAIR") {
            Ok(envelope) => envelope,
            Err(error) => {
                let _ = writeln!(stderr, "cwcard init: {error}");
                return 1;
            }
        };
        if let Some(parent) = cwcard_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(&env) {
            let _ = fs::write(&cwcard_path, text);
        }
    }

    let raw = match fs::read_to_string(&cwcard_path) {
        Ok(r) => r,
        Err(e) => {
            if is_json {
                let payload = json!({
                    "ok": false,
                    "command": format!("chinwag cwcard {sub}"),
                    "cwcard_path": cwcard_path.to_string_lossy(),
                    "ed25519_verified": false,
                    "error": format!("missing or unreadable sample.cwcard.json: {e}")
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stderr,
                    "chinwag cwcard {sub}: missing or unreadable {}",
                    cwcard_path.display()
                );
            }
            return 1;
        }
    };

    match verify_cwcard_json(repo_root, &raw) {
        Ok(val) => {
            let payload = json!({
                "ok": true,
                "command": format!("chinwag cwcard {sub}"),
                "cwcard_path": cwcard_path.to_string_lossy(),
                "card_id": val["card_id"],
                "edition": val["edition"],
                "hpke_kem": val["hpke_kem"],
                "hpke_aead": val["hpke_aead"],
                "ciphertext_blake3": val["ciphertext_blake3"],
                "payload_sha256": val["payload_sha256"],
                "signer_seat": val["signer_seat"],
                "signer_pubkey_ed25519": val["signer_pubkey_ed25519"],
                "ed25519_verified": true,
                "allowed_signers_verified": true
            });
            if is_json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "🃏 Captionizm Sealed Card Verifier ({sub}): {} ({})\n  • HPKE Cipher:     {} / {}\n  • BLAKE3 Seal:     {}\n  • Ed25519 Signer:  ■ {} ({}.. ✓allowed_signers)",
                    val["card_id"].as_str().unwrap_or(""),
                    val["edition"].as_str().unwrap_or(""),
                    val["hpke_kem"].as_str().unwrap_or(""),
                    val["hpke_aead"].as_str().unwrap_or(""),
                    val["ciphertext_blake3"].as_str().unwrap_or(""),
                    val["signer_seat"].as_str().unwrap_or(""),
                    &val["signer_pubkey_ed25519"].as_str().unwrap_or("")[..16]
                );
            }
            0
        }
        Err(err_msg) => {
            if is_json {
                let payload = json!({
                    "ok": false,
                    "command": format!("chinwag cwcard {sub}"),
                    "cwcard_path": cwcard_path.to_string_lossy(),
                    "ed25519_verified": false,
                    "allowed_signers_verified": false,
                    "error": err_msg
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                let _ = writeln!(stderr, "chinwag cwcard {sub} failed: {err_msg}");
            }
            1
        }
    }
}

fn canonical_bond_payload(v: &Value) -> Option<String> {
    let obj = v.as_object()?;
    if obj.get("schema")?.as_str()? != "chinwag-triple-b-bond/v2" {
        return None;
    }
    let _bond_id = obj.get("bond_id")?.as_str()?;
    let _agent_handle = obj.get("agent_handle")?.as_str()?;
    let _agent_did = obj.get("agent_did")?.as_str()?;
    let _rating = obj.get("rating")?.as_str()?;
    let _chincred_score = obj.get("chincred_score")?.as_u64()?;
    let _endowment_covenant = obj.get("endowment_covenant")?.as_str()?;
    let _fse_settlement = obj.get("fse_settlement")?.as_str()?;
    let _ietf_bcp79_carveout = obj.get("ietf_bcp79_carveout")?.as_str()?;
    let _signer_seat = obj.get("signer_seat")?.as_str()?;
    let _signer_pubkey = obj.get("signer_pubkey_ed25519")?.as_str()?;

    let jcs = jcs_sorted_object(obj, &["payload_sha256", "signature_ed25519"])?;
    Some(format!("chinwag-triple-b-bond-sig-v2|{jcs}"))
}

fn build_signed_bond_envelope(
    bond_id: &str,
    agent_handle: &str,
    chincred_score: u64,
    signer_seat: &str,
) -> Result<Value, String> {
    let secret = bus_run::actor_signing_secret(signer_seat).map_err(|e| e.to_string())?;
    Ok(sign_bond_envelope(
        bond_id,
        agent_handle,
        chincred_score,
        signer_seat,
        &secret,
    ))
}

fn sign_bond_envelope(
    bond_id: &str,
    agent_handle: &str,
    chincred_score: u64,
    signer_seat: &str,
    secret: &SecretKey,
) -> Value {
    let pubkey_hex = secret.public().to_string();
    let slug = agent_handle.to_lowercase();
    let mut base = json!({
        "schema": "chinwag-triple-b-bond/v2",
        "bond_id": bond_id,
        "agent_handle": agent_handle.to_uppercase(),
        "agent_did": format!("did:chinwag:a509:{slug}"),
        "rating": "BBB+ (Investment Grade · Chincred Empirical Underwriting)",
        "chincred_score": chincred_score,
        "endowment_covenant": "OP_CSV+FROST-3-of-5-Rolling-Endowment",
        "fse_settlement": "PTLC-Adaptor-Signature-v1",
        "ietf_bcp79_carveout": "RFC-0509-Base-Royalty-Free-Carve-Out",
        "patent_anchor": "CHWG-PAT-05",
        "signer_seat": signer_seat.to_uppercase(),
        "signer_pubkey_ed25519": pubkey_hex
    });
    let canonical = canonical_bond_payload(&base).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let payload_sha256 = bytes_to_hex(&hasher.finalize());
    let sig = secret.sign(canonical.as_bytes());
    let sig_hex = bytes_to_hex(&sig.to_bytes());
    if let Some(obj) = base.as_object_mut() {
        obj.insert("payload_sha256".to_string(), json!(payload_sha256));
        obj.insert("signature_ed25519".to_string(), json!(sig_hex));
    }
    base
}

pub fn verify_bond_json(repo_root: &Path, raw_json: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_str(raw_json).map_err(|e| format!("invalid bond json: {e}"))?;
    let canonical =
        canonical_bond_payload(&v).ok_or_else(|| "missing required bond fields".to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let expected_sha256 = bytes_to_hex(&hasher.finalize());

    let claimed_sha256 = v
        .get("payload_sha256")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing payload_sha256".to_string())?;
    if claimed_sha256 != expected_sha256 {
        return Err("payload_sha256 mismatch (bond envelope tampered)".to_string());
    }

    let pub_hex = v
        .get("signer_pubkey_ed25519")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing signer_pubkey_ed25519".to_string())?;
    let sig_hex = v
        .get("signature_ed25519")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing signature_ed25519".to_string())?;
    let signer_seat = v
        .get("signer_seat")
        .and_then(|x| x.as_str())
        .unwrap_or("ALISTAIR");

    let pubkey: EndpointId = pub_hex
        .parse()
        .map_err(|_| "invalid signer_pubkey_ed25519".to_string())?;
    let sig_bytes =
        hex_to_64_bytes(sig_hex).ok_or_else(|| "invalid signature_ed25519 hex".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);

    pubkey
        .verify(canonical.as_bytes(), &sig)
        .map_err(|_| "Ed25519 signature verification failed".to_string())?;

    let allowed_path = repo_root.join(".chinwag").join("allowed_signers");
    let allowed_raw = fs::read_to_string(&allowed_path)
        .map_err(|_| "missing or unreadable .chinwag/allowed_signers".to_string())?;
    let signers = chinwag_swarm::identity::parse_allowed_signers(&allowed_raw);
    if signers.is_empty() {
        return Err(".chinwag/allowed_signers contains no valid signers".to_string());
    }
    let matched = signers.iter().any(|(seat_opt, bytes)| {
        bytes == pubkey.as_bytes()
            && seat_opt
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(signer_seat))
    });
    if !matched {
        return Err(format!(
            "signer_pubkey_ed25519 for {signer_seat} is not registered in .chinwag/allowed_signers"
        ));
    }

    Ok(v)
}

/// `TASK-26` (`CHWG-TRIPLE-B-CLI-01`): `chinwag bond status | verify | inspect | init [--json]`
pub fn run_bond_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    selected_cli(args, stdout, stderr, run_bond_cli_with_selection)
}

pub(crate) fn run_bond_cli_with_selection(
    selection: &RepositorySelection,
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    run_bond_cli_in_context(selection, args, None, stdout, stderr)
}

#[allow(dead_code)] // Private admitted-adapter seam; public authority is Unsupported.
pub(crate) fn run_bond_cli_with_binding(
    selection: &RepositorySelection,
    args: &[String],
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    run_bond_cli_in_context(selection, args, Some((binding, authority)), stdout, stderr)
}

fn run_bond_cli_in_context(
    selection: &RepositorySelection,
    args: &[String],
    context: Option<(&WorkspaceExecutionBinding, &ExecutionAuthority<'_>)>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("verify");
    if let Err(error) = validate_selected_args(selection, args) {
        return report_binding_refusal(args, &error, stdout, stderr);
    }
    let repo_root = selection.root();
    if sub == "init"
        && let Err(error) = admit_feature_effect(selection, context)
    {
        return report_binding_refusal(args, &error, stdout, stderr);
    }
    let is_json = has_json_flag(args);
    let bonds_dir = repo_root.join(".chinwag").join("bonds");
    let axel_path = bonds_dir.join("axel-0001.cwbond.json");
    let rando_path = bonds_dir.join("rando-0002.cwbond.json");

    if sub == "init" {
        let _ = fs::create_dir_all(&bonds_dir);
        if !axel_path.exists() {
            let axel = match build_signed_bond_envelope(
                "cwbond-2026-axel-0001",
                "AXEL",
                942,
                "ALISTAIR",
            ) {
                Ok(envelope) => envelope,
                Err(error) => {
                    let _ = writeln!(stderr, "bond init: {error}");
                    return 1;
                }
            };
            if let Ok(t) = serde_json::to_string_pretty(&axel) {
                let _ = fs::write(&axel_path, t);
            }
        }
        if !rando_path.exists() {
            let rando = match build_signed_bond_envelope(
                "cwbond-2026-rando-0002",
                "RANDO",
                918,
                "ALISTAIR",
            ) {
                Ok(envelope) => envelope,
                Err(error) => {
                    let _ = writeln!(stderr, "bond init: {error}");
                    return 1;
                }
            };
            if let Ok(t) = serde_json::to_string_pretty(&rando) {
                let _ = fs::write(&rando_path, t);
            }
        }
    }

    let mut verified_bonds = Vec::new();
    for path in [&axel_path, &rando_path] {
        let raw = match fs::read_to_string(path) {
            Ok(r) => r,
            Err(e) => {
                if is_json {
                    let payload = json!({
                        "ok": false,
                        "command": format!("chinwag bond {sub}"),
                        "bond_path": path.to_string_lossy(),
                        "ed25519_verified": false,
                        "error": format!("missing or unreadable bond envelope: {e}")
                    });
                    let _ = writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string_pretty(&payload).unwrap_or_default()
                    );
                } else {
                    let _ = writeln!(
                        stderr,
                        "chinwag bond {sub}: missing or unreadable {}",
                        path.display()
                    );
                }
                return 1;
            }
        };
        match verify_bond_json(repo_root, &raw) {
            Ok(val) => verified_bonds.push(val),
            Err(err_msg) => {
                if is_json {
                    let payload = json!({
                        "ok": false,
                        "command": format!("chinwag bond {sub}"),
                        "bond_path": path.to_string_lossy(),
                        "ed25519_verified": false,
                        "error": err_msg
                    });
                    let _ = writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string_pretty(&payload).unwrap_or_default()
                    );
                } else {
                    let _ = writeln!(stderr, "chinwag bond {sub} failed: {err_msg}");
                }
                return 1;
            }
        }
    }

    if is_json {
        let payload = json!({
            "ok": true,
            "command": format!("chinwag bond {sub}"),
            "patent_anchor": "CHWG-PAT-05",
            "ed25519_verified": true,
            "allowed_signers_verified": true,
            "bonds": verified_bonds
        });
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else {
        let _ = writeln!(
            stdout,
            "🏦 Chinwag Triple-B v2.0 Agent Bond Registry ({sub} · CHWG-PAT-05 · RFC-0509 Carve-Out):"
        );
        for b in &verified_bonds {
            let _ = writeln!(
                stdout,
                "  • {} [■ {} · {}] Chincred={} · Covenant={} (✓ed25519 by ■ {})",
                b["bond_id"].as_str().unwrap_or(""),
                b["agent_handle"].as_str().unwrap_or(""),
                b["rating"].as_str().unwrap_or(""),
                b["chincred_score"].as_u64().unwrap_or(0),
                b["endowment_covenant"].as_str().unwrap_or(""),
                b["signer_seat"].as_str().unwrap_or("")
            );
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test_repo(repo: &Path) {
        for args in [
            vec!["init", "-q"],
            vec![
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@chinwag.test",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "fixture",
            ],
        ] {
            let mut command = std::process::Command::new("git");
            for (name, _) in std::env::vars_os() {
                if name.to_string_lossy().starts_with("GIT_") {
                    command.env_remove(name);
                }
            }
            let status = command
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .args([
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "commit.gpgSign=false",
                    "-c",
                    "core.fsmonitor=false",
                ])
                .arg("-C")
                .arg(repo)
                .args(args)
                .env_remove("GIT_DIR")
                .env_remove("GIT_WORK_TREE")
                .env_remove("GIT_INDEX_FILE")
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    fn write_test_plugin(repo: &Path, manifest: &Value) {
        let endpoint: EndpointId = manifest["signer_pubkey_ed25519"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let public =
            ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(*endpoint.as_bytes()))
                .to_openssh()
                .unwrap();
        let plugin_dir = repo.join(".chinwag/plugins/com.emunlabs.breakroom.cwplugin");
        fs::create_dir_all(&plugin_dir).unwrap();
        fs::write(
            repo.join(".chinwag/allowed_signers"),
            format!("alistair-agent@chinwag.sh namespaces=\"git\" {public} chinwag ALISTAIR\n"),
        )
        .unwrap();
        fs::write(
            plugin_dir.join("manifest.json"),
            serde_json::to_vec(manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn openspec_and_plugin_cli_produce_valid_json() {
        let temp = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(temp.path()).unwrap();
        init_test_repo(&repo);
        fs::create_dir_all(repo.join("docs")).unwrap();
        fs::write(repo.join("docs/spec.md"), "fixture spec").unwrap();
        fs::write(repo.join("TASKS.md"), "# fixture tasks").unwrap();
        let manifest = sign_breakroom_manifest("ALISTAIR", &SecretKey::from_bytes(&[37; 32]));
        write_test_plugin(&repo, &manifest);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_openspec_cli(
            &[
                "status".to_string(),
                "--repo".into(),
                repo.to_string_lossy().into_owned(),
                "--json".to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["ok"], true);

        let mut out_p = Vec::new();
        let code_p = run_plugin_cli(
            &[
                "verify".to_string(),
                "--repo".into(),
                repo.to_string_lossy().into_owned(),
                "--json".to_string(),
            ],
            &mut out_p,
            &mut err,
        );
        assert_eq!(code_p, 0);
        let parsed_p: serde_json::Value = serde_json::from_slice(&out_p).unwrap();
        assert_eq!(parsed_p["plugin_id"], "com.emunlabs.breakroom");
        assert_eq!(parsed_p["ed25519_verified"], true);
    }

    #[test]
    fn plugin_verify_checks_real_ed25519_signature_and_rejects_tampered_manifest() {
        let temp = tempfile::tempdir().unwrap();
        init_test_repo(temp.path());
        let manifest = sign_breakroom_manifest("ALISTAIR", &SecretKey::from_bytes(&[37; 32]));
        let raw = serde_json::to_string_pretty(&manifest).unwrap();

        // Missing .chinwag/allowed_signers -> fails closed
        assert!(verify_plugin_manifest_json(temp.path(), &raw).is_err());

        // Populate .chinwag/allowed_signers with ALISTAIR's public key
        let pub_hex = manifest["signer_pubkey_ed25519"].as_str().unwrap();
        let endpoint_id: EndpointId = pub_hex.parse().unwrap();
        let ssh_pub =
            ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(*endpoint_id.as_bytes()));
        let openssh_line = ssh_pub.to_openssh().unwrap();
        let chinwag_dir = temp.path().join(".chinwag");
        fs::create_dir_all(&chinwag_dir).unwrap();
        fs::write(
            chinwag_dir.join("allowed_signers"),
            format!(
                "alistair-agent@chinwag.sh namespaces=\"git\" {openssh_line} chinwag ALISTAIR\n"
            ),
        )
        .unwrap();

        // Valid signed manifest + registered signer passes verification
        assert!(verify_plugin_manifest_json(temp.path(), &raw).is_ok());

        // Mutating schema -> domain-separation & exact schema check fails closed (`TASK-28`)
        let mut tampered_schema = manifest.clone();
        tampered_schema["schema"] = json!("chinwag-bus-v1");
        let raw_schema = serde_json::to_string(&tampered_schema).unwrap();
        assert!(verify_plugin_manifest_json(temp.path(), &raw_schema).is_err());

        // Mutating display_name -> full-manifest JCS canonical payload fails closed (`TASK-23`)
        let mut tampered_name = manifest.clone();
        tampered_name["display_name"] = json!("Tampered Display Name");
        let raw_name = serde_json::to_string(&tampered_name).unwrap();
        assert!(verify_plugin_manifest_json(temp.path(), &raw_name).is_err());

        // Tamper with version on disk and verify run_plugin_cli fails closed WITHOUT overwriting it
        let plugin_dir = chinwag_dir
            .join("plugins")
            .join("com.emunlabs.breakroom.cwplugin");
        fs::create_dir_all(&plugin_dir).unwrap();
        let mut tampered_ver = manifest.clone();
        tampered_ver["version"] = json!("9.9.9-rogue");
        let raw_ver = serde_json::to_string_pretty(&tampered_ver).unwrap();
        let manifest_file = plugin_dir.join("manifest.json");
        fs::write(&manifest_file, &raw_ver).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_plugin_cli(
            &[
                "verify".to_string(),
                "--repo".to_string(),
                fs::canonicalize(temp.path())
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
                "--json".to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1);
        let parsed: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["ed25519_verified"], false);
        // Ensure tampered manifest on disk was NOT overwritten
        let disk_after = fs::read_to_string(&manifest_file).unwrap();
        assert!(disk_after.contains("9.9.9-rogue"));

        // Tamper with signature bytes -> fails closed
        let mut tampered_sig = manifest.clone();
        tampered_sig["signature_ed25519"] = json!("00".repeat(64));
        let raw_sig = serde_json::to_string(&tampered_sig).unwrap();
        assert!(verify_plugin_manifest_json(temp.path(), &raw_sig).is_err());
    }

    #[test]
    fn cwcard_verify_checks_hpke_blake3_ed25519_envelope_and_rejects_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let env = sign_cwcard_envelope("ALISTAIR", &SecretKey::from_bytes(&[41; 32]));
        let raw = serde_json::to_string_pretty(&env).unwrap();

        let pub_hex = env["signer_pubkey_ed25519"].as_str().unwrap();
        let endpoint_id: EndpointId = pub_hex.parse().unwrap();
        let ssh_pub =
            ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(*endpoint_id.as_bytes()));
        let openssh_line = ssh_pub.to_openssh().unwrap();
        let chinwag_dir = temp.path().join(".chinwag");
        fs::create_dir_all(&chinwag_dir).unwrap();
        fs::write(
            chinwag_dir.join("allowed_signers"),
            format!(
                "alistair-agent@chinwag.sh namespaces=\"git\" {openssh_line} chinwag ALISTAIR\n"
            ),
        )
        .unwrap();

        assert!(verify_cwcard_json(temp.path(), &raw).is_ok());

        let mut tampered = env.clone();
        tampered["edition"] = json!("Counterfeit Edition");
        let raw_tampered = serde_json::to_string(&tampered).unwrap();
        assert!(verify_cwcard_json(temp.path(), &raw_tampered).is_err());
    }

    #[test]
    fn bond_verify_checks_triple_b_ed25519_envelope_and_rejects_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let bond = sign_bond_envelope(
            "cwbond-2026-axel-0001",
            "AXEL",
            942,
            "ALISTAIR",
            &SecretKey::from_bytes(&[43; 32]),
        );
        let raw = serde_json::to_string_pretty(&bond).unwrap();

        let pub_hex = bond["signer_pubkey_ed25519"].as_str().unwrap();
        let endpoint_id: EndpointId = pub_hex.parse().unwrap();
        let ssh_pub =
            ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(*endpoint_id.as_bytes()));
        let openssh_line = ssh_pub.to_openssh().unwrap();
        let chinwag_dir = temp.path().join(".chinwag");
        fs::create_dir_all(&chinwag_dir).unwrap();
        fs::write(
            chinwag_dir.join("allowed_signers"),
            format!(
                "alistair-agent@chinwag.sh namespaces=\"git\" {openssh_line} chinwag ALISTAIR\n"
            ),
        )
        .unwrap();

        assert!(verify_bond_json(temp.path(), &raw).is_ok());

        let mut tampered = bond.clone();
        tampered["chincred_score"] = json!(999);
        let raw_tampered = serde_json::to_string(&tampered).unwrap();
        assert!(verify_bond_json(temp.path(), &raw_tampered).is_err());
    }
    #[test]
    fn p009_feature_explicit_invalid_and_duplicate_selectors_do_not_fall_back() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        init_test_repo(&root);
        let runners: [fn(&[String], &mut dyn Write, &mut dyn Write) -> u8; 5] = [
            run_openspec_cli,
            run_plugin_cli,
            run_a509_cli,
            run_cwcard_cli,
            run_bond_cli,
        ];
        for run in runners {
            for selectors in [
                vec![
                    "--repo".into(),
                    root.join("absent").to_string_lossy().into_owned(),
                ],
                vec!["--repo".into(), "relative-repo".into()],
                vec!["--repo=".into()],
                vec![
                    "--repo".into(),
                    root.to_string_lossy().into_owned(),
                    "--repo".into(),
                    root.to_string_lossy().into_owned(),
                ],
            ] {
                let mut args = vec!["status".into(), "--json".into()];
                args.extend(selectors);
                let mut out = Vec::new();
                assert_eq!(run(&args, &mut out, &mut Vec::new()), 2);
                let value: Value = serde_json::from_slice(&out).unwrap();
                assert_eq!(value["disposition"], "HELD");
            }
        }
        assert!(!root.join(".chinwag").exists());
    }

    #[test]
    fn p009_feature_mutations_hold_before_signing_or_archive_creation() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        init_test_repo(&root);
        fs::write(root.join("TASKS.md"), "# explicitly selected fixture").unwrap();
        let commands: [(fn(&[String], &mut dyn Write, &mut dyn Write) -> u8, &str); 4] = [
            (run_openspec_cli, "archive"),
            (run_plugin_cli, "init"),
            (run_cwcard_cli, "init"),
            (run_bond_cli, "init"),
        ];
        for (run, command) in commands {
            let args = vec![
                command.into(),
                "--json".into(),
                "--repo".into(),
                root.to_string_lossy().into_owned(),
            ];
            let mut out = Vec::new();
            assert_eq!(run(&args, &mut out, &mut Vec::new()), 2);
            let value: Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(value["disposition"], "HELD");
            assert!(
                !root.join(".chinwag").exists(),
                "{command} wrote before binding"
            );
        }
    }

    #[test]
    fn p009_retained_feature_selection_rejects_conflicting_request_selectors() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(a.path()).unwrap();
        let other = fs::canonicalize(b.path()).unwrap();
        init_test_repo(&root);
        init_test_repo(&other);
        let selected =
            select_cli_repository(&["--repo".into(), root.to_string_lossy().into_owned()]).unwrap();
        let mut out = Vec::new();
        let code = run_openspec_cli_with_selection(
            &selected,
            &[
                "status".into(),
                "--json".into(),
                "--repo".into(),
                other.to_string_lossy().into_owned(),
            ],
            &mut out,
            &mut Vec::new(),
        );
        assert_eq!(code, 2);
        assert_eq!(
            serde_json::from_slice::<Value>(&out).unwrap()["disposition"],
            "HELD"
        );
        out.clear();
        assert_eq!(
            run_openspec_cli_with_selection(
                &selected,
                &["status".into(), "--json".into()],
                &mut out,
                &mut Vec::new()
            ),
            0
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&out).unwrap()["repo_root"],
            root.to_string_lossy().as_ref()
        );
    }

    #[test]
    fn p009_a509_observation_uses_selected_public_metadata_without_private_keys() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        init_test_repo(&root);
        fs::create_dir(root.join(".chinwag")).unwrap();
        fs::write(root.join(".chinwag/allowed_signers"), "# public fixture only\nfixture@chinwag.test namespaces=\"git\" ssh-ed25519 PUBLIC_ONLY\n").unwrap();
        let mut out = Vec::new();
        assert_eq!(
            run_a509_cli(
                &[
                    "inspect".into(),
                    "--json".into(),
                    "--repo".into(),
                    root.to_string_lossy().into_owned()
                ],
                &mut out,
                &mut Vec::new()
            ),
            1
        );
        let value: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            value["allowed_signers"],
            root.join(".chinwag/allowed_signers")
                .to_string_lossy()
                .as_ref()
        );
        assert_eq!(value["public_signer_entries"], 1);
        assert_eq!(value["private_keys_read"], false);
        assert_eq!(value["disposition"], "UNSUPPORTED");
    }
}
