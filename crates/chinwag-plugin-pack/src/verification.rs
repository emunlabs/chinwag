//! Cryptographic provenance verifier, 7-store structural validator, live MCP drift gate, and native CLI runner.
#![forbid(unsafe_code)]

use crate::{
    PLUGIN_RELEASE_DOMAIN_TAG, PackError,
    archive::{unpack_deterministic_tar_gz, verify_png_dimensions_and_crc},
    compiler::release_manifest_signing_payload,
    manifest::{
        LoadedCanonicalBundle, REQUIRED_COMPLIANCE_STATEMENT, REQUIRED_MCP_REGISTRY_SCHEMA,
        check_json_no_hooks, check_toml_no_hooks, contains_mcp_token, inspect_text_invariants,
        read_regular_file_no_symlink,
    },
    targets::StoreTarget,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chinwag_mcp_private_anchored::{McpProfile, catalog_for_profile, live_tools_list_wire_json};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeValidatorMode {
    Auto,
    RequireAll,
    Skip,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub cryptographic_provenance_verified: bool,
    pub slsa_v1_verified: bool,
    pub sigstore_bundle_verified: bool,
    pub runtime_mcp_zero_drift_verified: bool,
    pub structural_targets_verified: Vec<StoreTarget>,
    pub native_validators_executed: Vec<String>,
}

/// Construct a Dead Simple Signing Envelope (DSSE) Pre-Authentication Encoding (PAE) byte vector.
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let prefix = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut out = Vec::with_capacity(prefix.len() + payload.len());
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Strictly verify a domain-separated Ed25519 signature (`"CHINWAG_PLUGIN_RELEASE_V1\0" || payload`)
/// using `VerifyingKey::verify_strict` to reject malleable or small-order signatures.
pub fn verify_domain_separated_ed25519(
    pubkey_bytes: &[u8; 32],
    payload: &[u8],
    sig_bytes: &[u8; 64],
) -> Result<(), PackError> {
    let vk =
        VerifyingKey::from_bytes(pubkey_bytes).map_err(|e| PackError::ProvenanceVerification {
            detail: format!("invalid Ed25519 verifying key: {e}"),
        })?;
    let sig = Signature::from_bytes(sig_bytes);
    let mut msg = Vec::with_capacity(PLUGIN_RELEASE_DOMAIN_TAG.len() + payload.len());
    msg.extend_from_slice(PLUGIN_RELEASE_DOMAIN_TAG);
    msg.extend_from_slice(payload);
    vk.verify_strict(&msg, &sig)
        .map_err(|e| PackError::ProvenanceVerification {
            detail: format!("Ed25519 verify_strict rejected signature: {e}"),
        })
}

/// Cross-crate runtime MCP drift gate (`CHWG-0253.20`):
/// Verifies that BOTH the static `chinwag-mcp` profile catalog AND a live JSON-RPC 2.0 `tools/list`
/// session over `ContextServer` match `chinwag-plugin.toml` for `blind-org` and `local-repository`
/// with zero drift in tool count, ordering, descriptions, `ToolAnnotations`, and `inputSchema`.
pub fn verify_runtime_mcp_catalog_zero_drift(
    bundle: &LoadedCanonicalBundle,
) -> Result<(), PackError> {
    for profile in McpProfile::ALL {
        let manifest_tools = bundle.tools_for_profile(profile);
        let runtime_catalog = catalog_for_profile(profile);
        if manifest_tools.len() != runtime_catalog.len() {
            return Err(PackError::CatalogDrift {
                detail: format!(
                    "profile `{profile}` tool count mismatch: manifest={} vs chinwag-mcp={}",
                    manifest_tools.len(),
                    runtime_catalog.len()
                ),
            });
        }
        for (m, r) in manifest_tools.iter().zip(runtime_catalog.iter()) {
            if m.name != r.name
                || m.description != r.description
                || m.annotations() != r.annotations
                || m.justification != r.justification
            {
                return Err(PackError::CatalogDrift {
                    detail: format!(
                        "profile `{profile}` descriptor mismatch on tool `{}` vs `{}`",
                        m.name, r.name
                    ),
                });
            }
        }

        // Speak live JSON-RPC 2.0 `initialize` + `tools/list` against `chinwag-mcp`!
        let wire = live_tools_list_wire_json(profile).map_err(|e| PackError::CatalogDrift {
            detail: format!("live chinwag-mcp tools/list failed for `{profile}`: {e}"),
        })?;
        let wire_tools = wire["tools"]
            .as_array()
            .ok_or_else(|| PackError::CatalogDrift {
                detail: format!("live tools/list missing `tools` array for `{profile}`"),
            })?;
        if wire_tools.len() != runtime_catalog.len() {
            return Err(PackError::CatalogDrift {
                detail: format!(
                    "live wire tools/list count {} != catalog {}",
                    wire_tools.len(),
                    runtime_catalog.len()
                ),
            });
        }
        for (expected, wire_tool) in runtime_catalog.iter().zip(wire_tools.iter()) {
            if wire_tool["name"].as_str() != Some(expected.name.as_str())
                || wire_tool["description"].as_str() != Some(expected.description.as_str())
                || wire_tool["inputSchema"] != expected.input_schema
            {
                return Err(PackError::CatalogDrift {
                    detail: format!("live wire schema/description drift on `{}`", expected.name),
                });
            }
            let ann = &wire_tool["annotations"];
            if ann["readOnlyHint"] != json!(expected.annotations.read_only_hint)
                || ann["destructiveHint"] != json!(expected.annotations.destructive_hint)
                || ann["idempotentHint"] != json!(expected.annotations.idempotent_hint)
                || ann["openWorldHint"] != json!(expected.annotations.open_world_hint)
            {
                return Err(PackError::CatalogDrift {
                    detail: format!(
                        "live wire ToolAnnotations drift on `{}`: {ann}",
                        expected.name
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Full release output directory verification (`--verify`).
pub fn verify_release_dir(
    out_dir: &Path,
    bundle: &LoadedCanonicalBundle,
    expected_pubkey: Option<&[u8; 32]>,
    native_mode: NativeValidatorMode,
) -> Result<VerificationReport, PackError> {
    verify_runtime_mcp_catalog_zero_drift(bundle)?;

    // 1. Verify Ed25519 release signature + SHA256SUMS + BLAKE3SUMS in constant time
    let pubkey_hex_raw = read_regular_file_no_symlink(&out_dir.join("release-signing-pubkey.hex"))?;
    let pubkey_hex = std::str::from_utf8(&pubkey_hex_raw)
        .map_err(|e| PackError::ProvenanceVerification {
            detail: e.to_string(),
        })?
        .trim();
    let pubkey_vec = hex::decode(pubkey_hex).map_err(|e| PackError::ProvenanceVerification {
        detail: format!("invalid pubkey hex: {e}"),
    })?;
    let pubkey_bytes: [u8; 32] =
        pubkey_vec
            .try_into()
            .map_err(|_| PackError::ProvenanceVerification {
                detail: "pubkey must be 32 bytes".into(),
            })?;
    if let Some(pinned_pk) = expected_pubkey
        && !bool::from(pubkey_bytes.ct_eq(pinned_pk))
    {
        return Err(PackError::ProvenanceVerification {
            detail: "release-signing-pubkey.hex does not match pinned expected verifying key"
                .into(),
        });
    }

    let sha256sums_bytes = read_regular_file_no_symlink(&out_dir.join("SHA256SUMS"))?;
    let blake3sums_bytes = read_regular_file_no_symlink(&out_dir.join("BLAKE3SUMS"))?;
    let sig_raw = read_regular_file_no_symlink(&out_dir.join("SHA256SUMS.sig"))?;
    let sig_bytes: [u8; 64] =
        sig_raw
            .try_into()
            .map_err(|_| PackError::ProvenanceVerification {
                detail: "SHA256SUMS.sig must be 64 bytes".into(),
            })?;

    let manifest_payload = release_manifest_signing_payload(&sha256sums_bytes, &blake3sums_bytes);
    verify_domain_separated_ed25519(&pubkey_bytes, &manifest_payload, &sig_bytes)?;

    let sha_map = parse_checksum_file(&sha256sums_bytes, "SHA256SUMS")?;
    let b3_map = parse_checksum_file(&blake3sums_bytes, "BLAKE3SUMS")?;
    if sha_map.keys().collect::<Vec<_>>() != b3_map.keys().collect::<Vec<_>>() {
        return Err(PackError::ProvenanceVerification {
            detail: "SHA256SUMS and BLAKE3SUMS file lists diverge".into(),
        });
    }
    let expected_archive_paths: BTreeSet<String> = StoreTarget::ALL
        .iter()
        .map(|t| {
            format!(
                "archives/{}",
                t.archive_filename(&bundle.manifest.plugin.id, &bundle.manifest.plugin.version)
            )
        })
        .collect();
    let mut expected_checksum_paths = expected_archive_paths.clone();
    expected_checksum_paths.insert("provenance.json".into());
    let actual_checksum_paths: BTreeSet<String> = sha_map.keys().cloned().collect();
    if actual_checksum_paths != expected_checksum_paths {
        return Err(PackError::ProvenanceVerification {
            detail: "SHA256SUMS / BLAKE3SUMS entry set does not match exact 7 archives + provenance.json".into(),
        });
    }
    for (rel, expected_sha_hex) in &sha_map {
        let file_bytes = read_regular_file_no_symlink(&out_dir.join(rel))?;
        let actual_sha = Sha256::digest(&file_bytes);
        let expected_sha =
            hex::decode(expected_sha_hex).map_err(|e| PackError::ProvenanceVerification {
                detail: format!("bad sha256 hex for `{rel}`: {e}"),
            })?;
        if !bool::from(actual_sha.as_slice().ct_eq(expected_sha.as_slice())) {
            return Err(PackError::ProvenanceVerification {
                detail: format!("SHA-256 digest mismatch on `{rel}`"),
            });
        }
        let expected_b3_hex = b3_map.get(rel).unwrap();
        let expected_b3 =
            hex::decode(expected_b3_hex).map_err(|e| PackError::ProvenanceVerification {
                detail: format!("bad blake3 hex for `{rel}`: {e}"),
            })?;
        let actual_b3 = blake3::hash(&file_bytes);
        if !bool::from(actual_b3.as_bytes().ct_eq(expected_b3.as_slice())) {
            return Err(PackError::ProvenanceVerification {
                detail: format!("BLAKE3 digest mismatch on `{rel}`"),
            });
        }
    }

    // 2. Verify SLSA v1.0 provenance.json & Sigstore DSSE bundle (`provenance.sigstore.json`)
    let provenance_bytes = read_regular_file_no_symlink(&out_dir.join("provenance.json"))?;
    let provenance: Value = serde_json::from_slice(&provenance_bytes).map_err(|e| {
        PackError::ProvenanceVerification {
            detail: format!("invalid provenance.json: {e}"),
        }
    })?;
    if provenance["_type"].as_str() != Some("https://in-toto.io/Statement/v1")
        || provenance["predicateType"].as_str() != Some("https://slsa.dev/provenance/v1")
    {
        return Err(PackError::ProvenanceVerification {
            detail: "provenance.json must be in-toto Statement/v1 + SLSA provenance/v1".into(),
        });
    }
    let subjects =
        provenance["subject"]
            .as_array()
            .ok_or_else(|| PackError::ProvenanceVerification {
                detail: "provenance.json missing subject array".into(),
            })?;
    if subjects.len() != StoreTarget::ALL.len() {
        return Err(PackError::ProvenanceVerification {
            detail: "provenance.json subject count != 7 store targets".into(),
        });
    }
    let mut seen_subjects = BTreeSet::new();
    for subj in subjects {
        let name = subj["name"]
            .as_str()
            .ok_or_else(|| PackError::ProvenanceVerification {
                detail: "subject missing name".into(),
            })?;
        if !expected_archive_paths.contains(name) || !seen_subjects.insert(name.to_owned()) {
            return Err(PackError::ProvenanceVerification {
                detail: format!("unexpected or duplicate provenance subject `{name}`"),
            });
        }
        let subj_sha =
            subj["digest"]["sha256"]
                .as_str()
                .ok_or_else(|| PackError::ProvenanceVerification {
                    detail: "subject missing sha256".into(),
                })?;
        let manifest_sha = sha_map
            .get(name)
            .ok_or_else(|| PackError::ProvenanceVerification {
                detail: format!("provenance subject `{name}` missing from SHA256SUMS"),
            })?;
        if !bool::from(subj_sha.as_bytes().ct_eq(manifest_sha.as_bytes())) {
            return Err(PackError::ProvenanceVerification {
                detail: format!("provenance subject `{name}` sha256 mismatch"),
            });
        }
        let subj_b3 =
            subj["digest"]["blake3"]
                .as_str()
                .ok_or_else(|| PackError::ProvenanceVerification {
                    detail: "subject missing blake3".into(),
                })?;
        let manifest_b3 = b3_map
            .get(name)
            .ok_or_else(|| PackError::ProvenanceVerification {
                detail: format!("provenance subject `{name}` missing from BLAKE3SUMS"),
            })?;
        if !bool::from(subj_b3.as_bytes().ct_eq(manifest_b3.as_bytes())) {
            return Err(PackError::ProvenanceVerification {
                detail: format!("provenance subject `{name}` blake3 mismatch"),
            });
        }
    }
    if seen_subjects != expected_archive_paths {
        return Err(PackError::ProvenanceVerification {
            detail: "provenance.json subject set does not cover all 7 expected archives".into(),
        });
    }

    let sigstore_raw = read_regular_file_no_symlink(&out_dir.join("provenance.sigstore.json"))?;
    let sigstore: Value =
        serde_json::from_slice(&sigstore_raw).map_err(|e| PackError::ProvenanceVerification {
            detail: format!("invalid provenance.sigstore.json: {e}"),
        })?;
    if sigstore["mediaType"].as_str()
        != Some("application/vnd.dev.sigstore.bundle+json;version=0.3")
    {
        return Err(PackError::ProvenanceVerification {
            detail: "unexpected sigstore bundle mediaType".into(),
        });
    }
    let bundled_pk = BASE64
        .decode(
            sigstore["verificationMaterial"]["publicKey"]["rawBytes"]
                .as_str()
                .unwrap_or(""),
        )
        .map_err(|e| PackError::ProvenanceVerification {
            detail: format!("invalid sigstore publicKey base64: {e}"),
        })?;
    if !bool::from(bundled_pk.as_slice().ct_eq(&pubkey_bytes)) {
        return Err(PackError::ProvenanceVerification {
            detail: "sigstore bundle publicKey does not match release-signing-pubkey.hex".into(),
        });
    }
    let dsse_payload_type = sigstore["dsseEnvelope"]["payloadType"]
        .as_str()
        .unwrap_or("");
    let dsse_payload = BASE64
        .decode(sigstore["dsseEnvelope"]["payload"].as_str().unwrap_or(""))
        .map_err(|e| PackError::ProvenanceVerification {
            detail: format!("invalid dsse payload base64: {e}"),
        })?;
    if dsse_payload_type != "application/vnd.in-toto+json"
        || !bool::from(dsse_payload.as_slice().ct_eq(&provenance_bytes))
    {
        return Err(PackError::ProvenanceVerification {
            detail: "dsseEnvelope payload does not match provenance.json".into(),
        });
    }
    let dsse_sig_vec = BASE64
        .decode(
            sigstore["dsseEnvelope"]["signatures"][0]["sig"]
                .as_str()
                .unwrap_or(""),
        )
        .map_err(|e| PackError::ProvenanceVerification {
            detail: format!("invalid dsse signature base64: {e}"),
        })?;
    let dsse_sig: [u8; 64] =
        dsse_sig_vec
            .try_into()
            .map_err(|_| PackError::ProvenanceVerification {
                detail: "dsse signature must be 64 bytes".into(),
            })?;
    let pae = dsse_pae(dsse_payload_type, &dsse_payload);
    verify_domain_separated_ed25519(&pubkey_bytes, &pae, &dsse_sig)?;

    // 3. Unpack all 7 archives, enforce exact set + byte parity with `targets/<slug>/`, and run per-store validators
    let targets_parent = out_dir.join("targets");
    verify_targets_parent_entries(&targets_parent)?;
    let mut verified_targets = Vec::new();
    for target in StoreTarget::ALL {
        let archive_name =
            target.archive_filename(&bundle.manifest.plugin.id, &bundle.manifest.plugin.version);
        let archive_bytes =
            read_regular_file_no_symlink(&out_dir.join("archives").join(&archive_name))?;
        let archived_files = unpack_deterministic_tar_gz(&archive_bytes)?;

        let target_root = targets_parent.join(target.slug());
        let disk_rel_set = collect_target_dir_regular_files(&target_root, target.slug())?;
        let archived_rel_set: BTreeSet<String> = archived_files.keys().cloned().collect();
        if disk_rel_set != archived_rel_set {
            return Err(PackError::StoreValidation {
                target: target.slug().into(),
                detail: "unpacked targets/<slug>/ file set diverges from authenticated archive"
                    .into(),
            });
        }

        for (rel, bytes) in &archived_files {
            let disk_path = target_root.join(rel);
            let disk_bytes = read_regular_file_no_symlink(&disk_path)?;
            if disk_bytes.len() != bytes.len()
                || !bool::from(disk_bytes.as_slice().ct_eq(bytes.as_slice()))
            {
                return Err(PackError::StoreValidation {
                    target: target.slug().into(),
                    detail: format!("unpacked target `{rel}` diverges from archive"),
                });
            }
            if rel.ends_with(".png") {
                verify_png_dimensions_and_crc(bytes, bundle.manifest.assets.icon_size_px)?;
            } else {
                let text = std::str::from_utf8(bytes).map_err(|e| PackError::StoreValidation {
                    target: target.slug().into(),
                    detail: format!("non-UTF-8 `{rel}`: {e}"),
                })?;
                let ctx = format!("{}:{rel}", target.slug());
                if rel.ends_with(".json") {
                    let v: Value =
                        serde_json::from_str(text).map_err(|e| PackError::StoreValidation {
                            target: target.slug().into(),
                            detail: format!("malformed JSON `{rel}`: {e}"),
                        })?;
                    check_json_no_hooks(&v, &ctx)?;
                } else {
                    inspect_text_invariants(text, &ctx, true)?;
                    if rel.ends_with(".toml") {
                        let v: toml::Value =
                            toml::from_str(text).map_err(|e| PackError::StoreValidation {
                                target: target.slug().into(),
                                detail: format!("malformed TOML `{rel}`: {e}"),
                            })?;
                        check_toml_no_hooks(&v, &ctx)?;
                    }
                }
            }
        }

        validate_target_structure(target, &archived_files, bundle)?;
        verified_targets.push(target);
    }

    // 4. Native host CLI validators (`claude`, `gemini`, `agy`, `grok`)
    let native_validators_executed = run_native_cli_validators(out_dir, bundle, native_mode)?;

    Ok(VerificationReport {
        cryptographic_provenance_verified: true,
        slsa_v1_verified: true,
        sigstore_bundle_verified: true,
        runtime_mcp_zero_drift_verified: true,
        structural_targets_verified: verified_targets,
        native_validators_executed,
    })
}

fn validate_target_structure(
    target: StoreTarget,
    files: &BTreeMap<String, Vec<u8>>,
    bundle: &LoadedCanonicalBundle,
) -> Result<(), PackError> {
    let id = &bundle.manifest.plugin.id;
    let remote_url = &bundle.manifest.endpoints.remote_mcp_url;
    let err = |detail: &str| PackError::StoreValidation {
        target: target.slug().into(),
        detail: detail.to_owned(),
    };
    let parse_json = |rel: &str| -> Result<Value, PackError> {
        let bytes = files
            .get(rel)
            .ok_or_else(|| err(&format!("missing required file `{rel}`")))?;
        serde_json::from_slice(bytes).map_err(|e| err(&format!("invalid JSON in `{rel}`: {e}")))
    };

    match target {
        StoreTarget::Claude => {
            let mkt = parse_json(".claude-plugin/marketplace.json")?;
            if mkt["description"].as_str().unwrap_or("").is_empty() {
                return Err(err("marketplace.json missing top-level description"));
            }
            let plug = parse_json(&format!("plugins/{id}/.claude-plugin/plugin.json"))?;
            if plug.get("hooks").is_some()
                || plug["icon"].as_str() != Some("assets/icon.png")
                || plug["privacyPolicyUrl"].as_str()
                    != Some(bundle.manifest.plugin.privacy_policy_url.as_str())
            {
                return Err(err(
                    "Claude plugin.json failed icon/privacyPolicyUrl/no-hooks check",
                ));
            }
            let mcp = parse_json(&format!("plugins/{id}/.mcp.json"))?;
            if mcp["mcpServers"][id]["url"].as_str() != Some(remote_url.as_str()) {
                return Err(err("Claude .mcp.json remote URL mismatch"));
            }
            let readme = std::str::from_utf8(
                files
                    .get(&format!("plugins/{id}/README.md"))
                    .ok_or_else(|| err("missing Claude README.md"))?,
            )
            .map_err(|_| err("non-utf8 README.md"))?;
            if readme.split_whitespace().count() < 40
                || !readme.contains(REQUIRED_COMPLIANCE_STATEMENT)
            {
                return Err(err(
                    "Claude README.md must be >=40 words and state SOC 2 posture",
                ));
            }
        }
        StoreTarget::Cursor => {
            let _mkt = parse_json(".cursor-plugin/marketplace.json")?;
            let plug = parse_json(&format!("plugins/{id}/.cursor-plugin/plugin.json"))?;
            if plug.get("hooks").is_some() || plug["mcpServers"].as_str() != Some("./mcp.json") {
                return Err(err("Cursor plugin.json invalid"));
            }
            let mcp = parse_json(&format!("plugins/{id}/mcp.json"))?;
            let ws_mcp = parse_json(".cursor/mcp.json")?;
            if mcp != ws_mcp || mcp["mcpServers"][id]["url"].as_str() != Some(remote_url.as_str()) {
                return Err(err("Cursor mcp.json mismatch"));
            }
        }
        StoreTarget::OpenAi => {
            let app = parse_json("openai-app.json")?;
            if app["name"].as_str() != Some("Chinwag") {
                return Err(err("OpenAI app name must be strictly `Chinwag`"));
            }
            for k in ["name", "subtitle", "description"] {
                let s = app[k].as_str().unwrap_or("");
                if s.is_empty() || contains_mcp_token(s) {
                    return Err(err(&format!(
                        "OpenAI `{k}` empty or contains forbidden `MCP` token"
                    )));
                }
            }
            let tools = app["tools"]
                .as_array()
                .ok_or_else(|| err("openai-app.json missing tools"))?;
            if tools.len() != bundle.tools_for_profile(McpProfile::BlindOrg).len() {
                return Err(err("OpenAI blind-org tool count mismatch"));
            }
            let golden = parse_json("review/golden-prompts.json")?;
            let cases = golden["cases"]
                .as_array()
                .ok_or_else(|| err("missing golden cases"))?;
            if cases.len() < 8 {
                return Err(err("OpenAI golden suite requires >= 8 cases"));
            }
            let _just = parse_json("review/annotation-justifications.json")?;
            if !files.contains_key(".codex/config.toml")
                || !files.contains_key(".codex-plugin/plugin.json")
            {
                return Err(err("OpenAI bundle missing Codex artifacts"));
            }
        }
        StoreTarget::Google => {
            let ext = parse_json("gemini/gemini-extension.json")?;
            if ext["mcpServers"][id]["httpUrl"].as_str() != Some(remote_url.as_str())
                || ext["contextFileName"].as_str() != Some("GEMINI.md")
            {
                return Err(err("gemini-extension.json invalid"));
            }
            let agy = parse_json(&format!("antigravity/plugins/{id}/plugin.json"))?;
            let agy_mcp = parse_json(&format!("antigravity/plugins/{id}/mcp_config.json"))?;
            if agy["displayName"].as_str() != Some("Chinwag")
                || agy_mcp["mcpServers"][id]["serverUrl"].as_str() != Some(remote_url.as_str())
            {
                return Err(err("Antigravity plugin.json or mcp_config.json invalid"));
            }
            if files.contains_key(&format!("antigravity/plugins/{id}/.mcp.json")) {
                return Err(err(
                    "Antigravity plugins/<id>/ must not contain .mcp.json (strict warning guard)",
                ));
            }
            let _compat = parse_json("antigravity/.mcp.json")?;
        }
        StoreTarget::VsCode => {
            let vs = parse_json(".vscode/mcp.json")?;
            if vs.get("mcpServers").is_some()
                || vs["servers"][id]["type"].as_str() != Some("http")
                || vs["servers"][id]["url"].as_str() != Some(remote_url.as_str())
            {
                return Err(err(
                    ".vscode/mcp.json must use top-level `servers` container",
                ));
            }
        }
        StoreTarget::McpRegistry => {
            let srv = parse_json("server.json")?;
            if srv["$schema"].as_str() != Some(REQUIRED_MCP_REGISTRY_SCHEMA)
                || srv["name"].as_str() != Some(bundle.manifest.mcp_registry.name.as_str())
                || srv["description"].as_str().map_or(0, |d| d.chars().count()) > 100
                || srv.get("packages").is_some()
                || srv["remotes"][0]["type"].as_str() != Some("streamable-http")
                || srv["remotes"][0]["url"].as_str() != Some(remote_url.as_str())
            {
                return Err(err("MCP Registry 2025-12-11 server.json invalid"));
            }
            let dry = parse_json("publisher-dry-run.json")?;
            if dry["status"].as_str() != Some("valid") {
                return Err(err("publisher-dry-run.json status not valid"));
            }
        }
        StoreTarget::Grok => {
            let toml_bytes = files
                .get("grok-plugin.toml")
                .ok_or_else(|| err("missing grok-plugin.toml"))?;
            let grok_doc: toml::Value = toml::from_str(
                std::str::from_utf8(toml_bytes).map_err(|_| err("non-utf8 grok-plugin.toml"))?,
            )
            .map_err(|e| err(&format!("invalid grok-plugin.toml: {e}")))?;
            if grok_doc
                .get("mcp_servers")
                .and_then(|t| t.get(id))
                .and_then(|t| t.get("url"))
                .and_then(toml::Value::as_str)
                != Some(remote_url.as_str())
            {
                return Err(err("grok-plugin.toml missing mcp_servers.<id>.url"));
            }
            let cfg_bytes = files
                .get(".grok/config.toml")
                .ok_or_else(|| err("missing .grok/config.toml"))?;
            let cfg_doc: toml::Value = toml::from_str(
                std::str::from_utf8(cfg_bytes).map_err(|_| err("non-utf8 .grok/config.toml"))?,
            )
            .map_err(|e| err(&format!("invalid .grok/config.toml: {e}")))?;
            if cfg_doc
                .get("mcp_servers")
                .and_then(|t| t.get(id))
                .and_then(|t| t.get("url"))
                .and_then(toml::Value::as_str)
                != Some(remote_url.as_str())
            {
                return Err(err(".grok/config.toml missing mcp_servers.<id>.url"));
            }
        }
    }
    Ok(())
}

fn run_native_cli_validators(
    out_dir: &Path,
    bundle: &LoadedCanonicalBundle,
    mode: NativeValidatorMode,
) -> Result<Vec<String>, PackError> {
    if mode == NativeValidatorMode::Skip {
        return Ok(Vec::new());
    }
    let id = &bundle.manifest.plugin.id;
    let claude_root = out_dir.join("targets/claude");
    let claude_plugin = out_dir.join(format!("targets/claude/plugins/{id}"));
    let gemini_dir = out_dir.join("targets/google/gemini");
    let agy_dir = out_dir.join(format!("targets/google/antigravity/plugins/{id}"));
    let grok_dir = out_dir.join("targets/grok");

    let specs: [(&str, &str, Vec<String>); 5] = [
        (
            "claude-marketplace",
            "claude",
            vec![
                "plugin".into(),
                "validate".into(),
                "--strict".into(),
                claude_root.display().to_string(),
            ],
        ),
        (
            "claude-directory",
            "claude",
            vec![
                "plugin".into(),
                "validate".into(),
                "--profile".into(),
                "directory".into(),
                "--strict".into(),
                claude_plugin.display().to_string(),
            ],
        ),
        (
            "gemini-extensions",
            "gemini",
            vec![
                "extensions".into(),
                "validate".into(),
                gemini_dir.display().to_string(),
            ],
        ),
        (
            "antigravity-strict",
            "agy",
            vec![
                "plugin".into(),
                "validate".into(),
                "--strict".into(),
                agy_dir.display().to_string(),
            ],
        ),
        (
            "grok-plugin",
            "grok",
            vec![
                "plugin".into(),
                "validate".into(),
                grok_dir.display().to_string(),
            ],
        ),
    ];

    let mut executed = Vec::new();
    for (label, bin, args) in specs {
        let Some(resolved) = find_executable_in_path(bin) else {
            if mode == NativeValidatorMode::RequireAll {
                return Err(PackError::NativeValidator {
                    validator: label.into(),
                    detail: format!("required native CLI `{bin}` not found on PATH"),
                });
            }
            continue;
        };
        let output = Command::new(&resolved).args(&args).output().map_err(|e| {
            PackError::NativeValidator {
                validator: label.into(),
                detail: format!("failed to spawn `{}`: {e}", resolved.display()),
            }
        })?;
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PackError::NativeValidator {
                validator: label.into(),
                detail: format!(
                    "exit={} stdout={} stderr={}",
                    output.status,
                    stdout.trim(),
                    stderr.trim()
                ),
            });
        }
        executed.push(label.to_owned());
    }
    Ok(executed)
}

fn find_executable_in_path(binary_name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn parse_checksum_file(bytes: &[u8], label: &str) -> Result<BTreeMap<String, String>, PackError> {
    let text = std::str::from_utf8(bytes).map_err(|e| PackError::ProvenanceVerification {
        detail: format!("non-UTF-8 {label}: {e}"),
    })?;
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let (digest, rel) =
            line.split_once("  ")
                .ok_or_else(|| PackError::ProvenanceVerification {
                    detail: format!("malformed checksum line in {label}: `{line}`"),
                })?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PackError::ProvenanceVerification {
                detail: format!("invalid 64-hex digest in {label}: `{digest}`"),
            });
        }
        validate_safe_relative_checksum_path(rel, label)?;
        if map.insert(rel.to_owned(), digest.to_owned()).is_some() {
            return Err(PackError::ProvenanceVerification {
                detail: format!("duplicate entry `{rel}` in {label}"),
            });
        }
    }
    if map.is_empty() {
        return Err(PackError::ProvenanceVerification {
            detail: format!("{label} is empty"),
        });
    }
    Ok(map)
}

fn validate_safe_relative_checksum_path(rel: &str, label: &str) -> Result<(), PackError> {
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.contains('\\')
        || rel.contains('\0')
        || Path::new(rel)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(PackError::ProvenanceVerification {
            detail: format!("unsafe or non-relative path `{rel}` in {label}"),
        });
    }
    Ok(())
}

fn verify_targets_parent_entries(targets_parent: &Path) -> Result<(), PackError> {
    let meta = fs::symlink_metadata(targets_parent).map_err(|e| PackError::Io {
        path: targets_parent.display().to_string(),
        message: e.to_string(),
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(PackError::SymlinkOrUnsafeFile {
            path: targets_parent.display().to_string(),
        });
    }
    let expected: BTreeSet<String> = StoreTarget::ALL
        .iter()
        .map(|t| t.slug().to_owned())
        .collect();
    let mut actual = BTreeSet::new();
    let entries = fs::read_dir(targets_parent).map_err(|e| PackError::Io {
        path: targets_parent.display().to_string(),
        message: e.to_string(),
    })?;
    for entry_res in entries {
        let entry = entry_res.map_err(|e| PackError::Io {
            path: targets_parent.display().to_string(),
            message: e.to_string(),
        })?;
        let p = entry.path();
        let em = fs::symlink_metadata(&p).map_err(|e| PackError::Io {
            path: p.display().to_string(),
            message: e.to_string(),
        })?;
        if em.file_type().is_symlink() || !em.file_type().is_dir() {
            return Err(PackError::SymlinkOrUnsafeFile {
                path: p.display().to_string(),
            });
        }
        let name =
            entry
                .file_name()
                .into_string()
                .map_err(|_| PackError::ProvenanceVerification {
                    detail: "non-UTF-8 directory under targets/".into(),
                })?;
        actual.insert(name);
    }
    if actual != expected {
        return Err(PackError::ProvenanceVerification {
            detail: "targets/ subdirectories do not match exact 7 expected store targets".into(),
        });
    }
    Ok(())
}

fn collect_target_dir_regular_files(
    target_root: &Path,
    target_slug: &str,
) -> Result<BTreeSet<String>, PackError> {
    let mut out = BTreeSet::new();
    walk_target_dir(target_root, "", target_slug, &mut out)?;
    Ok(out)
}

fn walk_target_dir(
    dir: &Path,
    rel_prefix: &str,
    target_slug: &str,
    out: &mut BTreeSet<String>,
) -> Result<(), PackError> {
    let meta = fs::symlink_metadata(dir).map_err(|e| PackError::Io {
        path: dir.display().to_string(),
        message: e.to_string(),
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(PackError::SymlinkOrUnsafeFile {
            path: dir.display().to_string(),
        });
    }
    let entries = fs::read_dir(dir).map_err(|e| PackError::Io {
        path: dir.display().to_string(),
        message: e.to_string(),
    })?;
    for entry_res in entries {
        let entry = entry_res.map_err(|e| PackError::Io {
            path: dir.display().to_string(),
            message: e.to_string(),
        })?;
        let path = entry.path();
        let entry_meta = fs::symlink_metadata(&path).map_err(|e| PackError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        if entry_meta.file_type().is_symlink() {
            return Err(PackError::SymlinkOrUnsafeFile {
                path: path.display().to_string(),
            });
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PackError::StoreValidation {
                target: target_slug.into(),
                detail: "non-UTF-8 filename in target tree".into(),
            })?;
        let rel = if rel_prefix.is_empty() {
            name
        } else {
            format!("{rel_prefix}/{name}")
        };
        if entry_meta.file_type().is_dir() {
            walk_target_dir(&path, &rel, target_slug, out)?;
        } else if entry_meta.file_type().is_file() {
            out.insert(rel);
        } else {
            return Err(PackError::SymlinkOrUnsafeFile {
                path: path.display().to_string(),
            });
        }
    }
    Ok(())
}
