//! Target 3: OpenAI ChatGPT Apps Directory & Codex bundle (app name strictly `Chinwag`, zero `MCP` token).
#![forbid(unsafe_code)]

use crate::{
    PackError,
    archive::BundleTree,
    manifest::LoadedCanonicalBundle,
    targets::{
        SharedCompiledAssets, canonical_json_bytes, remote_editor_config_bytes, render_store_readme,
    },
};
use chinwag_editor_config_private::Editor;
use chinwag_mcp_private_anchored::{McpProfile, catalog_for_profile};
use serde_json::{Value, json};

pub fn compile(
    bundle: &LoadedCanonicalBundle,
    assets: &SharedCompiledAssets,
) -> Result<BundleTree, PackError> {
    let p = &bundle.manifest.plugin;
    let v = &bundle.manifest.vendor;
    let oa = &bundle.manifest.openai;
    let ep = &bundle.manifest.endpoints;
    let mut tree = BundleTree::new();

    let runtime_blind_catalog = catalog_for_profile(McpProfile::BlindOrg);
    let tools_json: Vec<Value> = runtime_blind_catalog
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
                "annotations": {
                    "readOnlyHint": tool.annotations.read_only_hint,
                    "destructiveHint": tool.annotations.destructive_hint,
                    "idempotentHint": tool.annotations.idempotent_hint,
                    "openWorldHint": tool.annotations.open_world_hint,
                },
                "justification": tool.justification,
            })
        })
        .collect();

    let app_manifest = json!({
        "schemaVersion": "2026-01",
        "name": oa.app_name,
        "subtitle": oa.subtitle,
        "description": oa.user_description,
        "version": p.version,
        "vendor": {
            "name": v.name,
            "email": v.email,
            "url": v.url,
        },
        "homepageUrl": p.homepage_url,
        "documentationUrl": p.documentation_url,
        "supportUrl": p.support_url,
        "privacyPolicyUrl": p.privacy_policy_url,
        "termsOfServiceUrl": p.terms_of_service_url,
        "complianceStatement": p.compliance_statement,
        "icon": "assets/icon.png",
        "connector": {
            "transport": "streamable_http",
            "url": ep.remote_mcp_url,
            "oauth": {
                "issuer": ep.oauth_issuer_url,
                "authorizationUrl": ep.oauth_authorization_url,
                "tokenUrl": ep.oauth_token_url,
                "registrationUrl": ep.oauth_registration_url,
            }
        },
        "tools": tools_json,
    });
    tree.insert_file("openai-app.json", canonical_json_bytes(&app_manifest)?)?;

    let codex_plugin = json!({
        "name": p.id,
        "displayName": oa.app_name,
        "version": p.version,
        "description": oa.user_description,
        "author": {
            "name": v.name,
            "email": v.email,
            "url": v.url,
        },
        "homepage": p.homepage_url,
        "repository": p.repository_url,
        "license": p.license,
        "privacyPolicyUrl": p.privacy_policy_url,
        "icon": "assets/icon.png",
        "skills": "./skills/",
    });
    let codex_plugin_bytes = canonical_json_bytes(&codex_plugin)?;
    tree.insert_file(".codex-plugin/plugin.json", codex_plugin_bytes.clone())?;
    tree.insert_file("plugin.json", codex_plugin_bytes)?;

    let portable_connector = remote_editor_config_bytes(Editor::ClaudeCode, &ep.remote_mcp_url)?;
    tree.insert_file(".mcp.json", portable_connector.clone())?;
    tree.insert_file("mcp.json", portable_connector)?;

    let codex_toml = remote_editor_config_bytes(Editor::Codex, &ep.remote_mcp_url)?;
    tree.insert_file(".codex/config.toml", codex_toml)?;

    let golden_val: Value =
        serde_json::from_slice(&bundle.golden_prompts_raw).map_err(|e| PackError::Archive {
            detail: e.to_string(),
        })?;
    tree.insert_file(
        "review/golden-prompts.json",
        canonical_json_bytes(&golden_val)?,
    )?;

    let just_val: Value =
        serde_json::from_slice(&bundle.annotation_justifications_raw).map_err(|e| {
            PackError::Archive {
                detail: e.to_string(),
            }
        })?;
    tree.insert_file(
        "review/annotation-justifications.json",
        canonical_json_bytes(&just_val)?,
    )?;

    tree.insert_file("assets/icon.png", assets.icon_png_512.clone())?;
    tree.insert_file("assets/chinwag-logo.svg", bundle.svg_logo_bytes.clone())?;
    tree.insert_file(
        "README.md",
        render_store_readme(
            bundle,
            "Connect the Chinwag app from the ChatGPT Apps Directory or load `.codex/config.toml` in Codex.",
        ),
    )?;

    for (slug, skill) in &bundle.skills {
        tree.insert_file(
            format!("skills/{slug}/SKILL.md"),
            skill.markdown.as_bytes().to_vec(),
        )?;
    }

    Ok(tree)
}
