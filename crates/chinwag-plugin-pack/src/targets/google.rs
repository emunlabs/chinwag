//! Target 4: Google Gemini CLI (`gemini-extension.json`) & Antigravity (`plugin.json` + `mcp_config.json`).
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
use serde_json::json;

pub fn compile(
    bundle: &LoadedCanonicalBundle,
    assets: &SharedCompiledAssets,
) -> Result<BundleTree, PackError> {
    let p = &bundle.manifest.plugin;
    let v = &bundle.manifest.vendor;
    let id = &p.id;
    let remote_url = &bundle.manifest.endpoints.remote_mcp_url;
    let mut tree = BundleTree::new();

    // 1. Gemini CLI extension (`gemini/gemini-extension.json` + `GEMINI.md` + `skills/`)
    let gemini_settings_bytes = remote_editor_config_bytes(Editor::Gemini, remote_url)?;
    let gemini_settings: serde_json::Value = serde_json::from_slice(&gemini_settings_bytes)
        .map_err(|e| PackError::Archive {
            detail: e.to_string(),
        })?;
    let gemini_ext = json!({
        "name": id,
        "version": p.version,
        "description": p.description,
        "contextFileName": "GEMINI.md",
        "mcpServers": gemini_settings["mcpServers"],
    });
    tree.insert_file(
        "gemini/gemini-extension.json",
        canonical_json_bytes(&gemini_ext)?,
    )?;

    let gemini_md = format!(
        "# {display_name} Extension for Gemini CLI\n\n\
         {description}\n\n\
         Use the read-only blind organization tools (`chinwag_org_status`, `chinwag_run_status`, \
         `chinwag_board_status`, `chinwag_credit_ledger`, `chinwag_docs_search`, `chinwag_docs_get`) \
         to inspect verified delivery gates without reading or uploading repository source files.\n",
        display_name = p.display_name,
        description = p.description,
    );
    tree.insert_file("gemini/GEMINI.md", gemini_md.into_bytes())?;

    for (slug, skill) in &bundle.skills {
        tree.insert_file(
            format!("gemini/skills/{slug}/SKILL.md"),
            skill.markdown.as_bytes().to_vec(),
        )?;
    }

    // 2. Antigravity plugin (`antigravity/plugins/<id>/{plugin.json, mcp_config.json, ...}`)
    // Note: `.mcp.json` lives at `antigravity/.mcp.json` (above `plugins/<id>/`) so
    // `agy plugin validate --strict` produces zero Claude-filename warnings!
    let agy_compat_mcp = remote_editor_config_bytes(Editor::ClaudeCode, remote_url)?;
    tree.insert_file("antigravity/.mcp.json", agy_compat_mcp)?;

    let agy_plugin = json!({
        "name": id,
        "displayName": p.display_name,
        "version": p.version,
        "description": p.description,
        "author": {
            "name": v.name,
            "email": v.email,
            "url": v.url,
        },
        "homepage": p.homepage_url,
        "repository": p.repository_url,
        "license": p.license,
        "logo": "assets/chinwag-logo.svg",
        "skills": ["./skills"],
        "keywords": p.keywords,
    });
    tree.insert_file(
        format!("antigravity/plugins/{id}/plugin.json"),
        canonical_json_bytes(&agy_plugin)?,
    )?;

    let agy_mcp_config = json!({
        "mcpServers": {
            id: {
                "serverUrl": remote_url
            }
        }
    });
    tree.insert_file(
        format!("antigravity/plugins/{id}/mcp_config.json"),
        canonical_json_bytes(&agy_mcp_config)?,
    )?;

    tree.insert_file(
        format!("antigravity/plugins/{id}/README.md"),
        render_store_readme(
            bundle,
            "Install via the Antigravity Agent Marketplace or `gemini extensions install`.",
        ),
    )?;
    tree.insert_file(
        format!("antigravity/plugins/{id}/assets/chinwag-logo.svg"),
        bundle.svg_logo_bytes.clone(),
    )?;
    tree.insert_file(
        format!("antigravity/plugins/{id}/assets/icon.png"),
        assets.icon_png_512.clone(),
    )?;

    for (slug, skill) in &bundle.skills {
        tree.insert_file(
            format!("antigravity/plugins/{id}/skills/{slug}/SKILL.md"),
            skill.markdown.as_bytes().to_vec(),
        )?;
    }

    Ok(tree)
}
