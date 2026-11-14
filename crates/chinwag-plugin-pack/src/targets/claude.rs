//! Target 1: Anthropic Claude Code Marketplace & Directory bundle (`.claude-plugin/plugin.json` + `.mcp.json`).
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
    let mut tree = BundleTree::new();

    let marketplace = json!({
        "name": v.github_org,
        "description": p.summary,
        "owner": {
            "name": v.name,
            "email": v.email,
        },
        "plugins": [
            {
                "name": id,
                "source": format!("./plugins/{id}"),
                "description": p.description,
                "version": p.version,
                "homepage": p.homepage_url,
                "repository": p.repository_url,
                "license": p.license,
                "category": p.categories.first().cloned().unwrap_or_else(|| "developer-tools".into()),
                "keywords": p.keywords,
            }
        ]
    });
    tree.insert_file(
        ".claude-plugin/marketplace.json",
        canonical_json_bytes(&marketplace)?,
    )?;

    let plugin_manifest = json!({
        "name": id,
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
        "privacyPolicyUrl": p.privacy_policy_url,
        "icon": "assets/icon.png",
        "keywords": p.keywords,
    });
    tree.insert_file(
        format!("plugins/{id}/.claude-plugin/plugin.json"),
        canonical_json_bytes(&plugin_manifest)?,
    )?;

    let mcp_json = remote_editor_config_bytes(
        Editor::ClaudeCode,
        &bundle.manifest.endpoints.remote_mcp_url,
    )?;
    tree.insert_file(format!("plugins/{id}/.mcp.json"), mcp_json)?;

    let install_cmd = format!(
        "Install directly in Claude Code with `/plugin install {id} --marketplace {}`.",
        v.marketplace_slug
    );
    tree.insert_file(
        format!("plugins/{id}/README.md"),
        render_store_readme(bundle, &install_cmd),
    )?;
    tree.insert_file(
        format!("plugins/{id}/assets/icon.png"),
        assets.icon_png_512.clone(),
    )?;
    tree.insert_file(
        format!("plugins/{id}/assets/chinwag-logo.svg"),
        bundle.svg_logo_bytes.clone(),
    )?;

    for (slug, skill) in &bundle.skills {
        tree.insert_file(
            format!("plugins/{id}/skills/{slug}/SKILL.md"),
            skill.markdown.as_bytes().to_vec(),
        )?;
    }

    Ok(tree)
}
