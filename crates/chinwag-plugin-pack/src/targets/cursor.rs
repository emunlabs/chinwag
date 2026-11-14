//! Target 2: Cursor Marketplace & Workspace bundle (`.cursor-plugin/plugin.json` + `mcp.json`).
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
        "metadata": {
            "description": p.summary,
            "version": p.version,
        },
        "owner": {
            "name": v.name,
            "email": v.email,
        },
        "plugins": [
            {
                "name": id,
                "source": format!("plugins/{id}"),
                "description": p.description,
                "version": p.version,
                "author": {
                    "name": v.name,
                    "email": v.email,
                },
                "homepage": p.homepage_url,
                "repository": p.repository_url,
                "license": p.license,
                "category": p.categories.first().cloned().unwrap_or_else(|| "developer-tools".into()),
                "keywords": p.keywords,
            }
        ]
    });
    tree.insert_file(
        ".cursor-plugin/marketplace.json",
        canonical_json_bytes(&marketplace)?,
    )?;

    let plugin_manifest = json!({
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
        "mcpServers": "./mcp.json",
        "skills": "./skills/",
        "keywords": p.keywords,
    });
    tree.insert_file(
        format!("plugins/{id}/.cursor-plugin/plugin.json"),
        canonical_json_bytes(&plugin_manifest)?,
    )?;

    let mcp_json =
        remote_editor_config_bytes(Editor::Cursor, &bundle.manifest.endpoints.remote_mcp_url)?;
    tree.insert_file(format!("plugins/{id}/mcp.json"), mcp_json.clone())?;
    tree.insert_file(".cursor/mcp.json", mcp_json)?;

    tree.insert_file(
        format!("plugins/{id}/README.md"),
        render_store_readme(
            bundle,
            "Install from the Cursor Marketplace or copy `.cursor/mcp.json` into your workspace.",
        ),
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
