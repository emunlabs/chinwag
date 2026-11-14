//! Target 7: xAI Grok CLI plugin & `.grok/config.toml` bundle (`grok plugin validate` clean).
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
    let remote_url = &bundle.manifest.endpoints.remote_mcp_url;
    let mut tree = BundleTree::new();

    let grok_plugin_toml = format!(
        "schema_version = 1\n\n\
         [plugin]\n\
         name = {id}\n\
         display_name = {display_name}\n\
         version = {version}\n\
         description = {description}\n\
         license = {license}\n\
         homepage = {homepage}\n\
         repository = {repository}\n\
         privacy_policy_url = {privacy}\n\n\
         [vendor]\n\
         name = {vendor_name}\n\
         email = {vendor_email}\n\
         url = {vendor_url}\n\n\
         [mcp_servers.{raw_id}]\n\
         url = {url}\n",
        id = serde_json::to_string(&p.id).unwrap(),
        display_name = serde_json::to_string(&p.display_name).unwrap(),
        version = serde_json::to_string(&p.version).unwrap(),
        description = serde_json::to_string(&p.description).unwrap(),
        license = serde_json::to_string(&p.license).unwrap(),
        homepage = serde_json::to_string(&p.homepage_url).unwrap(),
        repository = serde_json::to_string(&p.repository_url).unwrap(),
        privacy = serde_json::to_string(&p.privacy_policy_url).unwrap(),
        vendor_name = serde_json::to_string(&v.name).unwrap(),
        vendor_email = serde_json::to_string(&v.email).unwrap(),
        vendor_url = serde_json::to_string(&v.url).unwrap(),
        raw_id = p.id,
        url = serde_json::to_string(remote_url).unwrap(),
    );
    tree.insert_file("grok-plugin.toml", grok_plugin_toml.into_bytes())?;

    let grok_config_toml = remote_editor_config_bytes(Editor::Grok, remote_url)?;
    tree.insert_file(".grok/config.toml", grok_config_toml)?;

    let plugin_json = json!({
        "name": p.id,
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
        ".claude-plugin/plugin.json",
        canonical_json_bytes(&plugin_json)?,
    )?;

    let mcp_json = remote_editor_config_bytes(Editor::ClaudeCode, remote_url)?;
    tree.insert_file(".mcp.json", mcp_json)?;

    tree.insert_file("assets/icon.png", assets.icon_png_512.clone())?;
    tree.insert_file("assets/chinwag-logo.svg", bundle.svg_logo_bytes.clone())?;
    tree.insert_file(
        "README.md",
        render_store_readme(
            bundle,
            "Install with `grok plugin install` or merge `.grok/config.toml` into your workspace.",
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
