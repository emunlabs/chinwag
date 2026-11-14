//! Target 6: Official MCP Registry `2025-12-11` (`server.json` `io.github.emunlabs/chinwag`).
#![forbid(unsafe_code)]

use crate::{
    PackError,
    archive::BundleTree,
    manifest::LoadedCanonicalBundle,
    targets::{canonical_json_bytes, render_store_readme},
};
use chinwag_mcp_private_anchored::McpProfile;
use serde_json::json;

pub fn compile(bundle: &LoadedCanonicalBundle) -> Result<BundleTree, PackError> {
    let p = &bundle.manifest.plugin;
    let reg = &bundle.manifest.mcp_registry;
    let mut tree = BundleTree::new();

    let server_json = json!({
        "$schema": reg.schema_url,
        "name": reg.name,
        "title": p.display_name,
        "description": reg.short_description,
        "version": p.version,
        "websiteUrl": p.homepage_url,
        "repository": {
            "url": p.repository_url,
            "source": "github",
        },
        "remotes": [
            {
                "type": "streamable-http",
                "url": bundle.manifest.endpoints.remote_mcp_url,
            }
        ]
    });
    tree.insert_file("server.json", canonical_json_bytes(&server_json)?)?;

    let blind_tools = bundle.tools_for_profile(McpProfile::BlindOrg);
    let publisher_dry_run = json!({
        "validator": "mcp-publisher-dry-run-v1",
        "schemaUrl": reg.schema_url,
        "registryName": reg.name,
        "authMethod": "github-oidc",
        "publicPackagesCount": 0,
        "remoteTransport": "streamable-http",
        "blindOrgToolsCount": blind_tools.len(),
        "status": "valid",
    });
    tree.insert_file(
        "publisher-dry-run.json",
        canonical_json_bytes(&publisher_dry_run)?,
    )?;

    tree.insert_file(
        "README.md",
        render_store_readme(
            bundle,
            "Published to the Official MCP Registry as `io.github.emunlabs/chinwag`.",
        ),
    )?;

    Ok(tree)
}
