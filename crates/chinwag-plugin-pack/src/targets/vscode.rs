//! Target 5: VS Code MCP Gallery & Workspace bundle (`.vscode/mcp.json` using `"servers"` root key).
#![forbid(unsafe_code)]

use crate::{
    PackError,
    archive::BundleTree,
    manifest::LoadedCanonicalBundle,
    targets::{canonical_json_bytes, remote_editor_config_bytes, render_store_readme},
};
use chinwag_editor_config_private::Editor;
use serde_json::json;

pub fn compile(bundle: &LoadedCanonicalBundle) -> Result<BundleTree, PackError> {
    let p = &bundle.manifest.plugin;
    let v = &bundle.manifest.vendor;
    let mut tree = BundleTree::new();

    let vscode_mcp =
        remote_editor_config_bytes(Editor::VsCode, &bundle.manifest.endpoints.remote_mcp_url)?;
    tree.insert_file(".vscode/mcp.json", vscode_mcp)?;

    let gallery_meta = json!({
        "id": p.id,
        "displayName": p.display_name,
        "version": p.version,
        "publisher": v.github_org,
        "description": p.description,
        "workspaceConfigPath": ".vscode/mcp.json",
        "privacyPolicyUrl": p.privacy_policy_url,
        "complianceStatement": p.compliance_statement,
    });
    tree.insert_file(
        "vscode-mcp-gallery.json",
        canonical_json_bytes(&gallery_meta)?,
    )?;

    tree.insert_file(
        "README.md",
        render_store_readme(
            bundle,
            "Add `.vscode/mcp.json` (`servers.chinwag`) to your VS Code workspace or install from the VS Code MCP Gallery.",
        ),
    )?;

    Ok(tree)
}
