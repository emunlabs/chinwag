//! Deterministic compilers for all 7 Frontier AI Model Plugin Stores.
#![forbid(unsafe_code)]

pub mod claude;
pub mod cursor;
pub mod google;
pub mod grok;
pub mod mcp_registry;
pub mod openai;
pub mod vscode;

use crate::{
    PackError,
    archive::{BundleTree, render_deterministic_icon_png},
    manifest::LoadedCanonicalBundle,
};
use chinwag_editor_config_private::{Editor, Plan, Remote, plan_remote};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoreTarget {
    Claude,
    Cursor,
    OpenAi,
    Google,
    VsCode,
    McpRegistry,
    Grok,
}

impl StoreTarget {
    pub const ALL: [Self; 7] = [
        Self::Claude,
        Self::Cursor,
        Self::OpenAi,
        Self::Google,
        Self::VsCode,
        Self::McpRegistry,
        Self::Grok,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::OpenAi => "openai",
            Self::Google => "google",
            Self::VsCode => "vscode",
            Self::McpRegistry => "mcp-registry",
            Self::Grok => "grok",
        }
    }

    pub fn archive_filename(self, plugin_id: &str, version: &str) -> String {
        format!("{plugin_id}-{}-{version}.tar.gz", self.slug())
    }
}

pub struct SharedCompiledAssets {
    pub icon_png_512: Vec<u8>,
}

impl SharedCompiledAssets {
    pub fn build(bundle: &LoadedCanonicalBundle) -> Result<Self, PackError> {
        let icon_png_512 = render_deterministic_icon_png(
            bundle.manifest.assets.icon_size_px,
            bundle.primary_rgb,
            bundle.accent_rgb,
        )?;
        Ok(Self { icon_png_512 })
    }
}

pub fn compile_target(
    target: StoreTarget,
    bundle: &LoadedCanonicalBundle,
    assets: &SharedCompiledAssets,
) -> Result<BundleTree, PackError> {
    match target {
        StoreTarget::Claude => claude::compile(bundle, assets),
        StoreTarget::Cursor => cursor::compile(bundle, assets),
        StoreTarget::OpenAi => openai::compile(bundle, assets),
        StoreTarget::Google => google::compile(bundle, assets),
        StoreTarget::VsCode => vscode::compile(bundle),
        StoreTarget::McpRegistry => mcp_registry::compile(bundle),
        StoreTarget::Grok => grok::compile(bundle, assets),
    }
}

/// Recursively canonicalize JSON object key order (`BTreeMap`) and serialize with 2-space indent + trailing newline.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, PackError> {
    let sorted = sort_json_keys(value);
    let mut text = serde_json::to_string_pretty(&sorted).map_err(|e| PackError::Archive {
        detail: format!("JSON serialize failed: {e}"),
    })?;
    text.push('\n');
    Ok(text.into_bytes())
}

fn sort_json_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by_key(|(a, _)| *a);
            let mut out = Map::new();
            for (k, v) in entries {
                out.insert(k.clone(), sort_json_keys(v));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_json_keys).collect()),
        other => other.clone(),
    }
}

/// Delegate remote MCP configuration generation to `chinwag-editor-config-private` so store bundles
/// and local editor installations share one authoritative serializer.
pub fn remote_editor_config_bytes(editor: Editor, remote_url: &str) -> Result<Vec<u8>, PackError> {
    match plan_remote(editor, None, Remote { url: remote_url }) {
        Ok(Plan::Proposed { bytes, .. }) => {
            if editor.is_toml() {
                Ok(bytes)
            } else {
                let parsed: Value =
                    serde_json::from_slice(&bytes).map_err(|e| PackError::Archive {
                        detail: format!("editor config JSON parse failed: {e}"),
                    })?;
                canonical_json_bytes(&parsed)
            }
        }
        other => Err(PackError::Archive {
            detail: format!("unexpected editor config plan result for {editor:?}: {other:?}"),
        }),
    }
}

pub fn render_store_readme(bundle: &LoadedCanonicalBundle, install_hint: &str) -> Vec<u8> {
    let p = &bundle.manifest.plugin;
    let v = &bundle.manifest.vendor;
    format!(
        "# {display_name}\n\n\
         {description}\n\n\
         ## Installation\n\n\
         {install_hint}\n\n\
         ## Blind Security Architecture\n\n\
         The remote {display_name} service exposes organization delivery posture, verified blind CI remediation \
         and pair-review run status, board gate counters, read-only credit pool summaries, and approved public \
         documentation. Zero repository source files, diffs, file paths, or local edit leases are transmitted \
         over the remote integration.\n\n\
         ## Compliance & Privacy\n\n\
         - Vendor: {vendor_name} ({vendor_url})\n\
         - Compliance: {compliance}\n\
         - Privacy Policy: {privacy}\n\
         - Terms of Service: {terms}\n\
         - Support: {support}\n",
        display_name = p.display_name,
        description = p.description,
        vendor_name = v.name,
        vendor_url = v.url,
        compliance = p.compliance_statement,
        privacy = p.privacy_policy_url,
        terms = p.terms_of_service_url,
        support = p.support_url,
    )
    .into_bytes()
}
