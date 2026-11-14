//! Canonical `chinwag-plugin.toml` loader and compile-time policy enforcement (`INV-NO-ENV-INTERPOLATION-01`).
#![forbid(unsafe_code)]

use crate::PackError;
use chinwag_editor_config_private::contains_env_interpolation;
use chinwag_mcp_private_anchored::{McpProfile, ToolAnnotationSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

pub const REQUIRED_COMPLIANCE_STATEMENT: &str = "Emun Labs is pursuing SOC 2.";
pub const REQUIRED_MCP_REGISTRY_SCHEMA: &str =
    "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json";

const FORBIDDEN_HOST_SUBSTRINGS: &[&str] = &["/Users/", "/home/", "C:\\Users\\"];

const FORBIDDEN_HOOK_TOKENS: &[&str] = &[
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "SubagentStop",
    "PreCompact",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPluginManifest {
    pub schema_version: u32,
    pub plugin: PluginIdentity,
    pub vendor: VendorMetadata,
    pub endpoints: EndpointMetadata,
    pub assets: AssetMetadata,
    pub openai: OpenAiMetadata,
    pub mcp_registry: McpRegistryMetadata,
    pub skills: SkillsMetadata,
    pub schemas: SchemasMetadata,
    pub tools: Vec<ManifestToolSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginIdentity {
    pub id: String,
    pub display_name: String,
    pub version: String,
    pub summary: String,
    pub description: String,
    pub license: String,
    pub homepage_url: String,
    pub repository_url: String,
    pub documentation_url: String,
    pub support_url: String,
    pub privacy_policy_url: String,
    pub terms_of_service_url: String,
    pub compliance_statement: String,
    pub categories: Vec<String>,
    pub keywords: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorMetadata {
    pub name: String,
    pub email: String,
    pub url: String,
    pub github_org: String,
    pub marketplace_slug: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointMetadata {
    pub remote_mcp_url: String,
    pub oauth_issuer_url: String,
    pub oauth_authorization_url: String,
    pub oauth_token_url: String,
    pub oauth_registration_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetMetadata {
    pub svg_logo: String,
    pub icon_size_px: u32,
    pub brand_primary_hex: String,
    pub brand_accent_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenAiMetadata {
    pub app_name: String,
    pub subtitle: String,
    pub user_description: String,
    pub golden_prompts_file: String,
    pub annotation_justifications_file: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpRegistryMetadata {
    pub name: String,
    pub schema_url: String,
    pub short_description: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillsMetadata {
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemasMetadata {
    pub vendor_lock_file: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestToolSpec {
    pub name: String,
    pub profile: McpProfile,
    pub description: String,
    pub read_only_hint: bool,
    pub destructive_hint: bool,
    pub idempotent_hint: bool,
    pub open_world_hint: bool,
    pub justification: String,
}

impl ManifestToolSpec {
    pub const fn annotations(&self) -> ToolAnnotationSpec {
        ToolAnnotationSpec {
            read_only_hint: self.read_only_hint,
            destructive_hint: self.destructive_hint,
            idempotent_hint: self.idempotent_hint,
            open_world_hint: self.open_world_hint,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoldenPromptSuite {
    pub schema_version: u32,
    pub app_name: String,
    pub cases: Vec<GoldenPromptCase>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoldenPromptCase {
    pub id: String,
    pub polarity: String,
    pub prompt: String,
    pub expected_tool: Option<String>,
    pub expected_behavior: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnnotationJustificationsDoc {
    pub schema_version: u32,
    pub tools: Vec<AnnotationJustificationEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnnotationJustificationEntry {
    pub name: String,
    pub profile: McpProfile,
    pub annotations: ToolAnnotationSpec,
    pub justification: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedSkill {
    pub slug: String,
    pub relative_path: String,
    pub description: String,
    pub markdown: String,
}

#[derive(Clone, Debug)]
pub struct LoadedCanonicalBundle {
    pub manifest_raw_bytes: Vec<u8>,
    pub manifest: CanonicalPluginManifest,
    pub svg_logo_bytes: Vec<u8>,
    pub primary_rgb: [u8; 3],
    pub accent_rgb: [u8; 3],
    pub skills: BTreeMap<String, LoadedSkill>,
    pub golden_prompts: GoldenPromptSuite,
    pub golden_prompts_raw: Vec<u8>,
    pub annotation_justifications: AnnotationJustificationsDoc,
    pub annotation_justifications_raw: Vec<u8>,
    pub vendor_lock: Value,
}

impl LoadedCanonicalBundle {
    pub fn load(manifest_path: &Path) -> Result<Self, PackError> {
        let manifest_raw_bytes = read_regular_file_no_symlink(manifest_path)?;
        let raw_str =
            std::str::from_utf8(&manifest_raw_bytes).map_err(|e| PackError::ManifestParse {
                path: manifest_path.display().to_string(),
                message: e.to_string(),
            })?;
        inspect_text_invariants(raw_str, "chinwag-plugin.toml", true)?;

        // Check raw TOML value for any `hooks` table or field before struct deserialization so
        // forbidden hooks produce a specific ForbiddenHook error rather than generic unknown field!
        let raw_toml: toml::Value =
            toml::from_str(raw_str).map_err(|e| PackError::ManifestParse {
                path: manifest_path.display().to_string(),
                message: e.to_string(),
            })?;
        check_toml_no_hooks(&raw_toml, "chinwag-plugin.toml")?;

        let manifest: CanonicalPluginManifest =
            toml::from_str(raw_str).map_err(|e| PackError::ManifestParse {
                path: manifest_path.display().to_string(),
                message: e.to_string(),
            })?;

        if manifest.schema_version != 1 {
            return Err(PackError::ManifestParse {
                path: manifest_path.display().to_string(),
                message: format!("unsupported schema_version {}", manifest.schema_version),
            });
        }

        let base_dir = manifest_path
            .parent()
            .ok_or_else(|| PackError::ManifestParse {
                path: manifest_path.display().to_string(),
                message: "manifest has no parent directory".into(),
            })?;

        let svg_path = resolve_safe_relative(base_dir, &manifest.assets.svg_logo)?;
        let svg_logo_bytes = read_regular_file_no_symlink(&svg_path)?;
        let svg_str =
            std::str::from_utf8(&svg_logo_bytes).map_err(|e| PackError::ManifestParse {
                path: svg_path.display().to_string(),
                message: e.to_string(),
            })?;
        inspect_text_invariants(svg_str, &manifest.assets.svg_logo, true)?;
        if !svg_str.contains("<svg") || !svg_str.contains("</svg>") {
            return Err(PackError::ManifestParse {
                path: svg_path.display().to_string(),
                message: "SVG logo missing <svg>...</svg> root element".into(),
            });
        }

        let primary_rgb = parse_hex_rgb(&manifest.assets.brand_primary_hex)?;
        let accent_rgb = parse_hex_rgb(&manifest.assets.brand_accent_hex)?;
        if manifest.assets.icon_size_px != 512 {
            return Err(PackError::ManifestParse {
                path: manifest_path.display().to_string(),
                message: "assets.icon_size_px must be 512 for store directory compliance".into(),
            });
        }

        let mut skills = BTreeMap::new();
        if manifest.skills.paths.is_empty() {
            return Err(PackError::ManifestParse {
                path: manifest_path.display().to_string(),
                message: "at least one canonical skill is required".into(),
            });
        }
        for rel_skill in &manifest.skills.paths {
            let skill_path = resolve_safe_relative(base_dir, rel_skill)?;
            let bytes = read_regular_file_no_symlink(&skill_path)?;
            let markdown = String::from_utf8(bytes).map_err(|e| PackError::ManifestParse {
                path: skill_path.display().to_string(),
                message: e.to_string(),
            })?;
            inspect_text_invariants(&markdown, rel_skill, true)?;
            let (slug, description) = parse_skill_frontmatter(&markdown, rel_skill)?;
            if skills.contains_key(&slug) {
                return Err(PackError::ManifestParse {
                    path: skill_path.display().to_string(),
                    message: format!("duplicate skill slug `{slug}`"),
                });
            }
            skills.insert(
                slug.clone(),
                LoadedSkill {
                    slug,
                    relative_path: rel_skill.clone(),
                    description,
                    markdown,
                },
            );
        }

        let golden_path = resolve_safe_relative(base_dir, &manifest.openai.golden_prompts_file)?;
        let golden_prompts_raw = read_regular_file_no_symlink(&golden_path)?;
        let golden_str =
            std::str::from_utf8(&golden_prompts_raw).map_err(|e| PackError::ManifestParse {
                path: golden_path.display().to_string(),
                message: e.to_string(),
            })?;
        inspect_text_invariants(golden_str, &manifest.openai.golden_prompts_file, true)?;
        let golden_json: Value =
            serde_json::from_str(golden_str).map_err(|e| PackError::ManifestParse {
                path: golden_path.display().to_string(),
                message: e.to_string(),
            })?;
        check_json_no_hooks(&golden_json, &manifest.openai.golden_prompts_file)?;
        let golden_prompts: GoldenPromptSuite =
            serde_json::from_str(golden_str).map_err(|e| PackError::ManifestParse {
                path: golden_path.display().to_string(),
                message: e.to_string(),
            })?;

        let just_path =
            resolve_safe_relative(base_dir, &manifest.openai.annotation_justifications_file)?;
        let annotation_justifications_raw = read_regular_file_no_symlink(&just_path)?;
        let just_str = std::str::from_utf8(&annotation_justifications_raw).map_err(|e| {
            PackError::ManifestParse {
                path: just_path.display().to_string(),
                message: e.to_string(),
            }
        })?;
        inspect_text_invariants(
            just_str,
            &manifest.openai.annotation_justifications_file,
            true,
        )?;
        let annotation_justifications: AnnotationJustificationsDoc = serde_json::from_str(just_str)
            .map_err(|e| PackError::ManifestParse {
                path: just_path.display().to_string(),
                message: e.to_string(),
            })?;

        let lock_path = resolve_safe_relative(base_dir, &manifest.schemas.vendor_lock_file)?;
        let lock_bytes = read_regular_file_no_symlink(&lock_path)?;
        let lock_str = std::str::from_utf8(&lock_bytes).map_err(|e| PackError::ManifestParse {
            path: lock_path.display().to_string(),
            message: e.to_string(),
        })?;
        inspect_text_invariants(lock_str, &manifest.schemas.vendor_lock_file, false)?;
        let vendor_lock: Value =
            serde_json::from_str(lock_str).map_err(|e| PackError::ManifestParse {
                path: lock_path.display().to_string(),
                message: e.to_string(),
            })?;

        let bundle = Self {
            manifest_raw_bytes,
            manifest,
            svg_logo_bytes,
            primary_rgb,
            accent_rgb,
            skills,
            golden_prompts,
            golden_prompts_raw,
            annotation_justifications,
            annotation_justifications_raw,
            vendor_lock,
        };
        bundle.validate_semantics()?;
        Ok(bundle)
    }

    pub fn tools_for_profile(&self, profile: McpProfile) -> Vec<&ManifestToolSpec> {
        self.manifest
            .tools
            .iter()
            .filter(|t| t.profile == profile)
            .collect()
    }

    pub fn validate_semantics(&self) -> Result<(), PackError> {
        let p = &self.manifest.plugin;
        if p.id.is_empty()
            || !p
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(PackError::ManifestParse {
                path: "plugin.id".into(),
                message: "plugin.id must match [a-z0-9-]+".into(),
            });
        }
        for (label, url) in [
            ("plugin.homepage_url", &p.homepage_url),
            ("plugin.repository_url", &p.repository_url),
            ("plugin.documentation_url", &p.documentation_url),
            ("plugin.support_url", &p.support_url),
            ("plugin.privacy_policy_url", &p.privacy_policy_url),
            ("plugin.terms_of_service_url", &p.terms_of_service_url),
            ("vendor.url", &self.manifest.vendor.url),
            (
                "endpoints.remote_mcp_url",
                &self.manifest.endpoints.remote_mcp_url,
            ),
            (
                "endpoints.oauth_issuer_url",
                &self.manifest.endpoints.oauth_issuer_url,
            ),
            (
                "endpoints.oauth_authorization_url",
                &self.manifest.endpoints.oauth_authorization_url,
            ),
            (
                "endpoints.oauth_token_url",
                &self.manifest.endpoints.oauth_token_url,
            ),
            (
                "endpoints.oauth_registration_url",
                &self.manifest.endpoints.oauth_registration_url,
            ),
        ] {
            if !url.starts_with("https://") {
                return Err(PackError::ManifestParse {
                    path: label.into(),
                    message: format!("HTTPS endpoint required, got `{url}`"),
                });
            }
        }

        // INV-COPY-SOC2-01
        if p.compliance_statement != REQUIRED_COMPLIANCE_STATEMENT {
            return Err(PackError::ComplianceViolation {
                context: "plugin.compliance_statement".into(),
                detail: format!(
                    "expected exact `{REQUIRED_COMPLIANCE_STATEMENT}`, got `{}`",
                    p.compliance_statement
                ),
            });
        }
        check_compliance_copy(&p.description, "plugin.description")?;
        check_compliance_copy(
            &self.manifest.openai.user_description,
            "openai.user_description",
        )?;

        // OpenAI ChatGPT Apps policy (`0253.15`): strictly `"Chinwag"`, zero `"MCP"` token
        let oa = &self.manifest.openai;
        if oa.app_name != "Chinwag" {
            return Err(PackError::OpenAiPolicyViolation {
                context: "openai.app_name".into(),
                detail: format!("app_name must be strictly `Chinwag`, got `{}`", oa.app_name),
            });
        }
        if self.golden_prompts.app_name != "Chinwag" {
            return Err(PackError::OpenAiPolicyViolation {
                context: "golden-prompts.json appName".into(),
                detail: "appName must be strictly `Chinwag`".into(),
            });
        }
        for (field, copy) in [
            ("openai.app_name", oa.app_name.as_str()),
            ("openai.subtitle", oa.subtitle.as_str()),
            ("openai.user_description", oa.user_description.as_str()),
        ] {
            if contains_mcp_token(copy) {
                return Err(PackError::OpenAiPolicyViolation {
                    context: field.into(),
                    detail: "user-facing OpenAI app copy must not contain the `MCP` token".into(),
                });
            }
        }

        let blind_names: BTreeSet<&str> = self
            .tools_for_profile(McpProfile::BlindOrg)
            .into_iter()
            .map(|t| t.name.as_str())
            .collect();
        if blind_names.is_empty() {
            return Err(PackError::CatalogDrift {
                detail: "blind-org profile must expose at least one tool".into(),
            });
        }

        if self.golden_prompts.cases.len() < 8 {
            return Err(PackError::OpenAiPolicyViolation {
                context: "golden-prompts.json".into(),
                detail: format!(
                    "expected >= 8 golden prompt cases, got {}",
                    self.golden_prompts.cases.len()
                ),
            });
        }
        let mut positives = 0usize;
        let mut negatives = 0usize;
        let mut seen_case_ids = BTreeSet::new();
        for case in &self.golden_prompts.cases {
            if !seen_case_ids.insert(case.id.as_str()) {
                return Err(PackError::OpenAiPolicyViolation {
                    context: case.id.clone(),
                    detail: "duplicate golden prompt case id".into(),
                });
            }
            if contains_mcp_token(&case.prompt) {
                return Err(PackError::OpenAiPolicyViolation {
                    context: case.id.clone(),
                    detail: "golden user prompt contains forbidden `MCP` token".into(),
                });
            }
            match case.polarity.as_str() {
                "positive" => {
                    positives += 1;
                    let tool = case.expected_tool.as_deref().ok_or_else(|| {
                        PackError::OpenAiPolicyViolation {
                            context: case.id.clone(),
                            detail: "positive golden case must declare expectedTool".into(),
                        }
                    })?;
                    if !blind_names.contains(tool) {
                        return Err(PackError::OpenAiPolicyViolation {
                            context: case.id.clone(),
                            detail: format!("positive case references non-blind-org tool `{tool}`"),
                        });
                    }
                }
                "negative" => {
                    negatives += 1;
                    if case.expected_tool.is_some() {
                        return Err(PackError::OpenAiPolicyViolation {
                            context: case.id.clone(),
                            detail: "negative golden case must have expectedTool = null".into(),
                        });
                    }
                }
                other => {
                    return Err(PackError::OpenAiPolicyViolation {
                        context: case.id.clone(),
                        detail: format!("invalid polarity `{other}`"),
                    });
                }
            }
        }
        if positives < 5 || negatives < 3 {
            return Err(PackError::OpenAiPolicyViolation {
                context: "golden-prompts.json".into(),
                detail: format!(
                    "expected >= 5 positive and >= 3 negative cases, got {positives} positive and {negatives} negative"
                ),
            });
        }

        // Official MCP Registry 2025-12-11 (`0253.17`)
        let reg = &self.manifest.mcp_registry;
        if reg.schema_url != REQUIRED_MCP_REGISTRY_SCHEMA {
            return Err(PackError::McpRegistryViolation {
                detail: format!(
                    "expected schema_url `{REQUIRED_MCP_REGISTRY_SCHEMA}`, got `{}`",
                    reg.schema_url
                ),
            });
        }
        let expected_reg_name = format!("io.github.{}/{}", self.manifest.vendor.github_org, p.id);
        if reg.name != expected_reg_name {
            return Err(PackError::McpRegistryViolation {
                detail: format!(
                    "registry name `{}` does not match canonical `{expected_reg_name}`",
                    reg.name
                ),
            });
        }
        let desc_len = reg.short_description.chars().count();
        if desc_len == 0 || desc_len > 100 {
            return Err(PackError::McpRegistryViolation {
                detail: format!(
                    "MCP Registry 2025-12-11 description must be 1..=100 chars, got {desc_len}"
                ),
            });
        }

        // Annotation justifications parity
        if self.annotation_justifications.tools.len() != self.manifest.tools.len() {
            return Err(PackError::CatalogDrift {
                detail:
                    "annotation-justifications.json tool count differs from chinwag-plugin.toml"
                        .into(),
            });
        }
        for (spec, just) in self
            .manifest
            .tools
            .iter()
            .zip(self.annotation_justifications.tools.iter())
        {
            if spec.name != just.name
                || spec.profile != just.profile
                || spec.annotations() != just.annotations
                || spec.justification.trim().is_empty()
                || spec.justification != just.justification
            {
                return Err(PackError::CatalogDrift {
                    detail: format!("annotation justification mismatch on tool `{}`", spec.name),
                });
            }
        }

        Ok(())
    }
}

pub fn contains_mcp_token(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| word.eq_ignore_ascii_case("mcp"))
}

pub fn check_compliance_copy(text: &str, context: &str) -> Result<(), PackError> {
    let lower = text.to_ascii_lowercase();
    for forbidden in [
        "soc 2 certified",
        "soc2 certified",
        "soc 2 compliant",
        "soc2 compliant",
        "soc 2 type ii certified",
        "tribunal",
    ] {
        if lower.contains(forbidden) {
            return Err(PackError::ComplianceViolation {
                context: context.into(),
                detail: format!("forbidden claim `{forbidden}` found"),
            });
        }
    }
    Ok(())
}

pub fn inspect_text_invariants(
    text: &str,
    context: &str,
    forbid_hook_tokens: bool,
) -> Result<(), PackError> {
    if forbid_hook_tokens {
        for hook in FORBIDDEN_HOOK_TOKENS {
            if text.contains(hook) {
                return Err(PackError::ForbiddenHook {
                    context: format!("{context} ({hook})"),
                });
            }
        }
    }
    if contains_env_interpolation(text) {
        return Err(PackError::ForbiddenEnvInterpolation {
            context: context.into(),
        });
    }
    for host_pat in FORBIDDEN_HOST_SUBSTRINGS {
        if text.contains(host_pat) {
            return Err(PackError::ForbiddenHardcodedHost {
                context: format!("{context} ({host_pat})"),
            });
        }
    }
    if let Some(priv_ip) = find_non_public_ipv4_token(text) {
        return Err(PackError::ForbiddenHardcodedHost {
            context: format!("{context} ({priv_ip})"),
        });
    }
    check_compliance_copy(text, context)?;
    Ok(())
}

/// Detect RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`), RFC 6598 CGNAT (`100.64/10`),
/// loopback (`127/8`), or link-local (`169.254/16`) IPv4 literals inside text (`INV-CUSTOMER-CONFIGURABLE-NO-HARDCODING-01`).
fn find_non_public_ipv4_token(text: &str) -> Option<String> {
    for raw in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let candidate = raw.trim_matches('.');
        let mut parts = candidate.split('.');
        let (Some(a), Some(b), Some(c), Some(d), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        let (Ok(o0), Ok(o1), Ok(_o2), Ok(_o3)) = (
            a.parse::<u8>(),
            b.parse::<u8>(),
            c.parse::<u8>(),
            d.parse::<u8>(),
        ) else {
            continue;
        };
        let is_non_public = o0 == 10
            || o0 == 127
            || (o0 == 172 && (16..=31).contains(&o1))
            || (o0 == 192 && o1 == 168)
            || (o0 == 100 && (64..=127).contains(&o1))
            || (o0 == 169 && o1 == 254);
        if is_non_public {
            return Some(candidate.to_owned());
        }
    }
    None
}

pub fn check_toml_no_hooks(val: &toml::Value, context: &str) -> Result<(), PackError> {
    match val {
        toml::Value::Table(map) => {
            for (k, v) in map {
                if k.eq_ignore_ascii_case("hooks")
                    || FORBIDDEN_HOOK_TOKENS
                        .iter()
                        .any(|h| k.eq_ignore_ascii_case(h))
                {
                    return Err(PackError::ForbiddenHook {
                        context: format!("{context}.{k}"),
                    });
                }
                check_toml_no_hooks(v, context)?;
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                check_toml_no_hooks(item, context)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn check_json_no_hooks(val: &Value, context: &str) -> Result<(), PackError> {
    inspect_json_invariants(val, context, true)
}

/// Recursively inspect every JSON key and string value for forbidden hooks, environment-variable
/// interpolation (`${...}`, `$ENV_VAR`, `%VAR%`), hardcoded workstation hosts, and compliance copy,
/// while permitting the standard JSON Schema meta-property key `"$schema"` (whose string value is
/// still strictly inspected).
pub fn inspect_json_invariants(
    val: &Value,
    context: &str,
    forbid_hook_tokens: bool,
) -> Result<(), PackError> {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                if forbid_hook_tokens
                    && (k.eq_ignore_ascii_case("hooks")
                        || FORBIDDEN_HOOK_TOKENS
                            .iter()
                            .any(|h| k.eq_ignore_ascii_case(h)))
                {
                    return Err(PackError::ForbiddenHook {
                        context: format!("{context}.{k}"),
                    });
                }
                if k != "$schema" {
                    inspect_text_invariants(k, context, forbid_hook_tokens)?;
                }
                inspect_json_invariants(v, context, forbid_hook_tokens)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                inspect_json_invariants(item, context, forbid_hook_tokens)?;
            }
        }
        Value::String(s) => {
            inspect_text_invariants(s, context, forbid_hook_tokens)?;
        }
        _ => {}
    }
    Ok(())
}

pub fn read_regular_file_no_symlink(path: &Path) -> Result<Vec<u8>, PackError> {
    let meta = fs::symlink_metadata(path).map_err(|e| PackError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(PackError::SymlinkOrUnsafeFile {
            path: path.display().to_string(),
        });
    }
    fs::read(path).map_err(|e| PackError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })
}

fn resolve_safe_relative(base_dir: &Path, rel: &str) -> Result<PathBuf, PackError> {
    let rel_path = Path::new(rel);
    if rel.is_empty()
        || rel_path.is_absolute()
        || rel_path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(PackError::ManifestParse {
            path: rel.into(),
            message: "canonical relative path must contain only normal path segments".into(),
        });
    }
    let mut cursor = base_dir.to_path_buf();
    for component in rel_path.components() {
        cursor.push(component);
        let meta = fs::symlink_metadata(&cursor).map_err(|e| PackError::Io {
            path: cursor.display().to_string(),
            message: e.to_string(),
        })?;
        if meta.file_type().is_symlink() {
            return Err(PackError::SymlinkOrUnsafeFile {
                path: cursor.display().to_string(),
            });
        }
    }
    Ok(cursor)
}

fn parse_hex_rgb(hex_color: &str) -> Result<[u8; 3], PackError> {
    let stripped = hex_color
        .strip_prefix('#')
        .ok_or_else(|| PackError::ManifestParse {
            path: "assets.hex_color".into(),
            message: format!("expected #RRGGBB color, got `{hex_color}`"),
        })?;
    if stripped.len() != 6 {
        return Err(PackError::ManifestParse {
            path: "assets.hex_color".into(),
            message: format!("expected 6 hex digits, got `{hex_color}`"),
        });
    }
    let bytes = hex::decode(stripped).map_err(|e| PackError::ManifestParse {
        path: "assets.hex_color".into(),
        message: e.to_string(),
    })?;
    Ok([bytes[0], bytes[1], bytes[2]])
}

fn parse_skill_frontmatter(markdown: &str, rel_path: &str) -> Result<(String, String), PackError> {
    let rest = markdown
        .strip_prefix("---\n")
        .ok_or_else(|| PackError::ManifestParse {
            path: rel_path.into(),
            message: "SKILL.md must begin with YAML frontmatter `---`".into(),
        })?;
    let end = rest
        .find("\n---\n")
        .ok_or_else(|| PackError::ManifestParse {
            path: rel_path.into(),
            message: "SKILL.md missing closing `---` frontmatter fence".into(),
        })?;
    let header = &rest[..end];
    let mut name = None;
    let mut description = None;
    for line in header.lines() {
        if let Some(v) = line.strip_prefix("name:") {
            name = Some(v.trim().trim_matches('"').to_owned());
        } else if let Some(v) = line.strip_prefix("description:") {
            description = Some(v.trim().trim_matches('"').to_owned());
        }
    }
    let slug = name
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PackError::ManifestParse {
            path: rel_path.into(),
            message: "SKILL.md frontmatter missing `name:`".into(),
        })?;
    let desc = description
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PackError::ManifestParse {
            path: rel_path.into(),
            message: "SKILL.md frontmatter missing `description:`".into(),
        })?;
    Ok((slug, desc))
}
