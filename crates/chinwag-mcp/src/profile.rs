//! MCP tool profiles (`local-repository` vs `blind-org`) and explicit `ToolAnnotations`.
#![forbid(unsafe_code)]

use rmcp::model::{Tool, ToolAnnotations};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{error::Error, fmt, str::FromStr, sync::Arc};

/// Runtime MCP capability profile (`INV-MCP-CLOUD-BOUNDARY-01`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum McpProfile {
    /// Admitted local repository stdio/loopback profile.
    LocalRepository,
    /// Blind remote organization metadata & public documentation profile (zero source/file/lease tools).
    BlindOrg,
}

impl McpProfile {
    pub const ALL: [Self; 2] = [Self::LocalRepository, Self::BlindOrg];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalRepository => "local-repository",
            Self::BlindOrg => "blind-org",
        }
    }
}

impl fmt::Display for McpProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for McpProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "local-repository" => Ok(Self::LocalRepository),
            "blind-org" => Ok(Self::BlindOrg),
            _ => Err("Expected --profile local-repository or blind-org"),
        }
    }
}

/// Explicit four-field MCP `ToolAnnotations` specification required on every Chinwag MCP tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolAnnotationSpec {
    pub read_only_hint: bool,
    pub destructive_hint: bool,
    pub idempotent_hint: bool,
    pub open_world_hint: bool,
}

impl ToolAnnotationSpec {
    pub fn into_rmcp(self) -> ToolAnnotations {
        ToolAnnotations::new()
            .read_only(self.read_only_hint)
            .destructive(self.destructive_hint)
            .idempotent(self.idempotent_hint)
            .open_world(self.open_world_hint)
    }
}

/// Canonical tool descriptor shared across runtime `chinwag-mcp` and `chinwag-plugin-pack`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileToolDescriptor {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub annotations: ToolAnnotationSpec,
    pub profile: McpProfile,
    pub justification: String,
}

/// Return the canonical ordered tool descriptors for `profile`.
pub fn catalog_for_profile(profile: McpProfile) -> Vec<ProfileToolDescriptor> {
    match profile {
        McpProfile::LocalRepository => local_repository_catalog(),
        McpProfile::BlindOrg => blind_org_catalog(),
    }
}

/// Convert `catalog_for_profile(profile)` into `rmcp::model::Tool` definitions with all four hints set.
pub fn rmcp_tools_for_profile(profile: McpProfile) -> Result<Vec<Tool>, Box<dyn Error>> {
    let mut tools = Vec::new();
    for entry in catalog_for_profile(profile) {
        let schema_obj = entry
            .input_schema
            .as_object()
            .ok_or("Tool input_schema must be a JSON object")?
            .clone();
        let tool = Tool::new(entry.name, entry.description, Arc::new(schema_obj))
            .with_annotations(entry.annotations.into_rmcp());
        tools.push(tool);
    }
    Ok(tools)
}

fn local_repository_catalog() -> Vec<ProfileToolDescriptor> {
    let read = json!({
        "type": "object",
        "properties": {
            "thread_id": { "type": "string", "minLength": 1, "maxLength": 65536 }
        },
        "required": ["thread_id"],
        "additionalProperties": false
    });
    let pin = json!({
        "type": "object",
        "properties": {
            "id": { "type": "string", "minLength": 1, "maxLength": 65536 },
            "thread_id": { "type": "string", "minLength": 1, "maxLength": 65536 },
            "file_path": { "type": "string", "minLength": 1, "maxLength": 65536 },
            "symbol_hash": { "type": "string", "minLength": 1, "maxLength": 65536 },
            "source_commit": { "type": "string", "minLength": 1, "maxLength": 65536 },
            "body": { "type": "string", "maxLength": 65536 },
            "created_at_ms": { "type": "integer", "minimum": 0 },
            "create_thread": {
                "type": "object",
                "properties": {
                    "repo_id": { "type": "string", "minLength": 1, "maxLength": 65536 },
                    "branch_ref": { "type": "string", "minLength": 1, "maxLength": 65536 },
                    "title": { "type": "string", "minLength": 1, "maxLength": 65536 }
                },
                "required": ["repo_id", "branch_ref", "title"],
                "additionalProperties": false
            }
        },
        "required": [
            "id",
            "thread_id",
            "file_path",
            "symbol_hash",
            "source_commit",
            "body",
            "created_at_ms"
        ],
        "additionalProperties": false
    });
    let handoff = json!({
        "type": "object",
        "properties": {
            "id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "pattern": "^[A-Za-z0-9._-]+$"
            },
            "thread_id": { "type": "string", "minLength": 1, "maxLength": 65536 },
            "target_label": { "type": "string", "minLength": 1, "maxLength": 65536 },
            "note": { "type": "string", "maxLength": 65536 },
            "created_at_ms": { "type": "integer", "minimum": 0 }
        },
        "required": ["id", "thread_id", "target_label", "note", "created_at_ms"],
        "additionalProperties": false
    });

    vec![
        ProfileToolDescriptor {
            name: "chinwag_read_thread".into(),
            description: "Read one private fixture thread with persisted messages and context pins."
                .into(),
            input_schema: read,
            annotations: ToolAnnotationSpec {
                read_only_hint: true,
                destructive_hint: false,
                idempotent_hint: true,
                open_world_hint: false,
            },
            profile: McpProfile::LocalRepository,
            justification: "Reads a bounded local repository thread snapshot without mutating state or contacting external services.".into(),
        },
        ProfileToolDescriptor {
            name: "chinwag_pin_context".into(),
            description: "Persist one context pin. Exact same ID/content is idempotent; conflicting reuse is refused. file_path is stored text, never opened.".into(),
            input_schema: pin,
            annotations: ToolAnnotationSpec {
                read_only_hint: false,
                destructive_hint: false,
                idempotent_hint: true,
                open_world_hint: false,
            },
            profile: McpProfile::LocalRepository,
            justification: "Appends an idempotent local context pin keyed by pin ID without deleting data or reaching external networks.".into(),
        },
        ProfileToolDescriptor {
            name: "chinwag_handoff".into(),
            description: "Record an unauthenticated local context offer for a caller-supplied target label. No recipient contacted. Exact request replay returns original snapshot; conflicting ID refused. Prior offers excluded from snapshots. No grant or flight receipt.".into(),
            input_schema: handoff,
            annotations: ToolAnnotationSpec {
                read_only_hint: false,
                destructive_hint: false,
                idempotent_hint: true,
                open_world_hint: false,
            },
            profile: McpProfile::LocalRepository,
            justification: "Records an idempotent local handoff offer in the admitted repository store without destructive changes or network egress.".into(),
        },
    ]
}

fn blind_org_catalog() -> Vec<ProfileToolDescriptor> {
    let opaque_id = || {
        json!({
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9._:-]+$"
        })
    };
    let read_only_closed = ToolAnnotationSpec {
        read_only_hint: true,
        destructive_hint: false,
        idempotent_hint: true,
        open_world_hint: false,
    };

    vec![
        ProfileToolDescriptor {
            name: "chinwag_org_status".into(),
            description: "Return the authorized blind organization velocity and posture summary with zero source code or file paths.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "org_id": opaque_id()
                },
                "required": ["org_id"],
                "additionalProperties": false
            }),
            annotations: read_only_closed,
            profile: McpProfile::BlindOrg,
            justification: "Read-only query over signed blind organization telemetry summaries; mutates nothing and never accesses external open-world resources or repository files.".into(),
        },
        ProfileToolDescriptor {
            name: "chinwag_run_status".into(),
            description: "Return verified blind CI remediation, pair review, or policy hold status for an opaque run reference.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "org_id": opaque_id(),
                    "run_ref": opaque_id()
                },
                "required": ["org_id", "run_ref"],
                "additionalProperties": false
            }),
            annotations: read_only_closed,
            profile: McpProfile::BlindOrg,
            justification: "Read-only lookup of a verified 12-beat blind run receipt by opaque reference; idempotent, non-destructive, and closed-world.".into(),
        },
        ProfileToolDescriptor {
            name: "chinwag_board_status".into(),
            description: "Return authorized blind delivery board progress and gate counts with zero file scopes or source contents.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "org_id": opaque_id()
                },
                "required": ["org_id"],
                "additionalProperties": false
            }),
            annotations: read_only_closed,
            profile: McpProfile::BlindOrg,
            justification: "Read-only query returning aggregated delivery board step and gate counters for the caller's authorized organization.".into(),
        },
        ProfileToolDescriptor {
            name: "chinwag_credit_ledger".into(),
            description: "Return role-limited organization credit pool balance and verified receipt summaries.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "org_id": opaque_id()
                },
                "required": ["org_id"],
                "additionalProperties": false
            }),
            annotations: read_only_closed,
            profile: McpProfile::BlindOrg,
            justification: "Read-only balance and receipt inspection on the authoritative organization credit ledger; cannot reserve, purchase, or debit credits.".into(),
        },
        ProfileToolDescriptor {
            name: "chinwag_docs_search".into(),
            description: "Search approved public Chinwag documentation topics.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 256
                    }
                },
                "required": ["query"],
                "additionalProperties": false
            }),
            annotations: read_only_closed,
            profile: McpProfile::BlindOrg,
            justification: "Read-only search against the curated Chinwag documentation corpus; idempotent, non-destructive, and closed to arbitrary web URLs.".into(),
        },
        ProfileToolDescriptor {
            name: "chinwag_docs_get".into(),
            description: "Retrieve an approved public Chinwag documentation entry by slug.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": "^[a-z0-9./_-]+$"
                    }
                },
                "required": ["slug"],
                "additionalProperties": false
            }),
            annotations: read_only_closed,
            profile: McpProfile::BlindOrg,
            justification: "Read-only retrieval of a version-pinned Chinwag documentation entry by canonical slug; zero mutation or open-world fetch.".into(),
        },
    ]
}
