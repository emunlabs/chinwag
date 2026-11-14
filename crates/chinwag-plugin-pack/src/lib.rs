//! Deterministic 7-Store AI Plugin Compiler, Structural/Native Validator, and Ed25519/SLSA Provenance Signer.
#![forbid(unsafe_code)]

pub mod archive;
pub mod compiler;
pub mod manifest;
pub mod targets;
pub mod verification;

use thiserror::Error;

/// Domain-separation prefix for detached Ed25519 signatures on Chinwag plugin release bundles (`INV-PLUGIN-PROVENANCE-01`).
pub const PLUGIN_RELEASE_DOMAIN_TAG: &[u8] = b"CHINWAG_PLUGIN_RELEASE_V1\0";

/// Errors returned by `chinwag-plugin-pack` during manifest loading, deterministic compilation, or verification.
#[derive(Debug, Error)]
pub enum PackError {
    #[error("I/O error on `{path}`: {message}")]
    Io { path: String, message: String },

    #[error("symlink or non-regular file refused on `{path}`")]
    SymlinkOrUnsafeFile { path: String },

    #[error("manifest parse error in `{path}`: {message}")]
    ManifestParse { path: String, message: String },

    #[error("forbidden hook declaration (`PreToolUse`/`PostToolUse`/`hooks`) in `{context}`")]
    ForbiddenHook { context: String },

    #[error("forbidden environment interpolation (`${{...}}`/`$ENV_VAR`/`%VAR%`) in `{context}`")]
    ForbiddenEnvInterpolation { context: String },

    #[error("forbidden hardcoded workstation path or internal IP in `{context}`")]
    ForbiddenHardcodedHost { context: String },

    #[error("compliance policy violation (`INV-COPY-SOC2-01`) in `{context}`: {detail}")]
    ComplianceViolation { context: String, detail: String },

    #[error("OpenAI ChatGPT Apps policy violation in `{context}`: {detail}")]
    OpenAiPolicyViolation { context: String, detail: String },

    #[error("MCP Registry 2025-12-11 schema violation: {detail}")]
    McpRegistryViolation { detail: String },

    #[error("tool catalog or annotation drift detected: {detail}")]
    CatalogDrift { detail: String },

    #[error("archive construction or extraction failed: {detail}")]
    Archive { detail: String },

    #[error("non-deterministic double-build mismatch on `{artifact}`")]
    NonDeterministicBuild { artifact: String },

    #[error("cryptographic provenance or digest verification failed: {detail}")]
    ProvenanceVerification { detail: String },

    #[error("store validation failed for `{target}`: {detail}")]
    StoreValidation { target: String, detail: String },

    #[error("native CLI validator `{validator}` failed: {detail}")]
    NativeValidator { validator: String, detail: String },
}
