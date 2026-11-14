// SPDX-License-Identifier: Apache-2.0

use crate::types::{
    CanonicalCommandTupleV1, DEFAULT_PROTECTED_BRANCHES, DEFAULT_PROTECTED_PATHS, Effect,
    ParseContext,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use thiserror::Error;

/// Customer-facing safety rule toggles mapped from `.chinwag/workflow.yaml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyToggle {
    RequireReviewBeforePushMain,
    RequireReviewBeforeAnyPush,
    ProtectSecretsAuthMigrations,
    ForbidDestructiveWorktreeOps,
    AlwaysOnContainmentInvariant,
}

/// Disposition returned by [`WorkflowSafetyPolicyV1::evaluate_tuple`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDisposition {
    /// Command is safe under the active policy (`ReadOnly` or ungated effect).
    Allow,
    /// Command triggers one or more customer safety toggles and requires explicit review / click approval.
    RequireReview,
    /// Command violates an always-on containment invariant (RCE config injection, `..` traversal escape, root/wildcard wipe).
    BlockHardInvariant,
}

/// Structured policy evaluation receipt for a parsed CLI command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationV1 {
    pub disposition: PolicyDisposition,
    pub triggered_effects: BTreeSet<Effect>,
    pub matched_toggles: Vec<SafetyToggle>,
    pub tuple: CanonicalCommandTupleV1,
    pub reason: String,
}

impl PolicyEvaluationV1 {
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self.disposition, PolicyDisposition::Allow)
    }
}

/// Errors encountered when parsing `.chinwag/workflow.yaml`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyParseError {
    #[error("workflow.yaml exceeds 128 KiB limit ({0} bytes)")]
    OversizedYaml(usize),
    #[error("invalid boolean value `{value}` for key `{key}`")]
    InvalidBoolean { key: String, value: String },
    #[error("unsafe or malformed path entry in `{key}`")]
    InvalidPathEntry { key: String },
    #[error("symlink or non-regular file rejected on workflow policy path: {0}")]
    UnsafeWorkflowFile(String),
    #[error("failed reading workflow policy file: {0}")]
    IoError(String),
}

/// Customer-configurable safety policy loaded from `.chinwag/workflow.yaml` (`:5487` & `chinwag-ci`).
///
/// Supports both the canonical `CHWG-0247` toggle names:
/// - `require_review_before_push_main`
/// - `protect_secrets_auth_migrations`
/// - `forbid_destructive_worktree_ops`
///
/// and the `:5487` `WorkflowConfig` YAML aliases:
/// - `require_click_before_push`
/// - `protect_sensitive_paths` / `ask_before_secrets`
/// - `protected_paths`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowSafetyPolicyV1 {
    pub require_review_before_push_main: bool,
    pub require_review_before_any_push: bool,
    pub protect_secrets_auth_migrations: bool,
    pub forbid_destructive_worktree_ops: bool,
    pub fail_closed_on_unknown_commands: bool,
    pub protected_paths: Vec<String>,
    pub protected_branches: Vec<String>,
}

impl Default for WorkflowSafetyPolicyV1 {
    fn default() -> Self {
        Self {
            require_review_before_push_main: true,
            require_review_before_any_push: false,
            protect_secrets_auth_migrations: true,
            forbid_destructive_worktree_ops: true,
            fail_closed_on_unknown_commands: false,
            protected_paths: DEFAULT_PROTECTED_PATHS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            protected_branches: DEFAULT_PROTECTED_BRANCHES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        }
    }
}

impl WorkflowSafetyPolicyV1 {
    /// Builds a [`ParseContext`] borrowing `protected_paths` and `protected_branches` from this policy,
    /// and safely resolving the checked-out Git branch from `workspace_root/.git/HEAD` when available.
    #[must_use]
    pub fn with_parse_context<'a, R, F>(&'a self, workspace_root: Option<&'a Path>, f: F) -> R
    where
        F: FnOnce(&ParseContext<'_>) -> R,
    {
        let path_refs: Vec<&str> = self.protected_paths.iter().map(String::as_str).collect();
        let branch_refs: Vec<&str> = self.protected_branches.iter().map(String::as_str).collect();
        let head_branch = workspace_root.and_then(resolve_repo_head_branch);
        let ctx = ParseContext {
            workspace_root,
            protected_paths: &path_refs,
            protected_branches: &branch_refs,
            current_branch: head_branch.as_deref(),
        };
        f(&ctx)
    }

    /// Returns the exact canonical [`Effect`] set gated by this policy configuration.
    #[must_use]
    pub fn gated_effects(&self) -> BTreeSet<Effect> {
        let mut set = Self::always_on_invariant_effects();
        if self.require_review_before_push_main {
            set.extend([
                Effect::PushMainBranch,
                Effect::ForcePushProtectedBranch,
                Effect::ForcePushRemote,
                Effect::MergePullRequest,
                Effect::MutateRepositoryVisibility,
                Effect::DeleteRelease,
            ]);
        }
        if self.require_review_before_any_push {
            set.insert(Effect::PushRemote);
        }
        if self.protect_secrets_auth_migrations {
            set.extend([
                Effect::MutateSecrets,
                Effect::ApplySchemaMigration,
                Effect::DestructiveSchemaReset,
                Effect::SensitivePathAccess,
            ]);
        }
        if self.forbid_destructive_worktree_ops {
            set.extend([
                Effect::RecursiveDelete,
                Effect::ForceDelete,
                Effect::DestructiveWorktreeOp,
            ]);
        }
        if self.fail_closed_on_unknown_commands {
            set.insert(Effect::UnrecognizedOrAmbiguousCommand);
        }
        set
    }

    /// Effects that ALWAYS trigger [`PolicyDisposition::BlockHardInvariant`] regardless of customer toggles.
    #[must_use]
    pub fn always_on_invariant_effects() -> BTreeSet<Effect> {
        BTreeSet::from([
            Effect::DynamicExecOrConfigEscape,
            Effect::PathTraversalEscape,
            Effect::RootOrWildcardDeleteHazard,
        ])
    }

    /// Evaluates a parsed [`CanonicalCommandTupleV1`] against this customer safety policy.
    #[must_use]
    pub fn evaluate_tuple(&self, tuple: CanonicalCommandTupleV1) -> PolicyEvaluationV1 {
        if tuple.fail_closed_reason.is_some() {
            let mut triggered = tuple.effects.clone();
            triggered.remove(&Effect::ReadOnly);
            return PolicyEvaluationV1 {
                disposition: PolicyDisposition::BlockHardInvariant,
                triggered_effects: triggered,
                matched_toggles: vec![SafetyToggle::AlwaysOnContainmentInvariant],
                reason: tuple
                    .fail_closed_reason
                    .clone()
                    .unwrap_or_else(|| "fail-closed syntax or bounds violation".to_string()),
                tuple,
            };
        }

        let hard_invariants = Self::always_on_invariant_effects();
        let mut triggered = BTreeSet::new();
        let mut toggles = BTreeSet::new();
        let mut hard_block = false;

        for &eff in &tuple.effects {
            if hard_invariants.contains(&eff) {
                triggered.insert(eff);
                toggles.insert(SafetyToggle::AlwaysOnContainmentInvariant);
                hard_block = true;
            }
            if self.require_review_before_push_main
                && matches!(
                    eff,
                    Effect::PushMainBranch
                        | Effect::ForcePushProtectedBranch
                        | Effect::ForcePushRemote
                        | Effect::MergePullRequest
                        | Effect::MutateRepositoryVisibility
                        | Effect::DeleteRelease
                )
            {
                triggered.insert(eff);
                toggles.insert(SafetyToggle::RequireReviewBeforePushMain);
            }
            if self.require_review_before_any_push && eff == Effect::PushRemote {
                triggered.insert(eff);
                toggles.insert(SafetyToggle::RequireReviewBeforeAnyPush);
            }
            if self.protect_secrets_auth_migrations
                && matches!(
                    eff,
                    Effect::MutateSecrets
                        | Effect::ApplySchemaMigration
                        | Effect::DestructiveSchemaReset
                        | Effect::SensitivePathAccess
                )
            {
                triggered.insert(eff);
                toggles.insert(SafetyToggle::ProtectSecretsAuthMigrations);
            }
            if self.forbid_destructive_worktree_ops
                && matches!(
                    eff,
                    Effect::RecursiveDelete | Effect::ForceDelete | Effect::DestructiveWorktreeOp
                )
            {
                triggered.insert(eff);
                toggles.insert(SafetyToggle::ForbidDestructiveWorktreeOps);
            }
            if self.fail_closed_on_unknown_commands && eff == Effect::UnrecognizedOrAmbiguousCommand
            {
                triggered.insert(eff);
                toggles.insert(SafetyToggle::AlwaysOnContainmentInvariant);
            }
        }

        let matched_toggles: Vec<SafetyToggle> = toggles.into_iter().collect();
        let (disposition, reason) = if hard_block {
            (
                PolicyDisposition::BlockHardInvariant,
                format!(
                    "blocked by always-on containment invariant ({:?})",
                    triggered
                ),
            )
        } else if !triggered.is_empty() {
            (
                PolicyDisposition::RequireReview,
                format!(
                    "gated by workflow safety toggles {:?} on effects {:?}",
                    matched_toggles, triggered
                ),
            )
        } else {
            (
                PolicyDisposition::Allow,
                format!(
                    "allowed ({} -> {})",
                    tuple.program.as_str(),
                    tuple.action.as_str()
                ),
            )
        };

        PolicyEvaluationV1 {
            disposition,
            triggered_effects: triggered,
            matched_toggles,
            tuple,
            reason,
        }
    }

    /// Loads `.chinwag/workflow.yaml` from `repo_root`, rejecting symlinks on `.chinwag`
    /// and `.chinwag/workflow.yaml`. Returns `Ok(Self::default())` if `.chinwag/workflow.yaml` is absent.
    pub fn load_from_repo_root(repo_root: &Path) -> Result<Self, PolicyParseError> {
        let dot_chinwag = repo_root.join(".chinwag");
        match std::fs::symlink_metadata(&dot_chinwag) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(PolicyParseError::UnsafeWorkflowFile(
                        ".chinwag must be a non-symlink directory".to_string(),
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(PolicyParseError::IoError(e.to_string())),
        }

        let wf_path = dot_chinwag.join("workflow.yaml");
        match std::fs::symlink_metadata(&wf_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(PolicyParseError::UnsafeWorkflowFile(
                        ".chinwag/workflow.yaml must be a regular non-symlink file".to_string(),
                    ));
                }
                let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
                if len > 128 * 1024 {
                    return Err(PolicyParseError::OversizedYaml(len));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(PolicyParseError::IoError(e.to_string())),
        }

        let raw = std::fs::read_to_string(&wf_path)
            .map_err(|e| PolicyParseError::IoError(e.to_string()))?;
        Self::from_workflow_yaml(&raw)
    }

    /// Parses `.chinwag/workflow.yaml` content without pulling a heavyweight YAML dependency.
    pub fn from_workflow_yaml(raw: &str) -> Result<Self, PolicyParseError> {
        if raw.len() > 128 * 1024 {
            return Err(PolicyParseError::OversizedYaml(raw.len()));
        }

        let mut policy = Self::default();
        let mut explicit_push_main: Option<bool> = None;
        let mut explicit_any_push: Option<bool> = None;
        let mut explicit_protect_sam: Option<bool> = None;
        let mut explicit_forbid_wt: Option<bool> = None;
        let mut legacy_click_push: Option<bool> = None;
        let mut legacy_protect_paths: Option<bool> = None;
        let mut legacy_ask_secrets: Option<bool> = None;

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum BlockListKind {
            None,
            ProtectedPaths,
            ProtectedBranches,
        }

        let mut active_list = BlockListKind::None;
        let mut list_accum: Vec<String> = Vec::new();

        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if active_list != BlockListKind::None {
                if let Some(item) = trimmed.strip_prefix("- ") {
                    let key_name = if active_list == BlockListKind::ProtectedPaths {
                        "protected_paths"
                    } else {
                        "protected_branches"
                    };
                    let scalar = parse_safe_yaml_scalar(item).ok_or_else(|| {
                        PolicyParseError::InvalidPathEntry {
                            key: key_name.to_string(),
                        }
                    })?;
                    list_accum.push(scalar);
                    continue;
                }
                match active_list {
                    BlockListKind::ProtectedPaths => {
                        policy.protected_paths = std::mem::take(&mut list_accum);
                    }
                    BlockListKind::ProtectedBranches => {
                        policy.protected_branches = std::mem::take(&mut list_accum);
                    }
                    BlockListKind::None => {}
                }
                active_list = BlockListKind::None;
            }

            let Some((k, v_raw)) = trimmed.split_once(':') else {
                continue;
            };
            let key = k.trim();
            let val_trimmed = strip_inline_yaml_comment(v_raw.trim());
            let val_clean = val_trimmed.trim_matches('"').trim_matches('\'');

            match key {
                "require_review_before_push_main" => {
                    explicit_push_main = Some(parse_yaml_bool(key, val_clean)?);
                }
                "require_review_before_any_push" => {
                    explicit_any_push = Some(parse_yaml_bool(key, val_clean)?);
                }
                "protect_secrets_auth_migrations" => {
                    explicit_protect_sam = Some(parse_yaml_bool(key, val_clean)?);
                }
                "forbid_destructive_worktree_ops" => {
                    explicit_forbid_wt = Some(parse_yaml_bool(key, val_clean)?);
                }
                "fail_closed_on_unknown_commands" => {
                    policy.fail_closed_on_unknown_commands = parse_yaml_bool(key, val_clean)?;
                }
                "require_click_before_push" => {
                    legacy_click_push = Some(parse_yaml_bool(key, val_clean)?);
                }
                "protect_sensitive_paths" => {
                    legacy_protect_paths = Some(parse_yaml_bool(key, val_clean)?);
                }
                "ask_before_secrets" => {
                    legacy_ask_secrets = Some(parse_yaml_bool(key, val_clean)?);
                }
                "protected_paths" => {
                    if val_trimmed.is_empty() {
                        active_list = BlockListKind::ProtectedPaths;
                        list_accum.clear();
                    } else if let Some(items) = parse_inline_yaml_list(val_trimmed, key)? {
                        policy.protected_paths = items;
                    }
                }
                "protected_branches" => {
                    if val_trimmed.is_empty() {
                        active_list = BlockListKind::ProtectedBranches;
                        list_accum.clear();
                    } else if let Some(items) = parse_inline_yaml_list(val_trimmed, key)? {
                        policy.protected_branches = items;
                    }
                }
                _ => {}
            }
        }

        match active_list {
            BlockListKind::ProtectedPaths => {
                policy.protected_paths = list_accum;
            }
            BlockListKind::ProtectedBranches => {
                policy.protected_branches = list_accum;
            }
            BlockListKind::None => {}
        }

        if let Some(b) = explicit_push_main.or(legacy_click_push) {
            policy.require_review_before_push_main = b;
        }
        if let Some(b) = explicit_any_push.or(legacy_click_push) {
            policy.require_review_before_any_push = b;
        }
        if let Some(b) = explicit_protect_sam {
            policy.protect_secrets_auth_migrations = b;
        } else if legacy_protect_paths.is_some() || legacy_ask_secrets.is_some() {
            policy.protect_secrets_auth_migrations =
                legacy_protect_paths.unwrap_or(false) || legacy_ask_secrets.unwrap_or(false);
        }
        if let Some(b) = explicit_forbid_wt {
            policy.forbid_destructive_worktree_ops = b;
        }

        Ok(policy)
    }
}

fn parse_yaml_bool(key: &str, raw: &str) -> Result<bool, PolicyParseError> {
    match raw {
        "true" | "True" | "TRUE" => Ok(true),
        "false" | "False" | "FALSE" => Ok(false),
        other => Err(PolicyParseError::InvalidBoolean {
            key: key.to_string(),
            value: other.to_string(),
        }),
    }
}

fn strip_inline_yaml_comment(s: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, ch) in s.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single
                && !in_double
                && (idx == 0 || s.as_bytes()[idx - 1].is_ascii_whitespace()) =>
            {
                return s[..idx].trim();
            }
            _ => {}
        }
    }
    s.trim()
}

fn parse_safe_yaml_scalar(raw: &str) -> Option<String> {
    let uncommented = strip_inline_yaml_comment(raw);
    let unquoted = uncommented
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| {
            uncommented
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
        })
        .unwrap_or(uncommented)
        .trim();
    if unquoted.is_empty()
        || unquoted == "~"
        || unquoted.eq_ignore_ascii_case("null")
        || unquoted.chars().any(char::is_control)
        || unquoted.split(['/', '\\']).any(|seg| seg == "..")
    {
        return None;
    }
    Some(unquoted.to_string())
}

fn parse_inline_yaml_list(raw: &str, key: &str) -> Result<Option<Vec<String>>, PolicyParseError> {
    let Some(inner) = raw.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return Ok(None);
    };
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let mut out = Vec::new();
    for part in trimmed.split(',') {
        let item =
            parse_safe_yaml_scalar(part).ok_or_else(|| PolicyParseError::InvalidPathEntry {
                key: key.to_string(),
            })?;
        out.push(item);
    }
    Ok(Some(out))
}

/// Safely resolves the symbolic branch checked out at `repo_root/.git/HEAD` (including linked Git worktree
/// `.git` gitfiles), rejecting symlinks and oversized files. Returns `None` on detached `HEAD` or non-Git dirs.
fn resolve_repo_head_branch(repo_root: &Path) -> Option<String> {
    let dot_git = repo_root.join(".git");
    let meta = std::fs::symlink_metadata(&dot_git).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }

    let git_dir = if meta.is_dir() {
        dot_git
    } else if meta.is_file() && meta.len() <= 4096 {
        let gitfile = std::fs::read_to_string(&dot_git).ok()?;
        let raw_dir = gitfile.lines().next()?.strip_prefix("gitdir:")?.trim();
        if raw_dir.is_empty() {
            return None;
        }
        let candidate = Path::new(raw_dir);
        let resolved = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            repo_root.join(candidate)
        };
        let gd_meta = std::fs::symlink_metadata(&resolved).ok()?;
        if gd_meta.file_type().is_symlink() || !gd_meta.is_dir() {
            return None;
        }
        resolved
    } else {
        return None;
    };

    let head_path = git_dir.join("HEAD");
    let head_meta = std::fs::symlink_metadata(&head_path).ok()?;
    if head_meta.file_type().is_symlink() || !head_meta.is_file() || head_meta.len() > 4096 {
        return None;
    }
    let head_raw = std::fs::read_to_string(&head_path).ok()?;
    let sym_ref = head_raw.lines().next()?.strip_prefix("ref:")?.trim();
    let branch = crate::path_norm::strip_git_ref_prefix(sym_ref).trim();
    if branch.is_empty() {
        None
    } else {
        Some(branch.to_string())
    }
}
