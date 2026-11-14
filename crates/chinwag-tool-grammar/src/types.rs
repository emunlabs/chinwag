// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// Canonical schema version tag for `ToolGrammarV1` parse outputs.
pub const TOOL_GRAMMAR_SCHEMA_V1: &str = "ToolGrammarV1";

/// Hard upper bound on argv token count to guarantee `<50 µs` bounded parsing.
pub const MAX_ARGV_TOKENS: usize = 512;

/// Hard upper bound on command-line byte length (`32 KiB`) to prevent DoS.
pub const MAX_COMMAND_BYTES: usize = 32 * 1024;

/// Maximum wrapper / shell `-c` / command-substitution recursion depth.
pub const MAX_UNWRAP_DEPTH: usize = 4;

/// Default protected branch patterns enforced when pushing or deleting remote refs.
pub const DEFAULT_PROTECTED_BRANCHES: &[&str] =
    &["main", "master", "prod", "production", "trunk", "release/*"];

/// Default protected path globs matching `.chinwag/workflow.yaml` defaults.
pub const DEFAULT_PROTECTED_PATHS: &[&str] = &[
    ".env*",
    "**/auth/**",
    "**/billing/**",
    "**/migrations/**",
    ".github/workflows/**",
];

/// Canonical CLI binary family after stripping filesystem prefixes (`/usr/bin/git` -> `Git`)
/// and transparent process/package wrappers (`env`, `command`, `sudo`, `npx`, `pnpm dlx`, `xargs`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Program {
    Git,
    Jj,
    Gh,
    Rm,
    Prisma,
    DrizzleKit,
    Sqlx,
    Wrangler,
    ShellWrapper,
    Unknown(String),
}

/// Alias matching spike blueprint terminology.
pub type CanonicalProgram = Program;

impl Program {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Git => "git",
            Self::Jj => "jj",
            Self::Gh => "gh",
            Self::Rm => "rm",
            Self::Prisma => "prisma",
            Self::DrizzleKit => "drizzle-kit",
            Self::Sqlx => "sqlx",
            Self::Wrangler => "wrangler",
            Self::ShellWrapper => "shell_wrapper",
            Self::Unknown(name) => name.as_str(),
        }
    }
}

/// Normalized, flag-order-immune semantic action extracted from `argv` or a shell command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    // Read-only inspection actions (`0` false-positive guarantee when uncontaminated)
    Status,
    Diff,
    Log,
    PrList,
    IssueView,
    MigrateInfo,
    ReadOnlyInspect,

    // Git mutating & remote actions
    Push,
    ForcePush,
    ResetHard,
    CleanUntracked,
    BranchDelete,
    CheckoutDiscard,
    ConfigMutate,
    WorktreeMutate,

    // Jujutsu (`jj`) mutating & remote actions
    GitPush,
    Abandon,
    OpRestore,
    BookmarkDelete,

    // GitHub CLI (`gh`) mutating & remote actions
    PrMerge,
    RepoEditVisibility,
    SecretSet,
    SecretDelete,
    ReleaseDelete,
    ApiMutate,

    // Filesystem deletion (`rm`)
    RecursiveDelete,
    ForceDelete,
    Delete,

    // Database & edge schema migration CLIs (`prisma`, `drizzle-kit`, `sqlx`, `wrangler d1`)
    MigrateDeploy,
    MigrateReset,
    SchemaPush,
    SchemaDrop,
    MigrateRun,
    MigrateRevert,
    D1MigrationsApply,
    D1Execute,

    // Fail-closed / escape / unrecognized fallback actions
    DynamicExecEscape,
    AmbiguousShellOrWrapper,
    UnknownAction,
}

/// Alias matching spike blueprint terminology.
pub type CanonicalAction = Action;

impl Action {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Diff => "diff",
            Self::Log => "log",
            Self::PrList => "pr_list",
            Self::IssueView => "issue_view",
            Self::MigrateInfo => "migrate_info",
            Self::ReadOnlyInspect => "read_only_inspect",
            Self::Push => "push",
            Self::ForcePush => "force_push",
            Self::ResetHard => "reset_hard",
            Self::CleanUntracked => "clean_untracked",
            Self::BranchDelete => "branch_delete",
            Self::CheckoutDiscard => "checkout_discard",
            Self::ConfigMutate => "config_mutate",
            Self::WorktreeMutate => "worktree_mutate",
            Self::GitPush => "git_push",
            Self::Abandon => "abandon",
            Self::OpRestore => "op_restore",
            Self::BookmarkDelete => "bookmark_delete",
            Self::PrMerge => "pr_merge",
            Self::RepoEditVisibility => "repo_edit_visibility",
            Self::SecretSet => "secret_set",
            Self::SecretDelete => "secret_delete",
            Self::ReleaseDelete => "release_delete",
            Self::ApiMutate => "api_mutate",
            Self::RecursiveDelete => "recursive_delete",
            Self::ForceDelete => "force_delete",
            Self::Delete => "delete",
            Self::MigrateDeploy => "migrate_deploy",
            Self::MigrateReset => "migrate_reset",
            Self::SchemaPush => "schema_push",
            Self::SchemaDrop => "schema_drop",
            Self::MigrateRun => "migrate_run",
            Self::MigrateRevert => "migrate_revert",
            Self::D1MigrationsApply => "d1_migrations_apply",
            Self::D1Execute => "d1_execute",
            Self::DynamicExecEscape => "dynamic_exec_escape",
            Self::AmbiguousShellOrWrapper => "ambiguous_shell_or_wrapper",
            Self::UnknownAction => "unknown_action",
        }
    }

    #[must_use]
    pub const fn is_read_only_action(&self) -> bool {
        matches!(
            self,
            Self::Status
                | Self::Diff
                | Self::Log
                | Self::PrList
                | Self::IssueView
                | Self::MigrateInfo
                | Self::ReadOnlyInspect
        )
    }
}

/// Orthogonal security effect primitives mapped onto `.chinwag/workflow.yaml` customer safety toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Effect {
    /// Pure read-only inspection (`git status`, `git diff`, `git log -p`, `gh pr list`, `jj log`, `sqlx migrate info`).
    ReadOnly,
    /// Non-force push to a non-protected remote branch (`git push origin feat/x`).
    PushRemote,
    /// Push targeting a protected branch (`main`, `master`, `prod`, `production`, `trunk`, `release/*`).
    PushMainBranch,
    /// Force push (`-f`, `--force`, `--force-with-lease`, `+refspec`, `--mirror`) or remote ref delete (`--delete`, `:ref`).
    ForcePushRemote,
    /// Force push or remote ref deletion targeting a protected branch (or refspec-less / `--mirror` / `--all` force push).
    ForcePushProtectedBranch,
    /// Merging a pull request into base branch (`gh pr merge`).
    MergePullRequest,
    /// Changing repository visibility or deleting/archiving a repository (`gh repo edit --visibility`).
    MutateRepositoryVisibility,
    /// Deleting a published release or tag (`gh release delete`).
    DeleteRelease,
    /// Reading, setting, or deleting secrets/tokens, or injecting HTTP auth headers (`gh secret set`, `-c http.extraheader`).
    MutateSecrets,
    /// Applying forward schema migrations or pushing schema (`prisma migrate deploy`, `sqlx migrate run`, `drizzle-kit push`, `wrangler d1 migrations apply`).
    ApplySchemaMigration,
    /// Destructive schema reset, drop, revert, or destructive SQL (`prisma migrate reset`, `drizzle-kit drop`, `sqlx migrate revert`, `DROP TABLE`).
    DestructiveSchemaReset,
    /// Destructive local worktree/history mutation (`git reset --hard`, `git clean -f`, `git branch -D`, `jj abandon`, `jj op restore`).
    DestructiveWorktreeOp,
    /// Recursive directory deletion (`rm -r`, `rm -R`, `rm --recursive`, `git clean -fd`).
    RecursiveDelete,
    /// Forced deletion (`rm -f`, `rm --force`).
    ForceDelete,
    /// Root, home, or top-level wildcard deletion hazard (`rm -rf /`, `rm -rf /*`, `rm -rf ~`, `--no-preserve-root`).
    RootOrWildcardDeleteHazard,
    /// Mutating sensitive or control-plane paths (`.env*`, `**/auth/**`, `**/migrations/**`, `.chinwag/**`, `.git/**`, `.github/workflows/**`).
    SensitivePathAccess,
    /// Lexical `..` traversal or `-C` / `--git-dir` / `--work-tree` escaping workspace root, or mutating system paths (`/etc/...`).
    PathTraversalEscape,
    /// Arbitrary command execution, privilege escalation, hook/config RCE (`git -c core.sshCommand`, `--upload-pack`, `GIT_SSH_COMMAND`, `sudo`, `$()`).
    DynamicExecOrConfigEscape,
    /// Unrecognized program/subcommand, dynamic `$VAR` command token, NUL byte, unclosed quote, or shell script ambiguity.
    UnrecognizedOrAmbiguousCommand,
}

/// Alias matching spike blueprint terminology.
pub type ToolEffect = Effect;

impl Effect {
    /// Severity rank used when summarizing compound shell chains (`a && b`).
    #[must_use]
    pub const fn severity_rank(self) -> u8 {
        match self {
            Self::ReadOnly => 0,
            Self::PushRemote => 20,
            Self::ForceDelete => 30,
            Self::DestructiveWorktreeOp => 35,
            Self::RecursiveDelete => 45,
            Self::ApplySchemaMigration => 50,
            Self::SensitivePathAccess => 55,
            Self::MergePullRequest => 60,
            Self::DeleteRelease => 65,
            Self::PushMainBranch => 70,
            Self::ForcePushRemote => 75,
            Self::MutateSecrets => 80,
            Self::DestructiveSchemaReset => 85,
            Self::MutateRepositoryVisibility => 88,
            Self::ForcePushProtectedBranch => 90,
            Self::UnrecognizedOrAmbiguousCommand => 92,
            Self::PathTraversalEscape => 96,
            Self::RootOrWildcardDeleteHazard => 98,
            Self::DynamicExecOrConfigEscape => 100,
        }
    }
}

/// Normalized target entities extracted from refspecs, path operands, remotes, secrets, or DB bindings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    Refspec {
        raw: String,
        src: Option<String>,
        dst: String,
        leading_plus_force: bool,
        colon_delete: bool,
        targets_protected_branch: bool,
    },
    Branch {
        name: String,
        protected: bool,
    },
    Path {
        raw: String,
        normalized: String,
        escapes_workspace: bool,
        control_plane: bool,
        sensitive: bool,
        root_or_wildcard_hazard: bool,
    },
    Remote {
        remote_or_repo: String,
    },
    Secret {
        name: String,
    },
    Database {
        engine: String,
        target: String,
    },
}

/// Alias matching spike blueprint terminology.
pub type CanonicalTarget = Target;

/// Environment variable assignment peeled from command prefix or `env` wrapper (`KEY=VALUE`).
/// Secret values are NEVER retained in canonical tuples (`ROG-580` / zero-secret-leak discipline).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EnvOverride {
    pub key: String,
    pub exec_or_loader_hazard: bool,
    pub secret_or_auth_override: bool,
    pub path_or_routing_override: bool,
}

/// Optional repository context for path containment and protected-branch/path customization.
#[derive(Debug, Clone)]
pub struct ParseContext<'a> {
    /// Optional lexical workspace root (e.g. `Some(Path::new("/workspace/repo"))`).
    pub workspace_root: Option<&'a Path>,
    /// Protected path globs (defaults to [`DEFAULT_PROTECTED_PATHS`]).
    pub protected_paths: &'a [&'a str],
    /// Protected branch patterns (defaults to [`DEFAULT_PROTECTED_BRANCHES`]).
    pub protected_branches: &'a [&'a str],
    /// Optional currently checked-out branch name for resolving bare `git push` / `git push origin HEAD`.
    pub current_branch: Option<&'a str>,
}

impl Default for ParseContext<'static> {
    fn default() -> Self {
        Self {
            workspace_root: None,
            protected_paths: DEFAULT_PROTECTED_PATHS,
            protected_branches: DEFAULT_PROTECTED_BRANCHES,
            current_branch: None,
        }
    }
}

/// Canonical `<50 µs` `ToolGrammarV1` parse result: `(program, action, effects, target_refs_or_paths)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalCommandTupleV1 {
    pub schema: String,
    pub program: Program,
    pub action: Action,
    pub effects: BTreeSet<Effect>,
    pub target_refs_or_paths: Vec<Target>,
    pub wrappers_peeled: Vec<String>,
    pub env_overrides: Vec<EnvOverride>,
    pub via_xargs: bool,
    pub elapsed_nanos: u64,
    pub elapsed_micros: u64,
    pub fail_closed_reason: Option<String>,
}

impl CanonicalCommandTupleV1 {
    /// Returns `true` iff `effects` is strictly `{Effect::ReadOnly}` and `fail_closed_reason` is `None`.
    #[must_use]
    pub fn is_strictly_read_only(&self) -> bool {
        self.fail_closed_reason.is_none()
            && self.effects.len() == 1
            && self.effects.contains(&Effect::ReadOnly)
    }

    /// Alias accessor matching `targets` field name in early design docs.
    #[must_use]
    pub fn targets(&self) -> &[Target] {
        &self.target_refs_or_paths
    }
}
