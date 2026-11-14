// SPDX-License-Identifier: Apache-2.0

use crate::grammar::{attach_path_target_effects, attach_read_path_target_effects};
use crate::path_norm::{
    analyze_path_target, apply_repo_dir_selector, check_non_chdir_repo_selector,
};
use crate::shell::lex_shell_command;
use crate::types::{Effect, EnvOverride, MAX_ARGV_TOKENS, MAX_UNWRAP_DEPTH, ParseContext, Target};
use std::collections::{BTreeMap, BTreeSet};

/// Inherited working-directory, Git worktree, and repository-redirection state carried across
/// shell segments (`cd`, `GIT_DIR=...; ...`, `export GIT_DIR=...`), wrapper peelers (`env -C`,
/// `sudo -D`, `pnpm -C`), and delegated inner shell scripts (`sh -c`, `npx -c`, `npm --call`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InheritedSelectorState {
    /// Effective process working-directory offset accumulated from `cd` / `env -C` / `sudo -D` / `pnpm -C`.
    pub cwd_offset: Option<String>,
    /// Normalized Git worktree override from `GIT_WORK_TREE` or `--work-tree` at last validation point.
    pub worktree_override: Option<String>,
    /// Raw unnormalized `GIT_WORK_TREE` / `--work-tree` string so subsequent `cd` / `-C` re-resolves against final `cwd`.
    pub raw_worktree: Option<String>,
    /// Raw unnormalized `GIT_DIR` / `--git-dir` string so subsequent `cd` / `-C` re-resolves against final `cwd`.
    pub raw_git_dir: Option<String>,
    /// Raw unnormalized Git directory/index env paths (`GIT_COMMON_DIR`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY`).
    pub raw_git_env_paths: BTreeMap<String, String>,
    /// Raw unnormalized colon-separated `GIT_ALTERNATE_OBJECT_DIRECTORIES` entries.
    pub raw_git_alt_obj_dirs: Vec<String>,
    /// Sticky monotonic flag indicating repository resolution was redirected away from the default workspace repo.
    pub repo_selector_redirected: bool,
}

impl InheritedSelectorState {
    /// Re-resolves raw `GIT_WORK_TREE`, `GIT_DIR`, and Git path environment selectors against the
    /// current `cwd_offset` (e.g. after subsequent `cd ..` or `-C ..`), emitting [`Effect::PathTraversalEscape`]
    /// if any selector now escapes the workspace boundary.
    pub fn revalidate_selectors(&mut self, ctx: &ParseContext<'_>, effects: &mut BTreeSet<Effect>) {
        if let Some(raw_wt) = self.raw_worktree.clone() {
            let (norm, escapes) = check_non_chdir_repo_selector(
                self.cwd_offset.as_deref(),
                &mut self.repo_selector_redirected,
                &raw_wt,
                ctx,
            );
            if escapes {
                effects.insert(Effect::PathTraversalEscape);
            }
            self.worktree_override = Some(norm);
        } else {
            self.worktree_override = None;
        }

        if let Some(raw_gd) = self.raw_git_dir.clone() {
            let (_norm, escapes) = check_non_chdir_repo_selector(
                self.cwd_offset.as_deref(),
                &mut self.repo_selector_redirected,
                &raw_gd,
                ctx,
            );
            if escapes {
                effects.insert(Effect::PathTraversalEscape);
            }
        }

        let env_vals: Vec<String> = self.raw_git_env_paths.values().cloned().collect();
        for raw_p in env_vals {
            let (_norm, escapes) = check_non_chdir_repo_selector(
                self.cwd_offset.as_deref(),
                &mut self.repo_selector_redirected,
                &raw_p,
                ctx,
            );
            if escapes {
                effects.insert(Effect::PathTraversalEscape);
            }
        }

        let alt_dirs = self.raw_git_alt_obj_dirs.clone();
        for entry in alt_dirs {
            let (_norm, escapes) = check_non_chdir_repo_selector(
                self.cwd_offset.as_deref(),
                &mut self.repo_selector_redirected,
                &entry,
                ctx,
            );
            if escapes {
                effects.insert(Effect::PathTraversalEscape);
            }
        }
    }

    /// Clears environment-backed Git path selectors on `env -i` / `exec -c` while preserving sticky `repo_selector_redirected`.
    pub fn clear_env_selectors(&mut self) {
        self.worktree_override = None;
        self.raw_worktree = None;
        self.raw_git_dir = None;
        self.raw_git_env_paths.clear();
        self.raw_git_alt_obj_dirs.clear();
    }

    /// Unsets a single environment-backed Git path selector (`env -u NAME`) using exact POSIX
    /// variable-name case while preserving sticky `repo_selector_redirected`.
    pub fn unset_env_selector(&mut self, name: &str) {
        match name {
            "GIT_WORK_TREE" => {
                self.worktree_override = None;
                self.raw_worktree = None;
            }
            "GIT_DIR" => {
                self.raw_git_dir = None;
            }
            "GIT_ALTERNATE_OBJECT_DIRECTORIES" => {
                self.raw_git_alt_obj_dirs.clear();
            }
            _ => {
                self.raw_git_env_paths.remove(name);
            }
        }
    }
}

/// Outcome of peeling leading `KEY=VALUE` environment overrides and transparent process/package wrappers.
#[derive(Debug, Clone)]
pub struct UnwrappedInvocation {
    /// Remaining unwrapped `argv` starting at the target binary (`git`, `rm`, `prisma`, etc.).
    pub argv: Vec<String>,
    /// Ordered list of wrappers peeled (`["env", "sudo", "npx"]`).
    pub wrappers_peeled: Vec<String>,
    /// Sanitized environment variable keys encountered (`KEY` only, never secret value!).
    pub env_overrides: Vec<EnvOverride>,
    /// Effects injected by wrappers themselves (e.g. `sudo`, `GIT_SSH_COMMAND`, `env -C ../outside`, `time -o .env`).
    pub wrapper_effects: BTreeSet<Effect>,
    /// File targets touched directly by wrappers (`time -o <file>`, `xargs -a <file>`).
    pub wrapper_targets: Vec<Target>,
    /// Effective working-directory offset accumulated from `env -C` / `sudo -D` / `pnpm -C`.
    pub cwd_offset: Option<String>,
    /// Explicit Git worktree override accumulated from `GIT_WORK_TREE` without mutating `cwd_offset`.
    pub worktree_override: Option<String>,
    /// Sticky monotonic flag indicating that environment overrides or directory flags redirected VCS repository resolution.
    pub repo_selector_redirected: bool,
    /// Full inherited selector state including raw relative Git path selectors for deferred `cwd` resolution.
    pub selector: InheritedSelectorState,
    /// True if invoked through `xargs` (meaning trailing target operands arrive dynamically from stdin).
    pub via_xargs: bool,
    /// True if `command -v` or `command -V` (POSIX read-only binary lookup, does NOT execute target!).
    pub is_command_lookup_only: bool,
    /// Inner shell script strings if unwrapped to `sh -c <script>` / `npx -c <s1> -c <s2>` / `npm --call=<s1> exec --call=<s2>`.
    pub delegated_shell_scripts: Vec<String>,
    /// Cumulative wrapper + recursion depth consumed so far.
    pub depth: usize,
    /// Optional fail-closed reason if wrapper syntax is malformed or exceeds depth.
    pub fail_closed_reason: Option<String>,
}

/// Extracts basename of a binary token (`/usr/bin/git` -> `git`, `@prisma/cli@5.0.0` -> `prisma`).
#[must_use]
pub fn normalize_binary_basename(raw_prog: &str) -> String {
    let trimmed = raw_prog.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Scoped npm package like `prisma@5.20.0` or `drizzle-kit@latest` (not filesystem path starting with `/` or `.`)
    if !trimmed.starts_with('/') && !trimmed.starts_with('.') {
        if let Some(scoped) = trimmed.strip_prefix('@') {
            if let Some((_scope, pkg_and_ver)) = scoped.split_once('/') {
                let pkg = pkg_and_ver.split('@').next().unwrap_or(pkg_and_ver);
                if pkg == "cli" && scoped.starts_with("prisma/") {
                    return "prisma".to_string();
                }
                return strip_exe_suffix(pkg).to_string();
            }
        } else if !trimmed.contains('/') && !trimmed.contains('\\') {
            let pkg = trimmed.split('@').next().unwrap_or(trimmed);
            return strip_exe_suffix(pkg).to_string();
        }
    }

    let after_slash = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed);
    strip_exe_suffix(after_slash).to_string()
}

fn strip_exe_suffix(name: &str) -> &str {
    name.strip_suffix(".exe").unwrap_or(name)
}

/// Returns `Some((key, val))` if `token` is a valid POSIX `KEY=VALUE` or bash/zsh `KEY+=VALUE` assignment.
#[must_use]
pub fn split_env_assignment(token: &str) -> Option<(&str, &str)> {
    let (key, val, _is_append) = split_env_assignment_with_op(token)?;
    Some((key, val))
}

/// Returns `Some((key, val, is_append))` if `token` is `KEY=VALUE` (`false`) or `KEY+=VALUE` (`true`).
#[must_use]
pub fn split_env_assignment_with_op(token: &str) -> Option<(&str, &str, bool)> {
    let (raw_key, val) = token.split_once('=')?;
    let (key, is_append) = match raw_key.strip_suffix('+') {
        Some(k) => (k, true),
        None => (raw_key, false),
    };
    if key.is_empty() {
        return None;
    }
    let mut chars = key.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((key, val, is_append))
}

/// Classifies an environment variable override without storing secret values.
#[must_use]
pub fn classify_env_override(
    key: &str,
    val: &str,
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    selector: &mut InheritedSelectorState,
) -> EnvOverride {
    classify_env_override_with_op(key, val, false, ctx, effects, selector)
}

/// Classifies an environment variable override (including `KEY+=VAL` append syntax) without storing secret values.
#[must_use]
pub fn classify_env_override_with_op(
    key: &str,
    val: &str,
    is_append: bool,
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    selector: &mut InheritedSelectorState,
) -> EnvOverride {
    let upper = key.to_ascii_uppercase();
    let exec_or_loader_hazard = matches!(
        upper.as_str(),
        "GIT_SSH_COMMAND"
            | "GIT_SSH"
            | "GIT_ASKPASS"
            | "SSH_ASKPASS"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_EXEC_PATH"
            | "GIT_TEMPLATE_DIR"
            | "GIT_EDITOR"
            | "GIT_SEQUENCE_EDITOR"
            | "GIT_PAGER"
            | "GIT_CONFIG_GLOBAL"
            | "GIT_CONFIG_SYSTEM"
            | "GIT_CONFIG_COUNT"
            | "GIT_CONFIG_PARAMETERS"
            | "GIT_ALLOW_PROTOCOL"
            | "GIT_PROTOCOL"
            | "GIT_PROTOCOL_FROM_USER"
            | "PAGER"
            | "MANPAGER"
            | "GH_PAGER"
            | "LESSOPEN"
            | "LESSCLOSE"
            | "VISUAL"
            | "EDITOR"
            | "NPM_CONFIG_SCRIPT_SHELL"
            | "NPM_CONFIG_SHELL_EMULATOR"
            | "NPM_CONFIG_USERCONFIG"
            | "NPM_CONFIG_GLOBALCONFIG"
            | "YARN_SCRIPT_SHELL"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "DYLD_INSERT_LIBRARIES"
            | "DYLD_LIBRARY_PATH"
            | "DYLD_FRAMEWORK_PATH"
            | "NODE_OPTIONS"
            | "BASH_ENV"
            | "ENV"
            | "SHELLOPTS"
            | "BASHOPTS"
            | "PS4"
            | "FPATH"
            | "ZDOTDIR"
            | "PATH"
            | "PROMPT_COMMAND"
            | "PYTHONSTARTUP"
            | "PYTHONPATH"
            | "RUBYOPT"
            | "PERL5OPT"
    ) || upper.starts_with("GIT_CONFIG_KEY_")
        || upper.starts_with("GIT_CONFIG_VALUE_")
        || upper.starts_with("BASH_FUNC_");

    let secret_or_auth_override = matches!(
        upper.as_str(),
        "GH_TOKEN"
            | "GITHUB_TOKEN"
            | "GIT_HTTP_LOW_SPEED_LIMIT"
            | "CLOUDFLARE_API_TOKEN"
            | "CLOUDFLARE_API_KEY"
            | "DATABASE_URL"
            | "AWS_SECRET_ACCESS_KEY"
            | "OPENAI_API_KEY"
            | "ANTHROPIC_API_KEY"
    );

    let path_or_routing_override = matches!(
        upper.as_str(),
        "GIT_DIR"
            | "GIT_WORK_TREE"
            | "GIT_COMMON_DIR"
            | "GIT_INDEX_FILE"
            | "GIT_OBJECT_DIRECTORY"
            | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
            | "GH_HOST"
            | "GH_REPO"
            | "JJ_CONFIG"
    );

    if exec_or_loader_hazard || upper == "JJ_CONFIG" {
        effects.insert(Effect::DynamicExecOrConfigEscape);
    }
    if is_append && path_or_routing_override {
        selector.repo_selector_redirected = true;
        effects.insert(Effect::DynamicExecOrConfigEscape);
        effects.insert(Effect::PathTraversalEscape);
    }
    if key == "GIT_WORK_TREE" {
        let (norm, escapes) = check_non_chdir_repo_selector(
            selector.cwd_offset.as_deref(),
            &mut selector.repo_selector_redirected,
            val,
            ctx,
        );
        if escapes {
            effects.insert(Effect::PathTraversalEscape);
        }
        selector.raw_worktree = Some(val.to_string());
        selector.worktree_override = Some(norm);
    } else if key == "GIT_DIR" {
        let (_norm, escapes) = check_non_chdir_repo_selector(
            selector.cwd_offset.as_deref(),
            &mut selector.repo_selector_redirected,
            val,
            ctx,
        );
        if escapes {
            effects.insert(Effect::PathTraversalEscape);
        }
        selector.raw_git_dir = Some(val.to_string());
    } else if matches!(
        key,
        "GIT_COMMON_DIR" | "GIT_INDEX_FILE" | "GIT_OBJECT_DIRECTORY"
    ) {
        let (_norm, escapes) = check_non_chdir_repo_selector(
            selector.cwd_offset.as_deref(),
            &mut selector.repo_selector_redirected,
            val,
            ctx,
        );
        if escapes {
            effects.insert(Effect::PathTraversalEscape);
        }
        selector
            .raw_git_env_paths
            .insert(key.to_string(), val.to_string());
    } else if key == "GIT_ALTERNATE_OBJECT_DIRECTORIES" {
        selector.repo_selector_redirected = true;
        let entries: Vec<String> = val
            .split(':')
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        for entry in &entries {
            let (_norm, escapes) = check_non_chdir_repo_selector(
                selector.cwd_offset.as_deref(),
                &mut selector.repo_selector_redirected,
                entry,
                ctx,
            );
            if escapes {
                effects.insert(Effect::PathTraversalEscape);
            }
        }
        selector.raw_git_alt_obj_dirs = entries;
    } else if matches!(
        upper.as_str(),
        "GIT_WORK_TREE"
            | "GIT_DIR"
            | "GIT_COMMON_DIR"
            | "GIT_INDEX_FILE"
            | "GIT_OBJECT_DIRECTORY"
            | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
    ) {
        // Non-canonical case (`git_work_tree=...`) must never clobber canonical uppercase selectors
        // on POSIX, while still validating paths for case-insensitive platforms.
        for entry in val.split(':').filter(|s| !s.is_empty()) {
            let (_norm, escapes) = check_non_chdir_repo_selector(
                selector.cwd_offset.as_deref(),
                &mut selector.repo_selector_redirected,
                entry,
                ctx,
            );
            if escapes {
                effects.insert(Effect::PathTraversalEscape);
            }
        }
        selector
            .raw_git_env_paths
            .insert(key.to_string(), val.to_string());
    }

    EnvOverride {
        key: key.to_string(),
        exec_or_loader_hazard,
        secret_or_auth_override,
        path_or_routing_override,
    }
}

/// Peels leading `KEY=VALUE` assignments and transparent launchers (`env`, `sudo`, `command`, `exec`,
/// `nohup`, `nice`, `timeout`, `stdbuf`, `time`, `xargs`, `npx`, `npm exec`, `pnpm`, `yarn`, `bunx`, `cargo sqlx`, `sh -c`).
#[must_use]
pub fn unwrap_invocation(tokens: &[String], ctx: &ParseContext<'_>) -> UnwrappedInvocation {
    unwrap_invocation_with_depth(tokens, ctx, 0)
}

/// Peels leading `KEY=VALUE` assignments and transparent launchers starting from `initial_depth`.
#[must_use]
pub fn unwrap_invocation_with_depth(
    tokens: &[String],
    ctx: &ParseContext<'_>,
    initial_depth: usize,
) -> UnwrappedInvocation {
    unwrap_invocation_with_state(
        tokens,
        ctx,
        &InheritedSelectorState::default(),
        initial_depth,
    )
}

/// Peels leading `KEY=VALUE` assignments and transparent launchers starting from `inherited` selector state and `initial_depth`.
#[must_use]
pub fn unwrap_invocation_with_state(
    tokens: &[String],
    ctx: &ParseContext<'_>,
    inherited: &InheritedSelectorState,
    initial_depth: usize,
) -> UnwrappedInvocation {
    let mut current: Vec<String> = tokens.to_vec();
    let mut wrappers_peeled: Vec<String> = Vec::new();
    let mut env_overrides: Vec<EnvOverride> = Vec::new();
    let mut wrapper_effects: BTreeSet<Effect> = BTreeSet::new();
    let mut wrapper_targets: Vec<Target> = Vec::new();
    let mut selector: InheritedSelectorState = inherited.clone();
    let mut via_xargs = false;
    let mut depth = initial_depth;

    macro_rules! finish_unwrap {
        ($argv:expr, $lookup:expr, $scripts:expr, $err:expr) => {{
            let cwd_offset = selector.cwd_offset.clone();
            let worktree_override = selector.worktree_override.clone();
            let repo_selector_redirected = selector.repo_selector_redirected;
            return UnwrappedInvocation {
                argv: $argv,
                wrappers_peeled,
                env_overrides,
                wrapper_effects,
                wrapper_targets,
                cwd_offset,
                worktree_override,
                repo_selector_redirected,
                selector,
                via_xargs,
                is_command_lookup_only: $lookup,
                delegated_shell_scripts: $scripts,
                depth,
                fail_closed_reason: $err,
            };
        }};
    }

    loop {
        // 1. Peel leading `KEY=VALUE` / `KEY+=VALUE` assignments
        let mut idx = 0usize;
        while idx < current.len() {
            if let Some((k, v, is_append)) = split_env_assignment_with_op(&current[idx]) {
                let ov = classify_env_override_with_op(
                    k,
                    v,
                    is_append,
                    ctx,
                    &mut wrapper_effects,
                    &mut selector,
                );
                env_overrides.push(ov);
                idx += 1;
            } else {
                break;
            }
        }
        if idx > 0 {
            current.drain(..idx);
        }

        if current.is_empty() {
            finish_unwrap!(Vec::new(), false, Vec::new(), None);
        }

        if depth >= MAX_UNWRAP_DEPTH {
            wrapper_effects.insert(Effect::DynamicExecOrConfigEscape);
            wrapper_effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            finish_unwrap!(
                current,
                false,
                Vec::new(),
                Some(format!(
                    "wrapper nesting exceeds MAX_UNWRAP_DEPTH ({MAX_UNWRAP_DEPTH})"
                ))
            );
        }

        let prog_base = normalize_binary_basename(&current[0]);
        match prog_base.as_str() {
            "env" => {
                depth += 1;
                wrappers_peeled.push("env".to_string());
                match peel_env_wrapper(
                    &current[1..],
                    ctx,
                    &mut wrapper_effects,
                    &mut env_overrides,
                    &mut selector,
                    &mut depth,
                ) {
                    Ok(rest) => current = rest,
                    Err(reason) => {
                        wrapper_effects.insert(Effect::DynamicExecOrConfigEscape);
                        wrapper_effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                        finish_unwrap!(current, false, Vec::new(), Some(reason));
                    }
                }
            }
            "sudo" | "doas" => {
                depth += 1;
                wrappers_peeled.push(prog_base.clone());
                // Privilege escalation is always a dynamic/containment escape hazard
                wrapper_effects.insert(Effect::DynamicExecOrConfigEscape);
                current = peel_sudo_wrapper(
                    &current[1..],
                    ctx,
                    &mut wrapper_effects,
                    &mut env_overrides,
                    &mut selector,
                );
            }
            "command" | "builtin" => {
                depth += 1;
                wrappers_peeled.push(prog_base.clone());
                let (lookup_only, rest) = peel_command_wrapper(&current[1..]);
                if lookup_only {
                    finish_unwrap!(rest, true, Vec::new(), None);
                }
                current = rest;
            }
            "exec" => {
                depth += 1;
                wrappers_peeled.push("exec".to_string());
                match peel_exec_wrapper(&current[1..], &mut wrapper_effects, &mut selector) {
                    Ok(rest) => current = rest,
                    Err(reason) => {
                        wrapper_effects.insert(Effect::DynamicExecOrConfigEscape);
                        wrapper_effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                        finish_unwrap!(current, false, Vec::new(), Some(reason));
                    }
                }
            }
            "nohup" => {
                depth += 1;
                wrappers_peeled.push("nohup".to_string());
                let mut k = 1usize;
                while k < current.len() && current[k].starts_with('-') {
                    if current[k] == "--" {
                        k += 1;
                        break;
                    }
                    k += 1;
                }
                current.drain(..k);
            }
            "time" => {
                depth += 1;
                wrappers_peeled.push("time".to_string());
                current = peel_time_wrapper(
                    &current[1..],
                    selector.cwd_offset.as_deref(),
                    ctx,
                    &mut wrapper_effects,
                    &mut wrapper_targets,
                );
            }
            "nice" => {
                depth += 1;
                wrappers_peeled.push("nice".to_string());
                current = peel_nice_wrapper(&current[1..]);
            }
            "timeout" => {
                depth += 1;
                wrappers_peeled.push("timeout".to_string());
                current = peel_timeout_wrapper(&current[1..]);
            }
            "stdbuf" => {
                depth += 1;
                wrappers_peeled.push("stdbuf".to_string());
                current = peel_stdbuf_wrapper(&current[1..]);
            }
            "xargs" => {
                depth += 1;
                wrappers_peeled.push("xargs".to_string());
                via_xargs = true;
                current = peel_xargs_wrapper(
                    &current[1..],
                    selector.cwd_offset.as_deref(),
                    ctx,
                    &mut wrapper_effects,
                    &mut wrapper_targets,
                );
                if current.is_empty() {
                    current.push("echo".to_string());
                }
            }
            "npx" | "bunx" => {
                depth += 1;
                wrappers_peeled.push(prog_base);
                match peel_npx_wrapper(&current[1..], &mut wrapper_effects) {
                    NpxPeelOutcome::Argv(rest) => current = rest,
                    NpxPeelOutcome::CallScripts { scripts, rest } => {
                        finish_unwrap!(rest, false, scripts, None);
                    }
                    NpxPeelOutcome::Error(reason) => {
                        wrapper_effects.insert(Effect::DynamicExecOrConfigEscape);
                        wrapper_effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                        finish_unwrap!(current, false, Vec::new(), Some(reason));
                    }
                }
            }
            "npm" => {
                if let Some(outcome) =
                    try_peel_npm_exec(&current[1..], ctx, &mut wrapper_effects, &mut selector)
                {
                    depth += 1;
                    wrappers_peeled.push("npm".to_string());
                    match outcome {
                        NpxPeelOutcome::Argv(rest) => current = rest,
                        NpxPeelOutcome::CallScripts { scripts, rest } => {
                            finish_unwrap!(rest, false, scripts, None);
                        }
                        NpxPeelOutcome::Error(reason) => {
                            wrapper_effects.insert(Effect::DynamicExecOrConfigEscape);
                            wrapper_effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                            finish_unwrap!(current, false, Vec::new(), Some(reason));
                        }
                    }
                } else {
                    break;
                }
            }
            "pnpm" | "yarn" => {
                if let Some(outcome) =
                    try_peel_pnpm_or_yarn(&current[1..], ctx, &mut wrapper_effects, &mut selector)
                {
                    depth += 1;
                    wrappers_peeled.push(prog_base);
                    match outcome {
                        NpxPeelOutcome::Argv(rest) => current = rest,
                        NpxPeelOutcome::CallScripts { scripts, rest } => {
                            finish_unwrap!(rest, false, scripts, None);
                        }
                        NpxPeelOutcome::Error(reason) => {
                            wrapper_effects.insert(Effect::DynamicExecOrConfigEscape);
                            wrapper_effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                            finish_unwrap!(current, false, Vec::new(), Some(reason));
                        }
                    }
                } else {
                    break;
                }
            }
            "cargo" => {
                if current.len() >= 2 && current[1] == "sqlx" {
                    depth += 1;
                    wrappers_peeled.push("cargo".to_string());
                    current.remove(0);
                } else {
                    break;
                }
            }
            "sh" | "bash" | "zsh" | "dash" | "ksh" => {
                if let Some((script, has_extra_args)) = extract_shell_dash_c_script(&current[1..]) {
                    depth += 1;
                    wrappers_peeled.push(prog_base);
                    if has_extra_args {
                        wrapper_effects.insert(Effect::DynamicExecOrConfigEscape);
                        wrapper_effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                    }
                    finish_unwrap!(Vec::new(), false, vec![script], None);
                }
                break;
            }
            _ => break,
        }
    }

    finish_unwrap!(current, false, Vec::new(), None)
}

fn peel_env_wrapper(
    args: &[String],
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    env_overrides: &mut Vec<EnvOverride>,
    selector: &mut InheritedSelectorState,
    depth: &mut usize,
) -> Result<Vec<String>, String> {
    let mut i = 0usize;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if matches!(tok.as_str(), "-" | "-i" | "--ignore-environment") {
            selector.clear_env_selectors();
            i += 1;
            continue;
        }
        if matches!(tok.as_str(), "-0" | "--null" | "-v" | "--debug") {
            i += 1;
            continue;
        }
        if tok == "--unset" {
            let Some(u_name) = args.get(i + 1) else {
                return Err("env --unset missing variable name".to_string());
            };
            selector.unset_env_selector(u_name);
            i += 2;
            continue;
        }
        if let Some(u_name) = tok.strip_prefix("--unset=") {
            selector.unset_env_selector(u_name);
            i += 1;
            continue;
        }
        if tok == "--chdir" {
            let Some(dir) = args.get(i + 1) else {
                return Err("env --chdir missing directory argument".to_string());
            };
            if apply_repo_dir_selector(
                &mut selector.cwd_offset,
                &mut selector.repo_selector_redirected,
                dir,
                ctx,
            ) {
                effects.insert(Effect::PathTraversalEscape);
            }
            selector.revalidate_selectors(ctx, effects);
            i += 2;
            continue;
        }
        if let Some(dir) = tok.strip_prefix("--chdir=") {
            if apply_repo_dir_selector(
                &mut selector.cwd_offset,
                &mut selector.repo_selector_redirected,
                dir,
                ctx,
            ) {
                effects.insert(Effect::PathTraversalEscape);
            }
            selector.revalidate_selectors(ctx, effects);
            i += 1;
            continue;
        }
        if tok == "--split-string" {
            if *depth >= MAX_UNWRAP_DEPTH {
                return Err(format!(
                    "env -S recursion exceeds MAX_UNWRAP_DEPTH ({MAX_UNWRAP_DEPTH})"
                ));
            }
            *depth += 1;
            let Some(split_raw) = args.get(i + 1) else {
                return Err("env --split-string missing string argument".to_string());
            };
            let rebuilt = expand_env_split_string(split_raw, &args[i + 2..], effects)?;
            return peel_env_wrapper(&rebuilt, ctx, effects, env_overrides, selector, depth);
        }
        if let Some(split_raw) = tok.strip_prefix("--split-string=") {
            if *depth >= MAX_UNWRAP_DEPTH {
                return Err(format!(
                    "env -S recursion exceeds MAX_UNWRAP_DEPTH ({MAX_UNWRAP_DEPTH})"
                ));
            }
            *depth += 1;
            let rebuilt = expand_env_split_string(split_raw, &args[i + 1..], effects)?;
            return peel_env_wrapper(&rebuilt, ctx, effects, env_overrides, selector, depth);
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            let mut extra_advance = 0usize;
            for (ci, ch) in short.char_indices() {
                let rest = &short[ci + ch.len_utf8()..];
                match ch {
                    'i' => selector.clear_env_selectors(),
                    '0' | 'v' => {}
                    'u' => {
                        if !rest.is_empty() {
                            selector.unset_env_selector(rest);
                        } else if let Some(u_name) = args.get(i + 1) {
                            selector.unset_env_selector(u_name);
                            extra_advance = 1;
                        } else {
                            return Err("env -u missing variable name".to_string());
                        }
                        break;
                    }
                    'C' => {
                        let dir = if !rest.is_empty() {
                            rest
                        } else if let Some(d) = args.get(i + 1) {
                            extra_advance = 1;
                            d.as_str()
                        } else {
                            return Err("env -C missing directory argument".to_string());
                        };
                        if apply_repo_dir_selector(
                            &mut selector.cwd_offset,
                            &mut selector.repo_selector_redirected,
                            dir,
                            ctx,
                        ) {
                            effects.insert(Effect::PathTraversalEscape);
                        }
                        selector.revalidate_selectors(ctx, effects);
                        break;
                    }
                    'P' => {
                        if rest.is_empty() {
                            if args.get(i + 1).is_none() {
                                return Err("env -P missing altpath argument".to_string());
                            }
                            extra_advance = 1;
                        }
                        // `env -P <altpath>` overrides binary search PATH -> fail closed!
                        effects.insert(Effect::DynamicExecOrConfigEscape);
                        break;
                    }
                    'S' => {
                        if *depth >= MAX_UNWRAP_DEPTH {
                            return Err(format!(
                                "env -S recursion exceeds MAX_UNWRAP_DEPTH ({MAX_UNWRAP_DEPTH})"
                            ));
                        }
                        *depth += 1;
                        let (split_raw, tail_start) = if !rest.is_empty() {
                            (rest, i + 1)
                        } else if let Some(s) = args.get(i + 1) {
                            (s.as_str(), i + 2)
                        } else {
                            return Err("env -S missing string argument".to_string());
                        };
                        let rebuilt =
                            expand_env_split_string(split_raw, &args[tail_start..], effects)?;
                        return peel_env_wrapper(
                            &rebuilt,
                            ctx,
                            effects,
                            env_overrides,
                            selector,
                            depth,
                        );
                    }
                    _ => {
                        effects.insert(Effect::DynamicExecOrConfigEscape);
                        effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                    }
                }
            }
            i += 1 + extra_advance;
            continue;
        }
        if tok.starts_with('-') {
            effects.insert(Effect::DynamicExecOrConfigEscape);
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            i += 1;
            continue;
        }
        break;
    }

    while i < args.len() {
        if let Some((k, v, is_append)) = split_env_assignment_with_op(&args[i]) {
            let ov = classify_env_override_with_op(k, v, is_append, ctx, effects, selector);
            env_overrides.push(ov);
            i += 1;
        } else {
            break;
        }
    }

    Ok(args.get(i..).unwrap_or(&[]).to_vec())
}

fn expand_env_split_string(
    split_raw: &str,
    trailing: &[String],
    effects: &mut BTreeSet<Effect>,
) -> Result<Vec<String>, String> {
    let lexed = lex_shell_command(split_raw);
    if let Some(err) = lexed.fail_closed_error {
        return Err(format!("env -S parse error: {err}"));
    }
    if lexed.segments.len() > 1 {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        return Err("env -S contains compound shell operators".to_string());
    }
    let mut rebuilt: Vec<String> = Vec::new();
    for seg in lexed.segments {
        if seg.word_has_var_expansion.iter().any(|&b| b)
            || seg.word_has_unquoted_glob.iter().any(|&b| b)
            || seg.word_has_unquoted_brace.iter().any(|&b| b)
            || seg.redir_has_var_expansion
            || seg.redir_has_unquoted_glob_or_brace
            || !seg.command_substitutions.is_empty()
            || !seg.output_redirections.is_empty()
            || !seg.input_redirections.is_empty()
            || seg.has_subshell_or_proc_subst
        {
            effects.insert(Effect::DynamicExecOrConfigEscape);
            return Err("env -S contains dynamic shell expansion or redirection".to_string());
        }
        rebuilt.extend(seg.words);
    }
    rebuilt.extend_from_slice(trailing);
    if rebuilt.len() > MAX_ARGV_TOKENS {
        return Err(format!(
            "env -S expanded argv length {} exceeds MAX_ARGV_TOKENS ({MAX_ARGV_TOKENS})",
            rebuilt.len()
        ));
    }
    Ok(rebuilt)
}

fn peel_sudo_wrapper(
    args: &[String],
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    env_overrides: &mut Vec<EnvOverride>,
    selector: &mut InheritedSelectorState,
) -> Vec<String> {
    let mut i = 0usize;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if matches!(
            tok.as_str(),
            "-u" | "--user" | "-g" | "--group" | "-C" | "-p" | "-h" | "-T"
        ) {
            i += 2;
            continue;
        }
        if tok == "-D" || tok == "--chdir" || tok == "-R" || tok == "--chroot" {
            if let Some(dir) = args.get(i + 1) {
                let escapes = apply_repo_dir_selector(
                    &mut selector.cwd_offset,
                    &mut selector.repo_selector_redirected,
                    dir,
                    ctx,
                );
                if escapes || tok == "-R" || tok == "--chroot" {
                    effects.insert(Effect::PathTraversalEscape);
                }
                selector.revalidate_selectors(ctx, effects);
            }
            i += 2;
            continue;
        }
        if let Some((is_chroot, dir)) = tok
            .strip_prefix("--chdir=")
            .map(|d| (false, d))
            .or_else(|| tok.strip_prefix("--chroot=").map(|d| (true, d)))
            .or_else(|| {
                if !tok.starts_with("--") {
                    tok.strip_prefix("-D")
                        .filter(|d| !d.is_empty())
                        .map(|d| (false, d))
                        .or_else(|| {
                            tok.strip_prefix("-R")
                                .filter(|d| !d.is_empty())
                                .map(|d| (true, d))
                        })
                } else {
                    None
                }
            })
        {
            let escapes = apply_repo_dir_selector(
                &mut selector.cwd_offset,
                &mut selector.repo_selector_redirected,
                dir,
                ctx,
            );
            if escapes || is_chroot {
                effects.insert(Effect::PathTraversalEscape);
            }
            selector.revalidate_selectors(ctx, effects);
            i += 1;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        if let Some((k, v, is_append)) = split_env_assignment_with_op(tok) {
            let ov = classify_env_override_with_op(k, v, is_append, ctx, effects, selector);
            env_overrides.push(ov);
            i += 1;
            continue;
        }
        break;
    }
    args.get(i..).unwrap_or(&[]).to_vec()
}

fn peel_command_wrapper(args: &[String]) -> (bool, Vec<String>) {
    let mut i = 0usize;
    let mut lookup_only = false;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            for ch in short.chars() {
                if ch == 'v' || ch == 'V' {
                    lookup_only = true;
                }
            }
            i += 1;
            continue;
        }
        break;
    }
    (lookup_only, args.get(i..).unwrap_or(&[]).to_vec())
}

fn peel_exec_wrapper(
    args: &[String],
    effects: &mut BTreeSet<Effect>,
    selector: &mut InheritedSelectorState,
) -> Result<Vec<String>, String> {
    let mut i = 0usize;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            let mut extra_advance = 0usize;
            for (ci, ch) in short.char_indices() {
                let rest = &short[ci + ch.len_utf8()..];
                match ch {
                    'c' => selector.clear_env_selectors(),
                    'l' => {}
                    'a' => {
                        if rest.is_empty() {
                            if args.get(i + 1).is_none() {
                                return Err("exec -a missing argv[0] name argument".to_string());
                            }
                            extra_advance = 1;
                        }
                        // `exec -a <name>` overrides `argv[0]`, altering multicall dispatch
                        // (e.g. `exec -a git-branch git -D show main`) -> DynamicExecOrConfigEscape!
                        effects.insert(Effect::DynamicExecOrConfigEscape);
                        break;
                    }
                    _ => return Err(format!("unrecognized exec flag `{tok}`")),
                }
            }
            i += 1 + extra_advance;
            continue;
        }
        if tok.starts_with('-') {
            return Err(format!("unrecognized exec flag `{tok}`"));
        }
        break;
    }
    Ok(args.get(i..).unwrap_or(&[]).to_vec())
}

fn peel_time_wrapper(
    args: &[String],
    cwd_offset: Option<&str>,
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    wrapper_targets: &mut Vec<Target>,
) -> Vec<String> {
    let mut i = 0usize;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if matches!(
            tok.as_str(),
            "--portability" | "--verbose" | "--quiet" | "--append"
        ) {
            i += 1;
            continue;
        }
        if tok == "--format" {
            i += if i + 1 < args.len() { 2 } else { 1 };
            continue;
        }
        if tok.starts_with("--format=") {
            i += 1;
            continue;
        }
        if tok == "--output" {
            if let Some(out_file) = args.get(i + 1) {
                record_wrapper_write_target(out_file, cwd_offset, ctx, effects, wrapper_targets);
                i += 2;
            } else {
                effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                i += 1;
            }
            continue;
        }
        if let Some(out_file) = tok.strip_prefix("--output=") {
            record_wrapper_write_target(out_file, cwd_offset, ctx, effects, wrapper_targets);
            i += 1;
            continue;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            let mut extra_advance = 0usize;
            for (ci, ch) in short.char_indices() {
                let rest = &short[ci + ch.len_utf8()..];
                match ch {
                    'f' => {
                        if rest.is_empty() && i + 1 < args.len() {
                            extra_advance = 1;
                        }
                        break;
                    }
                    'o' => {
                        let out_opt = if !rest.is_empty() {
                            Some(rest)
                        } else if let Some(next_f) = args.get(i + 1) {
                            extra_advance = 1;
                            Some(next_f.as_str())
                        } else {
                            None
                        };
                        if let Some(out_file) = out_opt {
                            record_wrapper_write_target(
                                out_file,
                                cwd_offset,
                                ctx,
                                effects,
                                wrapper_targets,
                            );
                        } else {
                            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                        }
                        break;
                    }
                    _ => {}
                }
            }
            i += 1 + extra_advance;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        break;
    }
    args.get(i..).unwrap_or(&[]).to_vec()
}

fn record_wrapper_write_target(
    raw_file: &str,
    cwd_offset: Option<&str>,
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    wrapper_targets: &mut Vec<Target>,
) {
    effects.insert(Effect::DestructiveWorktreeOp);
    let t = analyze_path_target(raw_file, cwd_offset, ctx);
    attach_path_target_effects(&t, effects);
    wrapper_targets.push(t);
}

fn peel_nice_wrapper(args: &[String]) -> Vec<String> {
    let mut i = 0usize;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if tok == "-n" || tok == "--adjustment" {
            i += 2;
            continue;
        }
        if tok.starts_with("-n") || tok.starts_with("--adjustment=") {
            i += 1;
            continue;
        }
        if let Some(rest) = tok.strip_prefix('-') {
            let digits = rest.strip_prefix(['+', '-']).unwrap_or(rest);
            if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
                i += 1;
                continue;
            }
        }
        break;
    }
    args.get(i..).unwrap_or(&[]).to_vec()
}

fn peel_timeout_wrapper(args: &[String]) -> Vec<String> {
    let mut i = 0usize;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if matches!(tok.as_str(), "-k" | "--kill-after" | "-s" | "--signal") {
            i += 2;
            continue;
        }
        if tok.starts_with("--kill-after=") || tok.starts_with("--signal=") {
            i += 1;
            continue;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            let mut extra_advance = 0usize;
            for (ci, ch) in short.char_indices() {
                let rest = &short[ci + ch.len_utf8()..];
                if matches!(ch, 'k' | 's') {
                    if rest.is_empty() {
                        extra_advance = 1;
                    }
                    break;
                }
            }
            i += 1 + extra_advance;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        break;
    }
    // Skip `<DURATION>` positional argument
    if i < args.len() {
        i += 1;
    }
    args.get(i..).unwrap_or(&[]).to_vec()
}

fn peel_stdbuf_wrapper(args: &[String]) -> Vec<String> {
    let mut i = 0usize;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if matches!(
            tok.as_str(),
            "-i" | "--input" | "-o" | "--output" | "-e" | "--error"
        ) {
            i += 2;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        break;
    }
    args.get(i..).unwrap_or(&[]).to_vec()
}

fn peel_xargs_wrapper(
    args: &[String],
    cwd_offset: Option<&str>,
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    wrapper_targets: &mut Vec<Target>,
) -> Vec<String> {
    let mut i = 0usize;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if tok == "-a" || tok == "--arg-file" {
            if let Some(arg_file) = args.get(i + 1) {
                let t = analyze_path_target(arg_file, cwd_offset, ctx);
                attach_read_path_target_effects(&t, effects);
                wrapper_targets.push(t);
            }
            i += 2;
            continue;
        }
        if let Some(arg_file) = tok.strip_prefix("--arg-file=")
            && !arg_file.is_empty()
        {
            let t = analyze_path_target(arg_file, cwd_offset, ctx);
            attach_read_path_target_effects(&t, effects);
            wrapper_targets.push(t);
            i += 1;
            continue;
        }
        if matches!(
            tok.as_str(),
            "--max-args"
                | "--max-lines"
                | "--max-procs"
                | "--max-chars"
                | "--delimiter"
                | "--replace"
                | "--eof"
        ) {
            i += 2;
            continue;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            let mut extra_advance = 0usize;
            for (ci, ch) in short.char_indices() {
                let rest = &short[ci + ch.len_utf8()..];
                if ch == 'a' {
                    if !rest.is_empty() {
                        let t = analyze_path_target(rest, cwd_offset, ctx);
                        attach_read_path_target_effects(&t, effects);
                        wrapper_targets.push(t);
                    } else if let Some(arg_file) = args.get(i + 1) {
                        let t = analyze_path_target(arg_file, cwd_offset, ctx);
                        attach_read_path_target_effects(&t, effects);
                        wrapper_targets.push(t);
                        extra_advance = 1;
                    }
                    break;
                }
                if matches!(
                    ch,
                    'n' | 'L' | 'l' | 'P' | 's' | 'd' | 'E' | 'e' | 'I' | 'J'
                ) {
                    if rest.is_empty() {
                        extra_advance = 1;
                    }
                    break;
                }
            }
            i += 1 + extra_advance;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        break;
    }
    args.get(i..).unwrap_or(&[]).to_vec()
}

fn inspect_node_pkg_flag(
    args: &[String],
    i: usize,
    effects: &mut BTreeSet<Effect>,
) -> Option<usize> {
    let tok = args[i].as_str();
    if matches!(
        tok,
        "--script-shell"
            | "--shell-emulator"
            | "--userconfig"
            | "--globalconfig"
            | "--rcfile"
            | "--editor"
            | "--bunfig"
    ) {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        return Some(if i + 1 < args.len() { 2 } else { 1 });
    }
    if tok.starts_with("--script-shell=")
        || tok.starts_with("--shell-emulator=")
        || tok.starts_with("--userconfig=")
        || tok.starts_with("--globalconfig=")
        || tok.starts_with("--rcfile=")
        || tok.starts_with("--editor=")
        || tok.starts_with("--bunfig=")
        || tok.starts_with("--config.")
    {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        return Some(1);
    }
    if matches!(
        tok,
        "--loglevel"
            | "--cache"
            | "--registry"
            | "--tag"
            | "--otp"
            | "--proxy"
            | "--https-proxy"
            | "--noproxy"
            | "--maxsockets"
            | "--fetch-retries"
            | "--fetch-timeout"
            | "--reporter"
            | "--store-dir"
            | "--virtual-store-dir"
            | "--modules-dir"
            | "--lockfile-dir"
            | "--global-dir"
            | "--global-bin-dir"
            | "--state-dir"
            | "--cache-dir"
            | "--config"
            | "--network-concurrency"
            | "--child-concurrency"
            | "--workspace-concurrency"
    ) {
        if tok == "--config" {
            effects.insert(Effect::DynamicExecOrConfigEscape);
        }
        return Some(if i + 1 < args.len() { 2 } else { 1 });
    }
    if tok.starts_with("--config=") {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        return Some(1);
    }
    None
}

enum NpxPeelOutcome {
    Argv(Vec<String>),
    CallScripts {
        scripts: Vec<String>,
        rest: Vec<String>,
    },
    Error(String),
}

fn peel_npx_wrapper(args: &[String], effects: &mut BTreeSet<Effect>) -> NpxPeelOutcome {
    let mut i = 0usize;
    let mut scripts: Vec<String> = Vec::new();
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if tok == "-c" || tok == "--call" {
            let Some(script) = args.get(i + 1) else {
                return NpxPeelOutcome::Error("npx --call/-c missing script argument".to_string());
            };
            scripts.push(script.clone());
            i += 2;
            continue;
        }
        if let Some(script) = tok
            .strip_prefix("--call=")
            .or_else(|| tok.strip_prefix("-c="))
        {
            scripts.push(script.to_string());
            i += 1;
            continue;
        }
        if let Some(consumed) = inspect_node_pkg_flag(args, i, effects) {
            i += consumed;
            continue;
        }
        if matches!(tok.as_str(), "-p" | "--package") {
            i += 2;
            continue;
        }
        if tok.starts_with("--package=") {
            i += 1;
            continue;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            let mut extra_advance = 0usize;
            for (ci, ch) in short.char_indices() {
                let rest = &short[ci + ch.len_utf8()..];
                if ch == 'c' {
                    if !rest.is_empty() {
                        let script = rest.strip_prefix('=').unwrap_or(rest);
                        scripts.push(script.to_string());
                    } else if let Some(script) = args.get(i + 1) {
                        scripts.push(script.clone());
                        extra_advance = 1;
                    } else {
                        return NpxPeelOutcome::Error("npx -c missing script argument".to_string());
                    }
                    break;
                }
                if ch == 'p' {
                    if rest.is_empty() {
                        extra_advance = 1;
                    }
                    break;
                }
            }
            i += 1 + extra_advance;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        break;
    }
    let rest = args.get(i..).unwrap_or(&[]).to_vec();
    if !scripts.is_empty() {
        NpxPeelOutcome::CallScripts { scripts, rest }
    } else {
        NpxPeelOutcome::Argv(rest)
    }
}

fn collect_post_positional_npm_call_flags(
    rest: &[String],
    effects: &mut BTreeSet<Effect>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let mut scripts = Vec::new();
    let mut filtered = Vec::with_capacity(rest.len());
    let mut i = 0usize;
    let mut after_dd = false;
    while i < rest.len() {
        let tok = &rest[i];
        if !after_dd && tok == "--" {
            after_dd = true;
            filtered.push(tok.clone());
            i += 1;
            continue;
        }
        if !after_dd && tok == "--call" {
            let Some(script) = rest.get(i + 1) else {
                return Err("npm --call missing script argument".to_string());
            };
            scripts.push(script.clone());
            i += 2;
            continue;
        }
        if !after_dd && let Some(script) = tok.strip_prefix("--call=") {
            scripts.push(script.to_string());
            i += 1;
            continue;
        }
        if !after_dd {
            let s = tok.as_str();
            if matches!(
                s,
                "--script-shell"
                    | "--shell-emulator"
                    | "--userconfig"
                    | "--globalconfig"
                    | "--rcfile"
                    | "--editor"
            ) {
                effects.insert(Effect::DynamicExecOrConfigEscape);
                i += if i + 1 < rest.len() { 2 } else { 1 };
                continue;
            }
            if s.starts_with("--script-shell=")
                || s.starts_with("--shell-emulator=")
                || s.starts_with("--userconfig=")
                || s.starts_with("--globalconfig=")
                || s.starts_with("--rcfile=")
                || s.starts_with("--editor=")
                || s.starts_with("--config.")
            {
                effects.insert(Effect::DynamicExecOrConfigEscape);
                i += 1;
                continue;
            }
        }
        filtered.push(tok.clone());
        i += 1;
    }
    Ok((scripts, filtered))
}

fn merge_pre_and_post_npx_outcomes(
    mut pre_scripts: Vec<String>,
    post: NpxPeelOutcome,
    scan_trailing_npm_call: bool,
    effects: &mut BTreeSet<Effect>,
) -> NpxPeelOutcome {
    match post {
        err @ NpxPeelOutcome::Error(_) => err,
        NpxPeelOutcome::CallScripts { scripts, rest } => {
            pre_scripts.extend(scripts);
            if scan_trailing_npm_call {
                match collect_post_positional_npm_call_flags(&rest, effects) {
                    Ok((more, clean_rest)) => {
                        pre_scripts.extend(more);
                        NpxPeelOutcome::CallScripts {
                            scripts: pre_scripts,
                            rest: clean_rest,
                        }
                    }
                    Err(e) => NpxPeelOutcome::Error(e),
                }
            } else {
                NpxPeelOutcome::CallScripts {
                    scripts: pre_scripts,
                    rest,
                }
            }
        }
        NpxPeelOutcome::Argv(rest) => {
            let clean_rest = if scan_trailing_npm_call {
                match collect_post_positional_npm_call_flags(&rest, effects) {
                    Ok((more, cr)) => {
                        pre_scripts.extend(more);
                        cr
                    }
                    Err(e) => return NpxPeelOutcome::Error(e),
                }
            } else {
                rest
            };
            if !pre_scripts.is_empty() {
                NpxPeelOutcome::CallScripts {
                    scripts: pre_scripts,
                    rest: clean_rest,
                }
            } else {
                NpxPeelOutcome::Argv(clean_rest)
            }
        }
    }
}

fn try_peel_npm_exec(
    args: &[String],
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    selector: &mut InheritedSelectorState,
) -> Option<NpxPeelOutcome> {
    let mut i = 0usize;
    let mut pre_scripts: Vec<String> = Vec::new();
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            return None;
        }
        if tok == "-c" || tok == "--call" {
            let Some(script) = args.get(i + 1) else {
                return Some(NpxPeelOutcome::Error(
                    "npm --call/-c missing script argument".to_string(),
                ));
            };
            pre_scripts.push(script.clone());
            i += 2;
            continue;
        }
        if let Some(script) = tok
            .strip_prefix("--call=")
            .or_else(|| tok.strip_prefix("-c="))
        {
            pre_scripts.push(script.to_string());
            i += 1;
            continue;
        }
        if tok == "--prefix" || tok == "-C" {
            if let Some(dir) = args.get(i + 1) {
                if apply_repo_dir_selector(
                    &mut selector.cwd_offset,
                    &mut selector.repo_selector_redirected,
                    dir,
                    ctx,
                ) {
                    effects.insert(Effect::PathTraversalEscape);
                }
                selector.revalidate_selectors(ctx, effects);
            }
            i += 2;
            continue;
        }
        if let Some(dir) = tok.strip_prefix("--prefix=") {
            if apply_repo_dir_selector(
                &mut selector.cwd_offset,
                &mut selector.repo_selector_redirected,
                dir,
                ctx,
            ) {
                effects.insert(Effect::PathTraversalEscape);
            }
            selector.revalidate_selectors(ctx, effects);
            i += 1;
            continue;
        }
        if let Some(consumed) = inspect_node_pkg_flag(args, i, effects) {
            i += consumed;
            continue;
        }
        if matches!(tok.as_str(), "-w" | "--workspace" | "-p" | "--package") {
            i += 2;
            continue;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            let mut extra_advance = 0usize;
            for (ci, ch) in short.char_indices() {
                let rest = &short[ci + ch.len_utf8()..];
                if ch == 'c' {
                    if !rest.is_empty() {
                        let script = rest.strip_prefix('=').unwrap_or(rest);
                        pre_scripts.push(script.to_string());
                    } else if let Some(script) = args.get(i + 1) {
                        pre_scripts.push(script.clone());
                        extra_advance = 1;
                    } else {
                        return Some(NpxPeelOutcome::Error(
                            "npm -c missing script argument".to_string(),
                        ));
                    }
                    break;
                }
                if ch == 'C' {
                    let dir_opt = if !rest.is_empty() {
                        Some(rest)
                    } else if let Some(d) = args.get(i + 1) {
                        extra_advance = 1;
                        Some(d.as_str())
                    } else {
                        None
                    };
                    if let Some(dir) = dir_opt {
                        if apply_repo_dir_selector(
                            &mut selector.cwd_offset,
                            &mut selector.repo_selector_redirected,
                            dir,
                            ctx,
                        ) {
                            effects.insert(Effect::PathTraversalEscape);
                        }
                        selector.revalidate_selectors(ctx, effects);
                    }
                    break;
                }
                if matches!(ch, 'w' | 'p') {
                    if rest.is_empty() {
                        extra_advance = 1;
                    }
                    break;
                }
            }
            i += 1 + extra_advance;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        break;
    }
    let sub = args.get(i)?.as_str();
    if matches!(sub, "exec" | "x") {
        let post = peel_npx_wrapper(args.get(i + 1..).unwrap_or(&[]), effects);
        return Some(merge_pre_and_post_npx_outcomes(
            pre_scripts,
            post,
            true,
            effects,
        ));
    }
    None
}

fn try_peel_pnpm_or_yarn(
    args: &[String],
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    selector: &mut InheritedSelectorState,
) -> Option<NpxPeelOutcome> {
    let mut i = 0usize;
    let mut pre_scripts: Vec<String> = Vec::new();
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            return None;
        }
        if tok == "-c" || tok == "--call" {
            let Some(script) = args.get(i + 1) else {
                return Some(NpxPeelOutcome::Error(
                    "pnpm/yarn --call/-c missing script argument".to_string(),
                ));
            };
            pre_scripts.push(script.clone());
            i += 2;
            continue;
        }
        if let Some(script) = tok
            .strip_prefix("--call=")
            .or_else(|| tok.strip_prefix("-c="))
        {
            pre_scripts.push(script.to_string());
            i += 1;
            continue;
        }
        if tok == "-C" || tok == "--dir" || tok == "--cwd" {
            if let Some(dir) = args.get(i + 1) {
                if apply_repo_dir_selector(
                    &mut selector.cwd_offset,
                    &mut selector.repo_selector_redirected,
                    dir,
                    ctx,
                ) {
                    effects.insert(Effect::PathTraversalEscape);
                }
                selector.revalidate_selectors(ctx, effects);
            }
            i += 2;
            continue;
        }
        if let Some(dir) = tok
            .strip_prefix("--dir=")
            .or_else(|| tok.strip_prefix("--cwd="))
        {
            if apply_repo_dir_selector(
                &mut selector.cwd_offset,
                &mut selector.repo_selector_redirected,
                dir,
                ctx,
            ) {
                effects.insert(Effect::PathTraversalEscape);
            }
            selector.revalidate_selectors(ctx, effects);
            i += 1;
            continue;
        }
        if let Some(consumed) = inspect_node_pkg_flag(args, i, effects) {
            i += consumed;
            continue;
        }
        if matches!(tok.as_str(), "-F" | "--filter" | "-p" | "--package") {
            i += 2;
            continue;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            let mut extra_advance = 0usize;
            for (ci, ch) in short.char_indices() {
                let rest = &short[ci + ch.len_utf8()..];
                if ch == 'c' {
                    if !rest.is_empty() {
                        let script = rest.strip_prefix('=').unwrap_or(rest);
                        pre_scripts.push(script.to_string());
                    } else if let Some(script) = args.get(i + 1) {
                        pre_scripts.push(script.clone());
                        extra_advance = 1;
                    } else {
                        return Some(NpxPeelOutcome::Error(
                            "pnpm/yarn -c missing script argument".to_string(),
                        ));
                    }
                    break;
                }
                if ch == 'C' {
                    let dir_opt = if !rest.is_empty() {
                        Some(rest)
                    } else if let Some(d) = args.get(i + 1) {
                        extra_advance = 1;
                        Some(d.as_str())
                    } else {
                        None
                    };
                    if let Some(dir) = dir_opt {
                        if apply_repo_dir_selector(
                            &mut selector.cwd_offset,
                            &mut selector.repo_selector_redirected,
                            dir,
                            ctx,
                        ) {
                            effects.insert(Effect::PathTraversalEscape);
                        }
                        selector.revalidate_selectors(ctx, effects);
                    }
                    break;
                }
                if matches!(ch, 'F' | 'p') {
                    if rest.is_empty() {
                        extra_advance = 1;
                    }
                    break;
                }
            }
            i += 1 + extra_advance;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        break;
    }
    let sub = args.get(i)?.as_str();
    if matches!(sub, "dlx" | "exec") {
        let post = peel_npx_wrapper(args.get(i + 1..).unwrap_or(&[]), effects);
        return Some(merge_pre_and_post_npx_outcomes(
            pre_scripts,
            post,
            false,
            effects,
        ));
    }
    let base = normalize_binary_basename(sub);
    if matches!(base.as_str(), "prisma" | "drizzle-kit" | "wrangler") {
        let rest = args.get(i..).unwrap_or(&[]).to_vec();
        if !pre_scripts.is_empty() {
            return Some(NpxPeelOutcome::CallScripts {
                scripts: pre_scripts,
                rest,
            });
        }
        return Some(NpxPeelOutcome::Argv(rest));
    }
    None
}

fn extract_shell_dash_c_script(args: &[String]) -> Option<(String, bool)> {
    let mut i = 0usize;
    let mut saw_c = false;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            i += 1;
            break;
        }
        if tok == "-o" || tok == "+o" {
            i += 2;
            continue;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            if short.contains('c') {
                saw_c = true;
                i += 1;
                break;
            }
            i += 1;
            continue;
        }
        break;
    }
    if saw_c {
        let script = args.get(i)?.clone();
        let has_extra_positional_args = i + 1 < args.len();
        return Some((script, has_extra_positional_args));
    }
    None
}
