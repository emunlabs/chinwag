// SPDX-License-Identifier: Apache-2.0

//! `chinwag-tool-grammar` (`ToolGrammarV1`) — pure-Rust (`#![forbid(unsafe_code)]`),
//! flag-order-immune `<50 µs` CLI parser and customer safety policy evaluator.
//!
//! Canonicalizes `argv` slices and POSIX shell command lines into deterministic
//! `(program, action, effects, target_refs_or_paths)` tuples for:
//! - `git` (`push`, `force_push`, `reset_hard`, `clean_untracked`, `branch_delete`, read-only `status`/`diff`/`log`)
//! - `jj` (`git_push`, `abandon`, `op_restore`, read-only `status`/`log`/`diff`)
//! - `gh` (`pr_merge`, `repo_edit_visibility`, `secret_set`, `release_delete`, read-only `pr_list`/`issue_view`)
//! - `rm` (`recursive_delete`, `force_delete`, `delete`, root/wildcard/traversal hazard detection)
//! - DB migration CLIs (`prisma`, `drizzle-kit`, `sqlx`, `wrangler d1`)

#![forbid(unsafe_code)]

pub mod grammar;
pub mod path_norm;
pub mod policy;
pub mod shell;
pub mod types;
pub mod wrappers;

use grammar::{attach_path_target_effects, attach_read_path_target_effects, evaluate_tool_argv};
use path_norm::{analyze_path_target, apply_repo_dir_selector};
pub use policy::{
    PolicyDisposition, PolicyEvaluationV1, PolicyParseError, SafetyToggle, WorkflowSafetyPolicyV1,
};
use shell::lex_shell_command;
use std::collections::BTreeSet;
use std::time::Instant;
pub use types::{
    Action, CanonicalAction, CanonicalCommandTupleV1, CanonicalProgram, CanonicalTarget,
    DEFAULT_PROTECTED_BRANCHES, DEFAULT_PROTECTED_PATHS, Effect, EnvOverride, MAX_ARGV_TOKENS,
    MAX_COMMAND_BYTES, MAX_UNWRAP_DEPTH, ParseContext, Program, TOOL_GRAMMAR_SCHEMA_V1, Target,
    ToolEffect,
};
use wrappers::{
    InheritedSelectorState, classify_env_override, classify_env_override_with_op,
    normalize_binary_basename, split_env_assignment_with_op, unwrap_invocation_with_state,
};

#[derive(Debug, Clone, Copy, Default)]
struct SegmentLexicalHazards {
    any_var: bool,
    any_glob: bool,
    any_brace: bool,
    redir_var: bool,
    redir_glob_or_brace: bool,
}

impl SegmentLexicalHazards {
    fn any_glob_or_brace(self) -> bool {
        self.any_glob || self.any_brace || self.redir_glob_or_brace
    }

    fn any_dynamic(self) -> bool {
        self.any_var || self.redir_var || self.any_glob_or_brace()
    }
}

/// Parses a pre-tokenized `argv` slice into a canonical `ToolGrammarV1` tuple in `<50 µs`.
#[must_use]
pub fn parse_argv<S: AsRef<str>>(argv: &[S]) -> CanonicalCommandTupleV1 {
    parse_argv_with_context(argv, &ParseContext::default())
}

/// Parses a pre-tokenized `argv` slice under an explicit [`ParseContext`].
#[must_use]
pub fn parse_argv_with_context<S: AsRef<str>>(
    argv: &[S],
    ctx: &ParseContext<'_>,
) -> CanonicalCommandTupleV1 {
    let started = Instant::now();
    let mut tuple = parse_argv_inner(argv, ctx, 0);
    record_elapsed(&mut tuple, started);
    tuple
}

/// Parses a POSIX shell command line (including `env K=V`, quotes, compound `&&`/`||`/`;`/`|`,
/// `sh -c`, `$(...)`, redirections, and wrappers) into a canonical `ToolGrammarV1` tuple in `<50 µs`.
#[must_use]
pub fn parse_shell_command(cmdline: &str) -> CanonicalCommandTupleV1 {
    parse_shell_command_with_context(cmdline, &ParseContext::default())
}

/// Parses a POSIX shell command line under an explicit [`ParseContext`].
#[must_use]
pub fn parse_shell_command_with_context(
    cmdline: &str,
    ctx: &ParseContext<'_>,
) -> CanonicalCommandTupleV1 {
    let started = Instant::now();
    let mut tuple = parse_shell_inner(cmdline, ctx, &InheritedSelectorState::default(), 0);
    record_elapsed(&mut tuple, started);
    tuple
}

/// Evaluates a pre-tokenized `argv` slice directly against a [`WorkflowSafetyPolicyV1`].
#[must_use]
pub fn evaluate_argv_policy<S: AsRef<str>>(
    argv: &[S],
    policy: &WorkflowSafetyPolicyV1,
) -> PolicyEvaluationV1 {
    let tuple = policy.with_parse_context(None, |ctx| parse_argv_with_context(argv, ctx));
    policy.evaluate_tuple(tuple)
}

/// Evaluates a POSIX shell command line directly against a [`WorkflowSafetyPolicyV1`].
#[must_use]
pub fn evaluate_shell_policy(cmdline: &str, policy: &WorkflowSafetyPolicyV1) -> PolicyEvaluationV1 {
    let tuple =
        policy.with_parse_context(None, |ctx| parse_shell_command_with_context(cmdline, ctx));
    policy.evaluate_tuple(tuple)
}

fn parse_argv_inner<S: AsRef<str>>(
    argv: &[S],
    ctx: &ParseContext<'_>,
    depth: usize,
) -> CanonicalCommandTupleV1 {
    if argv.len() > MAX_ARGV_TOKENS {
        return fail_closed_tuple(format!(
            "argv length {} exceeds MAX_ARGV_TOKENS ({MAX_ARGV_TOKENS})",
            argv.len()
        ));
    }

    let mut total_bytes = 0usize;
    let mut owned: Vec<String> = Vec::with_capacity(argv.len());
    for arg in argv {
        let s = arg.as_ref();
        total_bytes = total_bytes.saturating_add(s.len());
        if total_bytes > MAX_COMMAND_BYTES {
            return fail_closed_tuple(format!(
                "argv byte size exceeds MAX_COMMAND_BYTES ({MAX_COMMAND_BYTES})"
            ));
        }
        if s.as_bytes().contains(&0) {
            return fail_closed_tuple("embedded NUL byte in argv token".to_string());
        }
        owned.push(s.to_string());
    }

    let (tuple, _next_state) = evaluate_owned_tokens(
        &owned,
        SegmentLexicalHazards::default(),
        ctx,
        &InheritedSelectorState::default(),
        depth,
    );
    tuple
}

fn parse_shell_inner(
    cmdline: &str,
    ctx: &ParseContext<'_>,
    inherited: &InheritedSelectorState,
    depth: usize,
) -> CanonicalCommandTupleV1 {
    if depth > MAX_UNWRAP_DEPTH {
        return fail_closed_tuple(format!(
            "shell recursion exceeds MAX_UNWRAP_DEPTH ({MAX_UNWRAP_DEPTH})"
        ));
    }

    let lexed = lex_shell_command(cmdline);
    if let Some(err) = lexed.fail_closed_error {
        return fail_closed_tuple(err);
    }
    if lexed.segments.is_empty() {
        return CanonicalCommandTupleV1 {
            schema: TOOL_GRAMMAR_SCHEMA_V1.to_string(),
            program: Program::Unknown(String::new()),
            action: Action::ReadOnlyInspect,
            effects: BTreeSet::from([Effect::ReadOnly]),
            target_refs_or_paths: Vec::new(),
            wrappers_peeled: Vec::new(),
            env_overrides: Vec::new(),
            via_xargs: false,
            elapsed_nanos: 0,
            elapsed_micros: 0,
            fail_closed_reason: None,
        };
    }

    let mut segment_tuples: Vec<CanonicalCommandTupleV1> = Vec::with_capacity(lexed.segments.len());
    let mut cur_state: InheritedSelectorState = inherited.clone();
    let mut prev_was_piped = false;

    for seg in &lexed.segments {
        let seg_in_pipeline = prev_was_piped || seg.piped_to_next;
        let seg_base_state = cur_state.clone();

        let (mut tuple, next_state) = if seg.words.is_empty() {
            let mut effects = BTreeSet::new();
            let action = if seg.redir_has_var_expansion || seg.redir_has_unquoted_glob_or_brace {
                effects.insert(Effect::DynamicExecOrConfigEscape);
                effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                if seg.redir_has_unquoted_glob_or_brace {
                    effects.insert(Effect::SensitivePathAccess);
                }
                Action::AmbiguousShellOrWrapper
            } else {
                effects.insert(Effect::ReadOnly);
                Action::ReadOnlyInspect
            };
            (
                CanonicalCommandTupleV1 {
                    schema: TOOL_GRAMMAR_SCHEMA_V1.to_string(),
                    program: Program::ShellWrapper,
                    action,
                    effects,
                    target_refs_or_paths: Vec::new(),
                    wrappers_peeled: Vec::new(),
                    env_overrides: Vec::new(),
                    via_xargs: false,
                    elapsed_nanos: 0,
                    elapsed_micros: 0,
                    fail_closed_reason: None,
                },
                seg_base_state.clone(),
            )
        } else {
            let hazards = SegmentLexicalHazards {
                any_var: seg.word_has_var_expansion.iter().any(|&b| b),
                any_glob: seg.word_has_unquoted_glob.iter().any(|&b| b),
                any_brace: seg.word_has_unquoted_brace.iter().any(|&b| b),
                redir_var: seg.redir_has_var_expansion,
                redir_glob_or_brace: seg.redir_has_unquoted_glob_or_brace,
            };
            evaluate_owned_tokens(&seg.words, hazards, ctx, &seg_base_state, depth)
        };

        // Evaluate any `$(...)`, `<(...)`, `>(...)`, or `(...)` subshells in this segment,
        // inheriting `seg_base_state` (`cwd_offset`, `worktree_override`, `repo_selector_redirected`).
        for sub_cmd in &seg.command_substitutions {
            tuple.effects.remove(&Effect::ReadOnly);
            tuple.effects.insert(Effect::DynamicExecOrConfigEscape);
            let inner = parse_shell_inner(sub_cmd, ctx, &seg_base_state, depth + 1);
            merge_secondary_into_primary(&mut tuple, inner);
        }

        let seg_cwd = seg_base_state.cwd_offset.as_deref();

        // Evaluate file input redirections (`< .env`, `< ../outside`)
        for in_path in &seg.input_redirections {
            let t = analyze_path_target(in_path, seg_cwd, ctx);
            attach_read_path_target_effects(&t, &mut tuple.effects);
            tuple.target_refs_or_paths.push(t);
            normalize_effects_set(&mut tuple.effects);
        }

        // Evaluate file output redirections (`> .env`, `>&.env`, `&>.env`, `>> .github/workflows/ci.yml`, `> ../outside`)
        for redir_path in &seg.output_redirections {
            tuple.effects.remove(&Effect::ReadOnly);
            tuple.effects.insert(Effect::DestructiveWorktreeOp);
            let t = analyze_path_target(redir_path, seg_cwd, ctx);
            attach_path_target_effects(&t, &mut tuple.effects);
            tuple.target_refs_or_paths.push(t);
            if tuple.action.is_read_only_action() {
                tuple.action = Action::WorktreeMutate;
            }
        }

        if !seg_in_pipeline {
            cur_state = next_state;
        }
        prev_was_piped = seg.piped_to_next;
        segment_tuples.push(tuple);
    }

    let mut iter = segment_tuples.into_iter();
    let Some(mut acc) = iter.next() else {
        return fail_closed_tuple("empty segment iterator".to_string());
    };
    for next in iter {
        merge_secondary_into_primary(&mut acc, next);
    }
    normalize_effects_set(&mut acc.effects);
    acc
}

fn evaluate_owned_tokens(
    tokens: &[String],
    hazards: SegmentLexicalHazards,
    ctx: &ParseContext<'_>,
    inherited: &InheritedSelectorState,
    depth: usize,
) -> (CanonicalCommandTupleV1, InheritedSelectorState) {
    if tokens.is_empty() {
        let mut effects = BTreeSet::new();
        let action = if hazards.redir_var || hazards.redir_glob_or_brace {
            effects.insert(Effect::DynamicExecOrConfigEscape);
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            if hazards.redir_glob_or_brace {
                effects.insert(Effect::SensitivePathAccess);
            }
            Action::AmbiguousShellOrWrapper
        } else {
            effects.insert(Effect::ReadOnly);
            Action::ReadOnlyInspect
        };
        return (
            CanonicalCommandTupleV1 {
                schema: TOOL_GRAMMAR_SCHEMA_V1.to_string(),
                program: Program::Unknown(String::new()),
                action,
                effects,
                target_refs_or_paths: Vec::new(),
                wrappers_peeled: Vec::new(),
                env_overrides: Vec::new(),
                via_xargs: false,
                elapsed_nanos: 0,
                elapsed_micros: 0,
                fail_closed_reason: None,
            },
            inherited.clone(),
        );
    }

    // Any unquoted or double-quoted shell parameter expansion (`$VAR`, `${VAR}`, `$1`, `$@`),
    // unquoted pathname glob (`*`, `?`, `[...]`), unquoted brace expansion (`{a,b}`), or dynamic
    // stdin operand synthesis via `xargs` can synthesize arbitrary flags/targets at execution time
    // -> fail closed centrally across ALL tools!
    let unwrapped = unwrap_invocation_with_state(tokens, ctx, inherited, depth);
    let inv_state = unwrapped.selector.clone();
    let mut wrapper_effects = unwrapped.wrapper_effects;
    if tokens[0].starts_with('~') || unwrapped.argv.first().is_some_and(|a| a.starts_with('~')) {
        wrapper_effects.insert(Effect::PathTraversalEscape);
        wrapper_effects.insert(Effect::DynamicExecOrConfigEscape);
    }

    if let Some(reason) = unwrapped.fail_closed_reason {
        let mut t = fail_closed_tuple(reason);
        t.wrappers_peeled = unwrapped.wrappers_peeled;
        t.env_overrides = unwrapped.env_overrides;
        t.target_refs_or_paths = unwrapped.wrapper_targets;
        t.via_xargs = unwrapped.via_xargs;
        t.effects.extend(wrapper_effects);
        normalize_effects_set(&mut t.effects);
        return (t, inherited.clone());
    }

    let dynamic_hazard = hazards.any_dynamic() || unwrapped.via_xargs;
    let sensitive_dynamic = hazards.any_glob_or_brace() || unwrapped.via_xargs;

    if unwrapped.is_command_lookup_only {
        let mut effects = wrapper_effects;
        let mut action = Action::ReadOnlyInspect;
        if effects.contains(&Effect::DestructiveWorktreeOp) {
            action = Action::WorktreeMutate;
        }
        apply_central_dynamic_hazards(dynamic_hazard, sensitive_dynamic, &mut action, &mut effects);
        normalize_effects_set(&mut effects);
        return (
            CanonicalCommandTupleV1 {
                schema: TOOL_GRAMMAR_SCHEMA_V1.to_string(),
                program: Program::ShellWrapper,
                action,
                effects,
                target_refs_or_paths: unwrapped.wrapper_targets,
                wrappers_peeled: unwrapped.wrappers_peeled,
                env_overrides: unwrapped.env_overrides,
                via_xargs: unwrapped.via_xargs,
                elapsed_nanos: 0,
                elapsed_micros: 0,
                fail_closed_reason: None,
            },
            inherited.clone(),
        );
    }

    if !unwrapped.delegated_shell_scripts.is_empty() {
        let mut scripts_iter = unwrapped.delegated_shell_scripts.iter();
        let first_script = scripts_iter.next().map(String::as_str).unwrap_or("");
        let mut combined = parse_shell_inner(first_script, ctx, &inv_state, unwrapped.depth);
        for extra_script in scripts_iter {
            let next_t = parse_shell_inner(extra_script, ctx, &inv_state, unwrapped.depth);
            merge_secondary_into_primary(&mut combined, next_t);
        }
        if !unwrapped.argv.is_empty() {
            let clean_argv: Vec<String> = unwrapped
                .argv
                .iter()
                .filter(|t| t.as_str() != "--")
                .cloned()
                .collect();
            if !clean_argv.is_empty() {
                let rest_prog = normalize_binary_basename(&clean_argv[0]);
                let rest_out = evaluate_tool_argv(
                    &rest_prog,
                    &clean_argv,
                    &inv_state,
                    unwrapped.via_xargs,
                    ctx,
                );
                let rest_tuple = CanonicalCommandTupleV1 {
                    schema: TOOL_GRAMMAR_SCHEMA_V1.to_string(),
                    program: rest_out.program,
                    action: rest_out.action,
                    effects: rest_out.effects,
                    target_refs_or_paths: rest_out.targets,
                    wrappers_peeled: Vec::new(),
                    env_overrides: Vec::new(),
                    via_xargs: unwrapped.via_xargs,
                    elapsed_nanos: 0,
                    elapsed_micros: 0,
                    fail_closed_reason: None,
                };
                merge_secondary_into_primary(&mut combined, rest_tuple);
            }
        }
        let mut combined_wrappers = unwrapped.wrappers_peeled;
        combined_wrappers.extend(combined.wrappers_peeled);
        combined.wrappers_peeled = combined_wrappers;
        let mut combined_envs = unwrapped.env_overrides;
        combined_envs.extend(combined.env_overrides);
        combined.env_overrides = combined_envs;
        let mut combined_targets = unwrapped.wrapper_targets;
        combined_targets.extend(combined.target_refs_or_paths);
        combined.target_refs_or_paths = combined_targets;
        let wrapper_mutates_files = wrapper_effects.contains(&Effect::DestructiveWorktreeOp);
        combined.effects.extend(wrapper_effects);
        if wrapper_mutates_files && combined.action.is_read_only_action() {
            combined.action = Action::WorktreeMutate;
        }
        apply_central_dynamic_hazards(
            dynamic_hazard,
            sensitive_dynamic,
            &mut combined.action,
            &mut combined.effects,
        );
        combined.via_xargs |= unwrapped.via_xargs;
        normalize_effects_set(&mut combined.effects);
        return (combined, inherited.clone());
    }

    if unwrapped.argv.is_empty() {
        let persists_in_shell = unwrapped
            .wrappers_peeled
            .iter()
            .all(|w| matches!(w.as_str(), "command" | "builtin" | "exec"));
        let mut effects = wrapper_effects;
        let mut action = if effects.contains(&Effect::DestructiveWorktreeOp) {
            Action::WorktreeMutate
        } else {
            Action::ReadOnlyInspect
        };
        apply_central_dynamic_hazards(dynamic_hazard, sensitive_dynamic, &mut action, &mut effects);
        normalize_effects_set(&mut effects);
        let next_state = if persists_in_shell {
            inv_state
        } else {
            inherited.clone()
        };
        return (
            CanonicalCommandTupleV1 {
                schema: TOOL_GRAMMAR_SCHEMA_V1.to_string(),
                program: Program::ShellWrapper,
                action,
                effects,
                target_refs_or_paths: unwrapped.wrapper_targets,
                wrappers_peeled: unwrapped.wrappers_peeled,
                env_overrides: unwrapped.env_overrides,
                via_xargs: unwrapped.via_xargs,
                elapsed_nanos: 0,
                elapsed_micros: 0,
                fail_closed_reason: None,
            },
            next_state,
        );
    }

    let prog_base = normalize_binary_basename(&unwrapped.argv[0]);

    // Shell state builtins (`cd`, `pushd`, `popd`, `export`, `declare`, `typeset`, `readonly`, `local`)
    // mutate the current shell's working directory or environment for subsequent `;` / `&&` / `||`
    // segments both directly and when invoked via `command` / `builtin`.
    let only_shell_builtin_wrappers = unwrapped
        .wrappers_peeled
        .iter()
        .all(|w| matches!(w.as_str(), "command" | "builtin"));
    if only_shell_builtin_wrappers
        && !unwrapped.via_xargs
        && matches!(
            prog_base.as_str(),
            "cd" | "pushd" | "popd" | "export" | "declare" | "typeset" | "readonly" | "local"
        )
    {
        let (mut tuple, next_state) = evaluate_shell_state_builtin(
            &prog_base,
            &unwrapped.argv,
            hazards,
            ctx,
            inv_state,
            wrapper_effects,
            unwrapped.env_overrides,
        );
        tuple.wrappers_peeled = unwrapped.wrappers_peeled;
        return (tuple, next_state);
    }

    let mut outcome = evaluate_tool_argv(
        &prog_base,
        &unwrapped.argv,
        &inv_state,
        unwrapped.via_xargs,
        ctx,
    );

    let wrapper_mutates_files = wrapper_effects.contains(&Effect::DestructiveWorktreeOp);
    outcome.effects.extend(wrapper_effects);
    if wrapper_mutates_files && outcome.action.is_read_only_action() {
        outcome.action = Action::WorktreeMutate;
    }
    let mut all_targets = unwrapped.wrapper_targets;
    all_targets.extend(outcome.targets);

    apply_central_dynamic_hazards(
        dynamic_hazard,
        sensitive_dynamic,
        &mut outcome.action,
        &mut outcome.effects,
    );
    normalize_effects_set(&mut outcome.effects);

    (
        CanonicalCommandTupleV1 {
            schema: TOOL_GRAMMAR_SCHEMA_V1.to_string(),
            program: outcome.program,
            action: outcome.action,
            effects: outcome.effects,
            target_refs_or_paths: all_targets,
            wrappers_peeled: unwrapped.wrappers_peeled,
            env_overrides: unwrapped.env_overrides,
            via_xargs: unwrapped.via_xargs,
            elapsed_nanos: 0,
            elapsed_micros: 0,
            fail_closed_reason: None,
        },
        inherited.clone(),
    )
}

fn evaluate_shell_state_builtin(
    prog_base: &str,
    argv: &[String],
    hazards: SegmentLexicalHazards,
    ctx: &ParseContext<'_>,
    mut next_state: InheritedSelectorState,
    mut effects: BTreeSet<Effect>,
    mut env_overrides: Vec<EnvOverride>,
) -> (CanonicalCommandTupleV1, InheritedSelectorState) {
    let mut targets: Vec<Target> = Vec::new();
    let mut action = Action::ReadOnlyInspect;

    if prog_base == "popd" {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
        action = Action::AmbiguousShellOrWrapper;
    } else if prog_base == "cd" || prog_base == "pushd" {
        let prev_cwd = next_state.cwd_offset.clone();
        let mut positionals: Vec<&str> = Vec::new();
        let mut after_dd = false;
        for tok in argv.iter().skip(1) {
            let a = tok.as_str();
            if !after_dd && a == "--" {
                after_dd = true;
                continue;
            }
            if !after_dd {
                if a == "-" {
                    positionals.push("-");
                    continue;
                }
                if prog_base == "pushd" {
                    if a == "-n" {
                        continue;
                    }
                    if a.starts_with(['+', '-']) {
                        positionals.push(a);
                        continue;
                    }
                } else if a.starts_with('-') {
                    continue;
                }
            }
            positionals.push(a);
        }

        if positionals.len() > 1 {
            // `cd old new` 2-arg path substitution or unexpected trailing arguments -> fail closed
            effects.insert(Effect::DynamicExecOrConfigEscape);
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            action = Action::AmbiguousShellOrWrapper;
        } else if positionals.is_empty() {
            if prog_base == "pushd" {
                // Bare `pushd` swaps top two dynamic directory-stack entries
                effects.insert(Effect::DynamicExecOrConfigEscape);
                effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                action = Action::AmbiguousShellOrWrapper;
            } else {
                // Bare `cd` changes to `$HOME` (`~`), escaping workspace boundary
                effects.insert(Effect::PathTraversalEscape);
                action = Action::UnknownAction;
            }
        } else {
            let dir = positionals[0];
            if dir == "-" || (prog_base == "pushd" && dir.starts_with(['+', '-'])) {
                // `cd -` (`$OLDPWD`) or `pushd +N/-N` stack rotation -> dynamic destination
                effects.insert(Effect::DynamicExecOrConfigEscape);
                effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                action = Action::AmbiguousShellOrWrapper;
            } else {
                if apply_repo_dir_selector(
                    &mut next_state.cwd_offset,
                    &mut next_state.repo_selector_redirected,
                    dir,
                    ctx,
                ) {
                    effects.insert(Effect::PathTraversalEscape);
                    action = Action::UnknownAction;
                }
                next_state.revalidate_selectors(ctx, &mut effects);
                if effects.contains(&Effect::PathTraversalEscape) && action.is_read_only_action() {
                    action = Action::UnknownAction;
                }
                targets.push(analyze_path_target(dir, prev_cwd.as_deref(), ctx));
            }
        }
    } else {
        // `export`, `declare`, `typeset`, `readonly`, `local`
        let mut k = 1usize;
        let mut after_dd = false;
        while k < argv.len() {
            let a = argv[k].as_str();
            if !after_dd && a == "--" {
                after_dd = true;
                k += 1;
                continue;
            }
            if !after_dd
                && (a.starts_with('-') || a.starts_with('+'))
                && a.len() > 1
                && split_env_assignment_with_op(a).is_none()
            {
                let flags = &a[1..];
                if flags.contains('f') || flags.contains('F') {
                    effects.insert(Effect::DynamicExecOrConfigEscape);
                }
                if prog_base != "export" && flags.contains('n') {
                    // `declare -n` / `typeset -n` creates a nameref alias
                    effects.insert(Effect::DynamicExecOrConfigEscape);
                }
                k += 1;
                continue;
            }
            if let Some((key, val, is_append)) = split_env_assignment_with_op(a) {
                let ov = classify_env_override_with_op(
                    key,
                    val,
                    is_append,
                    ctx,
                    &mut effects,
                    &mut next_state,
                );
                env_overrides.push(ov);
            } else {
                let mut probe_state = next_state.clone();
                let ov = classify_env_override(a, ".", ctx, &mut effects, &mut probe_state);
                if ov.path_or_routing_override {
                    next_state.repo_selector_redirected = true;
                }
                env_overrides.push(ov);
            }
            k += 1;
        }
        if effects.contains(&Effect::DynamicExecOrConfigEscape) {
            action = Action::DynamicExecEscape;
        }
    }

    apply_central_dynamic_hazards(
        hazards.any_dynamic(),
        hazards.any_glob_or_brace(),
        &mut action,
        &mut effects,
    );
    normalize_effects_set(&mut effects);

    (
        CanonicalCommandTupleV1 {
            schema: TOOL_GRAMMAR_SCHEMA_V1.to_string(),
            program: Program::ShellWrapper,
            action,
            effects,
            target_refs_or_paths: targets,
            wrappers_peeled: Vec::new(),
            env_overrides,
            via_xargs: false,
            elapsed_nanos: 0,
            elapsed_micros: 0,
            fail_closed_reason: None,
        },
        next_state,
    )
}

fn apply_central_dynamic_hazards(
    dynamic_hazard: bool,
    sensitive_dynamic: bool,
    action: &mut Action,
    effects: &mut BTreeSet<Effect>,
) {
    if dynamic_hazard {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
        if sensitive_dynamic {
            effects.insert(Effect::SensitivePathAccess);
        }
        if action.is_read_only_action() {
            *action = Action::AmbiguousShellOrWrapper;
        }
    }
}

fn merge_secondary_into_primary(
    primary: &mut CanonicalCommandTupleV1,
    secondary: CanonicalCommandTupleV1,
) {
    let primary_max = max_severity(&primary.effects);
    let secondary_max = max_severity(&secondary.effects);

    if secondary_max > primary_max {
        primary.program = secondary.program;
        primary.action = secondary.action;
    }
    if primary.fail_closed_reason.is_none() {
        primary.fail_closed_reason = secondary.fail_closed_reason;
    }
    primary.effects.extend(secondary.effects);
    primary
        .target_refs_or_paths
        .extend(secondary.target_refs_or_paths);
    primary.wrappers_peeled.extend(secondary.wrappers_peeled);
    primary.env_overrides.extend(secondary.env_overrides);
    primary.via_xargs |= secondary.via_xargs;
    normalize_effects_set(&mut primary.effects);
}

fn max_severity(effects: &BTreeSet<Effect>) -> u8 {
    effects
        .iter()
        .copied()
        .map(Effect::severity_rank)
        .max()
        .unwrap_or(0)
}

fn normalize_effects_set(effects: &mut BTreeSet<Effect>) {
    if effects.len() > 1 {
        effects.remove(&Effect::ReadOnly);
    } else if effects.is_empty() {
        effects.insert(Effect::ReadOnly);
    }
}

fn fail_closed_tuple(reason: String) -> CanonicalCommandTupleV1 {
    CanonicalCommandTupleV1 {
        schema: TOOL_GRAMMAR_SCHEMA_V1.to_string(),
        program: Program::ShellWrapper,
        action: Action::AmbiguousShellOrWrapper,
        effects: BTreeSet::from([
            Effect::DynamicExecOrConfigEscape,
            Effect::UnrecognizedOrAmbiguousCommand,
        ]),
        target_refs_or_paths: Vec::new(),
        wrappers_peeled: Vec::new(),
        env_overrides: Vec::new(),
        via_xargs: false,
        elapsed_nanos: 0,
        elapsed_micros: 0,
        fail_closed_reason: Some(reason),
    }
}

fn record_elapsed(tuple: &mut CanonicalCommandTupleV1, started: Instant) {
    let elapsed = started.elapsed();
    let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
    tuple.elapsed_nanos = nanos;
    tuple.elapsed_micros = nanos / 1_000;
}
