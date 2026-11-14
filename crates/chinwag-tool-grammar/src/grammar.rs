// SPDX-License-Identifier: Apache-2.0

use crate::path_norm::{
    analyze_path_target, apply_repo_dir_selector, check_non_chdir_repo_selector,
    is_protected_branch_name, parse_git_refspec,
};
use crate::types::{Action, Effect, ParseContext, Program, Target};
use crate::wrappers::InheritedSelectorState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Arity of a declarative CLI flag in `ToolGrammarV1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagArity {
    /// Standalone boolean switch (`-f`, `--force`, `--no-pager`).
    None,
    /// Consumes an argument either attached (`-C/dir`, `--repo=o/r`) or as the next token (`-C /dir`, `--repo o/r`).
    SeparateOrAttachedValue,
    /// Optional attached `=value` only (`--force-with-lease[=ref]`, `--signed[=true]`); never consumes next separate token.
    OptionalAttachedEqualsValue,
    /// Key-value configuration override (`git -c k=v`, `jj --config k=v`).
    ConfigKeyValue,
}

/// Declarative specification of a pre-subcommand or persistent global CLI flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalFlagSpec {
    pub short: Option<char>,
    pub long: Option<&'static str>,
    pub arity: FlagArity,
    pub is_repo_dir: bool,
}

/// Declarative subcommand action rule inside a `ToolGrammarSpecV1` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubcommandRuleSpec {
    pub path: &'static [&'static str],
    pub default_action: Action,
    pub default_effects: &'static [Effect],
}

/// Compile-time declarative `ToolGrammarV1` descriptor for a CLI binary.
#[derive(Debug, Clone, Copy)]
pub struct ToolGrammarSpecV1 {
    pub binary: &'static str,
    pub global_flags: &'static [GlobalFlagSpec],
    pub subcommands: &'static [SubcommandRuleSpec],
}

pub const GIT_GLOBAL_FLAGS: &[GlobalFlagSpec] = &[
    GlobalFlagSpec {
        short: Some('C'),
        long: None,
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: true,
    },
    GlobalFlagSpec {
        short: Some('c'),
        long: None,
        arity: FlagArity::ConfigKeyValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--git-dir"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: true,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--work-tree"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: true,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--namespace"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--super-prefix"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--config-env"),
        arity: FlagArity::ConfigKeyValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--exec-path"),
        arity: FlagArity::OptionalAttachedEqualsValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--list-cmds"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: Some('p'),
        long: Some("--paginate"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: Some('P'),
        long: Some("--no-pager"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--no-replace-objects"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--bare"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--literal-pathspecs"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--glob-pathspecs"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--noglob-pathspecs"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--icase-pathspecs"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--no-optional-locks"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
];

pub const JJ_GLOBAL_FLAGS: &[GlobalFlagSpec] = &[
    GlobalFlagSpec {
        short: Some('R'),
        long: Some("--repository"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: true,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--at-op"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--at-operation"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--color"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--config"),
        arity: FlagArity::ConfigKeyValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--config-toml"),
        arity: FlagArity::ConfigKeyValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--config-file"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--ignore-working-copy"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--ignore-immutable"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--no-pager"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--quiet"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--verbose"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--debug"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
];

pub const GH_GLOBAL_FLAGS: &[GlobalFlagSpec] = &[
    GlobalFlagSpec {
        short: Some('R'),
        long: Some("--repo"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--hostname"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
];

pub const WRANGLER_GLOBAL_FLAGS: &[GlobalFlagSpec] = &[
    GlobalFlagSpec {
        short: Some('c'),
        long: Some("--config"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: Some('e'),
        long: Some("--env"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: false,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--cwd"),
        arity: FlagArity::SeparateOrAttachedValue,
        is_repo_dir: true,
    },
    GlobalFlagSpec {
        short: None,
        long: Some("--experimental-json-config"),
        arity: FlagArity::None,
        is_repo_dir: false,
    },
];

pub const BUILT_IN_TOOL_GRAMMARS_V1: &[ToolGrammarSpecV1] = &[
    ToolGrammarSpecV1 {
        binary: "git",
        global_flags: GIT_GLOBAL_FLAGS,
        subcommands: &[
            SubcommandRuleSpec {
                path: &["status"],
                default_action: Action::Status,
                default_effects: &[Effect::ReadOnly],
            },
            SubcommandRuleSpec {
                path: &["diff"],
                default_action: Action::Diff,
                default_effects: &[Effect::ReadOnly],
            },
            SubcommandRuleSpec {
                path: &["log"],
                default_action: Action::Log,
                default_effects: &[Effect::ReadOnly],
            },
            SubcommandRuleSpec {
                path: &["push"],
                default_action: Action::Push,
                default_effects: &[Effect::PushRemote],
            },
            SubcommandRuleSpec {
                path: &["reset"],
                default_action: Action::ResetHard,
                default_effects: &[Effect::DestructiveWorktreeOp],
            },
            SubcommandRuleSpec {
                path: &["clean"],
                default_action: Action::CleanUntracked,
                default_effects: &[Effect::DestructiveWorktreeOp],
            },
            SubcommandRuleSpec {
                path: &["branch"],
                default_action: Action::BranchDelete,
                default_effects: &[Effect::DestructiveWorktreeOp],
            },
        ],
    },
    ToolGrammarSpecV1 {
        binary: "jj",
        global_flags: JJ_GLOBAL_FLAGS,
        subcommands: &[
            SubcommandRuleSpec {
                path: &["status"],
                default_action: Action::Status,
                default_effects: &[Effect::ReadOnly],
            },
            SubcommandRuleSpec {
                path: &["log"],
                default_action: Action::Log,
                default_effects: &[Effect::ReadOnly],
            },
            SubcommandRuleSpec {
                path: &["diff"],
                default_action: Action::Diff,
                default_effects: &[Effect::ReadOnly],
            },
            SubcommandRuleSpec {
                path: &["git", "push"],
                default_action: Action::GitPush,
                default_effects: &[Effect::PushRemote],
            },
            SubcommandRuleSpec {
                path: &["abandon"],
                default_action: Action::Abandon,
                default_effects: &[Effect::DestructiveWorktreeOp],
            },
            SubcommandRuleSpec {
                path: &["op", "restore"],
                default_action: Action::OpRestore,
                default_effects: &[Effect::DestructiveWorktreeOp],
            },
        ],
    },
    ToolGrammarSpecV1 {
        binary: "gh",
        global_flags: GH_GLOBAL_FLAGS,
        subcommands: &[
            SubcommandRuleSpec {
                path: &["pr", "list"],
                default_action: Action::PrList,
                default_effects: &[Effect::ReadOnly],
            },
            SubcommandRuleSpec {
                path: &["issue", "view"],
                default_action: Action::IssueView,
                default_effects: &[Effect::ReadOnly],
            },
            SubcommandRuleSpec {
                path: &["pr", "merge"],
                default_action: Action::PrMerge,
                default_effects: &[Effect::MergePullRequest, Effect::PushMainBranch],
            },
            SubcommandRuleSpec {
                path: &["repo", "edit"],
                default_action: Action::RepoEditVisibility,
                default_effects: &[Effect::MutateRepositoryVisibility],
            },
            SubcommandRuleSpec {
                path: &["secret", "set"],
                default_action: Action::SecretSet,
                default_effects: &[Effect::MutateSecrets],
            },
            SubcommandRuleSpec {
                path: &["release", "delete"],
                default_action: Action::ReleaseDelete,
                default_effects: &[Effect::DeleteRelease],
            },
        ],
    },
    ToolGrammarSpecV1 {
        binary: "rm",
        global_flags: &[],
        subcommands: &[SubcommandRuleSpec {
            path: &[],
            default_action: Action::Delete,
            default_effects: &[Effect::DestructiveWorktreeOp],
        }],
    },
    ToolGrammarSpecV1 {
        binary: "prisma",
        global_flags: &[],
        subcommands: &[
            SubcommandRuleSpec {
                path: &["migrate", "deploy"],
                default_action: Action::MigrateDeploy,
                default_effects: &[Effect::ApplySchemaMigration],
            },
            SubcommandRuleSpec {
                path: &["migrate", "reset"],
                default_action: Action::MigrateReset,
                default_effects: &[Effect::ApplySchemaMigration, Effect::DestructiveSchemaReset],
            },
        ],
    },
    ToolGrammarSpecV1 {
        binary: "drizzle-kit",
        global_flags: &[],
        subcommands: &[
            SubcommandRuleSpec {
                path: &["push"],
                default_action: Action::SchemaPush,
                default_effects: &[Effect::ApplySchemaMigration],
            },
            SubcommandRuleSpec {
                path: &["drop"],
                default_action: Action::SchemaDrop,
                default_effects: &[Effect::ApplySchemaMigration, Effect::DestructiveSchemaReset],
            },
        ],
    },
    ToolGrammarSpecV1 {
        binary: "sqlx",
        global_flags: &[],
        subcommands: &[
            SubcommandRuleSpec {
                path: &["migrate", "info"],
                default_action: Action::MigrateInfo,
                default_effects: &[Effect::ReadOnly],
            },
            SubcommandRuleSpec {
                path: &["migrate", "run"],
                default_action: Action::MigrateRun,
                default_effects: &[Effect::ApplySchemaMigration],
            },
            SubcommandRuleSpec {
                path: &["migrate", "revert"],
                default_action: Action::MigrateRevert,
                default_effects: &[Effect::ApplySchemaMigration, Effect::DestructiveSchemaReset],
            },
        ],
    },
    ToolGrammarSpecV1 {
        binary: "wrangler",
        global_flags: WRANGLER_GLOBAL_FLAGS,
        subcommands: &[
            SubcommandRuleSpec {
                path: &["d1", "migrations", "apply"],
                default_action: Action::D1MigrationsApply,
                default_effects: &[Effect::ApplySchemaMigration],
            },
            SubcommandRuleSpec {
                path: &["d1", "execute"],
                default_action: Action::D1Execute,
                default_effects: &[Effect::ApplySchemaMigration],
            },
        ],
    },
];

/// Parsed evaluation from a tool's declarative grammar before merging wrapper metadata.
#[derive(Debug, Clone)]
pub struct GrammarOutcome {
    pub program: Program,
    pub action: Action,
    pub effects: BTreeSet<Effect>,
    pub targets: Vec<Target>,
}

/// Evaluates unwrapped `argv` (`[binary, arg1, arg2, ...]`) against `ToolGrammarV1`.
#[must_use]
pub fn evaluate_tool_argv(
    prog_base: &str,
    argv: &[String],
    selector: &InheritedSelectorState,
    via_xargs: bool,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let rest = argv.get(1..).unwrap_or(&[]);
    let cwd_offset = selector.cwd_offset.as_deref();
    if let Some(zsh_eq_cmd) = prog_base.strip_prefix('=')
        && !zsh_eq_cmd.is_empty()
        && !zsh_eq_cmd.starts_with('=')
    {
        let mut out = evaluate_tool_argv(zsh_eq_cmd, argv, selector, via_xargs, ctx);
        out.effects.remove(&Effect::ReadOnly);
        out.effects.insert(Effect::DynamicExecOrConfigEscape);
        out.effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
        if out.action.is_read_only_action() {
            out.action = Action::DynamicExecEscape;
        }
        return out;
    }
    if let Some(git_sub) = prog_base.strip_prefix("git-")
        && !git_sub.is_empty()
    {
        let is_modeled_git_subcommand = matches!(
            git_sub,
            "status"
                | "diff"
                | "diff-tree"
                | "diff-files"
                | "diff-index"
                | "range-diff"
                | "log"
                | "shortlog"
                | "whatchanged"
                | "show"
                | "rev-parse"
                | "rev-list"
                | "ls-files"
                | "ls-tree"
                | "cat-file"
                | "blame"
                | "annotate"
                | "grep"
                | "describe"
                | "name-rev"
                | "merge-base"
                | "for-each-ref"
                | "show-ref"
                | "verify-commit"
                | "verify-tag"
                | "fsck"
                | "count-objects"
                | "help"
                | "version"
                | "ls-remote"
                | "fetch"
                | "push"
                | "reset"
                | "clean"
                | "branch"
                | "checkout"
                | "switch"
                | "restore"
                | "config"
                | "worktree"
                | "remote"
                | "tag"
                | "rebase"
                | "bisect"
                | "filter-branch"
                | "hook"
                | "difftool"
                | "mergetool"
                | "add"
                | "am"
                | "apply"
                | "cherry-pick"
                | "clone"
                | "commit"
                | "format-patch"
                | "gc"
                | "init"
                | "maintenance"
                | "merge"
                | "mv"
                | "notes"
                | "prune"
                | "pull"
                | "reflog"
                | "repack"
                | "replace"
                | "revert"
                | "rm"
                | "sparse-checkout"
                | "stage"
                | "stash"
                | "submodule"
        );
        if !is_modeled_git_subcommand {
            let mut effects = BTreeSet::new();
            effects.insert(Effect::DynamicExecOrConfigEscape);
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            return GrammarOutcome {
                program: Program::Git,
                action: Action::DynamicExecEscape,
                effects,
                targets: Vec::new(),
            };
        }
        let mut synth = Vec::with_capacity(1 + rest.len());
        synth.push(git_sub.to_string());
        synth.extend_from_slice(rest);
        return analyze_git(&synth, selector, via_xargs, ctx);
    }
    match prog_base {
        "git" => analyze_git(rest, selector, via_xargs, ctx),
        "jj" => analyze_jj(rest, selector, via_xargs, ctx),
        "gh" => analyze_gh(rest, cwd_offset, via_xargs, ctx),
        "rm" => analyze_rm(rest, cwd_offset, via_xargs, ctx),
        "prisma" => analyze_prisma(rest, cwd_offset, ctx),
        "drizzle-kit" => analyze_drizzle_kit(rest, cwd_offset, ctx),
        "sqlx" => analyze_sqlx(rest, cwd_offset, ctx),
        "wrangler" => analyze_wrangler(rest, cwd_offset, selector.repo_selector_redirected, ctx),
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish" | "csh" | "tcsh" | "eval" | "."
        | "source" | "trap" | "alias" | "enable" | "fc" | "hash" | "setopt" | "shopt"
        | "python" | "python3" | "node" | "deno" | "bun" | "ruby" | "perl" | "php" | "lua" => {
            let mut effects = BTreeSet::new();
            effects.insert(Effect::DynamicExecOrConfigEscape);
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            GrammarOutcome {
                program: Program::ShellWrapper,
                action: Action::AmbiguousShellOrWrapper,
                effects,
                targets: Vec::new(),
            }
        }
        "npm" | "pnpm" | "yarn" => {
            let mut effects = BTreeSet::new();
            let is_cfg_mutate = rest.first().is_some_and(|t| t == "set")
                || (rest.iter().any(|t| t == "config")
                    && rest
                        .iter()
                        .any(|t| matches!(t.as_str(), "set" | "edit" | "delete")));
            if is_cfg_mutate {
                effects.insert(Effect::DynamicExecOrConfigEscape);
                effects.insert(Effect::SensitivePathAccess);
                GrammarOutcome {
                    program: Program::Unknown(prog_base.to_string()),
                    action: Action::ConfigMutate,
                    effects,
                    targets: Vec::new(),
                }
            } else {
                effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                GrammarOutcome {
                    program: Program::Unknown(prog_base.to_string()),
                    action: Action::UnknownAction,
                    effects,
                    targets: Vec::new(),
                }
            }
        }
        "echo" | "printf" | "true" | "pwd" | "whoami" | "uname" => {
            let mut effects = BTreeSet::new();
            effects.insert(Effect::ReadOnly);
            GrammarOutcome {
                program: Program::Unknown(prog_base.to_string()),
                action: Action::ReadOnlyInspect,
                effects,
                targets: Vec::new(),
            }
        }
        "date" => {
            let mut effects = BTreeSet::new();
            if rest
                .iter()
                .any(|a| a.starts_with("-s") || a.starts_with("--set"))
            {
                effects.insert(Effect::DynamicExecOrConfigEscape);
                effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
                GrammarOutcome {
                    program: Program::Unknown(prog_base.to_string()),
                    action: Action::DynamicExecEscape,
                    effects,
                    targets: Vec::new(),
                }
            } else {
                effects.insert(Effect::ReadOnly);
                GrammarOutcome {
                    program: Program::Unknown(prog_base.to_string()),
                    action: Action::ReadOnlyInspect,
                    effects,
                    targets: Vec::new(),
                }
            }
        }
        "ls" | "cat" | "head" | "tail" | "wc" | "grep" | "rg" => {
            analyze_read_utility(prog_base, rest, cwd_offset, via_xargs, ctx)
        }
        "find" => analyze_find(rest, cwd_offset, ctx),
        other => {
            let mut effects = BTreeSet::new();
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            GrammarOutcome {
                program: Program::Unknown(other.to_string()),
                action: Action::UnknownAction,
                effects,
                targets: Vec::new(),
            }
        }
    }
}

fn analyze_read_utility(
    prog_base: &str,
    rest: &[String],
    cwd_offset: Option<&str>,
    via_xargs: bool,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let mut effects = BTreeSet::new();
    let mut targets = Vec::new();
    if via_xargs {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        effects.insert(Effect::SensitivePathAccess);
    }
    let is_grep_like = matches!(prog_base, "grep" | "rg");
    let (opt_zone, post_dd) = split_at_dashdash(rest);
    let mut k = 0usize;
    while k < opt_zone.len() {
        let tok = opt_zone[k].as_str();
        if prog_base == "rg" && (tok == "--pre" || tok.starts_with("--pre=")) {
            effects.insert(Effect::DynamicExecOrConfigEscape);
            k += if tok == "--pre" && k + 1 < opt_zone.len() {
                2
            } else {
                1
            };
            continue;
        }
        if is_grep_like {
            if tok == "-f" || tok == "--file" {
                if let Some(f) = opt_zone.get(k + 1) {
                    let t = analyze_path_target(f, cwd_offset, ctx);
                    attach_read_path_target_effects(&t, &mut effects);
                    targets.push(t);
                }
                k += 2;
                continue;
            }
            if let Some(f) = tok.strip_prefix("--file=") {
                let t = analyze_path_target(f, cwd_offset, ctx);
                attach_read_path_target_effects(&t, &mut effects);
                targets.push(t);
                k += 1;
                continue;
            }
            if tok == "-e" || tok == "--regexp" {
                k += 2;
                continue;
            }
            if tok.starts_with("--regexp=") {
                k += 1;
                continue;
            }
            if let Some(short) = tok.strip_prefix('-')
                && !short.starts_with('-')
                && !short.is_empty()
            {
                let mut extra_advance = 0usize;
                for (ci, ch) in short.char_indices() {
                    let rest_ch = &short[ci + ch.len_utf8()..];
                    if ch == 'f' {
                        let f_opt = if !rest_ch.is_empty() {
                            Some(rest_ch)
                        } else if let Some(f) = opt_zone.get(k + 1) {
                            extra_advance = 1;
                            Some(f.as_str())
                        } else {
                            None
                        };
                        if let Some(f) = f_opt {
                            let t = analyze_path_target(f, cwd_offset, ctx);
                            attach_read_path_target_effects(&t, &mut effects);
                            targets.push(t);
                        }
                        break;
                    }
                    if matches!(ch, 'e' | 'm' | 'A' | 'B' | 'C' | 'd' | 'D') {
                        if rest_ch.is_empty() {
                            extra_advance = 1;
                        }
                        break;
                    }
                }
                k += 1 + extra_advance;
                continue;
            }
        }
        if !tok.starts_with('-') {
            let t = analyze_path_target(tok, cwd_offset, ctx);
            attach_read_path_target_effects(&t, &mut effects);
            targets.push(t);
        }
        k += 1;
    }
    for lit in post_dd {
        let t = analyze_path_target(lit, cwd_offset, ctx);
        attach_read_path_target_effects(&t, &mut effects);
        targets.push(t);
    }
    if effects.contains(&Effect::DynamicExecOrConfigEscape) {
        return GrammarOutcome {
            program: Program::Unknown(prog_base.to_string()),
            action: Action::DynamicExecEscape,
            effects,
            targets,
        };
    }
    if effects.is_empty() {
        effects.insert(Effect::ReadOnly);
    }
    GrammarOutcome {
        program: Program::Unknown(prog_base.to_string()),
        action: Action::ReadOnlyInspect,
        effects,
        targets,
    }
}

// ---------------------------------------------------------------------------
// 1. GIT GRAMMAR
// ---------------------------------------------------------------------------

fn is_git_remote_helper_transport(raw_arg: &str) -> bool {
    let s = raw_arg
        .strip_prefix("--repo=")
        .or_else(|| raw_arg.strip_prefix("--remote="))
        .unwrap_or(raw_arg);
    let s = s.strip_prefix('+').unwrap_or(s);
    let Some((scheme, _rest)) = s.split_once("::") else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'_' | b'-'))
}

fn analyze_git_read_pathspec(
    raw_path: &str,
    sel: &InheritedSelectorState,
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    targets: &mut Vec<Target>,
) {
    let primary_base = sel
        .worktree_override
        .as_deref()
        .or(sel.cwd_offset.as_deref());
    let t = analyze_path_target(raw_path, primary_base, ctx);
    attach_read_path_target_effects(&t, effects);
    targets.push(t);
    if let (Some(wt), Some(cwd)) = (sel.worktree_override.as_deref(), sel.cwd_offset.as_deref())
        && wt != cwd
    {
        let alt = analyze_path_target(raw_path, Some(cwd), ctx);
        attach_read_path_target_effects(&alt, effects);
    }
}

fn inspect_git_diff_or_grep_paths(
    sub: &str,
    sub_args: &[String],
    sel: &InheritedSelectorState,
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    targets: &mut Vec<Target>,
) {
    let (opt_zone, post_dd) = split_at_dashdash(sub_args);
    let has_no_index = opt_zone.iter().any(|t| t == "--no-index");
    if sub == "diff" {
        if !has_no_index {
            return;
        }
        let mut k = 0usize;
        while k < opt_zone.len() {
            let tok = opt_zone[k].as_str();
            if matches!(
                tok,
                "-U" | "--unified"
                    | "--output"
                    | "-O"
                    | "-S"
                    | "-G"
                    | "--inter-hunk-context"
                    | "--abbrev"
                    | "--diff-filter"
                    | "--find-renames"
                    | "--find-copies"
                    | "--relative"
                    | "--src-prefix"
                    | "--dst-prefix"
            ) {
                k += 2;
                continue;
            }
            if !tok.starts_with('-') && tok != "/dev/null" {
                analyze_git_read_pathspec(tok, sel, ctx, effects, targets);
            }
            k += 1;
        }
        for lit in post_dd {
            if lit != "-" && lit != "/dev/null" {
                analyze_git_read_pathspec(lit, sel, ctx, effects, targets);
            }
        }
    } else if sub == "grep" {
        let mut saw_pattern = false;
        let mut positionals: Vec<&str> = Vec::new();
        let mut k = 0usize;
        while k < opt_zone.len() {
            let tok = opt_zone[k].as_str();
            if tok == "-f" || tok == "--file" {
                saw_pattern = true;
                if let Some(f) = opt_zone.get(k + 1) {
                    analyze_git_read_pathspec(f, sel, ctx, effects, targets);
                }
                k += 2;
                continue;
            }
            if let Some(f) = tok.strip_prefix("--file=") {
                saw_pattern = true;
                analyze_git_read_pathspec(f, sel, ctx, effects, targets);
                k += 1;
                continue;
            }
            if tok == "-e" || tok == "--regexp" {
                saw_pattern = true;
                k += 2;
                continue;
            }
            if tok.starts_with("--regexp=") {
                saw_pattern = true;
                k += 1;
                continue;
            }
            if matches!(tok, "--max-depth" | "--threads" | "-O") {
                k += 2;
                continue;
            }
            if let Some(short) = tok.strip_prefix('-')
                && !short.starts_with('-')
                && !short.is_empty()
            {
                let mut extra_advance = 0usize;
                for (ci, ch) in short.char_indices() {
                    let rest_ch = &short[ci + ch.len_utf8()..];
                    if ch == 'f' {
                        saw_pattern = true;
                        let f_opt = if !rest_ch.is_empty() {
                            Some(rest_ch)
                        } else if let Some(f) = opt_zone.get(k + 1) {
                            extra_advance = 1;
                            Some(f.as_str())
                        } else {
                            None
                        };
                        if let Some(f) = f_opt {
                            analyze_git_read_pathspec(f, sel, ctx, effects, targets);
                        }
                        break;
                    }
                    if ch == 'e' {
                        saw_pattern = true;
                        if rest_ch.is_empty() {
                            extra_advance = 1;
                        }
                        break;
                    }
                    if matches!(ch, 'm' | 'A' | 'B' | 'C') {
                        if rest_ch.is_empty() {
                            extra_advance = 1;
                        }
                        break;
                    }
                }
                k += 1 + extra_advance;
                continue;
            }
            if !tok.starts_with('-') {
                positionals.push(tok);
            }
            k += 1;
        }
        if has_no_index {
            let skip_cnt = usize::from(!saw_pattern);
            for p in positionals.into_iter().skip(skip_cnt) {
                analyze_git_read_pathspec(p, sel, ctx, effects, targets);
            }
            for lit in post_dd {
                analyze_git_read_pathspec(lit, sel, ctx, effects, targets);
            }
        }
    }
}

fn analyze_git(
    args: &[String],
    selector: &InheritedSelectorState,
    via_xargs: bool,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let mut effects = BTreeSet::new();
    let mut targets = Vec::new();
    let mut local_sel = selector.clone();
    local_sel.revalidate_selectors(ctx, &mut effects);
    if local_sel.cwd_offset.as_deref().is_some_and(|d| d != ".")
        || local_sel.worktree_override.is_some()
    {
        local_sel.repo_selector_redirected = true;
    }

    let mut i = 0usize;
    let mut subcmd: Option<&str> = None;

    // Stage 2: Walk pre-subcommand global flags using `GIT_GLOBAL_FLAGS`
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--" {
            i += 1;
            subcmd = args.get(i).map(String::as_str);
            i += usize::from(subcmd.is_some());
            break;
        }
        if matches!(tok, "--version" | "-v" | "--help" | "-h") && subcmd.is_none() {
            if effects.contains(&Effect::DynamicExecOrConfigEscape) {
                return GrammarOutcome {
                    program: Program::Git,
                    action: Action::DynamicExecEscape,
                    effects,
                    targets,
                };
            }
            if effects.is_empty() {
                effects.insert(Effect::ReadOnly);
            }
            return GrammarOutcome {
                program: Program::Git,
                action: Action::ReadOnlyInspect,
                effects,
                targets,
            };
        }
        if let Some(val) = tok.strip_prefix("--exec-path=") {
            let _ = val;
            effects.insert(Effect::DynamicExecOrConfigEscape);
            i += 1;
            continue;
        }
        if tok == "--exec-path" && i + 1 == args.len() {
            if effects.contains(&Effect::DynamicExecOrConfigEscape) {
                return GrammarOutcome {
                    program: Program::Git,
                    action: Action::DynamicExecEscape,
                    effects,
                    targets,
                };
            }
            if effects.is_empty() {
                effects.insert(Effect::ReadOnly);
            }
            return GrammarOutcome {
                program: Program::Git,
                action: Action::ReadOnlyInspect,
                effects,
                targets,
            };
        }
        if tok == "--config-env"
            || tok.starts_with("--config-env=")
            || tok.starts_with("--upload-pack")
            || tok.starts_with("--receive-pack")
        {
            effects.insert(Effect::DynamicExecOrConfigEscape);
        }
        if tok == "--bare" {
            local_sel.repo_selector_redirected = true;
        }

        if let Some((consumed, maybe_dir, maybe_cfg)) = match_global_flag(GIT_GLOBAL_FLAGS, args, i)
        {
            if let Some(dir) = maybe_dir {
                if tok == "--git-dir" || tok.starts_with("--git-dir=") {
                    local_sel.raw_git_dir = Some(dir.clone());
                    let (_norm, escapes) = check_non_chdir_repo_selector(
                        local_sel.cwd_offset.as_deref(),
                        &mut local_sel.repo_selector_redirected,
                        &dir,
                        ctx,
                    );
                    if escapes {
                        effects.insert(Effect::PathTraversalEscape);
                    }
                } else if tok == "--work-tree" || tok.starts_with("--work-tree=") {
                    local_sel.raw_worktree = Some(dir.clone());
                    let (norm, escapes) = check_non_chdir_repo_selector(
                        local_sel.cwd_offset.as_deref(),
                        &mut local_sel.repo_selector_redirected,
                        &dir,
                        ctx,
                    );
                    if escapes {
                        effects.insert(Effect::PathTraversalEscape);
                    }
                    local_sel.worktree_override = Some(norm);
                } else {
                    if apply_repo_dir_selector(
                        &mut local_sel.cwd_offset,
                        &mut local_sel.repo_selector_redirected,
                        &dir,
                        ctx,
                    ) {
                        effects.insert(Effect::PathTraversalEscape);
                    }
                    local_sel.revalidate_selectors(ctx, &mut effects);
                }
            }
            if let Some(cfg_kv) = maybe_cfg {
                inspect_git_config_override(&cfg_kv, &mut effects);
            }
            i += consumed;
            continue;
        }

        if tok.starts_with('-') {
            // Unknown pre-subcommand flag -> fail closed
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            i += 1;
            continue;
        }

        subcmd = Some(tok);
        i += 1;
        break;
    }

    let Some(sub) = subcmd else {
        if effects.is_empty() {
            effects.insert(Effect::ReadOnly);
        }
        return GrammarOutcome {
            program: Program::Git,
            action: if effects.contains(&Effect::DynamicExecOrConfigEscape) {
                Action::DynamicExecEscape
            } else {
                Action::ReadOnlyInspect
            },
            effects,
            targets,
        };
    };

    let sub_args = args.get(i..).unwrap_or(&[]);

    if matches!(
        sub,
        "ls-remote"
            | "fetch"
            | "pull"
            | "push"
            | "clone"
            | "remote"
            | "submodule"
            | "archive"
            | "fetch-pack"
            | "send-pack"
            | "peek-remote"
    ) && sub_args
        .iter()
        .any(|a| a != "--" && is_git_remote_helper_transport(a))
    {
        effects.insert(Effect::DynamicExecOrConfigEscape);
    }

    // Split at first `--` into `(option_zone, post_dashdash_zone)` while scanning for dynamic helper/pager flags
    let (opt_zone, post_dd) = split_at_dashdash(sub_args);
    if matches!(sub, "filter-branch" | "hook")
        || (sub == "bisect" && opt_zone.iter().any(|t| t == "run"))
        || (sub == "submodule" && opt_zone.iter().any(|t| t == "foreach"))
    {
        effects.insert(Effect::DynamicExecOrConfigEscape);
    }
    for tok in opt_zone {
        if tok.starts_with("--upload-pack")
            || tok.starts_with("--receive-pack")
            || tok.starts_with("--exec=")
            || tok == "--exec"
            || tok == "--ext-diff"
        {
            effects.insert(Effect::DynamicExecOrConfigEscape);
        }
        if sub == "rebase"
            && (tok == "-x"
                || short_bundle_has_any(tok, &['x'])
                || (tok.starts_with("-x") && !tok.starts_with("--")))
        {
            effects.insert(Effect::DynamicExecOrConfigEscape);
        }
        if matches!(sub, "difftool" | "mergetool")
            && (tok == "-x"
                || tok.starts_with("--extcmd")
                || short_bundle_has_any(tok, &['x'])
                || (tok.starts_with("-x") && !tok.starts_with("--")))
        {
            effects.insert(Effect::DynamicExecOrConfigEscape);
        }
        if matches!(sub, "fetch" | "clone" | "ls-remote" | "pull")
            && (tok == "-u" || (tok.starts_with("-u") && !tok.starts_with("--")))
        {
            effects.insert(Effect::DynamicExecOrConfigEscape);
        }
        if sub == "grep"
            && (tok == "-O"
                || tok.starts_with("--open-files-in-pager")
                || short_bundle_has_any(tok, &['O']))
        {
            effects.insert(Effect::DynamicExecOrConfigEscape);
        }
        if sub == "help"
            && (tok == "-w"
                || tok == "--web"
                || tok == "-m"
                || tok == "--man"
                || short_bundle_has_any(tok, &['w', 'm']))
        {
            effects.insert(Effect::DynamicExecOrConfigEscape);
        }
    }

    if matches!(sub, "diff" | "grep") {
        inspect_git_diff_or_grep_paths(sub, sub_args, &local_sel, ctx, &mut effects, &mut targets);
    }

    let cwd_ref = local_sel.cwd_offset.as_deref();
    match sub {
        "status" => finalize_git_readonly(
            Action::Status,
            opt_zone,
            true,
            cwd_ref,
            ctx,
            effects,
            targets,
        ),
        "diff" | "diff-tree" | "diff-files" | "diff-index" | "range-diff" => {
            finalize_git_readonly(Action::Diff, opt_zone, true, cwd_ref, ctx, effects, targets)
        }
        "log" | "shortlog" | "whatchanged" => {
            finalize_git_readonly(Action::Log, opt_zone, true, cwd_ref, ctx, effects, targets)
        }
        "show" | "rev-parse" | "rev-list" | "ls-files" | "ls-tree" | "cat-file" | "blame"
        | "annotate" | "grep" | "describe" | "name-rev" | "merge-base" | "for-each-ref"
        | "show-ref" | "verify-commit" | "verify-tag" | "fsck" | "count-objects" | "help"
        | "version" | "ls-remote" => finalize_git_readonly(
            Action::ReadOnlyInspect,
            opt_zone,
            true,
            cwd_ref,
            ctx,
            effects,
            targets,
        ),
        "fetch" => analyze_git_fetch(opt_zone, post_dd, ctx, effects, targets),
        "push" => analyze_git_push(
            opt_zone,
            post_dd,
            local_sel.repo_selector_redirected,
            via_xargs,
            ctx,
            effects,
            targets,
        ),
        "reset" => analyze_git_reset(
            opt_zone, post_dd, &local_sel, via_xargs, ctx, effects, targets,
        ),
        "clean" => analyze_git_clean(
            opt_zone, post_dd, &local_sel, via_xargs, ctx, effects, targets,
        ),
        "branch" => analyze_git_branch(opt_zone, post_dd, via_xargs, ctx, effects, targets),
        "checkout" | "switch" => {
            if via_xargs {
                effects.insert(Effect::DynamicExecOrConfigEscape);
                effects.insert(Effect::SensitivePathAccess);
            }
            analyze_git_checkout(sub, opt_zone, post_dd, &local_sel, ctx, effects, targets)
        }
        "restore" => analyze_git_restore(
            opt_zone, post_dd, &local_sel, via_xargs, ctx, effects, targets,
        ),
        "config" => analyze_git_config_cmd(opt_zone, cwd_ref, ctx, effects, targets),
        "worktree" => analyze_git_worktree(opt_zone, effects, targets),
        "remote" => {
            let positional: Vec<&str> = opt_zone
                .iter()
                .map(String::as_str)
                .filter(|t| !t.starts_with('-'))
                .collect();
            if positional.is_empty() || matches!(positional[0], "show" | "get-url") {
                finalize_git_readonly(
                    Action::ReadOnlyInspect,
                    opt_zone,
                    false,
                    cwd_ref,
                    ctx,
                    effects,
                    targets,
                )
            } else {
                effects.insert(Effect::DestructiveWorktreeOp);
                effects.insert(Effect::SensitivePathAccess);
                GrammarOutcome {
                    program: Program::Git,
                    action: Action::ConfigMutate,
                    effects,
                    targets,
                }
            }
        }
        "tag" => {
            let has_delete_or_force = opt_zone.iter().any(|t| {
                matches!(t.as_str(), "--delete" | "--force") || short_bundle_has_any(t, &['d', 'f'])
            });
            let positional_cnt = opt_zone.iter().filter(|t| !t.starts_with('-')).count();
            let list_flag = opt_zone
                .iter()
                .any(|t| t == "--list" || short_bundle_has_any(t, &['l', 'v']));
            if !has_delete_or_force && (positional_cnt == 0 || list_flag) {
                finalize_git_readonly(
                    Action::ReadOnlyInspect,
                    opt_zone,
                    false,
                    cwd_ref,
                    ctx,
                    effects,
                    targets,
                )
            } else {
                effects.insert(Effect::DestructiveWorktreeOp);
                GrammarOutcome {
                    program: Program::Git,
                    action: Action::BranchDelete,
                    effects,
                    targets,
                }
            }
        }
        "add" | "am" | "apply" | "cherry-pick" | "clone" | "commit" | "format-patch" | "gc"
        | "init" | "maintenance" | "merge" | "mv" | "notes" | "prune" | "pull" | "rebase"
        | "reflog" | "repack" | "replace" | "revert" | "rm" | "sparse-checkout" | "stage"
        | "stash" | "submodule" | "bisect" | "difftool" | "mergetool" => {
            if effects.contains(&Effect::DynamicExecOrConfigEscape) {
                return GrammarOutcome {
                    program: Program::Git,
                    action: Action::DynamicExecEscape,
                    effects,
                    targets,
                };
            }
            effects.insert(Effect::DestructiveWorktreeOp);
            GrammarOutcome {
                program: Program::Git,
                action: Action::WorktreeMutate,
                effects,
                targets,
            }
        }
        _ => {
            // Unrecognized `git <name>` invokes `git-<name>` helper/plugin on `$GIT_EXEC_PATH` / `$PATH`
            // (e.g. `git remote-ext`, `git credential-store`, `git upload-pack`, `git shell`).
            effects.insert(Effect::DynamicExecOrConfigEscape);
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            GrammarOutcome {
                program: Program::Git,
                action: Action::DynamicExecEscape,
                effects,
                targets,
            }
        }
    }
}

fn finalize_git_readonly(
    mut action: Action,
    opt_zone: &[String],
    check_output_flag: bool,
    cwd_offset: Option<&str>,
    ctx: &ParseContext<'_>,
    mut effects: BTreeSet<Effect>,
    mut targets: Vec<Target>,
) -> GrammarOutcome {
    if check_output_flag {
        let mut idx = 0usize;
        while idx < opt_zone.len() {
            let tok = opt_zone[idx].as_str();
            let out_val = if let Some(v) = tok.strip_prefix("--output=") {
                Some(v)
            } else if tok == "--output" {
                idx += 1;
                opt_zone.get(idx).map(String::as_str)
            } else {
                None
            };
            if let Some(out_path) = out_val {
                let t = analyze_path_target(out_path, cwd_offset, ctx);
                attach_path_target_effects(&t, &mut effects);
                effects.insert(Effect::DestructiveWorktreeOp);
                action = Action::WorktreeMutate;
                targets.push(t);
            }
            idx += 1;
        }
    }
    if effects.contains(&Effect::DynamicExecOrConfigEscape) {
        return GrammarOutcome {
            program: Program::Git,
            action: Action::DynamicExecEscape,
            effects,
            targets,
        };
    }
    if effects.is_empty() {
        effects.insert(Effect::ReadOnly);
    }
    GrammarOutcome {
        program: Program::Git,
        action,
        effects,
        targets,
    }
}

fn analyze_git_fetch(
    opt_zone: &[String],
    post_dd: &[String],
    ctx: &ParseContext<'_>,
    mut effects: BTreeSet<Effect>,
    mut targets: Vec<Target>,
) -> GrammarOutcome {
    let mut is_force = false;
    let mut positionals: Vec<&str> = Vec::new();

    let mut k = 0usize;
    while k < opt_zone.len() {
        let tok = opt_zone[k].as_str();
        if matches!(
            tok,
            "--depth"
                | "--deepen"
                | "--shallow-since"
                | "--shallow-exclude"
                | "-j"
                | "--jobs"
                | "-o"
                | "--server-option"
                | "--refmap"
        ) {
            if tok == "--refmap" {
                effects.insert(Effect::DestructiveWorktreeOp);
            }
            k += 2;
            continue;
        }
        if tok.starts_with("--refmap=") {
            effects.insert(Effect::DestructiveWorktreeOp);
            k += 1;
            continue;
        }
        if tok == "--force" || tok == "--update-head-ok" {
            is_force = true;
            k += 1;
            continue;
        }
        if short_bundle_has_any(tok, &['f']) {
            is_force = true;
            k += 1;
            continue;
        }
        if !tok.starts_with('-') {
            positionals.push(tok);
        }
        k += 1;
    }
    for lit in post_dd {
        positionals.push(lit.as_str());
    }

    let refspecs = positionals.get(1..).unwrap_or(&[]);
    for raw_spec in refspecs {
        if raw_spec.contains(':') {
            effects.insert(Effect::DestructiveWorktreeOp);
            let parsed = parse_git_refspec(raw_spec, ctx);
            if let Target::Refspec {
                leading_plus_force,
                colon_delete,
                targets_protected_branch,
                ..
            } = &parsed
                && *targets_protected_branch
                && (*leading_plus_force || *colon_delete || is_force)
            {
                effects.insert(Effect::ForcePushProtectedBranch);
            }
            targets.push(parsed);
        }
    }

    if effects.contains(&Effect::DynamicExecOrConfigEscape) {
        return GrammarOutcome {
            program: Program::Git,
            action: Action::DynamicExecEscape,
            effects,
            targets,
        };
    }
    if effects.is_empty() {
        effects.insert(Effect::ReadOnly);
        return GrammarOutcome {
            program: Program::Git,
            action: Action::ReadOnlyInspect,
            effects,
            targets,
        };
    }
    GrammarOutcome {
        program: Program::Git,
        action: Action::WorktreeMutate,
        effects,
        targets,
    }
}

fn analyze_git_push(
    opt_zone: &[String],
    post_dd: &[String],
    repo_redirected: bool,
    via_xargs: bool,
    ctx: &ParseContext<'_>,
    mut effects: BTreeSet<Effect>,
    mut targets: Vec<Target>,
) -> GrammarOutcome {
    effects.insert(Effect::PushRemote);

    // If `GIT_DIR`, `--git-dir`, `--work-tree`, `--bare`, or `-C <dir>` redirected Git away from
    // `workspace_root` (sticky across `-C .`), do not assume `ctx.current_branch` applies!
    let effective_current_branch = if repo_redirected {
        None
    } else {
        ctx.current_branch
    };
    let push_ctx = ParseContext {
        workspace_root: ctx.workspace_root,
        protected_paths: ctx.protected_paths,
        protected_branches: ctx.protected_branches,
        current_branch: effective_current_branch,
    };

    let mut is_force = false;
    let mut is_delete_flag = false;
    let mut is_mirror_or_all = false;
    let mut positionals: Vec<&str> = Vec::new();

    let mut k = 0usize;
    while k < opt_zone.len() {
        let tok = opt_zone[k].as_str();
        if matches!(
            tok,
            "--repo" | "--receive-pack" | "--exec" | "-o" | "--push-option"
        ) {
            if let Some(val) = opt_zone.get(k + 1)
                && tok == "--repo"
            {
                targets.push(Target::Remote {
                    remote_or_repo: val.clone(),
                });
            }
            k += 2;
            continue;
        }
        if let Some(repo) = tok.strip_prefix("--repo=") {
            targets.push(Target::Remote {
                remote_or_repo: repo.to_string(),
            });
            k += 1;
            continue;
        }
        if tok == "--force"
            || tok == "--force-with-lease"
            || tok.starts_with("--force-with-lease=")
            || tok == "--force-if-includes"
        {
            is_force = true;
            k += 1;
            continue;
        }
        if tok == "--delete" {
            is_delete_flag = true;
            k += 1;
            continue;
        }
        if tok == "--mirror" {
            is_force = true;
            is_mirror_or_all = true;
            k += 1;
            continue;
        }
        if tok == "--all" || tok == "--branches" {
            is_mirror_or_all = true;
            k += 1;
            continue;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            // Note: `-o<val>` attaches push-option value; `-f`, `-d`, `-u`, `-v`, `-q`, `-n` bundle
            for (ci, ch) in short.char_indices() {
                if ch == 'o' {
                    if ci + 1 == short.len() {
                        k += 1;
                    }
                    break;
                }
                if ch == 'f' {
                    is_force = true;
                } else if ch == 'd' {
                    is_delete_flag = true;
                }
            }
            k += 1;
            continue;
        }
        if tok.starts_with('-') {
            k += 1;
            continue;
        }
        positionals.push(tok);
        k += 1;
    }

    for lit in post_dd {
        positionals.push(lit.as_str());
    }

    // First positional is `<remote>`, remaining positionals are `<refspec>...`
    let refspec_slices: &[&str] = if let Some((&remote, rest)) = positionals.split_first() {
        targets.push(Target::Remote {
            remote_or_repo: remote.to_string(),
        });
        rest
    } else {
        &[]
    };

    let mut any_refspec_plus_or_colon = false;
    let mut any_protected_target = false;

    for raw_spec in refspec_slices {
        let parsed = parse_git_refspec(raw_spec, &push_ctx);
        if let Target::Refspec {
            leading_plus_force,
            colon_delete,
            targets_protected_branch,
            ..
        } = &parsed
        {
            if *leading_plus_force || *colon_delete {
                any_refspec_plus_or_colon = true;
            }
            if *targets_protected_branch {
                any_protected_target = true;
            }
        }
        targets.push(parsed);
    }

    let effective_force = is_force || is_delete_flag || any_refspec_plus_or_colon;

    // When `--mirror` / `--all` / `via_xargs` is set, OR when `git push` is invoked without an
    // explicit refspec (`git push`, `git push origin`), fail closed by marking protected-branch
    // blast radius (`Effect::PushMainBranch`), because Git resolves implicit destinations through
    // `.git/config` (`remote.<name>.push`, `push.default`, `branch.<name>.merge`). Explicit `HEAD`
    // (`git push origin HEAD`) resolves against `effective_current_branch` in `parse_git_refspec`.
    if is_mirror_or_all || via_xargs || refspec_slices.is_empty() {
        any_protected_target = true;
    }

    if any_protected_target {
        effects.insert(Effect::PushMainBranch);
    }
    if effective_force {
        effects.insert(Effect::ForcePushRemote);
        if any_protected_target {
            effects.insert(Effect::ForcePushProtectedBranch);
        }
    }

    let action = if effective_force {
        Action::ForcePush
    } else {
        Action::Push
    };

    GrammarOutcome {
        program: Program::Git,
        action,
        effects,
        targets,
    }
}

fn analyze_git_worktree_pathspec(
    raw_path: &str,
    sel: &InheritedSelectorState,
    ctx: &ParseContext<'_>,
    effects: &mut BTreeSet<Effect>,
    targets: &mut Vec<Target>,
) {
    let primary_base = sel
        .worktree_override
        .as_deref()
        .or(sel.cwd_offset.as_deref());
    let t = analyze_path_target(raw_path, primary_base, ctx);
    attach_path_target_effects(&t, effects);
    targets.push(t);
    if let (Some(wt), Some(cwd)) = (sel.worktree_override.as_deref(), sel.cwd_offset.as_deref())
        && wt != cwd
    {
        let alt = analyze_path_target(raw_path, Some(cwd), ctx);
        attach_path_target_effects(&alt, effects);
    }
}

fn analyze_git_reset(
    opt_zone: &[String],
    post_dd: &[String],
    sel: &InheritedSelectorState,
    via_xargs: bool,
    ctx: &ParseContext<'_>,
    mut effects: BTreeSet<Effect>,
    mut targets: Vec<Target>,
) -> GrammarOutcome {
    if via_xargs {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        effects.insert(Effect::SensitivePathAccess);
    }
    let is_hard = opt_zone
        .iter()
        .any(|t| matches!(t.as_str(), "--hard" | "--merge" | "--keep"));
    for p in post_dd {
        analyze_git_worktree_pathspec(p, sel, ctx, &mut effects, &mut targets);
    }
    if is_hard {
        effects.insert(Effect::DestructiveWorktreeOp);
        GrammarOutcome {
            program: Program::Git,
            action: Action::ResetHard,
            effects,
            targets,
        }
    } else {
        effects.insert(Effect::DestructiveWorktreeOp);
        GrammarOutcome {
            program: Program::Git,
            action: Action::WorktreeMutate,
            effects,
            targets,
        }
    }
}

fn analyze_git_clean(
    opt_zone: &[String],
    post_dd: &[String],
    sel: &InheritedSelectorState,
    via_xargs: bool,
    ctx: &ParseContext<'_>,
    mut effects: BTreeSet<Effect>,
    mut targets: Vec<Target>,
) -> GrammarOutcome {
    if via_xargs {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        effects.insert(Effect::SensitivePathAccess);
    }
    let mut has_force = false;
    let mut has_dir = false;
    let mut has_dry_run = false;

    for tok in opt_zone {
        match tok.as_str() {
            "--force" => has_force = true,
            "--dry-run" => has_dry_run = true,
            _ if tok.starts_with('-') && !tok.starts_with("--") => {
                // Note `-e <pattern>` takes an argument
                for ch in tok[1..].chars() {
                    if ch == 'e' {
                        break;
                    }
                    match ch {
                        'f' => has_force = true,
                        'd' => has_dir = true,
                        'n' => has_dry_run = true,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    for p in post_dd {
        analyze_git_worktree_pathspec(p, sel, ctx, &mut effects, &mut targets);
    }

    if !has_force && has_dry_run && !via_xargs {
        return finalize_git_readonly(
            Action::ReadOnlyInspect,
            opt_zone,
            false,
            sel.cwd_offset.as_deref(),
            ctx,
            effects,
            targets,
        );
    }

    effects.insert(Effect::DestructiveWorktreeOp);
    if has_dir {
        effects.insert(Effect::RecursiveDelete);
    }
    GrammarOutcome {
        program: Program::Git,
        action: Action::CleanUntracked,
        effects,
        targets,
    }
}

fn analyze_git_branch(
    opt_zone: &[String],
    post_dd: &[String],
    via_xargs: bool,
    ctx: &ParseContext<'_>,
    mut effects: BTreeSet<Effect>,
    mut targets: Vec<Target>,
) -> GrammarOutcome {
    let mut is_delete = false;
    let mut is_force_delete = false;
    let mut is_move_or_copy = false;
    let mut is_list = false;
    let mut branch_names: Vec<&str> = Vec::new();

    let mut k = 0usize;
    while k < opt_zone.len() {
        let tok = opt_zone[k].as_str();
        if matches!(
            tok,
            "--contains"
                | "--no-contains"
                | "--merged"
                | "--no-merged"
                | "--points-at"
                | "--sort"
                | "--format"
                | "-u"
                | "--set-upstream-to"
        ) {
            is_list = true;
            k += 2;
            continue;
        }
        match tok {
            "--delete" => is_delete = true,
            "--force" => is_force_delete = true,
            "--move" | "--copy" => is_move_or_copy = true,
            "--list" | "--all" | "--remotes" | "--show-current" => is_list = true,
            _ if tok.starts_with('-') && !tok.starts_with("--") => {
                for ch in tok[1..].chars() {
                    match ch {
                        'd' => is_delete = true,
                        'D' => {
                            is_delete = true;
                            is_force_delete = true;
                        }
                        'f' => is_force_delete = true,
                        'm' => is_move_or_copy = true,
                        'M' => {
                            is_move_or_copy = true;
                            is_force_delete = true;
                        }
                        'c' | 'C' => is_move_or_copy = true,
                        'l' | 'a' | 'r' | 'v' => is_list = true,
                        _ => {}
                    }
                }
            }
            _ if !tok.starts_with('-') => branch_names.push(tok),
            _ => {}
        }
        k += 1;
    }
    for b in post_dd {
        branch_names.push(b.as_str());
    }

    if is_delete {
        effects.insert(Effect::DestructiveWorktreeOp);
        for name in &branch_names {
            let prot = is_protected_branch_name(name, ctx.protected_branches);
            if prot && is_force_delete {
                effects.insert(Effect::ForcePushProtectedBranch);
            }
            targets.push(Target::Branch {
                name: (*name).to_string(),
                protected: prot,
            });
        }
        if via_xargs && is_force_delete {
            effects.insert(Effect::ForcePushProtectedBranch);
        }
        return GrammarOutcome {
            program: Program::Git,
            action: Action::BranchDelete,
            effects,
            targets,
        };
    }

    if !is_move_or_copy && (branch_names.is_empty() || is_list) {
        return finalize_git_readonly(
            Action::ReadOnlyInspect,
            opt_zone,
            false,
            None,
            ctx,
            effects,
            targets,
        );
    }

    effects.insert(Effect::DestructiveWorktreeOp);
    GrammarOutcome {
        program: Program::Git,
        action: Action::WorktreeMutate,
        effects,
        targets,
    }
}

fn analyze_git_checkout(
    sub: &str,
    opt_zone: &[String],
    post_dd: &[String],
    sel: &InheritedSelectorState,
    ctx: &ParseContext<'_>,
    mut effects: BTreeSet<Effect>,
    mut targets: Vec<Target>,
) -> GrammarOutcome {
    let has_force = opt_zone.iter().any(|t| {
        matches!(t.as_str(), "--force" | "--discard-changes") || short_bundle_has_any(t, &['f'])
    });
    for p in post_dd {
        analyze_git_worktree_pathspec(p, sel, ctx, &mut effects, &mut targets);
    }
    if has_force || (sub == "checkout" && !post_dd.is_empty()) {
        effects.insert(Effect::DestructiveWorktreeOp);
        return GrammarOutcome {
            program: Program::Git,
            action: Action::CheckoutDiscard,
            effects,
            targets,
        };
    }
    effects.insert(Effect::DestructiveWorktreeOp);
    GrammarOutcome {
        program: Program::Git,
        action: Action::WorktreeMutate,
        effects,
        targets,
    }
}

fn analyze_git_restore(
    opt_zone: &[String],
    post_dd: &[String],
    sel: &InheritedSelectorState,
    via_xargs: bool,
    ctx: &ParseContext<'_>,
    mut effects: BTreeSet<Effect>,
    mut targets: Vec<Target>,
) -> GrammarOutcome {
    if via_xargs {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        effects.insert(Effect::SensitivePathAccess);
    }
    for tok in opt_zone.iter().filter(|t| !t.starts_with('-')) {
        analyze_git_worktree_pathspec(tok, sel, ctx, &mut effects, &mut targets);
    }
    for p in post_dd {
        analyze_git_worktree_pathspec(p, sel, ctx, &mut effects, &mut targets);
    }
    effects.insert(Effect::DestructiveWorktreeOp);
    GrammarOutcome {
        program: Program::Git,
        action: Action::CheckoutDiscard,
        effects,
        targets,
    }
}

fn analyze_git_config_cmd(
    opt_zone: &[String],
    cwd_offset: Option<&str>,
    ctx: &ParseContext<'_>,
    mut effects: BTreeSet<Effect>,
    mut targets: Vec<Target>,
) -> GrammarOutcome {
    let mut k = 0usize;
    while k < opt_zone.len() {
        let tok = opt_zone[k].as_str();
        if tok == "-f" || tok == "--file" {
            if let Some(f) = opt_zone.get(k + 1) {
                let t = analyze_path_target(f, cwd_offset, ctx);
                attach_read_path_target_effects(&t, &mut effects);
                targets.push(t);
            }
            k += 2;
            continue;
        }
        if let Some(f) = tok.strip_prefix("--file=").or_else(|| {
            if !tok.starts_with("--") {
                tok.strip_prefix("-f").filter(|r| !r.is_empty())
            } else {
                None
            }
        }) {
            let t = analyze_path_target(f, cwd_offset, ctx);
            attach_read_path_target_effects(&t, &mut effects);
            targets.push(t);
            k += 1;
            continue;
        }
        if tok == "--blob" || tok.starts_with("--blob=") {
            effects.insert(Effect::SensitivePathAccess);
        }
        k += 1;
    }
    let is_read = opt_zone.iter().any(|t| {
        matches!(
            t.as_str(),
            "--list" | "-l" | "--get" | "--get-all" | "--get-regexp" | "--get-urlmatch"
        )
    });
    let non_flags: Vec<&str> = opt_zone
        .iter()
        .map(String::as_str)
        .filter(|t| !t.starts_with('-'))
        .collect();
    if is_read
        || non_flags.len() == 1
            && !opt_zone.iter().any(|t| {
                matches!(
                    t.as_str(),
                    "--unset"
                        | "--unset-all"
                        | "--remove-section"
                        | "--rename-section"
                        | "--edit"
                        | "-e"
                )
            })
    {
        if effects.contains(&Effect::DynamicExecOrConfigEscape) {
            return GrammarOutcome {
                program: Program::Git,
                action: Action::DynamicExecEscape,
                effects,
                targets,
            };
        }
        if effects.is_empty() {
            effects.insert(Effect::ReadOnly);
        }
        return GrammarOutcome {
            program: Program::Git,
            action: Action::ReadOnlyInspect,
            effects,
            targets,
        };
    }
    if let Some(first_key) = non_flags.first() {
        inspect_git_config_override(first_key, &mut effects);
    }
    effects.insert(Effect::SensitivePathAccess);
    effects.insert(Effect::DynamicExecOrConfigEscape);
    GrammarOutcome {
        program: Program::Git,
        action: Action::ConfigMutate,
        effects,
        targets,
    }
}

fn analyze_git_worktree(
    opt_zone: &[String],
    mut effects: BTreeSet<Effect>,
    targets: Vec<Target>,
) -> GrammarOutcome {
    let sub = opt_zone
        .iter()
        .map(String::as_str)
        .find(|t| !t.starts_with('-'));
    if sub == Some("list") {
        if effects.contains(&Effect::DynamicExecOrConfigEscape) {
            return GrammarOutcome {
                program: Program::Git,
                action: Action::DynamicExecEscape,
                effects,
                targets,
            };
        }
        if effects.is_empty() {
            effects.insert(Effect::ReadOnly);
        }
        return GrammarOutcome {
            program: Program::Git,
            action: Action::ReadOnlyInspect,
            effects,
            targets,
        };
    }
    effects.insert(Effect::DestructiveWorktreeOp);
    GrammarOutcome {
        program: Program::Git,
        action: Action::WorktreeMutate,
        effects,
        targets,
    }
}

fn inspect_git_config_override(raw_kv: &str, effects: &mut BTreeSet<Effect>) {
    let key = raw_kv
        .split_once('=')
        .map(|(k, _)| k)
        .unwrap_or(raw_kv)
        .trim()
        .to_ascii_lowercase();

    if key == "http.extraheader"
        || (key.starts_with("http.") && key.ends_with(".extraheader"))
        || key.starts_with("credential.")
    {
        effects.insert(Effect::MutateSecrets);
        effects.insert(Effect::DynamicExecOrConfigEscape);
        return;
    }

    // Deny-by-default allowlist for `git -c <key>=<val>`: only purely cosmetic / non-executing
    // keys pass cleanly; every transport, pager, gpg, remote, alias, diff driver, or unknown key
    // emits `Effect::DynamicExecOrConfigEscape`.
    let is_safe_cosmetic = key.starts_with("color.")
        || key.starts_with("advice.")
        || key.starts_with("column.")
        || key.starts_with("versionsort.")
        || matches!(
            key.as_str(),
            "user.name"
                | "user.email"
                | "core.autocrlf"
                | "core.eol"
                | "core.safecrlf"
                | "core.quotepath"
                | "core.abbrev"
                | "core.precomposeunicode"
                | "core.ignorecase"
                | "core.filemode"
                | "status.short"
                | "status.branch"
                | "status.showstash"
                | "status.submodulesummary"
                | "i18n.commitencoding"
                | "i18n.logoutputencoding"
                | "diff.mnemonicprefix"
                | "diff.noprefix"
                | "diff.renames"
                | "diff.algorithm"
                | "diff.colormoved"
                | "diff.submodule"
                | "log.date"
                | "log.decorate"
                | "log.abbrevcommit"
                | "log.follow"
                | "fetch.prune"
                | "fetch.prunetags"
                | "gc.auto"
                | "init.defaultbranch"
                | "commit.gpgsign"
                | "tag.gpgsign"
        );
    if !is_safe_cosmetic {
        effects.insert(Effect::DynamicExecOrConfigEscape);
    }
}

// ---------------------------------------------------------------------------
// 2. JUJUTSU (`jj`) GRAMMAR
// ---------------------------------------------------------------------------

fn analyze_jj(
    args: &[String],
    selector: &InheritedSelectorState,
    via_xargs: bool,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let mut effects = BTreeSet::new();
    let mut targets = Vec::new();
    let mut local_sel = selector.clone();
    local_sel.revalidate_selectors(ctx, &mut effects);
    if local_sel.cwd_offset.as_deref().is_some_and(|d| d != ".") {
        local_sel.repo_selector_redirected = true;
    }
    let mut ignore_immutable = false;

    let (opt_zone, post_dd) = split_at_dashdash(args);
    let mut cleaned_tokens: Vec<&str> = Vec::new();

    let mut i = 0usize;
    while i < opt_zone.len() {
        let tok = opt_zone[i].as_str();
        if tok == "--ignore-immutable" {
            ignore_immutable = true;
            i += 1;
            continue;
        }
        if tok == "--config-file" {
            effects.insert(Effect::DynamicExecOrConfigEscape);
            if let Some(cfg_f) = opt_zone.get(i + 1) {
                let t = analyze_path_target(cfg_f, local_sel.cwd_offset.as_deref(), ctx);
                attach_read_path_target_effects(&t, &mut effects);
                targets.push(t);
            }
            i += 2;
            continue;
        }
        if let Some(cfg_f) = tok.strip_prefix("--config-file=") {
            effects.insert(Effect::DynamicExecOrConfigEscape);
            let t = analyze_path_target(cfg_f, local_sel.cwd_offset.as_deref(), ctx);
            attach_read_path_target_effects(&t, &mut effects);
            targets.push(t);
            i += 1;
            continue;
        }
        if let Some((consumed, maybe_dir, maybe_cfg)) =
            match_global_flag(JJ_GLOBAL_FLAGS, opt_zone, i)
        {
            if let Some(dir) = maybe_dir {
                if apply_repo_dir_selector(
                    &mut local_sel.cwd_offset,
                    &mut local_sel.repo_selector_redirected,
                    &dir,
                    ctx,
                ) {
                    effects.insert(Effect::PathTraversalEscape);
                }
                local_sel.revalidate_selectors(ctx, &mut effects);
            }
            if let Some(cfg_kv) = maybe_cfg {
                let key = cfg_kv
                    .split_once('=')
                    .map(|(k, _)| k)
                    .unwrap_or(&cfg_kv)
                    .trim()
                    .to_ascii_lowercase();
                let is_safe_jj_cfg = !cfg_kv.contains('\n')
                    && !cfg_kv.contains('[')
                    && matches!(key.as_str(), "ui.color" | "user.name" | "user.email");
                if !is_safe_jj_cfg {
                    effects.insert(Effect::DynamicExecOrConfigEscape);
                }
            }
            i += consumed;
            continue;
        }
        cleaned_tokens.push(tok);
        i += 1;
    }

    // Extract non-flag subcommand words while skipping command-local flags carefully
    let non_flags: Vec<&str> = cleaned_tokens
        .iter()
        .copied()
        .filter(|t| !t.starts_with('-'))
        .collect();

    let first = non_flags.first().copied();
    let second = non_flags.get(1).copied();
    let third = non_flags.get(2).copied();

    if first == Some("git")
        && args
            .iter()
            .any(|a| a != "--" && is_git_remote_helper_transport(a))
    {
        effects.insert(Effect::DynamicExecOrConfigEscape);
    }

    if cleaned_tokens
        .iter()
        .any(|t| matches!(*t, "--version" | "-V" | "--help" | "-h"))
        && first.is_none()
    {
        return finalize_jj_readonly(Action::ReadOnlyInspect, effects, targets);
    }

    match (first, second) {
        (None, _) | (Some("status" | "st"), _) => {
            finalize_jj_readonly(Action::Status, effects, targets)
        }
        (Some("log"), _) => finalize_jj_readonly(Action::Log, effects, targets),
        (Some("diff"), _) => finalize_jj_readonly(Action::Diff, effects, targets),
        (Some("show" | "evolog" | "obslog" | "interdiff" | "version" | "help" | "root"), _)
        | (Some("bookmark" | "b"), Some("list" | "l"))
        | (Some("tag"), Some("list"))
        | (Some("workspace"), Some("list" | "root"))
        | (Some("file"), Some("list" | "show" | "annotate"))
        | (Some("config"), Some("list" | "get" | "path"))
        | (Some("op" | "operation"), Some("log" | "show" | "diff")) => {
            finalize_jj_readonly(Action::ReadOnlyInspect, effects, targets)
        }
        (Some("config"), _) => {
            effects.insert(Effect::DynamicExecOrConfigEscape);
            effects.insert(Effect::SensitivePathAccess);
            GrammarOutcome {
                program: Program::Jj,
                action: Action::ConfigMutate,
                effects,
                targets,
            }
        }
        (Some("bisect"), Some("run")) | (Some("run"), _) => {
            effects.insert(Effect::DynamicExecOrConfigEscape);
            GrammarOutcome {
                program: Program::Jj,
                action: Action::DynamicExecEscape,
                effects,
                targets,
            }
        }
        (Some("git"), Some("remote")) => {
            if third.is_none() || matches!(third, Some("list" | "l")) {
                finalize_jj_readonly(Action::ReadOnlyInspect, effects, targets)
            } else {
                effects.insert(Effect::DestructiveWorktreeOp);
                effects.insert(Effect::SensitivePathAccess);
                GrammarOutcome {
                    program: Program::Jj,
                    action: Action::ConfigMutate,
                    effects,
                    targets,
                }
            }
        }

        (Some("git"), Some("push")) => {
            effects.insert(Effect::PushRemote);
            let mut is_force_like = ignore_immutable;
            let mut any_protected = false;
            let mut saw_explicit_bookmark = false;

            let mut k = 0usize;
            while k < cleaned_tokens.len() {
                let tok = cleaned_tokens[k];
                match tok {
                    "-b" | "--bookmark" | "--branch" => {
                        if let Some(&bname) = cleaned_tokens.get(k + 1) {
                            saw_explicit_bookmark = true;
                            let prot = is_protected_branch_name(bname, ctx.protected_branches);
                            if prot {
                                any_protected = true;
                            }
                            targets.push(Target::Branch {
                                name: bname.to_string(),
                                protected: prot,
                            });
                        }
                        k += 2;
                        continue;
                    }
                    "-N" | "--named" => {
                        if let Some(&spec) = cleaned_tokens.get(k + 1) {
                            saw_explicit_bookmark = true;
                            let bname = spec.split_once('=').map(|(n, _)| n).unwrap_or(spec);
                            let prot = is_protected_branch_name(bname, ctx.protected_branches);
                            if prot {
                                any_protected = true;
                            }
                            targets.push(Target::Branch {
                                name: bname.to_string(),
                                protected: prot,
                            });
                        }
                        k += 2;
                        continue;
                    }
                    "-r" | "--revisions" | "--revision" | "-c" | "--change" => {
                        // Pushing by revset (`-r`) or dynamic change (`-c`) can resolve to any
                        // bookmark pointing at that revision -> conservatively mark protected blast radius.
                        any_protected = true;
                        k += 2;
                        continue;
                    }
                    "--remote" => {
                        if let Some(&rem) = cleaned_tokens.get(k + 1) {
                            targets.push(Target::Remote {
                                remote_or_repo: rem.to_string(),
                            });
                        }
                        k += 2;
                        continue;
                    }
                    "--all" | "--tracked" => {
                        any_protected = true;
                    }
                    "--deleted" | "--allow-backwards" => {
                        is_force_like = true;
                    }
                    _ => {
                        if let Some(bname) = tok
                            .strip_prefix("--bookmark=")
                            .or_else(|| tok.strip_prefix("--branch="))
                        {
                            saw_explicit_bookmark = true;
                            let prot = is_protected_branch_name(bname, ctx.protected_branches);
                            if prot {
                                any_protected = true;
                            }
                            targets.push(Target::Branch {
                                name: bname.to_string(),
                                protected: prot,
                            });
                        } else if let Some(spec) = tok.strip_prefix("--named=") {
                            saw_explicit_bookmark = true;
                            let bname = spec.split_once('=').map(|(n, _)| n).unwrap_or(spec);
                            let prot = is_protected_branch_name(bname, ctx.protected_branches);
                            if prot {
                                any_protected = true;
                            }
                            targets.push(Target::Branch {
                                name: bname.to_string(),
                                protected: prot,
                            });
                        } else if let Some(rem) = tok.strip_prefix("--remote=") {
                            targets.push(Target::Remote {
                                remote_or_repo: rem.to_string(),
                            });
                        } else if tok.starts_with("--revisions=")
                            || tok.starts_with("--revision=")
                            || tok.starts_with("--change=")
                        {
                            any_protected = true;
                        } else if let Some(short) = tok.strip_prefix('-')
                            && !short.starts_with('-')
                            && !short.is_empty()
                        {
                            let mut extra_advance = 0usize;
                            for (ci, ch) in short.char_indices() {
                                let rest_ch = &short[ci + ch.len_utf8()..];
                                match ch {
                                    'b' => {
                                        let b_opt = if !rest_ch.is_empty() {
                                            Some(rest_ch.strip_prefix('=').unwrap_or(rest_ch))
                                        } else if let Some(&b) = cleaned_tokens.get(k + 1) {
                                            extra_advance = 1;
                                            Some(b)
                                        } else {
                                            None
                                        };
                                        if let Some(bname) = b_opt {
                                            saw_explicit_bookmark = true;
                                            let prot = is_protected_branch_name(
                                                bname,
                                                ctx.protected_branches,
                                            );
                                            if prot {
                                                any_protected = true;
                                            }
                                            targets.push(Target::Branch {
                                                name: bname.to_string(),
                                                protected: prot,
                                            });
                                        }
                                        break;
                                    }
                                    'N' => {
                                        let s_opt = if !rest_ch.is_empty() {
                                            Some(rest_ch.strip_prefix('=').unwrap_or(rest_ch))
                                        } else if let Some(&s) = cleaned_tokens.get(k + 1) {
                                            extra_advance = 1;
                                            Some(s)
                                        } else {
                                            None
                                        };
                                        if let Some(spec) = s_opt {
                                            saw_explicit_bookmark = true;
                                            let bname = spec
                                                .split_once('=')
                                                .map(|(n, _)| n)
                                                .unwrap_or(spec);
                                            let prot = is_protected_branch_name(
                                                bname,
                                                ctx.protected_branches,
                                            );
                                            if prot {
                                                any_protected = true;
                                            }
                                            targets.push(Target::Branch {
                                                name: bname.to_string(),
                                                protected: prot,
                                            });
                                        }
                                        break;
                                    }
                                    'r' | 'c' => {
                                        any_protected = true;
                                        if rest_ch.is_empty() {
                                            extra_advance = 1;
                                        }
                                        break;
                                    }
                                    'd' => {
                                        is_force_like = true;
                                    }
                                    _ => {}
                                }
                            }
                            k += 1 + extra_advance;
                            continue;
                        }
                    }
                }
                k += 1;
            }

            if via_xargs || !saw_explicit_bookmark {
                any_protected = true;
            }
            if any_protected {
                effects.insert(Effect::PushMainBranch);
            }
            if is_force_like {
                effects.insert(Effect::ForcePushRemote);
                if any_protected {
                    effects.insert(Effect::ForcePushProtectedBranch);
                }
            }

            GrammarOutcome {
                program: Program::Jj,
                action: Action::GitPush,
                effects,
                targets,
            }
        }

        (Some("abandon"), _) => {
            effects.insert(Effect::DestructiveWorktreeOp);
            if ignore_immutable {
                effects.insert(Effect::ForcePushProtectedBranch);
            }
            for &rev in non_flags.iter().skip(1).chain(
                post_dd
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .iter(),
            ) {
                let prot = is_protected_branch_name(rev, ctx.protected_branches)
                    || rev.contains("trunk()");
                if prot {
                    effects.insert(Effect::ForcePushProtectedBranch);
                }
                targets.push(Target::Branch {
                    name: rev.to_string(),
                    protected: prot,
                });
            }
            GrammarOutcome {
                program: Program::Jj,
                action: Action::Abandon,
                effects,
                targets,
            }
        }

        (Some("op" | "operation"), Some("restore" | "revert" | "abandon")) | (Some("undo"), _) => {
            effects.insert(Effect::DestructiveWorktreeOp);
            effects.insert(Effect::SensitivePathAccess);
            GrammarOutcome {
                program: Program::Jj,
                action: Action::OpRestore,
                effects,
                targets,
            }
        }

        (Some("bookmark" | "b"), Some("delete" | "d" | "forget" | "f")) => {
            effects.insert(Effect::DestructiveWorktreeOp);
            for &bname in non_flags.iter().skip(2) {
                let prot = is_protected_branch_name(bname, ctx.protected_branches);
                if prot {
                    effects.insert(Effect::ForcePushProtectedBranch);
                }
                targets.push(Target::Branch {
                    name: bname.to_string(),
                    protected: prot,
                });
            }
            GrammarOutcome {
                program: Program::Jj,
                action: Action::BookmarkDelete,
                effects,
                targets,
            }
        }

        _ => {
            effects.insert(Effect::DestructiveWorktreeOp);
            GrammarOutcome {
                program: Program::Jj,
                action: Action::WorktreeMutate,
                effects,
                targets,
            }
        }
    }
}

fn finalize_jj_readonly(
    action: Action,
    mut effects: BTreeSet<Effect>,
    targets: Vec<Target>,
) -> GrammarOutcome {
    if effects.contains(&Effect::DynamicExecOrConfigEscape) {
        return GrammarOutcome {
            program: Program::Jj,
            action: Action::DynamicExecEscape,
            effects,
            targets,
        };
    }
    if effects.is_empty() {
        effects.insert(Effect::ReadOnly);
    }
    GrammarOutcome {
        program: Program::Jj,
        action,
        effects,
        targets,
    }
}

// ---------------------------------------------------------------------------
// 3. GITHUB CLI (`gh`) GRAMMAR
// ---------------------------------------------------------------------------

fn analyze_gh(
    args: &[String],
    cwd_offset: Option<&str>,
    via_xargs: bool,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let mut effects = BTreeSet::new();
    let mut targets = Vec::new();

    let (opt_zone, post_dd) = split_at_dashdash(args);
    let mut rem_tokens: Vec<&str> = Vec::new();

    let mut i = 0usize;
    while i < opt_zone.len() {
        if let Some((consumed, _, _)) = match_global_flag(GH_GLOBAL_FLAGS, opt_zone, i) {
            let tok = opt_zone[i].as_str();
            let repo_val = if let Some(v) = tok
                .strip_prefix("--repo=")
                .or_else(|| tok.strip_prefix("-R"))
            {
                if v.is_empty() {
                    opt_zone.get(i + 1).map(String::as_str)
                } else {
                    Some(v)
                }
            } else {
                opt_zone.get(i + 1).map(String::as_str)
            };
            if let Some(r) = repo_val {
                if is_git_remote_helper_transport(r) {
                    effects.insert(Effect::DynamicExecOrConfigEscape);
                }
                targets.push(Target::Remote {
                    remote_or_repo: r.to_string(),
                });
            }
            i += consumed;
            continue;
        }
        rem_tokens.push(opt_zone[i].as_str());
        i += 1;
    }

    let non_flags: Vec<&str> = rem_tokens
        .iter()
        .copied()
        .filter(|t| !t.starts_with('-'))
        .collect();
    let noun = non_flags.first().copied();
    let verb = non_flags.get(1).copied();

    match (noun, verb) {
        (None, _) => {
            effects.insert(Effect::ReadOnly);
            GrammarOutcome {
                program: Program::Gh,
                action: Action::ReadOnlyInspect,
                effects,
                targets,
            }
        }
        (Some("pr"), Some("list" | "ls")) => {
            effects.insert(Effect::ReadOnly);
            GrammarOutcome {
                program: Program::Gh,
                action: Action::PrList,
                effects,
                targets,
            }
        }
        (Some("issue"), Some("view")) => {
            effects.insert(Effect::ReadOnly);
            GrammarOutcome {
                program: Program::Gh,
                action: Action::IssueView,
                effects,
                targets,
            }
        }
        (Some("pr"), Some("view" | "status" | "checks" | "diff"))
        | (Some("issue"), Some("list" | "ls" | "status"))
        | (Some("repo"), Some("view" | "list"))
        | (Some("release"), Some("list" | "ls" | "view"))
        | (Some("run" | "workflow"), Some("list" | "ls" | "view"))
        | (Some("secret" | "variable"), Some("list" | "ls"))
        | (Some("ssh-key" | "gpg-key" | "deploy-key"), Some("list" | "ls"))
        | (Some("config"), Some("get" | "list" | "ls"))
        | (Some("alias"), Some("list" | "ls"))
        | (Some("extension" | "ext"), Some("list" | "ls" | "search"))
        | (Some("status" | "search" | "version" | "help"), _) => {
            effects.insert(Effect::ReadOnly);
            GrammarOutcome {
                program: Program::Gh,
                action: Action::ReadOnlyInspect,
                effects,
                targets,
            }
        }
        (Some("config" | "alias"), _) => {
            effects.insert(Effect::DynamicExecOrConfigEscape);
            effects.insert(Effect::SensitivePathAccess);
            GrammarOutcome {
                program: Program::Gh,
                action: Action::ConfigMutate,
                effects,
                targets,
            }
        }
        (Some("extension" | "ext"), _) => {
            effects.insert(Effect::DynamicExecOrConfigEscape);
            effects.insert(Effect::SensitivePathAccess);
            GrammarOutcome {
                program: Program::Gh,
                action: Action::DynamicExecEscape,
                effects,
                targets,
            }
        }
        (Some("ssh-key" | "gpg-key" | "deploy-key"), _) => {
            effects.insert(Effect::MutateSecrets);
            GrammarOutcome {
                program: Program::Gh,
                action: Action::SecretSet,
                effects,
                targets,
            }
        }
        (Some("variable"), Some("set" | "delete" | "remove")) => {
            effects.insert(Effect::MutateSecrets);
            GrammarOutcome {
                program: Program::Gh,
                action: if verb == Some("set") {
                    Action::SecretSet
                } else {
                    Action::SecretDelete
                },
                effects,
                targets,
            }
        }
        (Some("auth"), Some("status")) => {
            let leaks_token = rem_tokens
                .iter()
                .any(|t| *t == "--show-token" || short_bundle_has_any(t, &['t']));
            if leaks_token {
                effects.insert(Effect::MutateSecrets);
                GrammarOutcome {
                    program: Program::Gh,
                    action: Action::SecretSet,
                    effects,
                    targets,
                }
            } else {
                effects.insert(Effect::ReadOnly);
                GrammarOutcome {
                    program: Program::Gh,
                    action: Action::ReadOnlyInspect,
                    effects,
                    targets,
                }
            }
        }
        (Some("pr"), Some("merge")) => {
            effects.insert(Effect::MergePullRequest);
            effects.insert(Effect::PushMainBranch);
            let is_admin = rem_tokens.contains(&"--admin");
            if is_admin {
                effects.insert(Effect::ForcePushProtectedBranch);
            }
            GrammarOutcome {
                program: Program::Gh,
                action: Action::PrMerge,
                effects,
                targets,
            }
        }
        (Some("repo"), Some("edit")) => {
            let changes_visibility = rem_tokens
                .iter()
                .any(|t| *t == "--visibility" || t.starts_with("--visibility="));
            if changes_visibility {
                effects.insert(Effect::MutateRepositoryVisibility);
                GrammarOutcome {
                    program: Program::Gh,
                    action: Action::RepoEditVisibility,
                    effects,
                    targets,
                }
            } else {
                effects.insert(Effect::MutateRepositoryVisibility);
                GrammarOutcome {
                    program: Program::Gh,
                    action: Action::ApiMutate,
                    effects,
                    targets,
                }
            }
        }
        (Some("repo"), Some("delete" | "archive" | "rename")) => {
            effects.insert(Effect::MutateRepositoryVisibility);
            if verb == Some("delete") {
                effects.insert(Effect::RecursiveDelete);
            }
            GrammarOutcome {
                program: Program::Gh,
                action: Action::RepoEditVisibility,
                effects,
                targets,
            }
        }
        (Some("secret"), Some("set")) => {
            effects.insert(Effect::MutateSecrets);
            if let Some(sec_name) = non_flags
                .get(2)
                .copied()
                .or_else(|| post_dd.first().map(String::as_str))
            {
                targets.push(Target::Secret {
                    name: sec_name.to_string(),
                });
            } else if via_xargs {
                targets.push(Target::Secret {
                    name: "<xargs-stdin>".to_string(),
                });
            }
            GrammarOutcome {
                program: Program::Gh,
                action: Action::SecretSet,
                effects,
                targets,
            }
        }
        (Some("secret"), Some("delete" | "remove")) | (Some("auth"), Some("token")) => {
            effects.insert(Effect::MutateSecrets);
            if let Some(sec_name) = non_flags
                .get(2)
                .copied()
                .or_else(|| post_dd.first().map(String::as_str))
            {
                targets.push(Target::Secret {
                    name: sec_name.to_string(),
                });
            }
            GrammarOutcome {
                program: Program::Gh,
                action: if verb == Some("token") {
                    Action::SecretSet
                } else {
                    Action::SecretDelete
                },
                effects,
                targets,
            }
        }
        (Some("repo"), Some("clone" | "sync" | "fork" | "create")) => {
            effects.insert(Effect::DestructiveWorktreeOp);
            if matches!(verb, Some("fork" | "create")) {
                effects.insert(Effect::MutateRepositoryVisibility);
            }
            if rem_tokens.iter().any(|t| is_git_remote_helper_transport(t)) {
                effects.insert(Effect::DynamicExecOrConfigEscape);
            }
            if verb == Some("clone")
                && let Some(dest_dir) = non_flags.get(3)
            {
                let t = analyze_path_target(dest_dir, cwd_offset, ctx);
                attach_path_target_effects(&t, &mut effects);
                targets.push(t);
            }
            for git_arg in post_dd {
                if is_git_remote_helper_transport(git_arg)
                    || git_arg.starts_with("--upload-pack")
                    || git_arg.starts_with("--config")
                    || git_arg.starts_with("--template")
                    || git_arg == "-u"
                    || git_arg == "-c"
                    || (git_arg.starts_with("-u") && !git_arg.starts_with("--"))
                    || (git_arg.starts_with("-c") && !git_arg.starts_with("--"))
                {
                    effects.insert(Effect::DynamicExecOrConfigEscape);
                }
            }
            GrammarOutcome {
                program: Program::Gh,
                action: if effects.contains(&Effect::DynamicExecOrConfigEscape) {
                    Action::DynamicExecEscape
                } else {
                    Action::WorktreeMutate
                },
                effects,
                targets,
            }
        }
        (Some("auth"), _) => {
            effects.insert(Effect::MutateSecrets);
            GrammarOutcome {
                program: Program::Gh,
                action: Action::SecretSet,
                effects,
                targets,
            }
        }
        (Some("release"), Some("delete" | "delete-asset")) => {
            effects.insert(Effect::DeleteRelease);
            effects.insert(Effect::ForcePushRemote);
            GrammarOutcome {
                program: Program::Gh,
                action: Action::ReleaseDelete,
                effects,
                targets,
            }
        }
        (Some("api"), _) => analyze_gh_api(&rem_tokens, post_dd, via_xargs, effects, targets),
        _ => {
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            GrammarOutcome {
                program: Program::Gh,
                action: Action::UnknownAction,
                effects,
                targets,
            }
        }
    }
}

fn analyze_gh_api(
    tokens: &[&str],
    post_dd: &[String],
    via_xargs: bool,
    mut effects: BTreeSet<Effect>,
    mut targets: Vec<Target>,
) -> GrammarOutcome {
    if via_xargs {
        effects.insert(Effect::DynamicExecOrConfigEscape);
        effects.insert(Effect::MutateSecrets);
    }
    let mut explicit_method: Option<String> = None;
    let mut has_body_field = false;
    let mut is_graphql = false;
    let mut endpoint: Option<&str> = None;

    let mut i = 1usize; // skip "api"
    while i < tokens.len() {
        let tok = tokens[i];
        if tok == "--method" {
            if let Some(&m) = tokens.get(i + 1) {
                explicit_method = Some(m.to_ascii_uppercase());
            }
            i += 2;
            continue;
        }
        if let Some(m) = tok.strip_prefix("--method=")
            && !m.is_empty()
        {
            explicit_method = Some(m.to_ascii_uppercase());
            i += 1;
            continue;
        }
        if tok == "graphql" && endpoint.is_none() {
            is_graphql = true;
            endpoint = Some(tok);
            i += 1;
            continue;
        }
        if matches!(tok, "--raw-field" | "--field" | "--input") {
            has_body_field = true;
            i += 2;
            continue;
        }
        if tok.starts_with("--raw-field=")
            || tok.starts_with("--field=")
            || tok.starts_with("--input=")
        {
            has_body_field = true;
            i += 1;
            continue;
        }
        if matches!(
            tok,
            "--header" | "--jq" | "--template" | "--cache" | "--hostname" | "--preview"
        ) {
            i += 2;
            continue;
        }
        if tok.starts_with("--") {
            i += 1;
            continue;
        }
        if let Some(short) = tok.strip_prefix('-')
            && !short.is_empty()
        {
            let mut extra_advance = 0usize;
            for (ci, ch) in short.char_indices() {
                let rest = &short[ci + ch.len_utf8()..];
                match ch {
                    'X' => {
                        if !rest.is_empty() {
                            let m = rest.strip_prefix('=').unwrap_or(rest);
                            explicit_method = Some(m.to_ascii_uppercase());
                        } else if let Some(&m) = tokens.get(i + 1) {
                            explicit_method = Some(m.to_ascii_uppercase());
                            extra_advance = 1;
                        }
                        break;
                    }
                    'f' | 'F' => {
                        has_body_field = true;
                        if rest.is_empty() {
                            extra_advance = 1;
                        }
                        break;
                    }
                    'H' | 'q' | 't' | 'p' => {
                        if rest.is_empty() {
                            extra_advance = 1;
                        }
                        break;
                    }
                    _ => {}
                }
            }
            i += 1 + extra_advance;
            continue;
        }
        if !tok.starts_with('-') && endpoint.is_none() {
            endpoint = Some(tok);
        }
        i += 1;
    }

    if endpoint.is_none() {
        endpoint = post_dd.first().map(String::as_str);
        if endpoint == Some("graphql") {
            is_graphql = true;
        }
    }

    let method = explicit_method.unwrap_or_else(|| {
        if has_body_field {
            "POST".to_string()
        } else {
            "GET".to_string()
        }
    });

    if let Some(ep) = endpoint {
        targets.push(Target::Remote {
            remote_or_repo: ep.to_string(),
        });
    }

    if matches!(method.as_str(), "GET" | "HEAD") && !via_xargs {
        if effects.is_empty() {
            effects.insert(Effect::ReadOnly);
        }
        return GrammarOutcome {
            program: Program::Gh,
            action: Action::ReadOnlyInspect,
            effects,
            targets,
        };
    }

    let ep_lower = endpoint.unwrap_or("").to_ascii_lowercase();
    let ep_trimmed = ep_lower.trim_matches('/');
    if ep_trimmed == "graphql" || ep_trimmed.ends_with("/graphql") {
        is_graphql = true;
    }
    if is_graphql || endpoint.is_none() {
        // GraphQL POST or missing endpoint can mutate arbitrary secrets, branches, or repo settings
        effects.insert(Effect::MutateSecrets);
        effects.insert(Effect::PushMainBranch);
        effects.insert(Effect::MutateRepositoryVisibility);
    }
    if ep_lower.contains("/secrets") || ep_lower.contains("/keys") {
        effects.insert(Effect::MutateSecrets);
    }
    if ep_lower.contains("/merges")
        || ep_lower.ends_with("/merge")
        || ep_lower.contains("/git/refs")
        || ep_lower.contains("/git/ref/")
    {
        effects.insert(Effect::PushMainBranch);
        if ep_lower.contains("/pulls/") && ep_lower.ends_with("/merge") {
            effects.insert(Effect::MergePullRequest);
        }
        if method == "DELETE" || method == "PATCH" {
            effects.insert(Effect::ForcePushProtectedBranch);
        }
    }
    if ep_lower.contains("/releases") && method == "DELETE" {
        effects.insert(Effect::DeleteRelease);
    }
    if effects.is_empty() {
        effects.insert(Effect::MutateRepositoryVisibility);
    }

    GrammarOutcome {
        program: Program::Gh,
        action: Action::ApiMutate,
        effects,
        targets,
    }
}

// ---------------------------------------------------------------------------
// 4. FILESYSTEM DELETION (`rm`) GRAMMAR
// ---------------------------------------------------------------------------

fn analyze_rm(
    args: &[String],
    cwd_offset: Option<&str>,
    via_xargs: bool,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let mut effects = BTreeSet::new();
    let mut targets = Vec::new();

    // Note: GNU `rm` permutes options across operands UP TO `--` (`rm ./dir -rf` is recursive+force!),
    // whereas everything AFTER `--` (`rm -- -rf`) is strictly a literal filename operand!
    let (opt_zone, post_dd) = split_at_dashdash(args);

    let mut is_recursive = false;
    let mut is_force = false;
    let mut no_preserve_root = false;
    let mut raw_operands: Vec<&str> = Vec::new();

    for tok in opt_zone {
        let s = tok.as_str();
        match s {
            "--recursive" => is_recursive = true,
            "--force" => is_force = true,
            "--no-preserve-root" => no_preserve_root = true,
            _ if s.starts_with("--") => {}
            _ if s.starts_with('-') && s.len() > 1 => {
                for ch in s[1..].chars() {
                    match ch {
                        'r' | 'R' => is_recursive = true,
                        'f' => is_force = true,
                        _ => {}
                    }
                }
            }
            _ => raw_operands.push(s),
        }
    }

    for lit in post_dd {
        raw_operands.push(lit.as_str());
    }

    if no_preserve_root {
        effects.insert(Effect::RootOrWildcardDeleteHazard);
    }

    effects.insert(Effect::DestructiveWorktreeOp);
    if is_recursive {
        effects.insert(Effect::RecursiveDelete);
    }
    if is_force {
        effects.insert(Effect::ForceDelete);
    }

    for op in &raw_operands {
        let t = analyze_path_target(op, cwd_offset, ctx);
        attach_path_target_effects(&t, &mut effects);
        targets.push(t);
    }

    if via_xargs {
        // `xargs rm [./dummy]` appends arbitrary uninspected stdin paths even when dummy operands precede them
        effects.insert(Effect::SensitivePathAccess);
        effects.insert(Effect::DynamicExecOrConfigEscape);
    }

    let action = if is_recursive {
        Action::RecursiveDelete
    } else if is_force {
        Action::ForceDelete
    } else {
        Action::Delete
    };

    GrammarOutcome {
        program: Program::Rm,
        action,
        effects,
        targets,
    }
}

fn analyze_find(
    args: &[String],
    cwd_offset: Option<&str>,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let mut effects = BTreeSet::new();
    let mut targets = Vec::new();
    let mut start_paths: Vec<&str> = Vec::new();
    let mut write_paths: Vec<&str> = Vec::new();
    let mut has_delete = false;
    let mut has_exec = false;

    // 1. Walk pre-expression options (`-H`, `-L`, `-P`, `-E`, `-X`, `-d`, `-s`, `-x`, `-O*`, `-D <opt>`, BSD `-f <path>` / `-Lf <path>` / `-f<path>`)
    let mut i = 0usize;
    while i < args.len() {
        let s = args[i].as_str();
        if s == "--" {
            i += 1;
            break;
        }
        if s == "-D" {
            i += if i + 1 < args.len() { 2 } else { 1 };
            continue;
        }
        if s.starts_with("-O") && s.len() > 2 {
            i += 1;
            continue;
        }
        if let Some(short) = s.strip_prefix('-')
            && !short.starts_with('-')
            && !short.is_empty()
        {
            let mut valid_pre_opts = true;
            let mut extra_advance = 0usize;
            for (ci, ch) in short.char_indices() {
                let rest = &short[ci + ch.len_utf8()..];
                if matches!(ch, 'H' | 'L' | 'P' | 'E' | 'X' | 'd' | 's' | 'x') {
                    continue;
                }
                if ch == 'f' {
                    if !rest.is_empty() {
                        start_paths.push(rest);
                    } else if let Some(p) = args.get(i + 1) {
                        start_paths.push(p.as_str());
                        extra_advance = 1;
                    }
                    break;
                }
                valid_pre_opts = false;
                break;
            }
            if valid_pre_opts {
                i += 1 + extra_advance;
                continue;
            }
        }
        break;
    }

    // 2. Collect ALL starting path operands prior to the first expression predicate (`-*`, `!`, `(`, `,`)
    while i < args.len() {
        let s = args[i].as_str();
        if s.starts_with('-') || matches!(s, "!" | "(" | ")" | ",") {
            break;
        }
        start_paths.push(s);
        i += 1;
    }
    if start_paths.is_empty() {
        start_paths.push(".");
    }

    // 3. Scan expression predicates for `-delete`, `-exec*`/`-ok*`, and file-writing predicates (`-fprint*`, `-fls`, `-fprintf`)
    while i < args.len() {
        let s = args[i].as_str();
        match s {
            "-delete" => has_delete = true,
            "-exec" | "-execdir" | "-ok" | "-okdir" => has_exec = true,
            "-fprint" | "-fprint0" | "-fls" => {
                if let Some(out_f) = args.get(i + 1) {
                    write_paths.push(out_f.as_str());
                    i += 2;
                    continue;
                }
                effects.insert(Effect::DestructiveWorktreeOp);
                effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            }
            "-fprintf" => {
                if let Some(out_f) = args.get(i + 1) {
                    write_paths.push(out_f.as_str());
                    i += if i + 2 < args.len() { 3 } else { 2 };
                    continue;
                }
                effects.insert(Effect::DestructiveWorktreeOp);
                effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            }
            _ => {}
        }
        i += 1;
    }

    for sp in &start_paths {
        let t = analyze_path_target(sp, cwd_offset, ctx);
        if has_delete {
            attach_path_target_effects(&t, &mut effects);
        } else {
            attach_read_path_target_effects(&t, &mut effects);
        }
        targets.push(t);
    }

    let has_file_write = !write_paths.is_empty();
    for wp in &write_paths {
        effects.insert(Effect::DestructiveWorktreeOp);
        let t = analyze_path_target(wp, cwd_offset, ctx);
        attach_path_target_effects(&t, &mut effects);
        targets.push(t);
    }

    if has_exec {
        effects.insert(Effect::DynamicExecOrConfigEscape);
    }
    if has_delete {
        effects.insert(Effect::RecursiveDelete);
        effects.insert(Effect::DestructiveWorktreeOp);
        return GrammarOutcome {
            program: Program::Rm,
            action: Action::RecursiveDelete,
            effects,
            targets,
        };
    }
    if has_exec {
        return GrammarOutcome {
            program: Program::ShellWrapper,
            action: Action::DynamicExecEscape,
            effects,
            targets,
        };
    }
    if has_file_write {
        return GrammarOutcome {
            program: Program::Unknown("find".to_string()),
            action: Action::WorktreeMutate,
            effects,
            targets,
        };
    }
    if effects.is_empty() {
        effects.insert(Effect::ReadOnly);
    }
    GrammarOutcome {
        program: Program::Unknown("find".to_string()),
        action: Action::ReadOnlyInspect,
        effects,
        targets,
    }
}

// ---------------------------------------------------------------------------
// 5. DATABASE & EDGE SCHEMA MIGRATION CLIs (`prisma`, `drizzle-kit`, `sqlx`, `wrangler`)
// ---------------------------------------------------------------------------

fn analyze_prisma(
    args: &[String],
    cwd_offset: Option<&str>,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let mut effects = BTreeSet::new();
    let mut targets = Vec::new();

    let mut non_flags: Vec<&str> = Vec::new();
    let mut has_force_reset = false;
    let mut has_check_only = false;
    let mut output_paths: Vec<String> = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--schema" {
            if let Some(p) = args.get(i + 1) {
                let t = analyze_path_target(p, cwd_offset, ctx);
                if let Target::Path {
                    escapes_workspace: true,
                    ..
                } = &t
                {
                    effects.insert(Effect::PathTraversalEscape);
                    targets.push(t);
                }
            }
            i += 2;
            continue;
        }
        if let Some(p) = tok.strip_prefix("--schema=") {
            let t = analyze_path_target(p, cwd_offset, ctx);
            if let Target::Path {
                escapes_workspace: true,
                ..
            } = &t
            {
                effects.insert(Effect::PathTraversalEscape);
                targets.push(t);
            }
            i += 1;
            continue;
        }
        if tok == "--file" {
            if let Some(p) = args.get(i + 1) {
                let t = analyze_path_target(p, cwd_offset, ctx);
                attach_read_path_target_effects(&t, &mut effects);
                targets.push(t);
            }
            i += 2;
            continue;
        }
        if let Some(p) = tok.strip_prefix("--file=") {
            let t = analyze_path_target(p, cwd_offset, ctx);
            attach_read_path_target_effects(&t, &mut effects);
            targets.push(t);
            i += 1;
            continue;
        }
        if matches!(tok, "--url" | "-n" | "--name") {
            i += 2;
            continue;
        }
        if matches!(tok, "-o" | "--output") {
            if let Some(p) = args.get(i + 1) {
                output_paths.push(p.clone());
            }
            i += 2;
            continue;
        }
        if let Some(p) = tok.strip_prefix("--output=") {
            output_paths.push(p.to_string());
            i += 1;
            continue;
        }
        if matches!(tok, "--force-reset" | "--accept-data-loss") {
            has_force_reset = true;
        }
        if tok == "--check" {
            has_check_only = true;
        }
        if !tok.starts_with('-') {
            non_flags.push(tok);
        }
        i += 1;
    }

    let first = non_flags.first().copied();
    let second = non_flags.get(1).copied();

    match (first, second) {
        (None, _)
        | (Some("validate" | "version" | "help"), _)
        | (Some("migrate"), Some("status" | "diff")) => {
            if !output_paths.is_empty() {
                effects.insert(Effect::DestructiveWorktreeOp);
                for out_p in &output_paths {
                    let t = analyze_path_target(out_p, cwd_offset, ctx);
                    attach_path_target_effects(&t, &mut effects);
                    targets.push(t);
                }
                return GrammarOutcome {
                    program: Program::Prisma,
                    action: Action::WorktreeMutate,
                    effects,
                    targets,
                };
            }
            if effects.is_empty() {
                effects.insert(Effect::ReadOnly);
            }
            GrammarOutcome {
                program: Program::Prisma,
                action: Action::ReadOnlyInspect,
                effects,
                targets,
            }
        }
        (Some("format"), _) if has_check_only => {
            if effects.is_empty() {
                effects.insert(Effect::ReadOnly);
            }
            GrammarOutcome {
                program: Program::Prisma,
                action: Action::ReadOnlyInspect,
                effects,
                targets,
            }
        }
        (Some("migrate"), Some("deploy" | "dev" | "resolve")) => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::SensitivePathAccess);
            targets.push(Target::Database {
                engine: "prisma".to_string(),
                target: format!("migrate {}", second.unwrap_or("deploy")),
            });
            GrammarOutcome {
                program: Program::Prisma,
                action: Action::MigrateDeploy,
                effects,
                targets,
            }
        }
        (Some("migrate"), Some("reset")) => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::DestructiveSchemaReset);
            effects.insert(Effect::SensitivePathAccess);
            targets.push(Target::Database {
                engine: "prisma".to_string(),
                target: "migrate reset".to_string(),
            });
            GrammarOutcome {
                program: Program::Prisma,
                action: Action::MigrateReset,
                effects,
                targets,
            }
        }
        (Some("db"), Some("push")) => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::SensitivePathAccess);
            if has_force_reset {
                effects.insert(Effect::DestructiveSchemaReset);
            }
            targets.push(Target::Database {
                engine: "prisma".to_string(),
                target: "db push".to_string(),
            });
            GrammarOutcome {
                program: Program::Prisma,
                action: if has_force_reset {
                    Action::MigrateReset
                } else {
                    Action::SchemaPush
                },
                effects,
                targets,
            }
        }
        (Some("db"), Some("execute")) => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::DestructiveSchemaReset);
            effects.insert(Effect::SensitivePathAccess);
            GrammarOutcome {
                program: Program::Prisma,
                action: Action::MigrateReset,
                effects,
                targets,
            }
        }
        _ => {
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            GrammarOutcome {
                program: Program::Prisma,
                action: Action::UnknownAction,
                effects,
                targets,
            }
        }
    }
}

fn analyze_drizzle_kit(
    args: &[String],
    cwd_offset: Option<&str>,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let mut effects = BTreeSet::new();
    let mut targets = Vec::new();
    let mut non_flags: Vec<&str> = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].as_str();
        if matches!(tok, "--config" | "--out" | "--schema") {
            if let Some(p) = args.get(i + 1) {
                let t = analyze_path_target(p, cwd_offset, ctx);
                if let Target::Path {
                    escapes_workspace: true,
                    ..
                } = &t
                {
                    effects.insert(Effect::PathTraversalEscape);
                    targets.push(t);
                }
            }
            i += 2;
            continue;
        }
        if let Some(p) = tok
            .strip_prefix("--config=")
            .or_else(|| tok.strip_prefix("--out="))
            .or_else(|| tok.strip_prefix("--schema="))
        {
            let t = analyze_path_target(p, cwd_offset, ctx);
            if let Target::Path {
                escapes_workspace: true,
                ..
            } = &t
            {
                effects.insert(Effect::PathTraversalEscape);
                targets.push(t);
            }
            i += 1;
            continue;
        }
        if tok == "--dialect" {
            i += 2;
            continue;
        }
        if !tok.starts_with('-') {
            non_flags.push(tok);
        }
        i += 1;
    }

    let sub = non_flags.first().copied().unwrap_or("");
    let base_sub = sub.split(':').next().unwrap_or(sub);

    match base_sub {
        "" | "check" | "export" | "version" | "help" => {
            if effects.is_empty() {
                effects.insert(Effect::ReadOnly);
            }
            GrammarOutcome {
                program: Program::DrizzleKit,
                action: Action::ReadOnlyInspect,
                effects,
                targets,
            }
        }
        "introspect" | "pull" => {
            effects.insert(Effect::DestructiveWorktreeOp);
            GrammarOutcome {
                program: Program::DrizzleKit,
                action: Action::WorktreeMutate,
                effects,
                targets,
            }
        }
        "push" => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::SensitivePathAccess);
            targets.push(Target::Database {
                engine: "drizzle-kit".to_string(),
                target: sub.to_string(),
            });
            GrammarOutcome {
                program: Program::DrizzleKit,
                action: Action::SchemaPush,
                effects,
                targets,
            }
        }
        "migrate" | "up" => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::SensitivePathAccess);
            targets.push(Target::Database {
                engine: "drizzle-kit".to_string(),
                target: sub.to_string(),
            });
            GrammarOutcome {
                program: Program::DrizzleKit,
                action: Action::MigrateDeploy,
                effects,
                targets,
            }
        }
        "drop" => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::DestructiveSchemaReset);
            effects.insert(Effect::SensitivePathAccess);
            targets.push(Target::Database {
                engine: "drizzle-kit".to_string(),
                target: "drop".to_string(),
            });
            GrammarOutcome {
                program: Program::DrizzleKit,
                action: Action::SchemaDrop,
                effects,
                targets,
            }
        }
        _ => {
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            GrammarOutcome {
                program: Program::DrizzleKit,
                action: Action::UnknownAction,
                effects,
                targets,
            }
        }
    }
}

fn analyze_sqlx(
    args: &[String],
    cwd_offset: Option<&str>,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let mut effects = BTreeSet::new();
    let mut targets = Vec::new();
    let mut non_flags: Vec<&str> = Vec::new();
    let mut has_check = false;

    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--source" {
            if let Some(p) = args.get(i + 1) {
                let t = analyze_path_target(p, cwd_offset, ctx);
                if let Target::Path {
                    escapes_workspace: true,
                    ..
                } = &t
                {
                    effects.insert(Effect::PathTraversalEscape);
                    targets.push(t);
                }
            }
            i += 2;
            continue;
        }
        if let Some(p) = tok.strip_prefix("--source=") {
            let t = analyze_path_target(p, cwd_offset, ctx);
            if let Target::Path {
                escapes_workspace: true,
                ..
            } = &t
            {
                effects.insert(Effect::PathTraversalEscape);
                targets.push(t);
            }
            i += 1;
            continue;
        }
        if matches!(tok, "-D" | "--database-url" | "--connect-options") {
            i += 2;
            continue;
        }
        if tok == "--check" {
            has_check = true;
        }
        if !tok.starts_with('-') {
            non_flags.push(tok);
        }
        i += 1;
    }

    let first = non_flags.first().copied();
    let second = non_flags.get(1).copied();

    match (first, second) {
        (None, _) | (Some("version" | "help"), _) => {
            if effects.is_empty() {
                effects.insert(Effect::ReadOnly);
            }
            GrammarOutcome {
                program: Program::Sqlx,
                action: Action::ReadOnlyInspect,
                effects,
                targets,
            }
        }
        (Some("migrate"), Some("info")) => {
            if effects.is_empty() {
                effects.insert(Effect::ReadOnly);
            }
            GrammarOutcome {
                program: Program::Sqlx,
                action: Action::MigrateInfo,
                effects,
                targets,
            }
        }
        (Some("prepare"), _) if has_check => {
            if effects.is_empty() {
                effects.insert(Effect::ReadOnly);
            }
            GrammarOutcome {
                program: Program::Sqlx,
                action: Action::ReadOnlyInspect,
                effects,
                targets,
            }
        }
        (Some("migrate"), Some("run")) => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::SensitivePathAccess);
            targets.push(Target::Database {
                engine: "sqlx".to_string(),
                target: "migrate run".to_string(),
            });
            GrammarOutcome {
                program: Program::Sqlx,
                action: Action::MigrateRun,
                effects,
                targets,
            }
        }
        (Some("migrate"), Some("revert")) => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::DestructiveSchemaReset);
            effects.insert(Effect::SensitivePathAccess);
            targets.push(Target::Database {
                engine: "sqlx".to_string(),
                target: "migrate revert".to_string(),
            });
            GrammarOutcome {
                program: Program::Sqlx,
                action: Action::MigrateRevert,
                effects,
                targets,
            }
        }
        (Some("database" | "db"), Some("drop" | "reset")) => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::DestructiveSchemaReset);
            effects.insert(Effect::SensitivePathAccess);
            targets.push(Target::Database {
                engine: "sqlx".to_string(),
                target: format!("database {}", second.unwrap_or("drop")),
            });
            GrammarOutcome {
                program: Program::Sqlx,
                action: Action::SchemaDrop,
                effects,
                targets,
            }
        }
        (Some("database" | "db"), Some("create" | "setup")) => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::SensitivePathAccess);
            GrammarOutcome {
                program: Program::Sqlx,
                action: Action::MigrateDeploy,
                effects,
                targets,
            }
        }
        _ => {
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            GrammarOutcome {
                program: Program::Sqlx,
                action: Action::UnknownAction,
                effects,
                targets,
            }
        }
    }
}

fn analyze_wrangler(
    args: &[String],
    initial_cwd: Option<&str>,
    initial_repo_redirected: bool,
    ctx: &ParseContext<'_>,
) -> GrammarOutcome {
    let mut effects = BTreeSet::new();
    let mut targets = Vec::new();
    let mut cwd_offset = initial_cwd.map(ToString::to_string);
    let mut repo_redirected = initial_repo_redirected;
    let mut non_flags: Vec<&str> = Vec::new();
    let mut sql_command: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "-c" || tok == "--config" {
            if let Some(cfg_p) = args.get(i + 1) {
                let t = analyze_path_target(cfg_p, cwd_offset.as_deref(), ctx);
                if let Target::Path {
                    escapes_workspace: true,
                    ..
                } = &t
                {
                    effects.insert(Effect::PathTraversalEscape);
                    targets.push(t);
                }
            }
            i += 2;
            continue;
        }
        if let Some(cfg_p) = tok.strip_prefix("--config=").or_else(|| {
            if !tok.starts_with("--") {
                tok.strip_prefix("-c").filter(|r| !r.is_empty())
            } else {
                None
            }
        }) {
            let t = analyze_path_target(cfg_p, cwd_offset.as_deref(), ctx);
            if let Target::Path {
                escapes_workspace: true,
                ..
            } = &t
            {
                effects.insert(Effect::PathTraversalEscape);
                targets.push(t);
            }
            i += 1;
            continue;
        }
        if let Some((consumed, maybe_dir, _)) = match_global_flag(WRANGLER_GLOBAL_FLAGS, args, i) {
            if let Some(dir) = maybe_dir
                && apply_repo_dir_selector(&mut cwd_offset, &mut repo_redirected, &dir, ctx)
            {
                effects.insert(Effect::PathTraversalEscape);
            }
            i += consumed;
            continue;
        }
        if tok == "--command" {
            if let Some(sql) = args.get(i + 1) {
                sql_command = Some(sql.clone());
            }
            i += 2;
            continue;
        }
        if let Some(sql) = tok.strip_prefix("--command=") {
            sql_command = Some(sql.to_string());
            i += 1;
            continue;
        }
        if tok == "--file" {
            if let Some(f) = args.get(i + 1) {
                let t = analyze_path_target(f, cwd_offset.as_deref(), ctx);
                attach_read_path_target_effects(&t, &mut effects);
                targets.push(t);
            }
            i += 2;
            continue;
        }
        if let Some(f) = tok.strip_prefix("--file=") {
            let t = analyze_path_target(f, cwd_offset.as_deref(), ctx);
            attach_read_path_target_effects(&t, &mut effects);
            targets.push(t);
            i += 1;
            continue;
        }
        if !tok.starts_with('-') {
            non_flags.push(tok);
        }
        i += 1;
    }

    let first = non_flags.first().copied();
    let second = non_flags.get(1).copied();
    let third = non_flags.get(2).copied();

    match (first, second, third) {
        (None, _, _)
        | (Some("whoami" | "version" | "help"), _, _)
        | (Some("d1"), Some("list" | "info"), _)
        | (Some("d1"), Some("migrations"), Some("list"))
        | (Some("secret"), Some("list"), _) => {
            if effects.is_empty() {
                effects.insert(Effect::ReadOnly);
            }
            GrammarOutcome {
                program: Program::Wrangler,
                action: Action::ReadOnlyInspect,
                effects,
                targets,
            }
        }
        (Some("d1"), Some("migrations"), Some("apply")) => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::SensitivePathAccess);
            let db_name = non_flags.get(3).copied().unwrap_or("d1");
            targets.push(Target::Database {
                engine: "wrangler_d1".to_string(),
                target: db_name.to_string(),
            });
            GrammarOutcome {
                program: Program::Wrangler,
                action: Action::D1MigrationsApply,
                effects,
                targets,
            }
        }
        (Some("d1"), Some("execute"), _) => {
            effects.insert(Effect::ApplySchemaMigration);
            effects.insert(Effect::SensitivePathAccess);
            if let Some(sql) = &sql_command
                && is_destructive_sql(sql)
            {
                effects.insert(Effect::DestructiveSchemaReset);
            }
            let db_name = third.unwrap_or("d1");
            targets.push(Target::Database {
                engine: "wrangler_d1".to_string(),
                target: db_name.to_string(),
            });
            GrammarOutcome {
                program: Program::Wrangler,
                action: Action::D1Execute,
                effects,
                targets,
            }
        }
        (Some("secret"), Some("put" | "delete" | "bulk"), _) => {
            effects.insert(Effect::MutateSecrets);
            if let Some(sec_name) = third {
                targets.push(Target::Secret {
                    name: sec_name.to_string(),
                });
            }
            GrammarOutcome {
                program: Program::Wrangler,
                action: if second == Some("delete") {
                    Action::SecretDelete
                } else {
                    Action::SecretSet
                },
                effects,
                targets,
            }
        }
        _ => {
            effects.insert(Effect::UnrecognizedOrAmbiguousCommand);
            GrammarOutcome {
                program: Program::Wrangler,
                action: Action::UnknownAction,
                effects,
                targets,
            }
        }
    }
}

fn is_destructive_sql(sql: &str) -> bool {
    let upper = sql.to_ascii_uppercase();
    upper.contains("DROP TABLE")
        || upper.contains("DROP DATABASE")
        || upper.contains("DROP SCHEMA")
        || upper.contains("DROP INDEX")
        || upper.contains("TRUNCATE ")
        || upper.contains("DELETE FROM ")
        || (upper.contains("ALTER TABLE") && upper.contains(" DROP "))
}

// ---------------------------------------------------------------------------
// SHARED CURSOR HELPERS
// ---------------------------------------------------------------------------

fn split_at_dashdash(args: &[String]) -> (&[String], &[String]) {
    if let Some(pos) = args.iter().position(|t| t == "--") {
        (&args[..pos], &args[pos + 1..])
    } else {
        (args, &[])
    }
}

fn short_bundle_has_any(tok: &str, needle: &[char]) -> bool {
    let Some(short) = tok.strip_prefix('-') else {
        return false;
    };
    if short.is_empty() || short.starts_with('-') {
        return false;
    }
    short.chars().any(|c| needle.contains(&c))
}

pub(crate) fn attach_path_target_effects(t: &Target, effects: &mut BTreeSet<Effect>) {
    if let Target::Path {
        escapes_workspace,
        control_plane,
        sensitive,
        root_or_wildcard_hazard,
        ..
    } = t
    {
        if *escapes_workspace {
            effects.insert(Effect::PathTraversalEscape);
        }
        if *control_plane || *sensitive {
            effects.insert(Effect::SensitivePathAccess);
        }
        if *root_or_wildcard_hazard {
            effects.insert(Effect::RootOrWildcardDeleteHazard);
        }
    }
}

pub(crate) fn attach_read_path_target_effects(t: &Target, effects: &mut BTreeSet<Effect>) {
    if let Target::Path {
        escapes_workspace,
        control_plane,
        sensitive,
        ..
    } = t
    {
        if *escapes_workspace {
            effects.insert(Effect::PathTraversalEscape);
        }
        if *control_plane || *sensitive {
            effects.insert(Effect::SensitivePathAccess);
        }
    }
}

fn match_global_flag(
    table: &[GlobalFlagSpec],
    args: &[String],
    idx: usize,
) -> Option<(usize, Option<String>, Option<String>)> {
    let tok = args[idx].as_str();
    if !tok.starts_with('-') || tok == "-" || tok == "--" {
        return None;
    }

    // 1. Long `--flag` or `--flag=val`
    if tok.starts_with("--") {
        for spec in table {
            let Some(long) = spec.long else {
                continue;
            };
            if tok == long {
                return match spec.arity {
                    FlagArity::None | FlagArity::OptionalAttachedEqualsValue => {
                        Some((1, None, None))
                    }
                    FlagArity::SeparateOrAttachedValue => {
                        let val = args.get(idx + 1).cloned().unwrap_or_default();
                        let consumed = if idx + 1 < args.len() { 2 } else { 1 };
                        let dir = if spec.is_repo_dir { Some(val) } else { None };
                        Some((consumed, dir, None))
                    }
                    FlagArity::ConfigKeyValue => {
                        let val = args.get(idx + 1).cloned().unwrap_or_default();
                        let consumed = if idx + 1 < args.len() { 2 } else { 1 };
                        Some((consumed, None, Some(val)))
                    }
                };
            }
            if let Some(rest) = tok.strip_prefix(long)
                && let Some(val) = rest.strip_prefix('=')
            {
                return match spec.arity {
                    FlagArity::None => None,
                    FlagArity::OptionalAttachedEqualsValue | FlagArity::SeparateOrAttachedValue => {
                        let dir = if spec.is_repo_dir {
                            Some(val.to_string())
                        } else {
                            None
                        };
                        Some((1, dir, None))
                    }
                    FlagArity::ConfigKeyValue => Some((1, None, Some(val.to_string()))),
                };
            }
        }
        return None;
    }

    // 2. Short `-X` or bundled `-P` or attached `-C/dir` / `-ck=v`
    let short_chars = &tok[1..];
    let first_ch = short_chars.chars().next()?;
    for spec in table {
        if spec.short == Some(first_ch) {
            let rest = &short_chars[first_ch.len_utf8()..];
            return match spec.arity {
                FlagArity::None | FlagArity::OptionalAttachedEqualsValue => {
                    if rest.is_empty()
                        || rest.chars().all(|ch| {
                            table
                                .iter()
                                .any(|s| s.short == Some(ch) && s.arity == FlagArity::None)
                        })
                    {
                        Some((1, None, None))
                    } else {
                        None
                    }
                }
                FlagArity::SeparateOrAttachedValue => {
                    let (consumed, val) = if !rest.is_empty() {
                        (1, rest.to_string())
                    } else if let Some(next_val) = args.get(idx + 1) {
                        (2, next_val.clone())
                    } else {
                        (1, String::new())
                    };
                    let dir = if spec.is_repo_dir { Some(val) } else { None };
                    Some((consumed, dir, None))
                }
                FlagArity::ConfigKeyValue => {
                    let (consumed, val) = if !rest.is_empty() {
                        (1, rest.to_string())
                    } else if let Some(next_val) = args.get(idx + 1) {
                        (2, next_val.clone())
                    } else {
                        (1, String::new())
                    };
                    Some((consumed, None, Some(val)))
                }
            };
        }
    }
    None
}
