// SPDX-License-Identifier: Apache-2.0

//! Modular repository safety gate wiring `.chinwag/workflow.yaml` and `.git/HEAD` onto
//! `chinwag-tool-grammar` (`ToolGrammarV1`). Kept self-contained in its own module so downstream
//! `Reflex-1` (`ADR-010`) and containment hooks can call [`evaluate_repo_shell_command`] and
//! [`evaluate_repo_argv`] with zero cross-branch merge friction.

use chinwag_tool_grammar::{
    Action, CanonicalCommandTupleV1, Effect, PolicyDisposition, PolicyEvaluationV1, Program,
    SafetyToggle, TOOL_GRAMMAR_SCHEMA_V1, WorkflowSafetyPolicyV1, parse_argv_with_context,
    parse_shell_command_with_context,
};
use std::collections::BTreeSet;
use std::path::Path;

/// Loads `.chinwag/workflow.yaml` from `repo_root` (failing closed on symlinks or invalid YAML)
/// and evaluates a POSIX shell command line against `ToolGrammarV1`.
#[must_use]
pub fn evaluate_repo_shell_command(repo_root: &Path, cmdline: &str) -> PolicyEvaluationV1 {
    match WorkflowSafetyPolicyV1::load_from_repo_root(repo_root) {
        Ok(policy) => {
            let tuple = policy.with_parse_context(Some(repo_root), |ctx| {
                parse_shell_command_with_context(cmdline, ctx)
            });
            policy.evaluate_tuple(tuple)
        }
        Err(err) => fail_closed_policy_load(err.to_string()),
    }
}

/// Loads `.chinwag/workflow.yaml` from `repo_root` (failing closed on symlinks or invalid YAML)
/// and evaluates a pre-tokenized `argv` slice against `ToolGrammarV1`.
#[must_use]
pub fn evaluate_repo_argv<S: AsRef<str>>(repo_root: &Path, argv: &[S]) -> PolicyEvaluationV1 {
    match WorkflowSafetyPolicyV1::load_from_repo_root(repo_root) {
        Ok(policy) => {
            let tuple = policy
                .with_parse_context(Some(repo_root), |ctx| parse_argv_with_context(argv, ctx));
            policy.evaluate_tuple(tuple)
        }
        Err(err) => fail_closed_policy_load(err.to_string()),
    }
}

fn fail_closed_policy_load(reason: String) -> PolicyEvaluationV1 {
    let effects = BTreeSet::from([
        Effect::SensitivePathAccess,
        Effect::UnrecognizedOrAmbiguousCommand,
    ]);
    PolicyEvaluationV1 {
        disposition: PolicyDisposition::BlockHardInvariant,
        triggered_effects: effects.clone(),
        matched_toggles: vec![SafetyToggle::AlwaysOnContainmentInvariant],
        tuple: CanonicalCommandTupleV1 {
            schema: TOOL_GRAMMAR_SCHEMA_V1.to_string(),
            program: Program::ShellWrapper,
            action: Action::AmbiguousShellOrWrapper,
            effects,
            target_refs_or_paths: Vec::new(),
            wrappers_peeled: Vec::new(),
            env_overrides: Vec::new(),
            via_xargs: false,
            elapsed_nanos: 0,
            elapsed_micros: 0,
            fail_closed_reason: Some(reason.clone()),
        },
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_gate_allows_readonly_and_gates_force_push_main() {
        let tmp = std::env::temp_dir().join(format!("cw_cli_tg_gate_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".chinwag")).unwrap();
        std::fs::write(
            tmp.join(".chinwag/workflow.yaml"),
            "require_review_before_push_main: true\nprotect_secrets_auth_migrations: true\nforbid_destructive_worktree_ops: true\n",
        )
        .unwrap();

        let ok = evaluate_repo_shell_command(&tmp, "git status -sb");
        assert_eq!(ok.disposition, PolicyDisposition::Allow);

        let hold = evaluate_repo_argv(&tmp, &["git", "push", "origin", "+HEAD:main"]);
        assert_eq!(hold.disposition, PolicyDisposition::RequireReview);
        assert!(
            hold.triggered_effects
                .contains(&Effect::ForcePushProtectedBranch)
        );

        let escape = evaluate_repo_shell_command(&tmp, "rm -rf ../outside");
        assert_eq!(escape.disposition, PolicyDisposition::BlockHardInvariant);

        // Checked-out `main` gates bare `git push` and `git push origin HEAD`, while checked-out `feat/*` allows!
        std::fs::create_dir_all(tmp.join(".git")).unwrap();
        std::fs::write(tmp.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        assert_eq!(
            evaluate_repo_shell_command(&tmp, "git push").disposition,
            PolicyDisposition::RequireReview
        );
        assert_eq!(
            evaluate_repo_shell_command(&tmp, "git push origin HEAD").disposition,
            PolicyDisposition::RequireReview
        );

        std::fs::write(tmp.join(".git/HEAD"), "ref: refs/heads/feat/sub-branch\n").unwrap();
        // Refspec-less `git push` stays gated because `.git/config` `remote.*.push` / `push.default`
        // can redirect an implicit push onto `main`, whereas explicit `HEAD` or `feat/*` is Allowed!
        assert_eq!(
            evaluate_repo_shell_command(&tmp, "git push").disposition,
            PolicyDisposition::RequireReview
        );
        assert_eq!(
            evaluate_repo_shell_command(&tmp, "git push origin HEAD").disposition,
            PolicyDisposition::Allow
        );
        assert_eq!(
            evaluate_repo_shell_command(&tmp, "git push origin feat/sub-branch").disposition,
            PolicyDisposition::Allow
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
