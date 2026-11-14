// SPDX-License-Identifier: Apache-2.0

use crate::types::{ParseContext, Target};
use std::path::Path;

/// Classifies a branch or ref name (`main`, `refs/heads/main`, `refs/for/release/1.0`)
/// against protected branch patterns (`main`, `master`, `prod`, `production`, `trunk`, `release/*`).
#[must_use]
pub fn is_protected_branch_name(raw_ref: &str, patterns: &[&str]) -> bool {
    let trimmed = raw_ref.trim().trim_start_matches('+');
    if trimmed.is_empty() {
        return false;
    }
    let short = strip_git_ref_prefix(trimmed);
    for pat in patterns {
        let pat = pat.trim();
        if pat.is_empty() {
            continue;
        }
        if let Some(prefix) = pat.strip_suffix("/*") {
            if short == prefix || short.starts_with(&format!("{prefix}/")) {
                return true;
            }
        } else if let Some(prefix) = pat.strip_suffix('*') {
            if short.starts_with(prefix) {
                return true;
            }
        } else if short.eq_ignore_ascii_case(pat) {
            return true;
        }
    }
    false
}

/// Strips standard and DWIM Git ref namespaces (`refs/heads/`, `heads/`, `refs/remotes/origin/`,
/// `remotes/origin/`, `refs/for/`, `refs/tags/`, `tags/`) and peel suffixes (`^{...}`)
/// to expose the logical branch or tag name.
#[must_use]
pub fn strip_git_ref_prefix(r: &str) -> &str {
    let base = r.split_once("^{").map(|(b, _)| b).unwrap_or(r);
    if let Some(rest) = base.strip_prefix("refs/heads/") {
        return rest;
    }
    if let Some(rest) = base.strip_prefix("refs/for/") {
        return rest;
    }
    if let Some(rest) = base.strip_prefix("refs/tags/") {
        return rest;
    }
    if let Some(rest) = base.strip_prefix("refs/remotes/") {
        if let Some((_remote, branch)) = rest.split_once('/') {
            return branch;
        }
        return rest;
    }
    if let Some(rest) = base.strip_prefix("heads/") {
        return rest;
    }
    if let Some(rest) = base.strip_prefix("tags/") {
        return rest;
    }
    if let Some(rest) = base.strip_prefix("remotes/") {
        if let Some((_remote, branch)) = rest.split_once('/') {
            return branch;
        }
        return rest;
    }
    base
}

/// Parses a Git push refspec (`+HEAD:refs/heads/main`, `:prod`, `main`, `feat:main`) into a [`Target::Refspec`].
#[must_use]
pub fn parse_git_refspec(raw: &str, ctx: &ParseContext<'_>) -> Target {
    let trimmed = raw.trim();
    let (leading_plus_force, body) = match trimmed.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };

    let is_implicit_head_dst = !body.contains(':') && (body == "HEAD" || body == "@");
    let (src, dst, colon_delete) = if let Some((lhs, rhs)) = body.split_once(':') {
        let colon_del = lhs.is_empty() && !rhs.is_empty();
        let src_opt = if lhs.is_empty() {
            None
        } else {
            Some(lhs.to_string())
        };
        (src_opt, rhs.to_string(), colon_del)
    } else if is_implicit_head_dst {
        let resolved = ctx.current_branch.unwrap_or(body).to_string();
        (Some(body.to_string()), resolved, false)
    } else {
        (Some(body.to_string()), body.to_string(), false)
    };

    // Fail closed when:
    // - pushing `HEAD` / `@` without `:destination` and `current_branch` is unknown,
    // - pushing bare `:` / `+:` ("matching" push refspec across all matching branches including `main`),
    // - pushing wildcard `*` refspec (`refs/heads/*:refs/heads/*`), or
    // - targeting any protected branch pattern (`main`, `master`, `prod`, `release/*`, etc.).
    let is_matching_or_wildcard = dst.trim().is_empty() || dst.contains('*');
    let targets_protected_branch = (is_implicit_head_dst && ctx.current_branch.is_none())
        || is_matching_or_wildcard
        || is_protected_branch_name(&dst, ctx.protected_branches);

    Target::Refspec {
        raw: trimmed.to_string(),
        src,
        dst,
        leading_plus_force,
        colon_delete,
        targets_protected_branch,
    }
}

/// Matches a normalized repo-relative path against a `.chinwag/workflow.yaml` protected glob pattern
/// (`.env*`, `**/auth/**`, `**/billing/**`, `**/migrations/**`, `.github/workflows/**`) with zero regex backtracking.
#[must_use]
pub fn matches_protected_glob(file_path: &str, pattern: &str) -> bool {
    let norm_path = file_path.trim().trim_start_matches("./").trim_matches('/');
    let norm_pat = pattern.trim().trim_start_matches("./").trim_matches('/');
    if norm_path.is_empty() || norm_pat.is_empty() {
        return false;
    }
    let basename = norm_path.rsplit('/').next().unwrap_or(norm_path);
    if let Some(stem) = norm_pat.strip_prefix("**/") {
        let stem_dir = stem.trim_end_matches("/**").trim_end_matches("/*");
        if norm_path == stem_dir
            || norm_path.starts_with(&format!("{stem_dir}/"))
            || norm_path.contains(&format!("/{stem_dir}/"))
            || norm_path.ends_with(&format!("/{stem_dir}"))
        {
            return true;
        }
        return matches_protected_glob(norm_path, stem);
    }
    if let Some(prefix) = norm_pat.strip_suffix("/**") {
        return norm_path == prefix || norm_path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = norm_pat.strip_suffix("/*") {
        return norm_path == prefix || norm_path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = norm_pat.strip_suffix('*') {
        return norm_path.starts_with(prefix) || basename.starts_with(prefix);
    }
    norm_path == norm_pat || basename == norm_pat
}

/// Returns `true` if the normalized path touches repository/VCS/CI/Chinwag control plane files.
#[must_use]
pub fn is_control_plane_path(norm_rel: &str) -> bool {
    let clean = norm_rel.trim_start_matches("./").trim_matches('/');
    if clean.is_empty() {
        return false;
    }
    let first = clean.split('/').next().unwrap_or(clean);
    matches!(first, ".git" | ".jj" | ".chinwag")
        || clean == ".github/workflows"
        || clean.starts_with(".github/workflows/")
        || clean.ends_with("/.git")
        || clean.contains("/.git/")
        || clean.ends_with("/.jj")
        || clean.contains("/.jj/")
        || clean.ends_with("/.chinwag")
        || clean.contains("/.chinwag/")
}

/// Returns `true` if an absolute path targets sensitive OS or user-home directories
/// (`/`, `/etc`, `/private/etc`, `/Users`, `/home`, `/var`, `/opt`, `/root`, `/usr`, `/System`, etc.).
#[must_use]
pub fn is_sensitive_system_abs_path(abs_path: &str) -> bool {
    let clean = abs_path.trim_matches('/');
    if clean.is_empty() {
        return true;
    }
    let first = clean.split('/').next().unwrap_or(clean);
    matches!(
        first,
        "etc"
            | "private"
            | "Users"
            | "home"
            | "var"
            | "opt"
            | "bin"
            | "sbin"
            | "usr"
            | "System"
            | "Library"
            | "root"
            | "boot"
            | "proc"
            | "sys"
            | "dev"
    ) && abs_path != "/dev/null"
}

/// Detects root, home-directory, or top-level wildcard deletion hazards (`rm -rf /`, `/*`, `~`, `~/*`, `*`, `.`, `..`).
#[must_use]
pub fn is_root_or_wildcard_delete_hazard(raw: &str, normalized: &str) -> bool {
    let t = raw.trim();
    if t.is_empty() {
        return false;
    }
    if matches!(
        t,
        "/" | "/*"
            | "//"
            | "//*"
            | "~"
            | "~/"
            | "~/*"
            | "$HOME"
            | "$HOME/"
            | "$HOME/*"
            | "${HOME}"
            | "${HOME}/*"
            | "*"
            | "./*"
            | "."
            | "./"
            | ".."
            | "../"
            | "../*"
    ) {
        return true;
    }
    if normalized == "/" || (normalized == "." && (t == "." || t == "./")) {
        return true;
    }
    if let Some(rest) = t.strip_prefix('/') {
        let clean = rest.trim_matches('/');
        if clean.is_empty() || clean == "*" || clean == ".." {
            return true;
        }
        let segs: Vec<&str> = clean.split('/').filter(|s| !s.is_empty()).collect();
        let is_system_root = !segs.is_empty()
            && matches!(
                segs[0],
                "bin"
                    | "sbin"
                    | "usr"
                    | "etc"
                    | "var"
                    | "System"
                    | "Library"
                    | "Users"
                    | "home"
                    | "root"
                    | "opt"
                    | "private"
            );
        if segs.len() == 1 && is_system_root {
            return true;
        }
        if segs.len() == 2
            && (segs[1] == "*"
                || matches!(
                    segs[0],
                    "bin" | "sbin" | "usr" | "etc" | "var" | "System" | "Library" | "root"
                ))
        {
            return true;
        }
    }
    false
}

/// Checks a repository directory selector (`git -C <dir>`, `jj -R <dir>`, `env -C <dir>`).
/// Returns `(normalized, escapes_workspace)`:
/// - If `ctx.workspace_root` is `Some(ws_root)`, any path outside `ws_root` escapes.
/// - If `ctx.workspace_root` is `None`, relative `..` escapes (`../sibling`) or absolute `..` traversal
///   (`/repo/../../outside`) or OS system directories (`/etc`) escape, whereas a clean absolute repo path
///   (`/repo`, `/workspace/app`) is accepted as the command's base repo anchor without false positives.
#[must_use]
pub fn check_repo_dir_selector(raw_dir: &str, ctx: &ParseContext<'_>) -> (String, bool) {
    let trimmed = raw_dir.trim();
    let slash_norm = if trimmed.contains('\\') {
        trimmed.replace('\\', "/")
    } else {
        trimmed.to_string()
    };

    if slash_norm.starts_with('~')
        || slash_norm.starts_with("$HOME")
        || slash_norm.starts_with("${HOME}")
    {
        return (slash_norm, true);
    }

    if slash_norm.starts_with('/') {
        let has_dotdot = slash_norm.split('/').any(|seg| seg == "..");
        let (abs_segs, popped_root) = normalize_abs_segments(&slash_norm);
        let abs_joined = if abs_segs.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", abs_segs.join("/"))
        };
        if let Some(ws_root) = ctx.workspace_root {
            let ws_str = ws_root.to_string_lossy();
            let (ws_segs, _) = normalize_abs_segments(&ws_str);
            if abs_segs.len() >= ws_segs.len() && abs_segs[..ws_segs.len()] == ws_segs[..] {
                let rel = abs_segs[ws_segs.len()..].join("/");
                return (if rel.is_empty() { ".".to_string() } else { rel }, false);
            }
            return (abs_joined, true);
        }
        let escapes = popped_root
            || has_dotdot && abs_segs.len() <= 1
            || is_sensitive_system_abs_path(&abs_joined);
        return (abs_joined, escapes);
    }

    resolve_lexical_workspace_path(&slash_norm, None, ctx.workspace_root)
}

/// Composes a process `chdir` directory selector (`-C <dir>`, `jj -R <dir>`, `env -C <dir>`) onto any prior
/// `cwd_offset`, updating `repo_selector_redirected` sticky-monotonically (`false -> true`, never reset by `-C .`).
/// Returns `true` if `raw_dir` escapes the workspace boundary.
#[must_use]
pub fn apply_repo_dir_selector(
    cwd_offset: &mut Option<String>,
    repo_selector_redirected: &mut bool,
    raw_dir: &str,
    ctx: &ParseContext<'_>,
) -> bool {
    let (norm, escapes) = resolve_selector_against_cwd(cwd_offset.as_deref(), raw_dir, ctx);
    if norm != "." || escapes {
        *repo_selector_redirected = true;
    }
    *cwd_offset = Some(norm);
    escapes
}

/// Evaluates a non-`chdir` repository or worktree selector (`GIT_DIR`, `GIT_WORK_TREE`,
/// `--git-dir`, `--work-tree`, etc.) relative to the current process `cwd_offset` WITHOUT
/// mutating `cwd_offset`, so repeated `GIT_WORK_TREE=src GIT_WORK_TREE=../outside` or
/// `--work-tree=src --work-tree=../outside` replace rather than compose directory changes.
/// Marks `repo_selector_redirected = true` and returns `(normalized_path, escapes_workspace)`.
#[must_use]
pub fn check_non_chdir_repo_selector(
    cwd_offset: Option<&str>,
    repo_selector_redirected: &mut bool,
    raw_dir: &str,
    ctx: &ParseContext<'_>,
) -> (String, bool) {
    *repo_selector_redirected = true;
    resolve_selector_against_cwd(cwd_offset, raw_dir, ctx)
}

fn resolve_selector_against_cwd(
    cwd_offset: Option<&str>,
    raw_dir: &str,
    ctx: &ParseContext<'_>,
) -> (String, bool) {
    let trimmed = raw_dir.trim();
    let slash_norm = if trimmed.contains('\\') {
        trimmed.replace('\\', "/")
    } else {
        trimmed.to_string()
    };

    if !slash_norm.starts_with('/')
        && !slash_norm.starts_with('~')
        && !slash_norm.starts_with("$HOME")
        && !slash_norm.starts_with("${HOME}")
    {
        if let Some(prev) = cwd_offset {
            if prev.starts_with('/') && ctx.workspace_root.is_none() {
                let joined = format!("{}/{}", prev.trim_end_matches('/'), slash_norm);
                check_repo_dir_selector(&joined, ctx)
            } else {
                resolve_lexical_workspace_path(&slash_norm, Some(prev), ctx.workspace_root)
            }
        } else {
            check_repo_dir_selector(&slash_norm, ctx)
        }
    } else {
        check_repo_dir_selector(&slash_norm, ctx)
    }
}

/// Lexically resolves a mutating/target `raw_path` given optional `cwd_offset` (from `-C <dir>`) and `ctx.workspace_root`.
#[must_use]
pub fn analyze_path_target(
    raw_path: &str,
    cwd_offset: Option<&str>,
    ctx: &ParseContext<'_>,
) -> Target {
    let trimmed = raw_path.trim();
    let slash_norm = if trimmed.contains('\\') {
        trimmed.replace('\\', "/")
    } else {
        trimmed.to_string()
    };

    let (normalized, escapes_workspace) =
        resolve_lexical_workspace_path(&slash_norm, cwd_offset, ctx.workspace_root);

    let root_hazard = is_root_or_wildcard_delete_hazard(trimmed, &normalized);
    let control_plane = is_control_plane_path(&normalized);
    let matches_glob = ctx
        .protected_paths
        .iter()
        .any(|pat| matches_protected_glob(&normalized, pat));
    let sensitive = control_plane || matches_glob;

    Target::Path {
        raw: trimmed.to_string(),
        normalized,
        escapes_workspace,
        control_plane,
        sensitive,
        root_or_wildcard_hazard: root_hazard,
    }
}

/// Resolves `path_str` lexically relative to `workspace_root` (if provided) and `cwd_offset`.
/// Returns `(normalized_display_path, escapes_workspace)`.
#[must_use]
pub fn resolve_lexical_workspace_path(
    path_str: &str,
    cwd_offset: Option<&str>,
    workspace_root: Option<&Path>,
) -> (String, bool) {
    if path_str.starts_with('~') || path_str.starts_with("$HOME") || path_str.starts_with("${HOME}")
    {
        return (path_str.to_string(), true);
    }

    if path_str.starts_with('/') {
        let (abs_segs, popped_root) = normalize_abs_segments(path_str);
        let abs_joined = if abs_segs.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", abs_segs.join("/"))
        };

        if let Some(ws_root) = workspace_root {
            let ws_str = ws_root.to_string_lossy();
            let (ws_segs, _) = normalize_abs_segments(&ws_str);
            if abs_segs.len() >= ws_segs.len() && abs_segs[..ws_segs.len()] == ws_segs[..] {
                let rel = abs_segs[ws_segs.len()..].join("/");
                let display = if rel.is_empty() { ".".to_string() } else { rel };
                return (display, false);
            }
            return (abs_joined, true);
        }
        // If `cwd_offset` was an absolute repo anchor (e.g. `-C /repo`), allow paths under that anchor
        if let Some(offset) = cwd_offset
            && offset.starts_with('/')
        {
            let (base_segs, _) = normalize_abs_segments(offset);
            if !base_segs.is_empty()
                && abs_segs.len() >= base_segs.len()
                && abs_segs[..base_segs.len()] == base_segs[..]
            {
                let rel = abs_segs[base_segs.len()..].join("/");
                let display = if rel.is_empty() { ".".to_string() } else { rel };
                return (display, popped_root);
            }
        }
        if abs_joined == "/dev/null" {
            return (abs_joined, false);
        }
        return (abs_joined, true);
    }

    // Relative path handling
    let mut stack: Vec<&str> = Vec::new();
    let mut escaped = false;

    if let Some(offset) = cwd_offset
        && !offset.starts_with('/')
        && !offset.starts_with('~')
    {
        for seg in offset.split(['/', '\\']) {
            match seg {
                "" | "." => {}
                ".." => {
                    if stack.pop().is_none() {
                        escaped = true;
                    }
                }
                other => stack.push(other),
            }
        }
    }

    for seg in path_str.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    escaped = true;
                }
            }
            other => stack.push(other),
        }
    }

    let normalized = if stack.is_empty() {
        if escaped {
            "..".to_string()
        } else {
            ".".to_string()
        }
    } else {
        stack.join("/")
    };

    (normalized, escaped)
}

fn normalize_abs_segments(abs_path: &str) -> (Vec<&str>, bool) {
    let mut stack: Vec<&str> = Vec::new();
    let mut popped_root = false;
    for seg in abs_path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    popped_root = true;
                }
            }
            other => stack.push(other),
        }
    }
    (stack, popped_root)
}
