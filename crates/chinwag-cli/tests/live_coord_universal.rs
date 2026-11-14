// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! End-to-end verification of `CHWG-0250` (`INV-UNIVERSAL-COORDINATION-01`):
//! 1. Transactional single-host CRDB auto-beacons (`TASK_CREATED`, `CLAIM_ACQUIRED`,
//!    `PR_OPENED`, `PR_MERGED`, `RELEASE_BUILT`) with zero external daemon.
//! 2. Live session leases & `<1ms` `[chinwag-bus-delta]` piggybacking across CLI & worktrees.
//! 3. Repo-local Git claim-check floor (`post-checkout`, `pre-commit`, `reference-transaction`)
//!    + `.chinwag/ACTIVE_WORK.md` with zero `$HOME` vendor dotfile hooks.
#![cfg(target_os = "macos")]

use chinwag_cli::live_coord::{
    ACTIVE_WORK_REL_PATH, AutoBeaconRequest, BeaconKind, INV_UNIVERSAL_COORDINATION,
    emit_transactional_beacon, path_matches_claim_glob, read_live_coord_snapshot,
};
use chinwag_snapshot_session_private::fast_crdb_header_stamp;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct IsolatedWorkspace {
    base: PathBuf,
    home: PathBuf,
    repo: PathBuf,
}

impl IsolatedWorkspace {
    fn new(label: &str) -> Self {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "chinwag-live-coord-{label}-{}-{id}",
                std::process::id()
            ));
        let _ = fs::remove_dir_all(&base);
        let home = base.join("home");
        let repo = base.join("repo");
        fs::create_dir_all(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(&repo).unwrap();
        fs::set_permissions(&repo, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            Command::new("git")
                .args(["init", "-b", "main"])
                .current_dir(&repo)
                .env("HOME", &home)
                .status()
                .unwrap()
                .success()
        );
        for (k, v) in [
            ("user.name", "Fixture Agent"),
            ("user.email", "fixture@chinwag.test"),
        ] {
            assert!(
                Command::new("git")
                    .args(["config", k, v])
                    .current_dir(&repo)
                    .env("HOME", &home)
                    .status()
                    .unwrap()
                    .success()
            );
        }

        fs::create_dir_all(repo.join("src/engine")).unwrap();
        fs::create_dir_all(repo.join("docs")).unwrap();
        fs::write(repo.join("src/engine/core.rs"), "pub fn v() -> u32 { 1 }\n").unwrap();
        fs::write(repo.join("docs/notes.md"), "# Notes\n").unwrap();
        fs::write(repo.join(".gitignore"), ".chinwag/\n").unwrap();

        assert!(
            Command::new("git")
                .args(["add", "."])
                .current_dir(&repo)
                .env("HOME", &home)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .args([
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-m",
                    "initial fixture"
                ])
                .current_dir(&repo)
                .env("HOME", &home)
                .status()
                .unwrap()
                .success()
        );

        Self { base, home, repo }
    }

    fn run_chinwag(&self, cwd: &Path, actor: Option<&str>, args: &[&str]) -> std::process::Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_chinwag"));
        cmd.args(args)
            .current_dir(cwd)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        if let Some(a) = actor {
            cmd.env("CHINWAG_ACTOR", a);
        }
        cmd.output().unwrap()
    }
}

impl Drop for IsolatedWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn init_installs_repo_local_hooks_with_zero_home_vendor_dotfiles() {
    let ws = IsolatedWorkspace::new("init-hooks");
    let out = ws.run_chinwag(
        &ws.repo,
        None,
        &[
            "init",
            "--repo",
            ws.repo.to_str().unwrap(),
            "--principal",
            "fixture@chinwag.test",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let receipt: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(receipt["result"], "local_initialized");
    assert_eq!(receipt["git_claim_hooks_installed"], true);
    assert_eq!(receipt["active_work_path"], ACTIVE_WORK_REL_PATH);

    // Zero `$HOME` vendor dotfile hooks created!
    for vendor_dir in [".claude", ".gemini", ".codex", ".config/git/hooks"] {
        assert!(
            !ws.home.join(vendor_dir).exists(),
            "must never touch $HOME/{vendor_dir}"
        );
    }

    // Repo-local Git hooks exist with 0700 executable permissions.
    for hook in ["post-checkout", "pre-commit", "reference-transaction"] {
        let hp = ws.repo.join(".git/hooks").join(hook);
        assert!(hp.is_file(), "missing repo-local hook {hook}");
        let mode = fs::metadata(&hp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "unexpected mode {mode:o} for {hook}");
    }
    assert!(ws.repo.join(ACTIVE_WORK_REL_PATH).is_file());
}

#[test]
fn transactional_auto_beacons_and_sub_millisecond_cli_delta_across_worktrees() {
    let ws = IsolatedWorkspace::new("beacons-delta");
    let init = ws.run_chinwag(
        &ws.repo,
        None,
        &[
            "init",
            "--repo",
            ws.repo.to_str().unwrap(),
            "--principal",
            "fixture@chinwag.test",
        ],
    );
    assert!(init.status.success());

    let actor_a = "ARCHITECT#0123456789abcdef0123456789abcdef";
    let actor_b = "RUST#fedcba9876543210fedcba9876543210";

    // Create a linked Git worktree for Actor B (`git worktree add`).
    let wt_b = ws.base.join("wt-actor-b");
    assert!(
        Command::new("git")
            .args([
                "worktree",
                "add",
                "-b",
                "feat/actor-b",
                wt_b.to_str().unwrap(),
                "HEAD"
            ])
            .current_dir(&ws.repo)
            .env_clear()
            .env("HOME", &ws.home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("CHINWAG_BIN", env!("CARGO_BIN_EXE_chinwag"))
            .status()
            .unwrap()
            .success()
    );

    // Register live session lease for Actor A.
    let lease_out = ws.run_chinwag(&ws.repo, Some(actor_a), &["bus", "session-lease", "--json"]);
    assert!(
        lease_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&lease_out.stderr)
    );

    // Prime Actor A's CLI cursor on `ws.repo` via `chinwag tasks --help`.
    let prime = ws.run_chinwag(&ws.repo, Some(actor_a), &["tasks", "--help"]);
    assert!(prime.status.success());
    assert!(String::from_utf8_lossy(&prime.stderr).is_empty());

    // Actor B emits all 5 canonical beacon kinds from its linked worktree `wt_b` with ZERO daemon!
    for (kind, paths) in [
        ("TASK_CREATED", ""),
        ("CLAIM_ACQUIRED", "src/engine/**,docs/spec.md"),
        ("PR_OPENED", ""),
    ] {
        let mut args = vec![
            "bus",
            "emit-beacon",
            "--kind",
            kind,
            "--task",
            "CHWG-0250",
            "--json",
        ];
        if !paths.is_empty() {
            args.extend(["--surfaces", paths]);
        }
        let res = ws.run_chinwag(&wt_b, Some(actor_b), &args);
        assert!(
            res.status.success(),
            "{kind} failed: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }

    // Verify snapshot shows active claims for `src/engine/**` and `docs/spec.md` + 3 beacons + Actor A session lease.
    let (_, db_v, claims, sessions, beacons) = read_live_coord_snapshot(&ws.repo).unwrap();
    assert!(db_v >= 4);
    assert_eq!(claims.len(), 2);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].actor_instance, actor_a);
    assert_eq!(beacons.len(), 3);
    assert_eq!(beacons[0].seq, 1);
    assert_eq!(beacons[2].seq, 3);

    // Next CLI command run by Actor A piggybacks `[chinwag-bus-delta · INV-UNIVERSAL-COORDINATION-01]`!
    let next_cli = ws.run_chinwag(&ws.repo, Some(actor_a), &["tasks", "--help"]);
    assert!(next_cli.status.success());
    let stderr_1 = String::from_utf8_lossy(&next_cli.stderr);
    assert!(
        stderr_1.contains(INV_UNIVERSAL_COORDINATION),
        "expected delta banner on stderr, got: {stderr_1}"
    );
    assert!(stderr_1.contains("CLAIM_ACQUIRED CHWG-0250"));
    assert!(stderr_1.contains("PR_OPENED CHWG-0250"));

    // Immediate subsequent CLI command by Actor A hits `<1ms` header stamp short-circuit with zero duplicate output!
    let t0 = Instant::now();
    let stamp = fast_crdb_header_stamp(&ws.repo).unwrap();
    let elapsed_us = t0.elapsed().as_micros();
    assert!(
        elapsed_us < 1_000,
        "expected <1000us header stamp, got {elapsed_us}us ({stamp:?})"
    );
    let repeat_cli = ws.run_chinwag(&ws.repo, Some(actor_a), &["tasks", "--help"]);
    assert!(repeat_cli.status.success());
    assert!(
        String::from_utf8_lossy(&repeat_cli.stderr).is_empty(),
        "must not re-emit already-seen beacons"
    );

    // Emit PR_MERGED and RELEASE_BUILT; verify PR_MERGED atomically releases Actor B's claims!
    for kind in ["PR_MERGED", "RELEASE_BUILT"] {
        let res = ws.run_chinwag(
            &wt_b,
            Some(actor_b),
            &[
                "bus",
                "emit-beacon",
                "--kind",
                kind,
                "--task",
                "CHWG-0250",
                "--json",
            ],
        );
        assert!(res.status.success());
    }
    let (_, _, claims_after, _, beacons_after) = read_live_coord_snapshot(&ws.repo).unwrap();
    assert!(
        claims_after.is_empty(),
        "PR_MERGED must atomically release claims: {claims_after:?}"
    );
    assert_eq!(beacons_after.len(), 5);
    assert_eq!(beacons_after[3].kind, "PR_MERGED");
    assert_eq!(beacons_after[4].kind, "RELEASE_BUILT");
}

#[test]
fn raw_git_only_local_agent_is_fenced_by_pre_commit_claim_hook_until_pr_merged() {
    let ws = IsolatedWorkspace::new("git-floor");
    let init = ws.run_chinwag(
        &ws.repo,
        None,
        &[
            "init",
            "--repo",
            ws.repo.to_str().unwrap(),
            "--principal",
            "fixture@chinwag.test",
        ],
    );
    assert!(init.status.success());

    let owner_actor = "ARCHITECT#0123456789abcdef0123456789abcdef";
    // Owner claims `src/engine/**` via single-host `chinwag bus beacon` (no daemon running!).
    let claim = ws.run_chinwag(
        &ws.repo,
        Some(owner_actor),
        &[
            "bus",
            "beacon",
            "--task",
            "CHWG-0250",
            "--surfaces",
            "src/engine/**",
            "--json",
        ],
    );
    assert!(
        claim.status.success(),
        "single-host bus beacon must succeed without daemon: {}",
        String::from_utf8_lossy(&claim.stderr)
    );

    // Verify `.chinwag/ACTIVE_WORK.md` displays the claimed surface for raw local models.
    let active_md = fs::read_to_string(ws.repo.join(ACTIVE_WORK_REL_PATH)).unwrap();
    assert!(active_md.contains("CHWG-0250"));
    assert!(active_md.contains("src/engine/**"));
    assert!(active_md.contains(owner_actor));

    // Raw Git-only local agent (zero CHINWAG_ACTOR env, zero MCP, zero chinwag CLI calls):
    // 1. Editing & committing an UNCLAIMED path (`docs/notes.md`) succeeds!
    fs::write(ws.repo.join("docs/notes.md"), "# Updated notes\n").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "docs/notes.md"])
            .current_dir(&ws.repo)
            .env("HOME", &ws.home)
            .status()
            .unwrap()
            .success()
    );
    let ok_commit = Command::new("git")
        .args([
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "docs update on unclaimed path",
        ])
        .current_dir(&ws.repo)
        .env_clear()
        .env("HOME", &ws.home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("CHINWAG_BIN", env!("CARGO_BIN_EXE_chinwag"))
        .output()
        .unwrap();
    assert!(
        ok_commit.status.success(),
        "unclaimed commit failed: {}",
        String::from_utf8_lossy(&ok_commit.stderr)
    );

    // 2. Raw Git-only local agent stages `src/engine/core.rs` (overlaps `src/engine/**`!) -> `git commit` FAILS CLOSED!
    fs::write(
        ws.repo.join("src/engine/core.rs"),
        "pub fn v() -> u32 { 99 }\n",
    )
    .unwrap();
    assert!(
        Command::new("git")
            .args(["add", "src/engine/core.rs"])
            .current_dir(&ws.repo)
            .env_clear()
            .env("HOME", &ws.home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .status()
            .unwrap()
            .success()
    );
    let blocked_commit = Command::new("git")
        .args([
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "colliding edit from raw git local model",
        ])
        .current_dir(&ws.repo)
        .env_clear()
        .env("HOME", &ws.home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("CHINWAG_BIN", env!("CARGO_BIN_EXE_chinwag"))
        .output()
        .unwrap();
    assert!(
        !blocked_commit.status.success(),
        "overlapping claimed commit MUST fail closed!"
    );
    let hook_stderr = String::from_utf8_lossy(&blocked_commit.stderr);
    assert!(
        hook_stderr.contains("chinwag claim-check BLOCKED"),
        "stderr={hook_stderr}"
    );
    assert!(hook_stderr.contains("CHWG-0250"));
    assert!(hook_stderr.contains(owner_actor));

    // 3. Same owner (`CHINWAG_ACTOR == owner_actor`) CAN commit its own claimed file!
    let owner_commit = Command::new("git")
        .args([
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "owner commit on claimed surface",
        ])
        .current_dir(&ws.repo)
        .env_clear()
        .env("HOME", &ws.home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("CHINWAG_ACTOR", owner_actor)
        .env("CHINWAG_BIN", env!("CARGO_BIN_EXE_chinwag"))
        .output()
        .unwrap();
    assert!(
        owner_commit.status.success(),
        "claim owner commit must succeed: {}",
        String::from_utf8_lossy(&owner_commit.stderr)
    );

    // 4. Owner emits `PR_MERGED` -> claim released -> another local agent can now commit `src/engine/core.rs`!
    let merged = ws.run_chinwag(
        &ws.repo,
        Some(owner_actor),
        &[
            "bus",
            "emit-beacon",
            "--kind",
            "PR_MERGED",
            "--task",
            "CHWG-0250",
        ],
    );
    assert!(merged.status.success());

    fs::write(
        ws.repo.join("src/engine/core.rs"),
        "pub fn v() -> u32 { 100 }\n",
    )
    .unwrap();
    assert!(
        Command::new("git")
            .args(["add", "src/engine/core.rs"])
            .current_dir(&ws.repo)
            .env_clear()
            .env("HOME", &ws.home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .status()
            .unwrap()
            .success()
    );
    let post_merge_commit = Command::new("git")
        .args([
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "post-merge follow-up",
        ])
        .current_dir(&ws.repo)
        .env_clear()
        .env("HOME", &ws.home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("CHINWAG_BIN", env!("CARGO_BIN_EXE_chinwag"))
        .output()
        .unwrap();
    assert!(
        post_merge_commit.status.success(),
        "post-merge commit should succeed once claim is released: {}",
        String::from_utf8_lossy(&post_merge_commit.stderr)
    );
}

#[test]
fn glob_overlap_matching_handles_recursive_single_segment_and_exact_paths() {
    assert!(path_matches_claim_glob(
        "crates/chinwag-cli/src/live_coord.rs",
        "crates/chinwag-cli/**"
    ));
    assert!(path_matches_claim_glob(
        "crates/chinwag-cli/src/live_coord.rs",
        "crates/chinwag-cli/src/*"
    ));
    assert!(!path_matches_claim_glob(
        "crates/chinwag-cli/src/board/mod.rs",
        "crates/chinwag-cli/src/*"
    ));
    assert!(!path_matches_claim_glob(
        "crates/chinwag-mcp/src/owner.rs",
        "crates/chinwag-cli/**"
    ));
}

#[test]
fn hooks_honor_repo_local_hooks_path_fail_closed_on_missing_bin_and_populate_fresh_worktrees() {
    // 1. External `core.hooksPath` (`$HOME/bad-hooks`) MUST fail closed during `chinwag init`
    // without creating `.chinwag/state.crdb`!
    let ws_bad = IsolatedWorkspace::new("bad-hooks");
    let ext_hooks = ws_bad.home.join("bad-hooks");
    assert!(
        Command::new("git")
            .args(["config", "core.hooksPath", ext_hooks.to_str().unwrap()])
            .current_dir(&ws_bad.repo)
            .env("HOME", &ws_bad.home)
            .status()
            .unwrap()
            .success()
    );
    let bad_init = ws_bad.run_chinwag(
        &ws_bad.repo,
        None,
        &[
            "init",
            "--repo",
            ws_bad.repo.to_str().unwrap(),
            "--principal",
            "fixture@chinwag.test",
        ],
    );
    assert!(
        !bad_init.status.success(),
        "external core.hooksPath outside repository must fail closed!"
    );
    assert!(
        !ws_bad.repo.join(".chinwag/state.crdb").exists(),
        "refused external core.hooksPath must not initialize .chinwag/state.crdb"
    );

    // 1b. Ancestor-symlink escape (`repo/hooks-link -> ../outside` with `core.hooksPath = hooks-link/hooks`)
    // MUST also fail closed without creating `.chinwag/state.crdb` or `outside/hooks`!
    let ws_sym = IsolatedWorkspace::new("sym-hooks");
    let outside_dir = ws_sym.base.join("outside");
    fs::create_dir_all(&outside_dir).unwrap();
    std::os::unix::fs::symlink(&outside_dir, ws_sym.repo.join("hooks-link")).unwrap();
    assert!(
        Command::new("git")
            .args(["config", "core.hooksPath", "hooks-link/hooks"])
            .current_dir(&ws_sym.repo)
            .env("HOME", &ws_sym.home)
            .status()
            .unwrap()
            .success()
    );
    let sym_init = ws_sym.run_chinwag(
        &ws_sym.repo,
        None,
        &[
            "init",
            "--repo",
            ws_sym.repo.to_str().unwrap(),
            "--principal",
            "fixture@chinwag.test",
        ],
    );
    assert!(
        !sym_init.status.success(),
        "ancestor-symlink core.hooksPath escape must fail closed!"
    );
    assert!(
        !ws_sym.repo.join(".chinwag/state.crdb").exists(),
        "refused symlink core.hooksPath must not initialize .chinwag/state.crdb"
    );
    assert!(
        !outside_dir.join("hooks").exists(),
        "refused symlink core.hooksPath must not create directories outside repository"
    );

    // 2. Repo-local `core.hooksPath` (`.githooks`) MUST be honored cleanly!
    let ws = IsolatedWorkspace::new("hardened-hooks");
    assert!(
        Command::new("git")
            .args(["config", "core.hooksPath", ".githooks"])
            .current_dir(&ws.repo)
            .env("HOME", &ws.home)
            .status()
            .unwrap()
            .success()
    );
    let ok_init = ws.run_chinwag(
        &ws.repo,
        None,
        &[
            "init",
            "--repo",
            ws.repo.to_str().unwrap(),
            "--principal",
            "fixture@chinwag.test",
        ],
    );
    assert!(
        ok_init.status.success(),
        "repo-local .githooks init failed: {}",
        String::from_utf8_lossy(&ok_init.stderr)
    );
    for hook in ["post-checkout", "pre-commit", "reference-transaction"] {
        assert!(
            ws.repo.join(".githooks").join(hook).is_file(),
            "missing hook {hook} in .githooks"
        );
    }

    // 3. Fresh linked `git worktree add` automatically creates `<wt>/.chinwag/ACTIVE_WORK.md` via post-checkout!
    let wt_fresh = ws.base.join("wt-fresh");
    assert!(
        Command::new("git")
            .args([
                "worktree",
                "add",
                "-b",
                "feat/fresh-wt",
                wt_fresh.to_str().unwrap(),
                "HEAD",
            ])
            .current_dir(&ws.repo)
            .env_clear()
            .env("HOME", &ws.home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("CHINWAG_BIN", env!("CARGO_BIN_EXE_chinwag"))
            .status()
            .unwrap()
            .success()
    );
    assert!(
        wt_fresh.join(ACTIVE_WORK_REL_PATH).is_file(),
        "fresh linked worktree must receive .chinwag/ACTIVE_WORK.md automatically"
    );

    // 4. `pre-commit` MUST fail closed (`exit != 0`) when `chinwag` binary is unavailable!
    fs::write(ws.repo.join("docs/notes.md"), "# Missing bin check\n").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "docs/notes.md"])
            .current_dir(&ws.repo)
            .env("HOME", &ws.home)
            .status()
            .unwrap()
            .success()
    );
    let missing_bin_commit = Command::new("git")
        .args([
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "unverified commit with missing chinwag binary",
        ])
        .current_dir(&ws.repo)
        .env_clear()
        .env("HOME", &ws.home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("CHINWAG_BIN", ws.base.join("missing-chinwag-bin"))
        .output()
        .unwrap();
    assert!(
        !missing_bin_commit.status.success(),
        "pre-commit must fail closed when chinwag binary is missing!"
    );
    let missing_stderr = String::from_utf8_lossy(&missing_bin_commit.stderr);
    assert!(
        missing_stderr.contains("chinwag binary unavailable"),
        "stderr={missing_stderr}"
    );
}

fn encode_openssh_ed25519_pubkey_blob(pk: &[u8; 32]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let key_type = b"ssh-ed25519";
    let mut wire = Vec::with_capacity(4 + key_type.len() + 4 + 32);
    wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    wire.extend_from_slice(key_type);
    wire.extend_from_slice(&(32_u32).to_be_bytes());
    wire.extend_from_slice(pk);

    let mut out = String::new();
    for chunk in wire.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[test]
fn security_invariants_impersonation_pr_merged_auth_allowed_signers_tilde_hooks_and_scrubbing() {
    // 1. `core.hooksPath = ~/.githooks` MUST fail closed during `chinwag init` without touching `$HOME`.
    let ws_tilde = IsolatedWorkspace::new("tilde-hooks");
    assert!(
        Command::new("git")
            .args(["config", "core.hooksPath", "~/.githooks"])
            .current_dir(&ws_tilde.repo)
            .env("HOME", &ws_tilde.home)
            .status()
            .unwrap()
            .success()
    );
    let tilde_init = ws_tilde.run_chinwag(
        &ws_tilde.repo,
        None,
        &[
            "init",
            "--repo",
            ws_tilde.repo.to_str().unwrap(),
            "--principal",
            "fixture@chinwag.test",
        ],
    );
    assert!(
        !tilde_init.status.success(),
        "core.hooksPath = ~/.githooks must fail closed!"
    );
    assert!(!ws_tilde.repo.join(".chinwag/state.crdb").exists());
    assert!(!ws_tilde.home.join(".githooks").exists());

    // 2. Initialize clean workspace + register two seats in `.chinwag/allowed_signers` (`AGENT-A` with key, `AGENT-B` without key).
    let ws = IsolatedWorkspace::new("sec-invariants");
    let init = ws.run_chinwag(
        &ws.repo,
        None,
        &[
            "init",
            "--repo",
            ws.repo.to_str().unwrap(),
            "--principal",
            "fixture@chinwag.test",
        ],
    );
    assert!(init.status.success());

    let seed_a = [0x42_u8; 32];
    let sk_a = iroh::SecretKey::from_bytes(&seed_a);
    let pk_a_b64 = encode_openssh_ed25519_pubkey_blob(sk_a.public().as_bytes());
    let seed_b = [0x99_u8; 32];
    let sk_b = iroh::SecretKey::from_bytes(&seed_b);
    let pk_b_b64 = encode_openssh_ed25519_pubkey_blob(sk_b.public().as_bytes());

    let signing_dir = ws.home.join(".chinwag/signing");
    fs::create_dir_all(&signing_dir).unwrap();
    fs::set_permissions(&signing_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let key_a_path = signing_dir.join("agent-a_ed25519.key");
    fs::write(&key_a_path, seed_a).unwrap();
    fs::set_permissions(&key_a_path, fs::Permissions::from_mode(0o600)).unwrap();

    let allowed_path = ws.repo.join(".chinwag/allowed_signers");
    let mut existing_allowed = fs::read_to_string(&allowed_path).unwrap_or_default();
    existing_allowed.push_str(&format!(
        "agent-a@chinwag.local namespaces=\"chinwag\" ssh-ed25519 {pk_a_b64} seat=AGENT-A\n\
         agent-b@chinwag.local namespaces=\"chinwag\" ssh-ed25519 {pk_b_b64} seat=AGENT-B\n"
    ));
    fs::write(&allowed_path, existing_allowed).unwrap();

    let actor_a = "AGENT-A#0123456789abcdef0123456789abcdef";
    let actor_b = "AGENT-B#fedcba9876543210fedcba9876543210";
    let actor_c_unreg = "AGENT-C#11112222333344445555666677778888";

    // 3. `--from` impersonation when `CHINWAG_ACTOR` is bound MUST fail closed (`INV-NO-SEAT-IMPERSONATION-01`).
    for bad_args in [
        vec![
            "bus",
            "emit-beacon",
            "--kind",
            "TASK_CREATED",
            "--task",
            "CHWG-0250",
            "--from",
            actor_b,
        ],
        vec!["bus", "session-lease", "--from", actor_b],
        vec![
            "bus",
            "check-claims",
            "--actor",
            actor_b,
            "--files",
            "src/engine/core.rs",
        ],
    ] {
        let imp = ws.run_chinwag(&ws.repo, Some(actor_a), &bad_args);
        assert!(
            !imp.status.success(),
            "cross-seat --from/--actor override must fail closed: {bad_args:?}"
        );
    }

    // 4. Registered seat `AGENT-B` WITHOUT matching key file fails closed (`unverified_registered_seat_signature`).
    let unverified_reg = ws.run_chinwag(
        &ws.repo,
        Some(actor_b),
        &[
            "bus",
            "emit-beacon",
            "--kind",
            "TASK_CREATED",
            "--task",
            "CHWG-0250",
        ],
    );
    assert!(
        !unverified_reg.status.success(),
        "registered seat without matching signing key must fail closed!"
    );
    assert!(
        String::from_utf8_lossy(&unverified_reg.stderr)
            .contains("unverified_registered_seat_signature")
    );

    // 5. Registered seat `AGENT-A` WITH valid `0600` key signs `chinwag-bus-sig-v2`, verifies against
    // repo `.chinwag/allowed_signers` (`sig_verified == true`), mirrors to `.chinwag/bus/messages.jsonl`
    // (`journal_mirrored == true`), and scrubs secrets + `/Users/...` host paths!
    let fake_gh = concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
    let fake_sk = concat!("sk", "-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
    let host_leak_path = concat!("/", "Users", "/alice_dev/secret_repo/core.rs");
    let dirty_summary = format!("tok={fake_gh} key={fake_sk} path={host_leak_path}");
    let claim_ok = ws.run_chinwag(
        &ws.repo,
        Some(actor_a),
        &[
            "bus",
            "emit-beacon",
            "--kind",
            "CLAIM_ACQUIRED",
            "--task",
            "CHWG-0250",
            "--surfaces",
            "src/engine/**",
            "--summary",
            &dirty_summary,
            "--json",
        ],
    );
    assert!(
        claim_ok.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&claim_ok.stderr)
    );
    let rcpt: Value = serde_json::from_slice(&claim_ok.stdout).unwrap();
    assert_eq!(rcpt["sig_verified"], true);
    assert_eq!(rcpt["journal_mirrored"], true);
    assert_eq!(rcpt["worktree"], ".");

    let journal_raw = fs::read_to_string(ws.repo.join(".chinwag/bus/messages.jsonl")).unwrap();
    let active_md = fs::read_to_string(ws.repo.join(ACTIVE_WORK_REL_PATH)).unwrap();
    for surface_txt in [&journal_raw, &active_md] {
        assert!(!surface_txt.contains(fake_gh));
        assert!(!surface_txt.contains(fake_sk));
        assert!(!surface_txt.contains("alice_dev"));
    }

    // 6. Unauthorized / cross-seat `PR_MERGED` (`LOCAL-CLI` or `AGENT-C`) MUST fail closed
    // (`unauthorized_pr_merged_release`) and preserve `AGENT-A`'s active claim!
    for attacker in [None, Some(actor_c_unreg)] {
        let spoof_merge = ws.run_chinwag(
            &ws.repo,
            attacker,
            &[
                "bus",
                "emit-beacon",
                "--kind",
                "PR_MERGED",
                "--task",
                "CHWG-0250",
            ],
        );
        assert!(
            !spoof_merge.status.success(),
            "unauthorized PR_MERGED from {attacker:?} must fail closed!"
        );
        assert!(
            String::from_utf8_lossy(&spoof_merge.stderr)
                .contains("not authorized to release active claims"),
            "stderr={}",
            String::from_utf8_lossy(&spoof_merge.stderr)
        );
    }
    let (_, _, claims_still_active, _, _) = read_live_coord_snapshot(&ws.repo).unwrap();
    assert_eq!(
        claims_still_active.len(),
        1,
        "attacker PR_MERGED must never release owner's active path claim!"
    );

    // 7. Verified claim owner `AGENT-A` emits `PR_MERGED` -> claim released cleanly!
    let owner_merge = ws.run_chinwag(
        &ws.repo,
        Some(actor_a),
        &[
            "bus",
            "emit-beacon",
            "--kind",
            "PR_MERGED",
            "--task",
            "CHWG-0250",
            "--json",
        ],
    );
    assert!(
        owner_merge.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&owner_merge.stderr)
    );
    let (_, _, claims_released, _, _) = read_live_coord_snapshot(&ws.repo).unwrap();
    assert!(claims_released.is_empty());
}

#[test]
fn rename_escape_no_verify_ref_tx_linked_worktree_rel_hooks_and_interleaved_cursor_are_fenced() {
    let ws = IsolatedWorkspace::new("fenced-edge-cases");
    assert!(
        Command::new("git")
            .args(["config", "core.hooksPath", ".githooks"])
            .current_dir(&ws.repo)
            .env("HOME", &ws.home)
            .status()
            .unwrap()
            .success()
    );
    let init = ws.run_chinwag(
        &ws.repo,
        None,
        &[
            "init",
            "--repo",
            ws.repo.to_str().unwrap(),
            "--principal",
            "fixture@chinwag.test",
        ],
    );
    assert!(init.status.success());

    let owner_b = "PEER-B#fedcba9876543210fedcba9876543210";
    let peer_a = "PEER-A#0123456789abcdef0123456789abcdef";

    // 1. Interleaved cursor check: `owner_b` emits `#1` (`CLAIM_ACQUIRED` on `src/engine/**`),
    // then `peer_a` emits `#2` (`TASK_CREATED` on `CHWG-0250-DOC`) BEFORE `peer_a` ever checks deltas.
    // `peer_a`'s next CLI command MUST still surface `owner_b`'s `#1` without self-echoing `#2`!
    let claim_b = ws.run_chinwag(
        &ws.repo,
        Some(owner_b),
        &[
            "bus",
            "emit-beacon",
            "--kind",
            "CLAIM_ACQUIRED",
            "--task",
            "CHWG-0250",
            "--surfaces",
            "src/engine/**",
            "--json",
        ],
    );
    assert!(claim_b.status.success());

    let task_a = emit_transactional_beacon(
        &ws.repo,
        &AutoBeaconRequest {
            kind: Some(BeaconKind::TaskCreated),
            actor: Some(peer_a.to_owned()),
            ticket_id: "CHWG-0250-DOC".to_owned(),
            ..Default::default()
        },
    )
    .expect("in-process emit_transactional_beacon for #2 must succeed");
    assert_eq!(task_a.seq, 2);

    let delta_a = ws.run_chinwag(&ws.repo, Some(peer_a), &["tasks", "--help"]);
    assert!(delta_a.status.success());
    let delta_stderr = String::from_utf8_lossy(&delta_a.stderr);
    assert!(
        delta_stderr.contains("#1 CLAIM_ACQUIRED CHWG-0250"),
        "peer_a must still receive unread #1 from owner_b; stderr={delta_stderr}"
    );
    assert!(
        !delta_stderr.contains("CHWG-0250-DOC"),
        "peer_a must not echo its own #2 beacon; stderr={delta_stderr}"
    );

    // 2. Fresh linked worktree under relative `core.hooksPath = .githooks` automatically receives
    // `.githooks/{post-checkout,pre-commit,reference-transaction}` AND fences overlapping commits!
    let wt_linked = ws.base.join("wt-linked-fenced");
    assert!(
        Command::new("git")
            .args([
                "worktree",
                "add",
                "-b",
                "feat/linked-fenced",
                wt_linked.to_str().unwrap(),
                "HEAD",
            ])
            .current_dir(&ws.repo)
            .env_clear()
            .env("HOME", &ws.home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("CHINWAG_BIN", env!("CARGO_BIN_EXE_chinwag"))
            .status()
            .unwrap()
            .success()
    );
    for hook in ["post-checkout", "pre-commit", "reference-transaction"] {
        assert!(
            wt_linked.join(".githooks").join(hook).is_file(),
            "linked worktree missing relative hook {hook}"
        );
    }

    // 3. Staged rename (`git mv src/engine/core.rs docs/escaped.rs`) inside `wt_linked` MUST fail closed!
    assert!(
        Command::new("git")
            .args(["mv", "src/engine/core.rs", "docs/escaped.rs"])
            .current_dir(&wt_linked)
            .env("HOME", &ws.home)
            .status()
            .unwrap()
            .success()
    );
    let rename_commit = Command::new("git")
        .args([
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "rename escape",
        ])
        .current_dir(&wt_linked)
        .env_clear()
        .env("HOME", &ws.home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("CHINWAG_BIN", env!("CARGO_BIN_EXE_chinwag"))
        .output()
        .unwrap();
    assert!(
        !rename_commit.status.success(),
        "staged rename out of claimed glob must fail closed!"
    );
    assert!(
        String::from_utf8_lossy(&rename_commit.stderr).contains("src/engine/core.rs"),
        "stderr={}",
        String::from_utf8_lossy(&rename_commit.stderr)
    );

    // 4. `git commit --no-verify` bypassing `pre-commit` MUST still fail closed in
    // `reference-transaction prepared` without advancing `HEAD`!
    let head_before = String::from_utf8_lossy(
        &Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&wt_linked)
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_owned();

    let no_verify_commit = Command::new("git")
        .args([
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--no-verify",
            "-m",
            "bypass pre-commit attempt",
        ])
        .current_dir(&wt_linked)
        .env_clear()
        .env("HOME", &ws.home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("CHINWAG_BIN", env!("CARGO_BIN_EXE_chinwag"))
        .output()
        .unwrap();
    assert!(
        !no_verify_commit.status.success(),
        "git commit --no-verify on claimed surface must fail closed in reference-transaction prepared!"
    );
    let head_after = String::from_utf8_lossy(
        &Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&wt_linked)
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_owned();
    assert_eq!(
        head_before, head_after,
        "HEAD must not advance when reference-transaction prepared blocks conflicting commit!"
    );
}
