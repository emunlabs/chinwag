// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]

//! End to end: the environment built for a seat makes a real `git commit` in a
//! temp repo produce an SSH-signed commit by a temp key, even when the repo
//! carries a conflicting local identity and the inherited environment already
//! has a `GIT_CONFIG_COUNT` entry.

use chinwag_cli::seat_signing::{SIGNING_EMAIL, SeatSigning, build};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let n = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("chinwag-seat-signing-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("home/.chinwag/signing")).expect("create signing dir");
        fs::create_dir_all(root.join("repo/.chinwag")).expect("create repo dir");
        Self { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn repo(&self) -> PathBuf {
        self.root.join("repo")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A git command isolated from the developer's own configuration.
fn git(fixture: &Fixture, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(fixture.repo())
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HOME", fixture.home())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args(args);
    command
}

fn run(mut command: Command) -> Output {
    let output = command.output().expect("spawn command");
    // Report the program and arguments only, never the environment.
    assert!(
        output.status.success(),
        "{:?} {:?} failed: {}",
        command.get_program(),
        command.get_args().collect::<Vec<_>>(),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Apply the inherited `GIT_CONFIG_*` entry plus the seat's appended entries.
fn with_seat_env(command: &mut Command, signing: &SeatSigning) {
    command
        .env("GIT_CONFIG_KEY_0", "core.abbrev")
        .env("GIT_CONFIG_VALUE_0", "12")
        .envs(signing.env.iter().cloned());
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn make_key(path: &Path, comment: &str) {
    let output = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path)
        .output()
        .expect("spawn ssh-keygen");
    assert!(output.status.success(), "ssh-keygen failed");
}

#[test]
fn seat_env_signs_a_commit_with_the_seat_key_and_keeps_existing_config() {
    let fixture = Fixture::new();
    make_key(
        &fixture.home().join(".chinwag/signing/eng_ed25519"),
        "eng test",
    );

    // allowed_signers: principal = the committer email, key = the seat's public key.
    let public = fs::read_to_string(fixture.home().join(".chinwag/signing/eng_ed25519.pub"))
        .expect("read public key");
    let key_fields: Vec<&str> = public.split_whitespace().take(2).collect();
    fs::write(
        fixture.repo().join(".chinwag/allowed_signers"),
        format!(
            "{SIGNING_EMAIL} {} chinwag ENG signing\n",
            key_fields.join(" ")
        ),
    )
    .expect("write allowed_signers");

    run(git(&fixture, &["init", "-q"]));
    // The repo-wide override that the per-seat environment has to beat.
    run(git(
        &fixture,
        &["config", "user.name", "Gemini PM (Antigravity)"],
    ));
    run(git(
        &fixture,
        &["config", "user.email", "gemini-pm@chinwag.sh"],
    ));
    run(git(
        &fixture,
        &["config", "user.signingkey", "/nonexistent/signer"],
    ));
    run(git(&fixture, &["config", "commit.gpgsign", "false"]));

    // The environment the engine would inherit already carries one entry.
    let signing = build("ENG", &fixture.home(), &fixture.repo(), Some("1"));
    assert!(signing.is_active(), "{:?}", signing.warning);
    let mut command = git(
        &fixture,
        &[
            "commit",
            "--allow-empty",
            "-q",
            "-m",
            "signed by seat key",
            "--trailer",
            "Agent: ENG",
        ],
    );
    with_seat_env(&mut command, &signing);
    run(command);

    // Commit identity comes from the seat, not the repo-local override.
    let log = stdout(&run(git(
        &fixture,
        &["log", "-1", "--format=%an|%ae|%cn|%ce"],
    )));
    assert_eq!(
        log,
        format!("ENG (agent)|{SIGNING_EMAIL}|ENG (agent)|{SIGNING_EMAIL}")
    );

    // The Agent trailer is present.
    let body = stdout(&run(git(&fixture, &["log", "-1", "--format=%B"])));
    assert!(body.ends_with("Agent: ENG"), "{body}");

    // It carries an SSH signature.
    let raw = stdout(&run(git(&fixture, &["cat-file", "-p", "HEAD"])));
    assert!(raw.contains("-----BEGIN SSH SIGNATURE-----"));

    // And it verifies against the allowed signers file the env pointed at.
    let mut verify = git(&fixture, &["verify-commit", "HEAD"]);
    with_seat_env(&mut verify, &signing);
    let verified = run(verify);
    let report = String::from_utf8_lossy(&verified.stderr).into_owned();
    assert!(report.contains("Good \"git\" signature"), "{report}");
    assert!(report.contains(SIGNING_EMAIL), "{report}");

    // The pre-existing GIT_CONFIG entry still applies next to ours.
    let mut abbrev = git(&fixture, &["config", "--get", "core.abbrev"]);
    with_seat_env(&mut abbrev, &signing);
    assert_eq!(stdout(&run(abbrev)), "12");
}

#[test]
fn missing_key_leaves_commits_on_the_repo_identity() {
    let fixture = Fixture::new();
    let signing = build("RUST", &fixture.home(), &fixture.repo(), None);
    assert!(!signing.is_active());
    assert!(signing.warning.is_some());

    run(git(&fixture, &["init", "-q"]));
    run(git(&fixture, &["config", "user.name", "Repo Identity"]));
    run(git(
        &fixture,
        &["config", "user.email", "repo@example.invalid"],
    ));
    run(git(&fixture, &["config", "commit.gpgsign", "false"]));
    let mut command = git(&fixture, &["commit", "--allow-empty", "-q", "-m", "plain"]);
    command.envs(signing.env.iter().cloned());
    run(command);
    let log = stdout(&run(git(&fixture, &["log", "-1", "--format=%an|%ae"])));
    assert_eq!(log, "Repo Identity|repo@example.invalid");
    let raw = stdout(&run(git(&fixture, &["cat-file", "-p", "HEAD"])));
    assert!(!raw.contains("SSH SIGNATURE"));
}
