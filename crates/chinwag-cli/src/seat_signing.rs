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

//! Per-seat git signing environment for engine processes spawned by
//! `chinwag agent-dispatch`.
//!
//! Each seat (ARCHITECT, RUST, ENG, ...) owns an Ed25519 key under
//! `~/.chinwag/signing/<seat>_ed25519(.pub)`. When a key pair exists, the
//! engine process is given `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/
//! `GIT_CONFIG_VALUE_n` entries that make git sign commits as that seat. These
//! entries use git's command-level config scope, so they win over repo-local
//! overrides. They are appended after any entries already in the environment.
//!
//! No git hooks are involved. The commit trailer is requested through the seat
//! brief plus the `CHINWAG_AGENT` environment variable.

use std::path::{Path, PathBuf};

/// Brian's GitHub noreply address. Per-agent commits use it so GitHub can tie
/// the signing keys uploaded under `spector-in-london` to the commit.
pub const SIGNING_EMAIL: &str = "2736922+spector-in-london@users.noreply.github.com";

/// Number of `GIT_CONFIG_*` entries this module appends.
const ENTRY_COUNT: u64 = 6;

/// Environment to add to a seat's engine process, or a reason it was skipped.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SeatSigning {
    /// Variables to set on the child process. Empty when signing is skipped.
    pub env: Vec<(String, String)>,
    /// Human-readable reason signing was skipped, if it was.
    pub warning: Option<String>,
}

impl SeatSigning {
    /// True when the engine process will sign commits as the seat.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.env.is_empty()
    }

    fn skipped(reason: String) -> Self {
        Self {
            env: Vec::new(),
            warning: Some(reason),
        }
    }
}

/// Lower-case file stem for a seat name, or `None` if the name is not a plain
/// seat identifier (letters, digits and `-` only).
#[must_use]
pub fn seat_slug(seat: &str) -> Option<String> {
    let seat = seat.trim();
    if seat.is_empty()
        || seat.starts_with('-')
        || !seat.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return None;
    }
    Some(seat.to_ascii_lowercase())
}

fn key_paths(home: &Path, slug: &str) -> (PathBuf, PathBuf) {
    let dir = home.join(".chinwag").join("signing");
    (
        dir.join(format!("{slug}_ed25519.pub")),
        dir.join(format!("{slug}_ed25519")),
    )
}

/// Build the signing environment for `seat`.
///
/// `existing_count` is the current value of `GIT_CONFIG_COUNT` in the
/// environment the engine will inherit (`None` when unset). Existing
/// `GIT_CONFIG_KEY_i`/`VALUE_i` entries stay untouched; new entries start at
/// index `existing_count` and `GIT_CONFIG_COUNT` is raised accordingly.
///
/// Never panics and never reads key contents: it only checks that the key
/// files exist. Missing keys, a bad seat name or an unparsable existing count
/// produce no environment and a warning.
#[must_use]
pub fn build(
    seat: &str,
    home: &Path,
    repo_root: &Path,
    existing_count: Option<&str>,
) -> SeatSigning {
    let seat = seat.trim();
    let Some(slug) = seat_slug(seat) else {
        return SeatSigning::skipped(format!(
            "seat {seat:?} is not a plain seat name; commit signing not injected"
        ));
    };
    let (public_key, private_key) = key_paths(home, &slug);
    if !public_key.is_file() || !private_key.is_file() {
        return SeatSigning::skipped(format!(
            "no signing key pair for seat {seat} at {}; commit signing not injected",
            public_key.display()
        ));
    }
    let base = match existing_count {
        None => 0,
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(n) if n < 1_000_000 => n,
            _ => {
                return SeatSigning::skipped(
                    "GIT_CONFIG_COUNT in the environment is not a usable count; \
                     commit signing not injected"
                        .to_owned(),
                );
            }
        },
    };

    let seat_upper = seat.to_ascii_uppercase();
    let allowed_signers = repo_root.join(".chinwag").join("allowed_signers");
    let entries: [(&str, String); ENTRY_COUNT as usize] = [
        ("user.name", format!("{seat_upper} (agent)")),
        ("user.email", SIGNING_EMAIL.to_owned()),
        ("user.signingkey", public_key.to_string_lossy().into_owned()),
        ("gpg.format", "ssh".to_owned()),
        ("commit.gpgsign", "true".to_owned()),
        (
            "gpg.ssh.allowedSignersFile",
            allowed_signers.to_string_lossy().into_owned(),
        ),
    ];

    let mut env = Vec::with_capacity(entries.len() * 2 + 2);
    for (offset, (key, value)) in (0..).zip(entries) {
        let index = base + offset;
        env.push((format!("GIT_CONFIG_KEY_{index}"), key.to_owned()));
        env.push((format!("GIT_CONFIG_VALUE_{index}"), value));
    }
    env.push((
        "GIT_CONFIG_COUNT".to_owned(),
        (base + ENTRY_COUNT).to_string(),
    ));
    env.push(("CHINWAG_AGENT".to_owned(), seat_upper));
    SeatSigning { env, warning: None }
}

/// [`build`] using the real process environment for `GIT_CONFIG_COUNT`.
#[must_use]
pub fn resolve(seat: &str, home: &Path, repo_root: &Path) -> SeatSigning {
    let existing = std::env::var("GIT_CONFIG_COUNT").ok();
    build(seat, home, repo_root, existing.as_deref())
}

/// Note appended to the seat brief when signing is injected.
#[must_use]
pub fn brief_note(seat: &str) -> String {
    let seat = seat.trim().to_ascii_uppercase();
    format!(
        "\n--- Commit Signing ({seat}) ---\nGit in this session signs commits as \"{seat} (agent)\" with your own seat key. \
         Every commit you make must carry the trailer `Agent: {seat}`, for example \
         `git commit --trailer \"Agent: {seat}\" -m ...` (CHINWAG_AGENT={seat} is set in your environment). \
         Do not use git hooks to add it and do not change user.name, user.email or user.signingkey."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Home(PathBuf);

    impl Home {
        fn new() -> Self {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "chinwag-seat-signing-unit-{}-{n}",
                std::process::id()
            ));
            fs::create_dir_all(root.join(".chinwag/signing")).expect("create fixture home");
            Self(root)
        }

        fn add_seat_keys(&self, slug: &str) {
            let (public_key, private_key) = key_paths(&self.0, slug);
            fs::write(public_key, "ssh-ed25519 AAAA test\n").expect("write public key");
            fs::write(private_key, "not a real key\n").expect("write placeholder key file");
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn get<'a>(signing: &'a SeatSigning, key: &str) -> Option<&'a str> {
        signing
            .env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn slug_accepts_seat_names_and_rejects_everything_else() {
        assert_eq!(seat_slug("ENG").as_deref(), Some("eng"));
        assert_eq!(seat_slug(" GEMINI-PM ").as_deref(), Some("gemini-pm"));
        assert_eq!(seat_slug("DEV-3").as_deref(), Some("dev-3"));
        for bad in ["", "  ", "INFRA BOT (GROK)", "../eng", "a/b", "-x", "EN\nG"] {
            assert_eq!(seat_slug(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn builds_six_entries_from_zero_when_count_is_unset() {
        let home = Home::new();
        home.add_seat_keys("eng");
        let repo = home.0.join("repo");
        let signing = build("ENG", &home.0, &repo, None);

        assert!(signing.is_active());
        assert_eq!(signing.warning, None);
        let expected = [
            ("user.name", "ENG (agent)".to_owned()),
            ("user.email", SIGNING_EMAIL.to_owned()),
            (
                "user.signingkey",
                home.0
                    .join(".chinwag/signing/eng_ed25519.pub")
                    .to_string_lossy()
                    .into_owned(),
            ),
            ("gpg.format", "ssh".to_owned()),
            ("commit.gpgsign", "true".to_owned()),
            (
                "gpg.ssh.allowedSignersFile",
                repo.join(".chinwag/allowed_signers")
                    .to_string_lossy()
                    .into_owned(),
            ),
        ];
        for (i, (key, value)) in expected.iter().enumerate() {
            assert_eq!(get(&signing, &format!("GIT_CONFIG_KEY_{i}")), Some(*key));
            assert_eq!(
                get(&signing, &format!("GIT_CONFIG_VALUE_{i}")),
                Some(value.as_str())
            );
        }
        assert_eq!(get(&signing, "GIT_CONFIG_COUNT"), Some("6"));
        assert_eq!(get(&signing, "CHINWAG_AGENT"), Some("ENG"));
        assert_eq!(get(&signing, "GIT_CONFIG_KEY_6"), None);
    }

    #[test]
    fn appends_after_existing_entries_without_touching_them() {
        let home = Home::new();
        home.add_seat_keys("architect");
        let signing = build("architect", &home.0, &home.0, Some("3"));

        assert_eq!(get(&signing, "GIT_CONFIG_COUNT"), Some("9"));
        for i in 0..3 {
            assert_eq!(get(&signing, &format!("GIT_CONFIG_KEY_{i}")), None);
            assert_eq!(get(&signing, &format!("GIT_CONFIG_VALUE_{i}")), None);
        }
        assert_eq!(get(&signing, "GIT_CONFIG_KEY_3"), Some("user.name"));
        assert_eq!(
            get(&signing, "GIT_CONFIG_VALUE_3"),
            Some("ARCHITECT (agent)")
        );
        assert_eq!(
            get(&signing, "GIT_CONFIG_KEY_8"),
            Some("gpg.ssh.allowedSignersFile")
        );
        assert_eq!(get(&signing, "CHINWAG_AGENT"), Some("ARCHITECT"));
    }

    #[test]
    fn existing_count_with_whitespace_is_accepted() {
        let home = Home::new();
        home.add_seat_keys("rust");
        let signing = build("RUST", &home.0, &home.0, Some(" 1\n"));
        assert_eq!(get(&signing, "GIT_CONFIG_COUNT"), Some("7"));
        assert_eq!(get(&signing, "GIT_CONFIG_KEY_1"), Some("user.name"));
    }

    #[test]
    fn unusable_existing_count_injects_nothing_and_warns() {
        let home = Home::new();
        home.add_seat_keys("eng");
        for bad in ["", "abc", "-1", "1.5", "99999999999999999999", "2000000"] {
            let signing = build("ENG", &home.0, &home.0, Some(bad));
            assert!(!signing.is_active(), "{bad:?}");
            assert!(
                signing
                    .warning
                    .as_deref()
                    .is_some_and(|w| w.contains("GIT_CONFIG_COUNT")),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn missing_key_files_inject_nothing_and_warn() {
        let home = Home::new();
        let none = build("FLINT", &home.0, &home.0, None);
        assert_eq!(none.env, Vec::new());
        assert!(none.warning.as_deref().is_some_and(|w| w.contains("FLINT")));

        // Public key only: signing would fail at commit time, so still skip.
        let (public_key, _) = key_paths(&home.0, "flint");
        fs::write(public_key, "ssh-ed25519 AAAA test\n").expect("write public key");
        assert!(!build("FLINT", &home.0, &home.0, None).is_active());

        // Private key only is equally unusable for the configured .pub path.
        let other = Home::new();
        let (_, private_key) = key_paths(&other.0, "infra");
        fs::write(private_key, "x").expect("write private placeholder");
        assert!(!build("INFRA", &other.0, &other.0, None).is_active());
    }

    #[test]
    fn invalid_seat_names_never_reach_the_filesystem() {
        let home = Home::new();
        let signing = build("INFRA BOT (GROK)", &home.0, &home.0, None);
        assert!(!signing.is_active());
        assert!(signing.warning.is_some());
        assert!(!build("../../etc/passwd", &home.0, &home.0, None).is_active());
    }

    #[test]
    fn brief_note_asks_for_the_trailer() {
        let note = brief_note("eng");
        assert!(note.contains("Agent: ENG"));
        assert!(note.contains("--trailer"));
        assert!(note.contains("CHINWAG_AGENT=ENG"));
    }
}
