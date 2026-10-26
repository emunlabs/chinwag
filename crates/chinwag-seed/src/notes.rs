//! Byte-exact, append-only publication of capsules into a Git notes ref.
//!
//! This primitive neither creates source commits nor approves their contents.
//! A private staging ref is based on one observed notes tip; compare-and-swap
//! publishes that complete tree. A crash may leave an owned staging ref and
//! unreachable objects, but cannot publish half a note.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use rand::{RngCore, SeedableRng, rngs::StdRng};

use crate::vault::{Binding, MAX_CAPSULE_BYTES};

pub const NOTES_REF: &str = "refs/notes/emun-vault";
const STAGE_PREFIX: &str = "refs/notes/emun-vault-stage/";
const MAX_TREE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("expected a full lowercase source commit object id")]
    InvalidOid,
    #[error("the source object is missing or is not a commit")]
    NotACommit,
    #[error("the capsule exceeds its size limit")]
    Size,
    #[error("this commit already has a different capsule")]
    ExistingDifferent,
    #[error("this commit has no capsule")]
    MissingNote,
    #[error("the notes reference is symbolic")]
    SymbolicRef,
    #[error("Git did not preserve the capsule bytes")]
    ReadbackMismatch,
    #[error("the notes reference changed during publication")]
    StaleTip,
    #[error("the notes reference kept changing; publication was refused")]
    Contention,
    #[error("could not obtain entropy for the private staging reference")]
    Entropy,
    #[error("the local Git operation failed")]
    Git,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Publication {
    Created,
    AlreadyPresent,
}

struct Git {
    repo: PathBuf,
}

struct Output {
    status: ExitStatus,
    bytes: Vec<u8>,
}

impl Git {
    fn run(&self, args: &[&str], input: Option<&[u8]>, limit: usize) -> Result<Output, Error> {
        let mut command = Command::new("/usr/bin/git");
        // A caller's shell must not redirect this operation into another repo,
        // object directory, index, namespace, config include, or notes ref.
        for (key, _) in std::env::vars_os() {
            if key.as_encoded_bytes().starts_with(b"GIT_") {
                command.env_remove(key);
            }
        }
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "--no-replace-objects",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.pager=cat",
                "-c",
                "credential.helper=",
                "-c",
                "gc.auto=0",
                "-C",
            ])
            .arg(&self.repo)
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|_| Error::Git)?;
        if let Some(input) = input {
            let result = child.stdin.take().ok_or(Error::Git)?.write_all(input);
            if result.is_err() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Git);
            }
        }
        let mut bytes = Vec::new();
        let result = child
            .stdout
            .take()
            .ok_or(Error::Git)?
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes);
        if result.is_err() || bytes.len() > limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Git);
        }
        let status = child.wait().map_err(|_| Error::Git)?;
        Ok(Output { status, bytes })
    }

    fn checked(&self, args: &[&str], input: Option<&[u8]>, limit: usize) -> Result<Vec<u8>, Error> {
        let out = self.run(args, input, limit)?;
        out.status.success().then_some(out.bytes).ok_or(Error::Git)
    }

    fn tip(&self, reference: &str) -> Result<Option<String>, Error> {
        let symbolic = self.run(
            &["symbolic-ref", "--quiet", "--no-recurse", reference],
            None,
            1024,
        )?;
        match symbolic.status.code() {
            Some(0) => return Err(Error::SymbolicRef),
            Some(1) => {}
            _ => return Err(Error::Git),
        }
        let out = self.run(
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                reference,
            ],
            None,
            128,
        )?;
        match out.status.code() {
            Some(0) => Ok(Some(parse_oid_line(&out.bytes)?)),
            Some(1) => Ok(None),
            _ => Err(Error::Git),
        }
    }

    fn validate_commit(&self, oid: &str) -> Result<(), Error> {
        Binding::public_chinwag(oid).map_err(|_| Error::InvalidOid)?;
        let out = self.run(&["cat-file", "-t", oid], None, 64)?;
        if out.status.success() && out.bytes == b"commit\n" {
            Ok(())
        } else {
            Err(Error::NotACommit)
        }
    }

    fn read_blob(&self, blob: &str) -> Result<Vec<u8>, Error> {
        let size = self.checked(&["cat-file", "-s", blob], None, 64)?;
        let size: usize = std::str::from_utf8(&size)
            .map_err(|_| Error::Git)?
            .trim()
            .parse()
            .map_err(|_| Error::Git)?;
        if size > MAX_CAPSULE_BYTES {
            return Err(Error::Size);
        }
        let bytes = self.checked(&["cat-file", "blob", blob], None, MAX_CAPSULE_BYTES)?;
        if bytes.len() != size {
            return Err(Error::ReadbackMismatch);
        }
        Ok(bytes)
    }

    fn note_at(&self, tip: Option<&str>, oid: &str) -> Result<Option<Vec<u8>>, Error> {
        let Some(tip) = tip else {
            return Ok(None);
        };
        self.validate_commit(tip)?;
        let entries = self.checked(
            &["ls-tree", "-r", "-z", "--full-tree", tip],
            None,
            MAX_TREE_BYTES,
        )?;
        let mut found = None;
        for entry in entries.split(|b| *b == 0).filter(|entry| !entry.is_empty()) {
            let separator = entry.iter().position(|b| *b == b'\t').ok_or(Error::Git)?;
            let (metadata, remainder) = entry.split_at(separator);
            let path = &remainder[1..];
            if path.iter().copied().filter(|b| *b != b'/').ne(oid.bytes()) {
                continue;
            }
            if found.is_some() {
                return Err(Error::Git);
            }
            let fields = metadata.split(|b| *b == b' ').collect::<Vec<_>>();
            if fields.len() != 3 || fields[0] != b"100644" || fields[1] != b"blob" {
                return Err(Error::Git);
            }
            let blob = std::str::from_utf8(fields[2]).map_err(|_| Error::Git)?;
            Binding::public_chinwag(blob).map_err(|_| Error::Git)?;
            found = Some(self.read_blob(blob)?);
        }
        Ok(found)
    }
}

fn parse_oid_line(bytes: &[u8]) -> Result<String, Error> {
    let oid = std::str::from_utf8(bytes)
        .map_err(|_| Error::Git)?
        .strip_suffix('\n')
        .ok_or(Error::Git)?;
    Binding::public_chinwag(oid).map_err(|_| Error::Git)?;
    Ok(oid.to_owned())
}

struct Stage {
    git: Git,
    reference: String,
    tip: Option<String>,
}

impl Drop for Stage {
    fn drop(&mut self) {
        if let Some(tip) = &self.tip {
            // Never delete a ref another writer changed after our last read.
            let _ = self.git.run(
                &["update-ref", "--no-deref", "-d", &self.reference, tip],
                None,
                1024,
            );
        }
    }
}

struct Prepared {
    stage: Stage,
    expected: Option<String>,
    candidate: String,
}

impl Prepared {
    fn publish(self) -> Result<(), Error> {
        if self.stage.git.tip(NOTES_REF)? != self.expected {
            return Err(Error::StaleTip);
        }
        let zero = "0".repeat(self.candidate.len());
        let old = self.expected.as_deref().unwrap_or(&zero);
        let out = self.stage.git.run(
            &["update-ref", "--no-deref", NOTES_REF, &self.candidate, old],
            None,
            1024,
        )?;
        if !out.status.success() {
            return if self.stage.git.tip(NOTES_REF)? != self.expected {
                Err(Error::StaleTip)
            } else {
                Err(Error::Git)
            };
        }
        Ok(())
    }
}

enum Preparation {
    Present,
    Ready(Prepared),
}

fn prepare(repo: &Path, oid: &str, capsule: &[u8]) -> Result<Preparation, Error> {
    let git = Git {
        repo: repo.to_owned(),
    };
    git.validate_commit(oid)?;
    if capsule.len() > MAX_CAPSULE_BYTES {
        return Err(Error::Size);
    }
    let expected = git.tip(NOTES_REF)?;
    if let Some(existing) = git.note_at(expected.as_deref(), oid)? {
        return if existing == capsule {
            Ok(Preparation::Present)
        } else {
            Err(Error::ExistingDifferent)
        };
    }
    let mut nonce = [0u8; 16];
    StdRng::try_from_os_rng()
        .map_err(|_| Error::Entropy)?
        .fill_bytes(&mut nonce);
    let reference = format!(
        "{STAGE_PREFIX}{}",
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    if git.tip(&reference)?.is_some() {
        return Err(Error::Git);
    }
    let mut stage = Stage {
        git,
        reference,
        tip: None,
    };
    if let Some(base) = &expected {
        let zero = "0".repeat(base.len());
        stage.git.checked(
            &["update-ref", "--no-deref", &stage.reference, base, &zero],
            None,
            1024,
        )?;
        stage.tip = Some(base.clone());
    }
    let blob = parse_oid_line(&stage.git.checked(
        &["hash-object", "-w", "--stdin"],
        Some(capsule),
        128,
    )?)?;
    stage.git.checked(
        &[
            "notes",
            &format!("--ref={}", stage.reference),
            "add",
            "-C",
            &blob,
            oid,
        ],
        None,
        1024,
    )?;
    let candidate = stage.git.tip(&stage.reference)?.ok_or(Error::Git)?;
    stage.tip = Some(candidate.clone());
    if stage.git.note_at(Some(&candidate), oid)?.as_deref() != Some(capsule) {
        return Err(Error::ReadbackMismatch);
    }
    Ok(Preparation::Ready(Prepared {
        stage,
        expected,
        candidate,
    }))
}

/// Publish one capsule without replacing any existing capsule.
/// A moved notes tip is rebuilt from its winner, at most eight times.
pub fn publish_exact(repo: &Path, oid: &str, capsule: &[u8]) -> Result<Publication, Error> {
    for _ in 0..MAX_ATTEMPTS {
        match prepare(repo, oid, capsule)? {
            Preparation::Present => return Ok(Publication::AlreadyPresent),
            Preparation::Ready(note) => match note.publish() {
                Ok(()) => return Ok(Publication::Created),
                Err(Error::StaleTip) => continue,
                Err(error) => return Err(error),
            },
        }
    }
    Err(Error::Contention)
}

/// Read one accepted capsule from a single observed notes snapshot.
/// This operation creates no objects or refs.
pub fn read_exact(repo: &Path, oid: &str) -> Result<Vec<u8>, Error> {
    let git = Git {
        repo: repo.to_owned(),
    };
    git.validate_commit(oid)?;
    git.note_at(git.tip(NOTES_REF)?.as_deref(), oid)?
        .ok_or(Error::MissingNote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Recipient, Slot, open, seal};

    struct Fixture {
        directory: tempfile::TempDir,
        first: String,
        second: String,
        tree: String,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let git = Git {
                repo: directory.path().to_owned(),
            };
            git.checked(&["init", "--quiet", "--initial-branch=main"], None, 1024)
                .unwrap();
            for (name, value) in [
                ("user.name", "Synthetic Fixture"),
                ("user.email", "fixture@example.invalid"),
                ("commit.gpgSign", "false"),
            ] {
                git.checked(&["config", name, value], None, 1024).unwrap();
            }
            std::fs::write(directory.path().join("fixture.txt"), b"synthetic only\n").unwrap();
            git.checked(&["add", "fixture.txt"], None, 1024).unwrap();
            let tree = parse_oid_line(&git.checked(&["write-tree"], None, 128).unwrap()).unwrap();
            let first = parse_oid_line(
                &git.checked(&["commit-tree", &tree], Some(b"fixture one\n"), 128)
                    .unwrap(),
            )
            .unwrap();
            let second = parse_oid_line(
                &git.checked(
                    &["commit-tree", &tree, "-p", &first],
                    Some(b"fixture two\n"),
                    128,
                )
                .unwrap(),
            )
            .unwrap();
            git.checked(&["update-ref", "refs/heads/main", &first], None, 1024)
                .unwrap();
            Self {
                directory,
                first,
                second,
                tree,
            }
        }

        fn path(&self) -> &Path {
            self.directory.path()
        }
        fn git(&self) -> Git {
            Git {
                repo: self.path().to_owned(),
            }
        }
        fn capsule(&self, last: u8) -> Vec<u8> {
            let mut bytes = (0..=255).collect::<Vec<u8>>();
            bytes.extend_from_slice(&[0, 0xff, last]);
            bytes
        }
    }

    #[test]
    fn preserves_binary_bytes_and_refuses_replacement() {
        let fixture = Fixture::new();
        let capsule = fixture.capsule(b'\n');
        assert_eq!(
            publish_exact(fixture.path(), &fixture.first, &capsule).unwrap(),
            Publication::Created
        );
        assert_eq!(read_exact(fixture.path(), &fixture.first).unwrap(), capsule);
        assert_eq!(
            fixture
                .git()
                .checked(
                    &[
                        "notes",
                        &format!("--ref={NOTES_REF}"),
                        "show",
                        &fixture.first
                    ],
                    None,
                    MAX_CAPSULE_BYTES
                )
                .unwrap(),
            capsule
        );
        let tip = fixture.git().tip(NOTES_REF).unwrap();
        assert_eq!(
            publish_exact(fixture.path(), &fixture.first, &capsule).unwrap(),
            Publication::AlreadyPresent
        );
        assert_eq!(fixture.git().tip(NOTES_REF).unwrap(), tip);
        assert!(matches!(
            publish_exact(fixture.path(), &fixture.first, &fixture.capsule(b'x')),
            Err(Error::ExistingDifferent)
        ));
        assert_eq!(fixture.git().tip(NOTES_REF).unwrap(), tip);
        assert_eq!(read_exact(fixture.path(), &fixture.first).unwrap(), capsule);
        let other = fixture.capsule(b'x');
        publish_exact(fixture.path(), &fixture.second, &other).unwrap();
        assert_eq!(read_exact(fixture.path(), &fixture.second).unwrap(), other);
        assert_eq!(read_exact(fixture.path(), &fixture.first).unwrap(), capsule);
    }

    #[test]
    fn rejects_revisions_missing_objects_and_non_commits_before_notes_write() {
        let fixture = Fixture::new();
        for oid in [
            "HEAD",
            "../main",
            "",
            "1111111111111111111111111111111111111111\n",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "0123456789012345678901234567890123456789^{commit}",
        ] {
            assert!(matches!(
                publish_exact(fixture.path(), oid, b"unused"),
                Err(Error::InvalidOid)
            ));
        }
        let blob = parse_oid_line(
            &fixture
                .git()
                .checked(&["hash-object", "-w", "--stdin"], Some(b"blob"), 128)
                .unwrap(),
        )
        .unwrap();
        for oid in [&blob, &fixture.tree, &"f".repeat(40)] {
            assert!(matches!(
                publish_exact(fixture.path(), oid, b"unused"),
                Err(Error::NotACommit)
            ));
        }
        assert!(fixture.git().tip(NOTES_REF).unwrap().is_none());
        assert!(matches!(
            read_exact(fixture.path(), &fixture.first),
            Err(Error::MissingNote)
        ));
        assert!(fixture.git().tip(NOTES_REF).unwrap().is_none());
    }

    fn ready(fixture: &Fixture, oid: &str, capsule: &[u8]) -> Prepared {
        let Preparation::Ready(note) = prepare(fixture.path(), oid, capsule).unwrap() else {
            panic!("unexpected existing note");
        };
        note
    }

    #[test]
    fn stale_prepared_note_cannot_replace_another_winner_and_rebuild_keeps_both() {
        let fixture = Fixture::new();
        let first = fixture.capsule(1);
        let second = fixture.capsule(2);
        let a = ready(&fixture, &fixture.first, &first);
        let b = ready(&fixture, &fixture.second, &second);
        a.publish().unwrap();
        assert!(matches!(b.publish(), Err(Error::StaleTip)));
        publish_exact(fixture.path(), &fixture.second, &second).unwrap();
        assert_eq!(read_exact(fixture.path(), &fixture.first).unwrap(), first);
        assert_eq!(read_exact(fixture.path(), &fixture.second).unwrap(), second);
    }

    #[test]
    fn same_commit_race_is_idempotent_or_refused_after_compare_and_swap() {
        let fixture = Fixture::new();
        let first = fixture.capsule(1);
        let different = fixture.capsule(2);
        let a = ready(&fixture, &fixture.first, &first);
        let same = ready(&fixture, &fixture.first, &first);
        let other = ready(&fixture, &fixture.first, &different);
        a.publish().unwrap();
        assert!(matches!(same.publish(), Err(Error::StaleTip)));
        assert!(matches!(other.publish(), Err(Error::StaleTip)));
        assert_eq!(
            publish_exact(fixture.path(), &fixture.first, &first).unwrap(),
            Publication::AlreadyPresent
        );
        assert!(matches!(
            publish_exact(fixture.path(), &fixture.first, &different),
            Err(Error::ExistingDifferent)
        ));
        assert_eq!(read_exact(fixture.path(), &fixture.first).unwrap(), first);
    }

    #[test]
    fn dropping_a_prepared_note_leaves_no_accepted_note_or_owned_staging_ref() {
        let fixture = Fixture::new();
        let note = ready(&fixture, &fixture.first, &fixture.capsule(1));
        let reference = note.stage.reference.clone();
        assert!(fixture.git().tip(NOTES_REF).unwrap().is_none());
        drop(note);
        assert!(fixture.git().tip(&reference).unwrap().is_none());
        assert!(fixture.git().tip(NOTES_REF).unwrap().is_none());
    }

    #[test]
    fn symbolic_notes_ref_cannot_redirect_a_write_into_a_branch() {
        let fixture = Fixture::new();
        fixture
            .git()
            .checked(&["symbolic-ref", NOTES_REF, "refs/heads/main"], None, 1024)
            .unwrap();
        assert!(matches!(
            publish_exact(fixture.path(), &fixture.first, &fixture.capsule(1)),
            Err(Error::SymbolicRef)
        ));
        assert!(matches!(
            read_exact(fixture.path(), &fixture.first),
            Err(Error::SymbolicRef)
        ));
        assert_eq!(
            fixture.git().tip("refs/heads/main").unwrap(),
            Some(fixture.first.clone())
        );
    }

    #[test]
    fn publishing_changes_no_head_index_worktree_config_or_remotes_and_runs_no_hooks() {
        let fixture = Fixture::new();
        let paths = [".git/HEAD", ".git/index", ".git/config", "fixture.txt"];
        let before = paths.map(|path| std::fs::read(fixture.path().join(path)).unwrap());
        let marker = fixture.path().join("hook-ran");
        let hook = fixture.path().join(".git/hooks/post-commit");
        std::fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        publish_exact(fixture.path(), &fixture.first, &fixture.capsule(1)).unwrap();
        for (path, bytes) in paths.into_iter().zip(before) {
            assert_eq!(std::fs::read(fixture.path().join(path)).unwrap(), bytes);
        }
        assert_eq!(
            fixture.git().tip("refs/heads/main").unwrap(),
            Some(fixture.first.clone())
        );
        assert!(!marker.exists());
        assert!(
            fixture
                .git()
                .checked(&["remote"], None, 1024)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn sealed_note_round_trip_is_bound_to_the_exact_commit() {
        let fixture = Fixture::new();
        let demo = Recipient::generate().unwrap();
        let organization = Recipient::generate().unwrap();
        let binding = Binding::public_chinwag(&fixture.first).unwrap();
        let capsule = seal(
            &binding,
            b"synthetic two-agent flight fixture",
            &demo.public,
            &organization.public,
        )
        .unwrap();
        publish_exact(fixture.path(), &fixture.first, &capsule).unwrap();
        let stored = read_exact(fixture.path(), &fixture.first).unwrap();
        assert_eq!(
            open(&binding, Slot::Demo, demo.secret_bytes(), &stored).unwrap(),
            b"synthetic two-agent flight fixture"
        );
        let wrong = Binding::public_chinwag(&fixture.second).unwrap();
        assert!(open(&wrong, Slot::Demo, demo.secret_bytes(), &stored).is_err());
    }
}
