//! Original one-file installs with separate fixture and repository entry policies.
#![deny(unsafe_code)]
#[allow(unsafe_code)]
mod checked_close;
pub mod completion;
mod fs;
pub mod observer;
mod repository;
use crate::{Editor, Launch, Plan, plan};
use fs::{Anchor, DirId, FileId, Image};
pub use repository::{
    ConfigureFailure, ConfigureReceipt, RepositoryRequest, configure, configure_initialized,
};
use rustix::fs::{Mode, fchmod, fsync, renameat};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write, path::Path};

const LOCK: &str = "chinwag-install.lock";
const INTENT: &str = "chinwag-install.intent";
const COMPLETED: &str = "chinwag-install.completed";
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}
#[derive(Debug, PartialEq, Eq)]
pub struct Refused {
    pub reason: &'static str,
    pub staging_created_no_cleanup: bool,
}
fn refused(reason: &'static str) -> Refused {
    Refused {
        reason,
        staging_created_no_cleanup: false,
    }
}

pub struct FixtureTarget {
    inner: Target,
}
struct Target {
    anchor: Anchor,
    editor: Editor,
    name: &'static str,
}
/// Constructed by an actual bounded readonly inspection. No public constructor.
pub struct Observation {
    parent: DirId,
    target: &'static str,
    original: Option<Image>,
}
impl Observation {
    pub fn sha256(&self) -> Option<[u8; 32]> {
        self.original.as_ref().map(|x| digest(&x.bytes))
    }
}
#[must_use = "Handle the unchanged receipt or retain the staged operation"]
pub enum Preparation {
    Unchanged { sha256: [u8; 32] },
    Ready(Box<Prepared>),
}
/// Internal owner-preserving result. Observational hashes never reconstruct Target.
enum OwnedPreparation {
    Unchanged {
        sha256: [u8; 32],
        target: Target,
        original: Image,
    },
    Ready(Box<Prepared>),
}
/// The staging owner is consumed by commit. Drop closes FDs and retains the lock.
#[must_use = "Dropping this owner retains the staging lock; it does not cancel the operation"]
pub struct Prepared {
    target: Target,
    original: Option<Image>,
    staged: Vec<u8>,
    file: File,
    id: FileId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub target_basename: &'static str,
    pub parent_dev: i32,
    pub parent_ino: u64,
    pub original_sha256: Option<[u8; 32]>,
    pub staged_sha256: [u8; 32],
    pub staged_dev: i32,
    pub staged_ino: u64,
}
#[derive(Debug)]
#[must_use = "Persist and inspect commit outcomes; unknown outcomes must not be replayed"]
pub enum CommitOutcome {
    InstalledAndReadBack {
        evidence: Evidence,
        completion: Box<completion::Completed>,
    },
    BeforeCommitRefused {
        evidence: Evidence,
        reason: &'static str,
        intent_created_no_cleanup: bool,
    },
    CommitOutcomeUnknown {
        evidence: Evidence,
        reason: &'static str,
    },
}
impl FixtureTarget {
    pub fn open(repo: &Path, editor: Editor) -> Result<Self, Refused> {
        let (child, name) = match editor {
            Editor::ClaudeCode => (None, ".mcp.json"),
            Editor::Cursor => (Some(".cursor"), "mcp.json"),
            Editor::Codex => (Some(".codex"), "config.toml"),
            Editor::Gemini => (Some(".gemini"), "settings.json"),
        };
        Ok(Self {
            inner: Target {
                anchor: Anchor::open_fixture(repo, child).map_err(refused)?,
                editor,
                name,
            },
        })
    }
    pub fn inspect(&self) -> Result<Observation, Refused> {
        self.inner.inspect()
    }
    pub fn prepare(
        self,
        observation: Observation,
        launch: Launch<'_>,
    ) -> Result<Preparation, Refused> {
        match self.inner.prepare_owned(observation, launch, None)? {
            OwnedPreparation::Unchanged { sha256, target, .. } => {
                // Existing fixture API retains its old observational result.
                drop(target);
                Ok(Preparation::Unchanged { sha256 })
            }
            OwnedPreparation::Ready(prepared) => Ok(Preparation::Ready(prepared)),
        }
    }
}
impl Target {
    fn check_guard(&self, guard: Option<&repository::OuterGuard>) -> fs::Result<()> {
        match (self.anchor.preserves_target_mode(), guard) {
            (true, Some(guard)) => guard.verify_target(self),
            (false, None) => Ok(()),
            _ => Err("install_policy_guard_mismatch"),
        }
    }
    fn inspect(&self) -> Result<Observation, Refused> {
        let parent = self.anchor.check().map_err(refused)?;
        self.anchor.require_absent(LOCK).map_err(refused)?;
        self.anchor.require_absent(INTENT).map_err(refused)?;
        self.anchor.require_absent(COMPLETED).map_err(refused)?;
        let original = self.anchor.read(self.name).map_err(refused)?;
        self.anchor.check().map_err(refused)?;
        Ok(Observation {
            parent,
            target: self.name,
            original,
        })
    }
    fn prepare_owned(
        self,
        observation: Observation,
        launch: Launch<'_>,
        guard: Option<&repository::OuterGuard>,
    ) -> Result<OwnedPreparation, Refused> {
        self.check_guard(guard).map_err(refused)?;
        if observation.parent != self.anchor.check().map_err(refused)?
            || observation.target != self.name
        {
            return Err(refused("observation_target_mismatch"));
        }
        self.anchor.require_absent(LOCK).map_err(refused)?;
        self.anchor.require_absent(INTENT).map_err(refused)?;
        self.anchor.require_absent(COMPLETED).map_err(refused)?;
        if self.anchor.read(self.name).map_err(refused)? != observation.original {
            return Err(refused("stale_preimage"));
        }
        let proposed = plan(
            self.editor,
            observation.original.as_ref().map(|x| x.bytes.as_slice()),
            launch,
        )
        .map_err(|_| refused("planner_refused"))?;
        let Plan::Proposed {
            bytes,
            relative_path,
        } = proposed
        else {
            if self.anchor.check().map_err(refused)? != observation.parent
                || self.anchor.read(self.name).map_err(refused)? != observation.original
            {
                return Err(refused("stale_preimage"));
            }
            let image = observation
                .original
                .ok_or_else(|| refused("missing_unchanged_preimage"))?;
            return Ok(OwnedPreparation::Unchanged {
                sha256: digest(&image.bytes),
                target: self,
                original: image,
            });
        };
        if relative_path != self.editor.relative_path() {
            return Err(refused("planner_target_mismatch"));
        }
        self.check_guard(guard).map_err(refused)?;
        let mut file = self.anchor.exclusive(LOCK).map_err(refused)?;
        // From this point every failure retains the owned lock for inspection.
        let staged = (|| {
            self.check_guard(guard)?;
            FileId::read(&file)?;
            if self.anchor.read(self.name)? != observation.original {
                return Err("stale_preimage");
            }
            self.anchor.check()?;
            self.check_guard(guard)?;
            file.write_all(&bytes).map_err(|_| "staging_write")?;
            if self.anchor.preserves_target_mode() {
                let mode = observation
                    .original
                    .as_ref()
                    .map_or(0o600, |image| image.id.permissions());
                fchmod(&file, Mode::from_raw_mode(mode)).map_err(|_| "staging_mode")?;
            }
            file.sync_all().map_err(|_| "staging_sync")?;
            let id = self.anchor.verify(&mut file, LOCK, &bytes)?;
            fsync(&self.anchor.fd).map_err(|_| "staging_parent_sync")?;
            self.anchor.check()?;
            Ok::<_, &'static str>(id)
        })()
        .map_err(|reason| Refused {
            reason,
            staging_created_no_cleanup: true,
        })?;
        Ok(OwnedPreparation::Ready(Box::new(Prepared {
            target: self,
            original: observation.original,
            staged: bytes,
            file,
            id: staged,
        })))
    }
}
#[derive(Clone, Copy)]
enum Fault {
    None,
    #[cfg(test)]
    BeforeRename,
    #[cfg(test)]
    AfterRename,
}
impl Prepared {
    pub fn commit(self: Box<Self>) -> CommitOutcome {
        (*self).commit_inner(Fault::None)
    }
    fn commit_inner(self, fault: Fault) -> CommitOutcome {
        self.commit_with_guard(fault, None)
    }
    fn commit_repository(self: Box<Self>, guard: &repository::OuterGuard) -> CommitOutcome {
        (*self).commit_with_guard(Fault::None, Some(guard))
    }
    fn commit_with_guard(
        mut self,
        fault: Fault,
        guard: Option<&repository::OuterGuard>,
    ) -> CommitOutcome {
        let parent = match self.target.anchor.check() {
            Ok(parent) => parent,
            Err(reason) => {
                // The last captured anchor still identifies the staged operation.
                let evidence = self.evidence();
                return CommitOutcome::BeforeCommitRefused {
                    evidence,
                    reason,
                    intent_created_no_cleanup: false,
                };
            }
        };
        let evidence = Evidence {
            parent_dev: parent.dev,
            parent_ino: parent.ino,
            ..self.evidence()
        };
        let body = serde_json::to_vec(
            &serde_json::json!({"format":"chinwag-private-config-intent/v1",
            "target":evidence.target_basename,"parent_dev":evidence.parent_dev,"parent_ino":evidence.parent_ino,
            "original_sha256":evidence.original_sha256.map(|h| hex(&h)),"staged_sha256":hex(&evidence.staged_sha256),
            "staged_dev":evidence.staged_dev,"staged_ino":evidence.staged_ino}),
        );
        let Ok(body) = body else {
            return CommitOutcome::BeforeCommitRefused {
                evidence,
                reason: "intent_encoding",
                intent_created_no_cleanup: false,
            };
        };
        let check = self.check_staged(guard);
        if let Err(reason) = check {
            return CommitOutcome::BeforeCommitRefused {
                evidence,
                reason,
                intent_created_no_cleanup: false,
            };
        }
        let mut intent = match self.target.anchor.exclusive(INTENT) {
            Ok(file) => file,
            Err(reason) => {
                return CommitOutcome::BeforeCommitRefused {
                    evidence,
                    reason,
                    intent_created_no_cleanup: false,
                };
            }
        };
        let before = (|| {
            self.target.check_guard(guard)?;
            FileId::read(&intent)?;
            intent.write_all(&body).map_err(|_| "intent_write")?;
            intent.sync_all().map_err(|_| "intent_sync")?;
            self.target.anchor.verify(&mut intent, INTENT, &body)?;
            fsync(&self.target.anchor.fd).map_err(|_| "intent_parent_sync")?;
            self.check_staged(guard)?;
            self.target.anchor.verify(&mut intent, INTENT, &body)?;
            #[cfg(test)]
            if matches!(fault, Fault::BeforeRename) {
                return Err("fixture_before_rename");
            }
            Ok::<_, &'static str>(())
        })();
        if let Err(reason) = before {
            return CommitOutcome::BeforeCommitRefused {
                evidence,
                reason,
                intent_created_no_cleanup: true,
            };
        }
        // No result after this attempted rename may be classified as a safe retry.
        if renameat(
            &self.target.anchor.fd,
            LOCK,
            &self.target.anchor.fd,
            self.target.name,
        )
        .is_err()
        {
            return CommitOutcome::CommitOutcomeUnknown {
                evidence,
                reason: "rename_attempt_unconfirmed",
            };
        }
        #[cfg(test)]
        if matches!(fault, Fault::AfterRename) {
            return CommitOutcome::CommitOutcomeUnknown {
                evidence,
                reason: "fixture_after_rename_before_sync",
            };
        }
        let _ = fault;
        let after = (|| {
            self.target.check_guard(guard)?;
            fsync(&self.target.anchor.fd).map_err(|_| "post_rename_sync")?;
            let id = self
                .target
                .anchor
                .verify(&mut self.file, self.target.name, &self.staged)?;
            if id != self.id {
                return Err("installed_identity_changed");
            }
            self.target.anchor.verify(&mut intent, INTENT, &body)?;
            self.target.anchor.check()?;
            self.target.anchor.require_absent(COMPLETED)?;
            Ok::<_, &'static str>(())
        })();
        match after {
            Ok(()) => CommitOutcome::InstalledAndReadBack {
                evidence: evidence.clone(),
                completion: Box::new(completion::Completed::from_original(
                    self, intent, body, evidence,
                )),
            },
            Err(reason) => CommitOutcome::CommitOutcomeUnknown { evidence, reason },
        }
    }
    fn evidence(&self) -> Evidence {
        // This is the held staged object's captured identity, not a new lookup.
        let parent = self.target.anchor.identity();
        Evidence {
            target_basename: self.target.name,
            parent_dev: parent.dev,
            parent_ino: parent.ino,
            original_sha256: self.original.as_ref().map(|x| digest(&x.bytes)),
            staged_sha256: digest(&self.staged),
            staged_dev: self.id.dev,
            staged_ino: self.id.ino,
        }
    }
    fn check_staged(&mut self, guard: Option<&repository::OuterGuard>) -> fs::Result<()> {
        self.target.check_guard(guard)?;
        self.target.anchor.check()?;
        self.target.anchor.require_absent(COMPLETED)?;
        if self.target.anchor.read(self.target.name)? != self.original {
            return Err("stale_preimage");
        }
        let id = self
            .target
            .anchor
            .verify(&mut self.file, LOCK, &self.staged)?;
        if id != self.id {
            return Err("staging_identity_changed");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
