//! Intake of an operator-pinned bundle into a new, owned Git quarantine.
//! This verifies bytes, Git objects and a signer, never tests or model review.
//! Private directories are a trusted ownership boundary, not an OS sandbox
//! against another process running as the same user.

use crate::{
    bundle::{BundleExpectation, MAX_BUNDLE_BYTES},
    bundle_io::{bounded_read, canonical, prefixed, private_empty_directory, private_file},
    cargo::CommandReport,
    owned_process::execute_guarded,
};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{process::Command, sync::OwnedSemaphorePermit, sync::Semaphore};

const ATTEMPT: &str = ".chinwag-intake-attempt.json";
const SIGNERS: &str = ".chinwag-intake-allowed-signers";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_LIMIT: usize = 64 * 1024;

/// Configured before exposing any tool. None of these fields are MCP inputs.
pub struct BundleOperatorConfig {
    pub bundle: PathBuf,
    pub quarantine: PathBuf,
    pub empty_templates: PathBuf,
    pub builder_signers: PathBuf,
    pub expected: BundleExpectation,
}

pub use crate::bundle_io::Error;

pub struct BundleVerifier {
    bundle_path: PathBuf,
    bundle: File,
    quarantine: PathBuf,
    quarantine_dir: File,
    templates: PathBuf,
    _templates_dir: File,
    signer_snapshot: String,
    expected: BundleExpectation,
    attempted: AtomicBool,
    available: Arc<Semaphore>,
}

/// An authenticated object observation. It conveys no write or seal authority.
pub struct VerifiedBundle {
    expected: BundleExpectation,
    quarantine: PathBuf,
    templates: PathBuf,
    _quarantine_dir: File,
    _templates_dir: File,
    available: Arc<Semaphore>,
}

/// A checkout of the verified commit into a new operator-owned directory.
/// It has not run Cargo or obtained a model review and conveys no write lease.
pub struct MaterializedBundle {
    expected: BundleExpectation,
    path: PathBuf,
    _directory: File,
}

impl MaterializedBundle {
    pub fn expectation(&self) -> &BundleExpectation {
        &self.expected
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl VerifiedBundle {
    /// Consumes this observation for one checkout attempt. `worktree` must come
    /// from the operator, never a model tool argument. Cargo build scripts are
    /// outside this filesystem/process boundary; this is not an OS sandbox.
    ///
    /// ```compile_fail
    /// use chinwag_seed::bundle_intake::VerifiedBundle;
    /// fn replay(bundle: VerifiedBundle, path: &std::path::Path) {
    ///     let first = bundle.materialize(path);
    ///     let second = bundle.materialize(path);
    /// }
    /// ```
    pub async fn materialize(
        self,
        worktree: &std::path::Path,
    ) -> Result<MaterializedBundle, Error> {
        let job = Arc::new(
            self.available
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Busy)?,
        );
        let worktree = canonical(worktree)?;
        for path in [&self.quarantine, &self.templates] {
            if worktree.starts_with(path) || path.starts_with(&worktree) {
                return Err(Error::Scope);
            }
        }
        let directory = private_empty_directory(&worktree)?;
        let marker = serde_json::to_vec(&serde_json::json!({
            "version":1, "oid":self.expected.oid(), "tree":self.expected.tree(),
            "bundle_blake3":self.expected.hash(), "worktree":worktree,
            "state":"materialization_attempt_no_automatic_retry"
        }))
        .map_err(|_| Error::Scope)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(
                self.quarantine
                    .join(".chinwag-materialization-attempt.json"),
            )?;
        file.write_all(&marker)?;
        file.sync_all()?;
        self._quarantine_dir.sync_all()?;
        let mut command =
            crate::git_env::command(&worktree, &self.templates, &self.quarantine.join(SIGNERS));
        command
            .env("GIT_NO_LAZY_FETCH", "1")
            .arg(prefixed("--git-dir=", &self.quarantine))
            .arg(prefixed("--work-tree=", &worktree))
            .args(["checkout", self.expected.oid(), "--", "."]);
        let report = execute_guarded(command, COMMAND_TIMEOUT, OUTPUT_LIMIT, job.clone()).await?;
        if !report.success {
            return Err(Error::Git {
                stage: "materialize",
                report: Box::new(report),
            });
        }
        let mut refs = crate::git_env::command(
            &self.quarantine,
            &self.templates,
            &self.quarantine.join(SIGNERS),
        );
        refs.args(["for-each-ref", "--format=%(refname)"]);
        let report = execute_guarded(refs, COMMAND_TIMEOUT, OUTPUT_LIMIT, job).await?;
        if !report.success {
            return Err(Error::Git {
                stage: "materialize-refs",
                report: Box::new(report),
            });
        }
        if !report.stdout.is_empty() {
            return Err(Error::Refs);
        }
        directory.sync_all()?;
        Ok(MaterializedBundle {
            expected: self.expected,
            path: worktree,
            _directory: directory,
        })
    }

    pub fn hash(&self) -> [u8; 32] {
        self.expected.hash()
    }

    pub fn size(&self) -> u64 {
        self.expected.size()
    }

    pub fn oid(&self) -> &str {
        self.expected.oid()
    }

    pub fn tree(&self) -> &str {
        self.expected.tree()
    }

    pub fn signer(&self) -> [u8; 32] {
        self.expected.builder()
    }
}

impl BundleVerifier {
    pub fn open(config: BundleOperatorConfig) -> Result<Self, Error> {
        let bundle_path = canonical(&config.bundle)?;
        let quarantine = canonical(&config.quarantine)?;
        let templates = canonical(&config.empty_templates)?;
        let signers_path = canonical(&config.builder_signers)?;
        if quarantine.starts_with(&templates)
            || templates.starts_with(&quarantine)
            || bundle_path.starts_with(&quarantine)
            || bundle_path.starts_with(&templates)
            || signers_path.starts_with(&quarantine)
            || signers_path.starts_with(&templates)
            || bundle_path == signers_path
        {
            return Err(Error::Scope);
        }
        let quarantine_dir = private_empty_directory(&quarantine)?;
        let templates_dir = private_empty_directory(&templates)?;
        let mut bundle = private_file(&bundle_path)?;
        let blob = bounded_read(&mut bundle, MAX_BUNDLE_BYTES)?;
        config.expected.matches_blob(&blob)?;
        let mut signers = private_file(&signers_path)?;
        let text =
            String::from_utf8(bounded_read(&mut signers, 4096)?).map_err(|_| Error::Scope)?;
        let signer_snapshot = config.expected.signer_snapshot(&text)?;
        Ok(Self {
            bundle_path,
            bundle,
            quarantine,
            quarantine_dir,
            templates,
            _templates_dir: templates_dir,
            signer_snapshot,
            expected: config.expected,
            attempted: AtomicBool::new(false),
            available: Arc::new(Semaphore::new(1)),
        })
    }

    fn check_bundle(&self) -> Result<(), Error> {
        let mut file = self.bundle.try_clone()?;
        let held = file.metadata()?;
        let current = fs::symlink_metadata(&self.bundle_path)?;
        if !current.is_file()
            || current.dev() != held.dev()
            || current.ino() != held.ino()
            || current.nlink() != 1
        {
            return Err(Error::Scope);
        }
        self.expected
            .matches_blob(&bounded_read(&mut file, MAX_BUNDLE_BYTES)?)?;
        Ok(())
    }

    fn arm(&self) -> Result<(), Error> {
        if self.attempted.swap(true, Ordering::AcqRel) {
            return Err(Error::AlreadyAttempted);
        }
        let marker = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "oid": self.expected.oid(),
            "tree": self.expected.tree(),
            "bytes": self.expected.size(),
            "blake3": self.expected.hash(),
            "builder": self.expected.builder(),
            "state": "armed_no_automatic_retry"
        }))
        .map_err(|_| Error::Scope)?;
        self.write_new(ATTEMPT, &marker)?;
        self.write_new(SIGNERS, self.signer_snapshot.as_bytes())?;
        Ok(())
    }

    fn write_new(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.quarantine.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.quarantine_dir.sync_all()?;
        Ok(())
    }

    fn command(&self) -> Command {
        crate::git_env::command(
            &self.quarantine,
            &self.templates,
            &self.quarantine.join(SIGNERS),
        )
    }

    async fn run(
        &self,
        stage: &'static str,
        args: &[&OsStr],
        job: &Arc<OwnedSemaphorePermit>,
    ) -> Result<CommandReport, Error> {
        let mut command = self.command();
        command.args(args);
        let report = execute_guarded(command, COMMAND_TIMEOUT, OUTPUT_LIMIT, job.clone()).await?;
        if !report.success {
            return Err(Error::Git {
                stage,
                report: Box::new(report),
            });
        }
        Ok(report)
    }

    pub async fn verify(&self) -> Result<VerifiedBundle, Error> {
        let job = Arc::new(
            self.available
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Busy)?,
        );
        if self.attempted.load(Ordering::Acquire) {
            return Err(Error::AlreadyAttempted);
        }
        self.check_bundle()?;
        self.arm()?;
        let format = format!("--object-format={}", self.expected.object_format());
        let template = prefixed("--template=", &self.templates);
        self.run(
            "init",
            &[
                OsStr::new("init"),
                OsStr::new("--bare"),
                OsStr::new(&format),
                &template,
                self.quarantine.as_os_str(),
            ],
            &job,
        )
        .await?;
        for (stage, operation) in [("header", "verify"), ("unbundle", "unbundle")] {
            self.run(
                stage,
                &[
                    OsStr::new("bundle"),
                    OsStr::new(operation),
                    self.bundle_path.as_os_str(),
                ],
                &job,
            )
            .await?;
        }
        let kind = self
            .run(
                "object",
                &[
                    OsStr::new("cat-file"),
                    OsStr::new("-t"),
                    OsStr::new(self.expected.oid()),
                ],
                &job,
            )
            .await?;
        if kind.stdout != b"commit\n" {
            return Err(Error::Object);
        }
        let tree_expression = format!("{}^{{tree}}", self.expected.oid());
        let tree = self
            .run(
                "tree",
                &[
                    OsStr::new("rev-parse"),
                    OsStr::new("--verify"),
                    OsStr::new("--end-of-options"),
                    OsStr::new(&tree_expression),
                ],
                &job,
            )
            .await?;
        if tree.stdout != format!("{}\n", self.expected.tree()).as_bytes() {
            return Err(Error::Object);
        }
        self.run(
            "signature",
            &[
                OsStr::new("verify-commit"),
                OsStr::new("--"),
                OsStr::new(self.expected.oid()),
            ],
            &job,
        )
        .await?;
        let refs = self
            .run(
                "refs",
                &[
                    OsStr::new("for-each-ref"),
                    OsStr::new("--format=%(refname)"),
                ],
                &job,
            )
            .await?;
        if !refs.stdout.is_empty() {
            return Err(Error::Refs);
        }
        self.check_bundle()?;
        Ok(VerifiedBundle {
            expected: self.expected.clone(),
            quarantine: self.quarantine.clone(),
            templates: self.templates.clone(),
            _quarantine_dir: self.quarantine_dir.try_clone()?,
            _templates_dir: self._templates_dir.try_clone()?,
            available: self.available.clone(),
        })
    }
}

#[cfg(test)]
#[path = "bundle_intake_tests.rs"]
mod tests;
