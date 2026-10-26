//! A single operator-pinned export into an owned bare repository and staging directory.
//! The source repository is read only. Private directories are trusted ownership,
//! not an OS sandbox against another process running as the same user.

use crate::{
    bundle::{BundleExpectation, GitCandidate, MAX_BUNDLE_BYTES},
    bundle_io::{
        bounded_read, canonical, prefixed, private_directory, private_empty_directory, private_file,
    },
    cargo::CommandReport,
    owned_process::execute_guarded_streams,
};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    process::Command,
    sync::{OwnedSemaphorePermit, Semaphore},
};

pub use crate::bundle_io::Error;

const ATTEMPT: &str = ".chinwag-export-attempt.json";
const SIGNERS: &str = ".chinwag-export-allowed-signers";
const BUNDLE: &str = "candidate.bundle";
const CANDIDATE_REF: &str = "refs/chinwag/candidate";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const DIAGNOSTIC_LIMIT: usize = 64 * 1024;

/// All paths and candidate metadata are operator configuration, never MCP input.
pub struct ExportOperatorConfig {
    pub source: PathBuf,
    pub export: PathBuf,
    pub staging: PathBuf,
    pub empty_templates: PathBuf,
    pub builder_signers: PathBuf,
    pub candidate: GitCandidate,
}

pub struct BundleExporter {
    source: PathBuf,
    git_dir: PathBuf,
    objects: PathBuf,
    export: PathBuf,
    staging: PathBuf,
    templates: PathBuf,
    _source_dirs: [File; 3],
    _export_dir: File,
    staging_dir: File,
    _templates_dir: File,
    candidate: GitCandidate,
    signer_snapshot: String,
    attempted: AtomicBool,
    available: Arc<Semaphore>,
}

/// Exact read-back bytes with metadata. This is no Cargo, review or seal authority.
pub struct PreparedBundle {
    expected: BundleExpectation,
    bytes: Vec<u8>,
}

impl PreparedBundle {
    pub fn expectation(&self) -> &BundleExpectation {
        &self.expected
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl BundleExporter {
    pub fn open(config: ExportOperatorConfig) -> Result<Self, Error> {
        let source = canonical(&config.source)?;
        let export = canonical(&config.export)?;
        let staging = canonical(&config.staging)?;
        let templates = canonical(&config.empty_templates)?;
        let signers = canonical(&config.builder_signers)?;
        let scopes = [&source, &export, &staging, &templates];
        for (index, path) in scopes.iter().enumerate() {
            for other in &scopes[index + 1..] {
                if path.starts_with(other) || other.starts_with(path) {
                    return Err(Error::Scope);
                }
            }
        }
        if [&export, &staging, &templates]
            .iter()
            .any(|path| signers.starts_with(path))
        {
            return Err(Error::Scope);
        }
        let git_dir = canonical(&source.join(".git"))?;
        let objects = canonical(&git_dir.join("objects"))?;
        if objects
            .as_os_str()
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control())
        {
            return Err(Error::Scope);
        }
        for path in [
            git_dir.join("commondir"),
            git_dir.join("shallow"),
            objects.join("info/alternates"),
        ] {
            match fs::symlink_metadata(path) {
                Ok(_) => return Err(Error::Scope),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let source_dirs = [
            private_directory(&source)?,
            private_directory(&git_dir)?,
            private_directory(&objects)?,
        ];
        let export_dir = private_empty_directory(&export)?;
        let staging_dir = private_empty_directory(&staging)?;
        let templates_dir = private_empty_directory(&templates)?;
        let text = String::from_utf8(bounded_read(&mut private_file(&signers)?, 4096)?)
            .map_err(|_| Error::Scope)?;
        let signer_snapshot = config.candidate.signer_snapshot(&text)?;
        Ok(Self {
            source,
            git_dir,
            objects,
            export,
            staging,
            templates,
            _source_dirs: source_dirs,
            _export_dir: export_dir,
            staging_dir,
            _templates_dir: templates_dir,
            candidate: config.candidate,
            signer_snapshot,
            attempted: AtomicBool::new(false),
            available: Arc::new(Semaphore::new(1)),
        })
    }

    fn write_new(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.staging.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.staging_dir.sync_all()?;
        Ok(())
    }

    fn arm(&self) -> Result<(), Error> {
        if self.attempted.swap(true, Ordering::AcqRel) {
            return Err(Error::AlreadyAttempted);
        }
        let marker = serde_json::to_vec(&serde_json::json!({
            "version":1, "oid":self.candidate.oid(), "tree":self.candidate.tree(),
            "builder":self.candidate.builder(), "state":"armed_no_automatic_retry"
        }))
        .map_err(|_| Error::Scope)?;
        self.write_new(ATTEMPT, &marker)?;
        self.write_new(SIGNERS, self.signer_snapshot.as_bytes())
    }

    fn command(&self, cwd: &Path, source: bool) -> Command {
        let mut command =
            crate::git_env::command(cwd, &self.templates, &self.staging.join(SIGNERS));
        command.env("GIT_NO_LAZY_FETCH", "1");
        if source {
            command.arg(prefixed("--git-dir=", &self.git_dir));
            command.arg(prefixed("--work-tree=", &self.source));
        }
        command
    }

    async fn run(
        &self,
        stage: &'static str,
        mut command: Command,
        args: &[&OsStr],
        stdout_limit: usize,
        job: &Arc<OwnedSemaphorePermit>,
    ) -> Result<CommandReport, Error> {
        command.args(args);
        let report = execute_guarded_streams(
            command,
            COMMAND_TIMEOUT,
            stdout_limit,
            DIAGNOSTIC_LIMIT,
            job.clone(),
        )
        .await?;
        if !report.success {
            return Err(Error::Git {
                stage,
                report: Box::new(report),
            });
        }
        Ok(report)
    }

    pub async fn prepare(&self) -> Result<PreparedBundle, Error> {
        let job = Arc::new(
            self.available
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Busy)?,
        );
        self.arm()?;
        let kind = self
            .run(
                "source-object",
                self.command(&self.source, true),
                &[
                    OsStr::new("cat-file"),
                    OsStr::new("-t"),
                    OsStr::new(self.candidate.oid()),
                ],
                DIAGNOSTIC_LIMIT,
                &job,
            )
            .await?;
        if kind.stdout != b"commit\n" {
            return Err(Error::Object);
        }
        let tree_expression = format!("{}^{{tree}}", self.candidate.oid());
        let tree = self
            .run(
                "source-tree",
                self.command(&self.source, true),
                &[
                    OsStr::new("rev-parse"),
                    OsStr::new("--verify"),
                    OsStr::new("--end-of-options"),
                    OsStr::new(&tree_expression),
                ],
                DIAGNOSTIC_LIMIT,
                &job,
            )
            .await?;
        if tree.stdout != format!("{}\n", self.candidate.tree()).as_bytes() {
            return Err(Error::Object);
        }
        self.run(
            "source-signature",
            self.command(&self.source, true),
            &[
                OsStr::new("verify-commit"),
                OsStr::new("--"),
                OsStr::new(self.candidate.oid()),
            ],
            DIAGNOSTIC_LIMIT,
            &job,
        )
        .await?;
        let format = format!("--object-format={}", self.candidate.object_format());
        let template = prefixed("--template=", &self.templates);
        self.run(
            "export-init",
            self.command(&self.export, false),
            &[
                OsStr::new("init"),
                OsStr::new("--bare"),
                OsStr::new(&format),
                &template,
                self.export.as_os_str(),
            ],
            DIAGNOSTIC_LIMIT,
            &job,
        )
        .await?;
        let info = self.export.join("objects/info");
        let mut alternates = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(info.join("alternates"))?;
        alternates.write_all(self.objects.as_os_str().as_bytes())?;
        alternates.write_all(b"\n")?;
        alternates.sync_all()?;
        File::open(info)?.sync_all()?;
        let zero = "0".repeat(self.candidate.oid().len());
        self.run(
            "export-ref",
            self.command(&self.export, false),
            &[
                OsStr::new("update-ref"),
                OsStr::new("--no-deref"),
                OsStr::new(CANDIDATE_REF),
                OsStr::new(self.candidate.oid()),
                OsStr::new(&zero),
            ],
            DIAGNOSTIC_LIMIT,
            &job,
        )
        .await?;
        let bundle = self
            .run(
                "export-bundle",
                self.command(&self.export, false),
                &[
                    OsStr::new("bundle"),
                    OsStr::new("create"),
                    OsStr::new("-"),
                    OsStr::new(CANDIDATE_REF),
                ],
                MAX_BUNDLE_BYTES,
                &job,
            )
            .await?;
        self.write_new(BUNDLE, &bundle.stdout)?;
        let bytes = bounded_read(
            &mut private_file(&self.staging.join(BUNDLE))?,
            MAX_BUNDLE_BYTES,
        )?;
        if bytes != bundle.stdout {
            return Err(Error::Object);
        }
        let expected = BundleExpectation::from_candidate(
            self.candidate.clone(),
            *blake3::hash(&bytes).as_bytes(),
            bytes.len() as u64,
        )?;
        Ok(PreparedBundle { expected, bytes })
    }
}

#[cfg(test)]
#[path = "bundle_export_tests.rs"]
mod tests;
