//! One original local Git email query, then a retained configuration preimage.
use crate::{MAX_CONFIG_BYTES, StartFailure, fs};
use chinwag_host_process::owned_spawn::{Exit, OwnedChild, SpawnStdio, spawn_at};
use chinwag_signing::ConfigPreimageConstraint;
use fs::{Anchor, GitConfigFile, GitConfigImage, Image, QueryArtifact, QueryFile};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    marker::PhantomData,
    os::fd::AsFd,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

const GUARD: &[u8] = b"chinwag original repo-local principal query v1\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalState {
    Pending { pid: u32 },
    Unknown { pid: u32, reason: &'static str },
    Ready,
    Refused { reason: &'static str },
}

pub(crate) struct PrincipalPreimage {
    pub repo_anchor: Anchor,
    pub git_anchor: Anchor,
    pub config: GitConfigFile,
    pub image: GitConfigImage,
}
impl PrincipalPreimage {
    fn check_metadata(&self) -> Result<(), &'static str> {
        self.repo_anchor.check()?;
        self.git_anchor.check()?;
        if self.git_anchor.identify_git_config(&self.config)? != self.image.id {
            return Err("principal_config_preimage_changed");
        }
        Ok(())
    }
    pub fn verify(&mut self) -> Result<(), &'static str> {
        self.check_metadata()?;
        if self.git_anchor.read_git_config(&mut self.config)? != self.image {
            return Err("principal_config_preimage_changed");
        }
        Ok(())
    }
    pub fn constraint(&self) -> Result<ConfigPreimageConstraint, &'static str> {
        let repo = self.repo_anchor.check()?;
        let git = self.git_anchor.check()?;
        Ok(ConfigPreimageConstraint::new(
            (repo.dev, repo.ino),
            (git.dev, git.ino),
            (self.image.id.dev, self.image.id.ino),
            Sha256::digest(&self.image.bytes).into(),
        ))
    }
}

/// Cannot be constructed from a principal string, receipt, or observed inode.
#[must_use = "Transfer the original held preimage into the original signing attempt"]
pub struct ResolvedPrincipal {
    pub(crate) repo: PathBuf,
    pub(crate) principal: String,
    pub(crate) preimage: PrincipalPreimage,
    _thread: PhantomData<Rc<()>>,
}
impl ResolvedPrincipal {
    pub fn principal(&self) -> &str {
        &self.principal
    }
    pub fn repository(&self) -> &Path {
        &self.repo
    }
    /// Close the actual retained descriptors without starting signing.
    pub fn finish(self) -> Result<usize, StartFailure> {
        let PrincipalPreimage {
            config,
            repo_anchor,
            git_anchor,
            ..
        } = self.preimage;
        let file = config.close();
        let git = git_anchor.close_all();
        let repo = repo_anchor.close_all();
        file.map_err(StartFailure)?;
        Ok(1 + git.map_err(StartFailure)? + repo.map_err(StartFailure)?)
    }
}

#[must_use = "Retain the same original lookup and child while pending or unknown"]
pub struct PrincipalLookup {
    repo: PathBuf,
    preimage: PrincipalPreimage,
    pending: Option<QueryFile>,
    output: Option<QueryFile>,
    error: Option<QueryFile>,
    child: Option<OwnedChild>,
    deadline: Option<Instant>,
    state: PrincipalState,
    principal: Option<String>,
    terminal_images: Option<[Image; 3]>,
    _thread: PhantomData<Rc<()>>,
}

#[must_use = "This failure retains the original lookup; never remint or replay it"]
pub struct PrincipalFailure {
    original: Box<PrincipalLookup>,
    reason: &'static str,
}
impl std::fmt::Debug for PrincipalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrincipalFailure")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for PrincipalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}
impl std::error::Error for PrincipalFailure {}
impl PrincipalFailure {
    pub fn reason(&self) -> &'static str {
        self.reason
    }
    pub fn into_original(self) -> PrincipalLookup {
        *self.original
    }
}

impl PrincipalLookup {
    pub fn start(repo: &Path) -> Result<Self, StartFailure> {
        let repo_anchor = Anchor::open_fixture(repo, None).map_err(StartFailure)?;
        let git_anchor =
            Anchor::open_fixture(repo, Some(fs::ChildDirectory::Git)).map_err(StartFailure)?;
        repo_anchor
            .require_absent(".chinwag")
            .map_err(StartFailure)?;
        for name in ["commondir", "config.worktree", "config.lock"] {
            git_anchor.require_absent(name).map_err(StartFailure)?;
        }
        let mut config = git_anchor.open_git_config().map_err(StartFailure)?;
        let image = git_anchor
            .read_git_config(&mut config)
            .map_err(StartFailure)?;
        let mut lookup = Self {
            repo: repo.to_owned(),
            preimage: PrincipalPreimage {
                repo_anchor,
                git_anchor,
                config,
                image,
            },
            pending: None,
            output: None,
            error: None,
            child: None,
            deadline: None,
            state: PrincipalState::Refused {
                reason: "principal_not_started",
            },
            principal: None,
            terminal_images: None,
            _thread: PhantomData,
        };
        if let Err(reason) = lookup.prepare() {
            // prepare stores a successfully spawned child immediately and has
            // no fallible work afterward. Errors here never lose an active child.
            lookup.state = PrincipalState::Refused { reason };
        }
        Ok(lookup)
    }
    fn prepare(&mut self) -> Result<(), &'static str> {
        let args = [
            "-c",
            "protocol.allow=never",
            "config",
            "--file",
            "-",
            "--no-includes",
            "--null",
            "--get-all",
            "user.email",
        ]
        .into_iter()
        .map(|s| CString::new(s).map_err(|_| "query_argument"))
        .collect::<Result<Vec<_>, _>>()?;
        let env = [
            "PATH=/usr/bin:/bin",
            "HOME=/var/empty",
            "LC_ALL=C",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_SYSTEM=/dev/null",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_CONFIG_COUNT=0",
            "GIT_TERMINAL_PROMPT=0",
        ]
        .into_iter()
        .map(|s| CString::new(s).map_err(|_| "query_environment"))
        .collect::<Result<Vec<_>, _>>()?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or("query_deadline")?;
        self.preimage.verify()?;
        let git = &self.preimage.git_anchor;
        self.pending = Some(QueryFile::create(git, QueryArtifact::Pending, GUARD)?);
        self.output = Some(QueryFile::create(git, QueryArtifact::Output, b"")?);
        self.error = Some(QueryFile::create(git, QueryArtifact::Error, b"")?);
        self.preimage.verify()?;
        self.preimage.config.rewind_input()?;
        let output = self.output.as_ref().ok_or("query_output_missing")?;
        let error = self.error.as_ref().ok_or("query_error_missing")?;
        let child = spawn_at(
            c"/usr/bin/git",
            &args,
            &env,
            self.preimage.repo_anchor.fd.as_fd(),
            SpawnStdio {
                input: self.preimage.config.input(),
                output: output.output(),
                error: error.output(),
            },
        )
        .map_err(|_| "principal_query_spawn")?;
        let pid = child.pid();
        self.child = Some(child);
        self.deadline = Some(deadline);
        self.state = PrincipalState::Pending { pid };
        Ok(())
    }
    pub fn state(&self) -> PrincipalState {
        self.state
    }
    fn check_live(&self) -> Result<(), &'static str> {
        // stdin shares its open-file offset with the child. Do not seek/read it
        // while the child is active; check its full captured metadata instead.
        self.preimage.check_metadata()?;
        for file in [&self.pending, &self.output, &self.error] {
            file.as_ref()
                .ok_or("query_file_missing")?
                .check_instance(&self.preimage.git_anchor)?;
        }
        Ok(())
    }
    pub fn poll(&mut self, now: Instant) -> PrincipalState {
        let PrincipalState::Pending { pid } = self.state else {
            return self.state;
        };
        if let Err(reason) = self.check_live() {
            self.state = PrincipalState::Unknown { pid, reason };
            return self.state;
        }
        if self.deadline.is_none_or(|deadline| now >= deadline) {
            self.state = PrincipalState::Unknown {
                pid,
                reason: "principal_query_timeout",
            };
            return self.state;
        }
        let observed = self.child.as_mut().map(OwnedChild::try_wait);
        match observed {
            Some(Ok(None)) => {}
            Some(Ok(Some(exit))) => {
                self.state = match self.read_terminal(exit) {
                    Ok(()) => PrincipalState::Ready,
                    Err(reason) => PrincipalState::Refused { reason },
                };
            }
            _ => {
                self.state = PrincipalState::Unknown {
                    pid,
                    reason: "principal_query_wait_unknown",
                }
            }
        }
        self.state
    }
    /// Observe only the original unknown child. A late exit never grants Ready.
    pub fn observe_child(&mut self) -> std::io::Result<Option<Exit>> {
        if !matches!(self.state, PrincipalState::Unknown { .. }) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        self.child
            .as_mut()
            .ok_or(std::io::ErrorKind::InvalidInput)?
            .try_wait()
    }
    fn read_terminal(&mut self, exit: Exit) -> Result<(), &'static str> {
        self.preimage.verify()?;
        let git = &self.preimage.git_anchor;
        let pending = self
            .pending
            .as_mut()
            .ok_or("query_pending_missing")?
            .read(git)?;
        let output = self
            .output
            .as_mut()
            .ok_or("query_output_missing")?
            .read(git)?;
        let error = self
            .error
            .as_mut()
            .ok_or("query_error_missing")?
            .read(git)?;
        if pending.bytes != GUARD {
            return Err("principal_query_guard_changed");
        }
        if exit != Exit::Code(0) {
            return Err(if exit == Exit::Code(1) {
                "local_principal_missing"
            } else {
                "local_principal_query_refused"
            });
        }
        if !error.bytes.is_empty() {
            return Err("principal_query_diagnostic_present");
        }
        let principal = parse_output(&output.bytes)?;
        self.preimage.verify()?;
        self.terminal_images = Some([pending, output, error]);
        self.principal = Some(principal);
        Ok(())
    }
    fn release_query_files(&mut self) -> Result<(), &'static str> {
        self.preimage.verify()?;
        let [pending, output, error] = self.terminal_images.take().ok_or("query_images_missing")?;
        if self
            .pending
            .as_mut()
            .ok_or("query_pending_missing")?
            .read(&self.preimage.git_anchor)?
            != pending
            || self
                .output
                .as_mut()
                .ok_or("query_output_missing")?
                .read(&self.preimage.git_anchor)?
                != output
            || self
                .error
                .as_mut()
                .ok_or("query_error_missing")?
                .read(&self.preimage.git_anchor)?
                != error
        {
            return Err("query_terminal_image_changed");
        }
        // Release the pending guard last. Any earlier error retains the marker.
        self.output
            .take()
            .ok_or("query_output_missing")?
            .release(&self.preimage.git_anchor, &output)?;
        self.preimage.verify()?;
        if self
            .pending
            .as_mut()
            .ok_or("query_pending_missing")?
            .read(&self.preimage.git_anchor)?
            != pending
        {
            return Err("query_terminal_image_changed");
        }
        self.error
            .take()
            .ok_or("query_error_missing")?
            .release(&self.preimage.git_anchor, &error)?;
        self.preimage.verify()?;
        self.pending
            .take()
            .ok_or("query_pending_missing")?
            .release(&self.preimage.git_anchor, &pending)?;
        self.preimage.verify()
    }
    pub fn resolve(mut self) -> Result<ResolvedPrincipal, PrincipalFailure> {
        let result = if self.state != PrincipalState::Ready {
            Err("original_principal_not_ready")
        } else if self.principal.is_none() {
            Err("original_principal_missing")
        } else {
            self.release_query_files()
        };
        if let Err(reason) = result {
            if matches!(self.state, PrincipalState::Ready) {
                self.state = PrincipalState::Refused { reason };
            }
            return Err(PrincipalFailure {
                original: Box::new(self),
                reason,
            });
        }
        let Some(principal) = self.principal.take() else {
            return Err(PrincipalFailure {
                original: Box::new(self),
                reason: "original_principal_missing",
            });
        };
        Ok(ResolvedPrincipal {
            repo: self.repo,
            principal,
            preimage: self.preimage,
            _thread: PhantomData,
        })
    }
}

fn parse_output(bytes: &[u8]) -> Result<String, &'static str> {
    if bytes.len() > MAX_CONFIG_BYTES || bytes.last() != Some(&0) {
        return Err("local_principal_output_invalid");
    }
    let value = &bytes[..bytes.len() - 1];
    if value.contains(&0) {
        return Err("local_principal_ambiguous");
    }
    let principal = std::str::from_utf8(value).map_err(|_| "local_principal_encoding")?;
    chinwag_signing::validate_principal(principal).map_err(|_| "local_principal_invalid")?;
    Ok(principal.to_owned())
}
