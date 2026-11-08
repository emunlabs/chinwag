// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Public fixture preparation only, never execution or admission authority.
//! Read the exact admitted Git object instead of trusting a dirty working tree.
//! Fresh owned staging excludes .git, home directories and credentials.

use crate::{
    profile::{BoundProfiles, CommandProfile},
    storage::CiphertextStore,
};
#[cfg(target_os = "macos")]
use rustix::fd::AsFd;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

pub const FIXTURE_GIT_PATH: &str = "ci/chinwag-ci-loop-fixture/fixture.rs";
const MAX_FIXTURE: usize = 1024 * 1024;
#[derive(Debug, thiserror::Error)]
pub enum PreparationError {
    #[error("CI public fixture is missing, changed, unbounded or not from the admitted source")]
    Fixture,
    #[error("CI sandbox staging namespace already exists or is not owner controlled; preserve it")]
    Namespace,
    #[error("CI owned Git preparation child did not close successfully within its bound")]
    Child,
}
pub struct PreparedFixture {
    directory: CiphertextStore,
    path: PathBuf,
    command_profile: [u8; 32],
    fixture_digest: [u8; 32],
    source_commit: String,
}
impl PreparedFixture {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }
    pub fn fixture_digest(&self) -> [u8; 32] {
        self.fixture_digest
    }
    pub fn command_profile_digest(&self) -> [u8; 32] {
        self.command_profile
    }
    /// Recheck the descriptor-bound staging and its exact named fixture before
    /// a later admitted execution. The public file is not an execution grant.
    pub fn verify_unchanged(&self, profile: &CommandProfile) -> Result<(), PreparationError> {
        if self.command_profile != profile.digest() {
            return Err(PreparationError::Fixture);
        }
        self.directory
            .check()
            .map_err(|_| PreparationError::Namespace)?;
        let named_root =
            CiphertextStore::open(&self.path).map_err(|_| PreparationError::Namespace)?;
        let held =
            fs::fstat(self.directory.directory()).map_err(|_| PreparationError::Namespace)?;
        let named = fs::fstat(named_root.directory()).map_err(|_| PreparationError::Namespace)?;
        if named.st_dev != held.st_dev || named.st_ino != held.st_ino {
            return Err(PreparationError::Namespace);
        }
        let d = fs::openat(
            self.directory.directory(),
            "fixture",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| PreparationError::Namespace)?;
        let ds = fs::fstat(&d).map_err(|_| PreparationError::Namespace)?;
        if FileType::from_raw_mode(ds.st_mode) != FileType::Directory
            || ds.st_uid != rustix::process::geteuid().as_raw()
            || ds.st_mode & 0o7777 != 0o755
        {
            return Err(PreparationError::Namespace);
        }
        let fd = fs::openat(
            &d,
            "fixture.rs",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| PreparationError::Namespace)?;
        let start = fs::fstat(&fd).map_err(|_| PreparationError::Namespace)?;
        if FileType::from_raw_mode(start.st_mode) != FileType::RegularFile
            || start.st_uid != rustix::process::geteuid().as_raw()
            || start.st_nlink != 1
            || start.st_mode & 0o7777 != 0o444
            || start.st_size < 1
            || start.st_size as u64 > MAX_FIXTURE as u64
        {
            return Err(PreparationError::Namespace);
        }
        #[cfg(target_os = "macos")]
        crate::macos_acl::require_absent(fd.as_fd()).map_err(|_| PreparationError::Namespace)?;
        let file = File::from(fd);
        let mut bytes = Vec::with_capacity(start.st_size as usize);
        (&file)
            .take(MAX_FIXTURE as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PreparationError::Fixture)?;
        let end = fs::fstat(&file).map_err(|_| PreparationError::Namespace)?;
        let named = fs::statat(&d, "fixture.rs", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| PreparationError::Namespace)?;
        if bytes.len() != start.st_size as usize
            || end.st_size != start.st_size
            || end.st_ino != start.st_ino
            || end.st_dev != start.st_dev
            || named.st_ino != end.st_ino
            || named.st_dev != end.st_dev
            || named.st_size != end.st_size
        {
            return Err(PreparationError::Namespace);
        }
        profile
            .verify_fixture(&bytes)
            .map_err(|_| PreparationError::Fixture)?;
        self.directory
            .check()
            .map_err(|_| PreparationError::Namespace)?;
        Ok(())
    }
}
async fn git_output(
    checkout: &Path,
    args: &[String],
    limit: usize,
) -> Result<Vec<u8>, PreparationError> {
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .args([
            "--no-pager",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.allow=never",
            "-C",
        ])
        .arg(checkout)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|_| PreparationError::Child)?;
    let mut out = child
        .stdout
        .take()
        .ok_or(PreparationError::Child)?
        .take(limit as u64 + 1);
    let mut err = child
        .stderr
        .take()
        .ok_or(PreparationError::Child)?
        .take(4097);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = timeout(Duration::from_secs(10), async {
        let (_, _, exit) = tokio::try_join!(
            out.read_to_end(&mut stdout),
            err.read_to_end(&mut stderr),
            child.wait()
        )?;
        Ok::<_, std::io::Error>(exit)
    })
    .await;
    match result {
        Ok(Ok(exit)) if exit.success() && stdout.len() <= limit && stderr.is_empty() => Ok(stdout),
        _ => {
            // Own direct Git child only. No hooks, shell, pager or filters are
            // invoked. Unknown close is a failure, never a readiness witness.
            let _ = child.start_kill();
            let _ = timeout(Duration::from_secs(5), child.wait()).await;
            Err(PreparationError::Child)
        }
    }
}
async fn pinned_bytes(checkout: &Path, source: &str) -> Result<Vec<u8>, PreparationError> {
    if source.len() != 40
        || !source
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !checkout.is_absolute()
        || checkout
            .canonicalize()
            .map_err(|_| PreparationError::Fixture)?
            != checkout
    {
        return Err(PreparationError::Fixture);
    }
    let head = git_output(
        checkout,
        &[
            "rev-parse".into(),
            "--verify".into(),
            "HEAD^{commit}".into(),
        ],
        64,
    )
    .await?;
    if head != format!("{source}\n").as_bytes() {
        return Err(PreparationError::Fixture);
    }
    let object = format!("{source}:{FIXTURE_GIT_PATH}");
    let size = git_output(
        checkout,
        &["cat-file".into(), "-s".into(), object.clone()],
        32,
    )
    .await?;
    let count = std::str::from_utf8(&size)
        .ok()
        .and_then(|s| s.strip_suffix('\n'))
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or(PreparationError::Fixture)?;
    if count == 0 || count > MAX_FIXTURE {
        return Err(PreparationError::Fixture);
    }
    let bytes = git_output(
        checkout,
        &["cat-file".into(), "blob".into(), object],
        MAX_FIXTURE,
    )
    .await?;
    if bytes.len() != count {
        return Err(PreparationError::Fixture);
    }
    Ok(bytes)
}
fn materialize(
    profile: &CommandProfile,
    source: &str,
    bytes: &[u8],
    path: &Path,
) -> Result<PreparedFixture, PreparationError> {
    profile
        .verify_fixture(bytes)
        .map_err(|_| PreparationError::Fixture)?;
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| PreparationError::Namespace)?;
    let directory = CiphertextStore::open(path).map_err(|_| PreparationError::Namespace)?;
    fs::mkdirat(directory.directory(), "fixture", Mode::from_raw_mode(0o755))
        .map_err(|_| PreparationError::Namespace)?;
    fs::mkdirat(
        directory.directory(),
        "empty-docker-config",
        Mode::from_raw_mode(0o700),
    )
    .map_err(|_| PreparationError::Namespace)?;
    let fixture = fs::openat(
        directory.directory(),
        "fixture",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PreparationError::Namespace)?;
    // Correct mode of this freshly created PUBLIC source directory only. No
    // existing permission repair and no credential/configuration copying.
    fs::fchmod(&fixture, Mode::from_raw_mode(0o755)).map_err(|_| PreparationError::Namespace)?;
    let fd = fs::openat(
        &fixture,
        "fixture.rs",
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| PreparationError::Namespace)?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .map_err(|_| PreparationError::Fixture)?;
    fs::fchmod(&file, Mode::from_raw_mode(0o444)).map_err(|_| PreparationError::Namespace)?;
    file.sync_all().map_err(|_| PreparationError::Fixture)?;
    fs::fsync(&fixture).map_err(|_| PreparationError::Fixture)?;
    fs::fsync(directory.directory()).map_err(|_| PreparationError::Fixture)?;
    let result = PreparedFixture {
        directory,
        path: path.into(),
        command_profile: profile.digest(),
        fixture_digest: Sha256::digest(bytes).into(),
        source_commit: source.into(),
    };
    result.verify_unchanged(profile)?;
    Ok(result)
}
/// Stage bytes only. The separately admitted runner must still enforce current
/// certificate/run/keys and own the full container lifecycle before capture.
pub async fn prepare(
    profiles: &BoundProfiles,
    checkout: &Path,
) -> Result<PreparedFixture, PreparationError> {
    let bytes = pinned_bytes(checkout, profiles.intended_source()).await?;
    materialize(
        profiles.command(),
        profiles.intended_source(),
        &bytes,
        &profiles.command().execution_directory(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::CommandProfileSpec;
    use std::{os::unix::fs::PermissionsExt, process::Command as SyncCommand};
    fn profile(bytes: &[u8]) -> CommandProfile {
        CommandProfile::parse(
            &serde_json::to_vec(&CommandProfileSpec {
                version: 1,
                execution_id: [31; 32],
                rust_image: format!("docker.io/library/rust@sha256:{}", "a".repeat(64)),
                fixture_sha256: Sha256::digest(bytes).into(),
                timeout_seconds: 60,
                isolation: "UNPRIVILEGED_NETWORKLESS_DOCKER_FIXED_RUST_FIXTURE_V1".into(),
            })
            .unwrap(),
        )
        .unwrap()
    }
    fn git(path: &Path, args: &[&str]) -> Vec<u8> {
        let out = SyncCommand::new("/usr/bin/git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args([
                "-c",
                "user.name=CI public fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
            ])
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success());
        out.stdout
    }
    #[tokio::test]
    async fn dirty_worktree_and_symlink_do_not_replace_the_pinned_git_object() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        git(&root, &["init", "-q"]);
        let file = root.join(FIXTURE_GIT_PATH);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"public committed fixture").unwrap();
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "public controlled fixture"]);
        let sha = String::from_utf8(git(&root, &["rev-parse", "HEAD"])).unwrap();
        let sha = sha.trim();
        std::fs::write(&file, b"different working copy").unwrap();
        assert_eq!(
            pinned_bytes(&root, sha).await.unwrap(),
            b"public committed fixture"
        );
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("/definitely-not-readable-test-target", &file).unwrap();
        assert_eq!(
            pinned_bytes(&root, sha).await.unwrap(),
            b"public committed fixture"
        );
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, b"next public fixture").unwrap();
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "next public fixture"]);
        assert!(pinned_bytes(&root, sha).await.is_err());
        let next = String::from_utf8(git(&root, &["rev-parse", "HEAD"])).unwrap();
        git(&root, &["update-ref", "HEAD", sha]);
        git(&root, &["replace", sha, next.trim()]);
        assert_eq!(
            pinned_bytes(&root, sha).await.unwrap(),
            b"public committed fixture"
        );
    }
    #[test]
    fn staging_is_fresh_read_only_public_bytes_and_changed_or_preexisting_paths_refuse() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let p = profile(b"public fixture");
        let stage = root.join("stage");
        let prepared = materialize(&p, &"a".repeat(40), b"public fixture", &stage).unwrap();
        assert_eq!(
            std::fs::metadata(&stage).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(stage.join("fixture"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(stage.join("fixture/fixture.rs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        assert!(materialize(&p, &"a".repeat(40), b"public fixture", &stage).is_err());
        let other = root.join("other");
        assert!(materialize(&p, &"a".repeat(40), b"changed fixture", &other).is_err());
        assert!(!other.exists());
        std::fs::set_permissions(
            stage.join("fixture/fixture.rs"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(stage.join("fixture/fixture.rs"), b"changed fixture").unwrap();
        assert!(prepared.verify_unchanged(&p).is_err());
    }
    #[test]
    fn renaming_staging_and_replacing_its_path_cannot_validate_the_old_descriptor() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let p = profile(b"public fixture");
        let stage = root.join("stage");
        let prepared = materialize(&p, &"a".repeat(40), b"public fixture", &stage).unwrap();
        std::fs::rename(&stage, root.join("preserved-original-stage")).unwrap();
        std::fs::create_dir(&stage).unwrap();
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(prepared.verify_unchanged(&p).is_err());
    }
}
