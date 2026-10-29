//! Fixed Cargo verification with bounded output and an owned process group.
//! This controls process lifetime. It is not an OS sandbox for build scripts.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{process::Command, sync::Semaphore};

use crate::owned_process::execute_guarded;

pub use crate::owned_process::{CommandReport, Error};

const OUTPUT_BYTES_PER_STREAM: usize = 256 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub struct Verification {
    pub check: CommandReport,
    pub test: Option<CommandReport>,
}

impl Verification {
    pub fn passed(&self) -> bool {
        self.check.success && self.test.as_ref().is_some_and(|test| test.success)
    }
}

#[derive(Clone)]
pub struct CargoVerifier {
    workspace: PathBuf,
    toolchain: PathBuf,
    cache: PathBuf,
    target: PathBuf,
    available: Arc<Semaphore>,
}

impl CargoVerifier {
    /// These paths come from the operator, never from model tool arguments.
    /// The model can request verification, but cannot select a program or flags.
    pub fn new(
        workspace: &Path,
        toolchain: &Path,
        cache: &Path,
        target: &Path,
    ) -> Result<Self, Error> {
        let directory = |path: &Path| {
            path.canonicalize()
                .ok()
                .filter(|path| path.is_dir())
                .ok_or(Error::Configuration)
        };
        let workspace = directory(workspace)?;
        let toolchain = directory(toolchain)?;
        let cache = directory(cache)?;
        let target = directory(target)?;
        if !target.starts_with(workspace.join("target"))
            || !["cargo", "rustc", "rustdoc"]
                .iter()
                .all(|name| toolchain.join(name).is_file())
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            workspace,
            toolchain,
            cache,
            target,
            available: Arc::new(Semaphore::new(1)),
        })
    }

    fn base_command(&self) -> Command {
        let mut command = Command::new(self.toolchain.join("cargo"));
        command
            .current_dir(&self.workspace)
            .env_clear()
            .env("CARGO_HOME", &self.cache)
            .env("RUSTC", self.toolchain.join("rustc"))
            .env("RUSTDOC", self.toolchain.join("rustdoc"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.toolchain.display()),
            )
            .env("LC_ALL", "C")
            .env("CARGO_TERM_COLOR", "never");
        command
    }

    fn command(&self, operation: &str) -> Command {
        let mut command = self.base_command();
        command
            .args([
                operation,
                "--workspace",
                "--all-targets",
                "--locked",
                "--offline",
                "--target-dir",
            ])
            .arg(&self.target);
        command
    }

    /// Fixed Stage-1 build. The native directory and compiler flags are an
    /// operator-supplied build recipe, never arguments to a model tool.
    /// Existing owned-group wait and bounded-output rules apply unchanged.
    pub async fn build_release(
        &self,
        native_inputs: &Path,
        rustflags: &str,
    ) -> Result<CommandReport, Error> {
        if !native_inputs.is_absolute()
            || !native_inputs.is_dir()
            || rustflags.len() > 4096
            || rustflags.contains('\0')
            || self.target != self.workspace.join("target")
        {
            return Err(Error::Configuration);
        }
        let permit = Arc::new(
            self.available
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Busy)?,
        );
        let mut command = self.base_command();
        command
            .env("CHINWAG_PRIVATE_CRSQL_INPUTS", native_inputs)
            .env("RUSTFLAGS", rustflags)
            .args([
                "build",
                "--release",
                "--package",
                "chinwag-cli",
                "--bin",
                "chinwag",
                "--locked",
                "--offline",
                "--target-dir",
            ])
            .arg(&self.target);
        execute_guarded(command, COMMAND_TIMEOUT, OUTPUT_BYTES_PER_STREAM, permit).await
    }

    pub async fn verify(&self) -> Result<Verification, Error> {
        let permit = Arc::new(
            self.available
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Busy)?,
        );
        let check = execute_guarded(
            self.command("check"),
            COMMAND_TIMEOUT,
            OUTPUT_BYTES_PER_STREAM,
            permit.clone(),
        )
        .await?;
        let test = if check.success {
            Some(
                execute_guarded(
                    self.command("test"),
                    COMMAND_TIMEOUT,
                    OUTPUT_BYTES_PER_STREAM,
                    permit.clone(),
                )
                .await?,
            )
        } else {
            None
        };
        Ok(Verification { check, test })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn real_offline_cargo_verifies_a_crate_and_rejects_invalid_rust() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("src")).unwrap();
        fs::create_dir(root.join("target")).unwrap();
        let cache = root.join("empty-cargo-cache");
        fs::create_dir(&cache).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='seed-cargo-fixture'\nversion='0.0.0'\nedition='2024'\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"seed-cargo-fixture\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "#[test] fn actual_test() { assert_eq!(2 + 2, 4); }\n",
        )
        .unwrap();
        let rustc = chinwag_test_fixtures::rustc();
        let verifier =
            CargoVerifier::new(root, rustc.parent().unwrap(), &cache, &root.join("target"))
                .unwrap();
        let permit = verifier.available.try_acquire().unwrap();
        assert!(matches!(verifier.clone().verify().await, Err(Error::Busy)));
        drop(permit);
        let report = verifier.verify().await.unwrap();
        assert!(report.passed(), "{report:?}");
        assert!(String::from_utf8_lossy(&report.test.unwrap().stdout).contains("1 passed"));
        fs::write(root.join("src/lib.rs"), "fn broken( {\n").unwrap();
        let report = verifier.verify().await.unwrap();
        assert!(!report.passed());
        assert!(!report.check.success);
        assert!(report.test.is_none());
        assert!(!report.check.stderr.is_empty());
        assert!(matches!(
            CargoVerifier::new(root, rustc.parent().unwrap(), &cache, root),
            Err(Error::Configuration)
        ));
    }
}
