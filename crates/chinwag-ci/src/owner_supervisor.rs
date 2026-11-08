// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Fixed owner worker, never an arbitrary process launcher. A missed native
//! close deadline is held until this parent observes its original OS child exit.
use crate::{
    owner_cli,
    runtime::{RootConfiguration, StudioConfiguration},
};
use serde::Serialize;
use std::{
    future::Future,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{ExitStatus, Stdio},
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    time::{Instant, timeout_at},
};

#[derive(Clone, Copy)]
pub enum OwnerKind {
    Root,
    Studio,
}
#[derive(Serialize)]
struct OwnerExit {
    classification: &'static str,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stop_requested: bool,
    forced: bool,
    deadline_exceeded: bool,
    os_exit_observed: bool,
}
impl OwnerExit {
    fn observed(status: ExitStatus, stop_requested: bool, forced: bool, hard: Instant) -> Self {
        let deadline_exceeded = Instant::now() >= hard;
        Self {
            classification: if status.success() && !forced && !deadline_exceeded {
                "CI_OWNER_EXIT_OBSERVED"
            } else {
                "CI_OWNER_HELD_OR_FORCED_EXIT_OBSERVED"
            },
            exit_code: status.code(),
            signal: status.signal(),
            stop_requested,
            forced,
            deadline_exceeded,
            os_exit_observed: true,
        }
    }
    fn clean(&self) -> bool {
        self.exit_code == Some(0)
            && self.signal.is_none()
            && !self.forced
            && !self.deadline_exceeded
            && self.os_exit_observed
    }
}
async fn watch_child<S: Future<Output = ()>>(
    child: &mut Child,
    hard: Instant,
    stop: S,
) -> std::io::Result<OwnerExit> {
    tokio::pin!(stop);
    let stopped = tokio::select! {
        status = child.wait() => return Ok(OwnerExit::observed(status?, false, false, hard)),
        _ = &mut stop => true,
        _ = tokio::time::sleep_until(hard) => false,
    };
    if let Some(status) = child.try_wait()? {
        return Ok(OwnerExit::observed(status, stopped, false, hard));
    }
    if stopped {
        let pid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| std::io::Error::other("owned child unavailable"))?;
        // The exact owned unreaped child cannot have its PID reused.
        let _signal = rustix::process::kill_process(pid, rustix::process::Signal::INT);
        let drain = hard.min(Instant::now() + Duration::from_secs(12));
        if let Ok(status) = timeout_at(drain, child.wait()).await {
            return Ok(OwnerExit::observed(status?, true, false, hard));
        }
    }
    // A late status after the hard bound is still held, even if exit code is 0.
    if let Some(status) = child.try_wait()? {
        return Ok(OwnerExit::observed(status, stopped, false, hard));
    }
    let _kill_result = child.start_kill();
    // SIGKILL issuance/kill_on_drop is not OS completion. Retain the same child
    // and wait. A kernel reap error remains unknown, never a completion receipt.
    Ok(OwnerExit::observed(
        child.wait().await?,
        stopped,
        true,
        hard,
    ))
}
pub async fn run(kind: OwnerKind, config: &Path) -> Result<(), ()> {
    // Only this owner's declared public configuration is parsed by the parent;
    // custody, ledgers, stores and keys are opened exclusively by its worker.
    let (seconds, worker) = match kind {
        OwnerKind::Root => (
            owner_cli::read_public::<RootConfiguration>(config)
                .map_err(|_| ())?
                .lifetime_seconds,
            "__ci-owned-root",
        ),
        OwnerKind::Studio => (
            owner_cli::read_public::<StudioConfiguration>(config)
                .map_err(|_| ())?
                .lifetime_seconds,
            "__ci-owned-studio",
        ),
    };
    if !(30..=3600).contains(&seconds) {
        return Err(());
    }
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| ())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| ())?;
    let hard = Instant::now() + Duration::from_secs(seconds + 2);
    let mut command = Command::new(std::env::current_exe().map_err(|_| ())?);
    command
        .arg(worker)
        .arg(config)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|_| ())?;
    let stop = async {
        tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
    };
    let observed = watch_child(&mut child, hard, stop).await.map_err(|_| ())?;
    println!("{}", serde_json::to_string(&observed).map_err(|_| ())?);
    if observed.clean() { Ok(()) } else { Err(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MODE: &str = "CHINWAG_CI_TEST_OWNER_PROCESS";
    #[tokio::test]
    async fn worker_fixture() {
        let Some(mode) = std::env::var_os(MODE) else {
            return;
        };
        let mut signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
        if let Some(path) = std::env::var_os("CHINWAG_CI_TEST_OWNER_READY") {
            std::fs::write(path, b"ready").unwrap();
        }
        match mode.to_str().unwrap() {
            "clean" => {}
            "failure" => std::process::exit(17),
            "cooperative" => {
                signal.recv().await;
            }
            "bind" | "close" => std::future::pending::<()>().await,
            _ => panic!("unknown test fixture"),
        }
    }
    async fn exercise(mode: &str, cancel: bool) -> OwnerExit {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "owner_supervisor::tests::worker_fixture",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MODE, mode)
            .env("CHINWAG_CI_TEST_OWNER_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        while !ready.exists() {
            assert!(Instant::now() < until);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let start = Instant::now();
        let stop = async {
            if cancel {
                tokio::time::sleep(Duration::from_millis(20)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let result = watch_child(&mut child, start + Duration::from_millis(180), stop)
            .await
            .unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(child.try_wait().unwrap().is_some());
        result
    }
    #[tokio::test]
    async fn actual_clean_exit_and_failure_keep_their_original_status() {
        assert!(exercise("clean", false).await.clean());
        let failure = exercise("failure", false).await;
        assert_eq!(failure.exit_code, Some(17));
        assert!(!failure.clean());
        assert!(!failure.forced);
        let late = OwnerExit::observed(
            ExitStatus::from_raw(0),
            false,
            false,
            Instant::now() - Duration::from_millis(1),
        );
        assert!(late.deadline_exceeded);
        assert!(!late.clean());
    }
    #[tokio::test]
    async fn cooperative_stop_is_os_observed_without_force() {
        let exit = exercise("cooperative", true).await;
        assert!(exit.clean());
        assert!(exit.stop_requested);
        assert!(!exit.forced);
    }
    #[tokio::test]
    async fn stalled_bind_process_is_killed_waited_and_never_clean() {
        let exit = exercise("bind", false).await;
        assert_eq!(exit.signal, Some(9));
        assert!(exit.forced);
        assert!(!exit.clean());
    }
    #[tokio::test]
    async fn stalled_first_close_process_is_killed_waited_and_never_restarted() {
        let exit = exercise("close", true).await;
        assert_eq!(exit.signal, Some(9));
        assert!(exit.forced);
        assert!(exit.stop_requested);
        assert!(!exit.clean());
    }
}
