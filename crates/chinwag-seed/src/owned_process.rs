use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
use std::{
    process::{ExitStatus, Stdio},
    sync::Arc,
    time::Duration,
};
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::OwnedSemaphorePermit,
    time::{Instant, sleep, timeout},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "Cargo verification needs existing workspace, toolchain, cache and workspace target directories"
    )]
    Configuration,
    #[error("Cargo verification is already running")]
    Busy,
    #[error("Cargo verification could not start its child process")]
    Spawn,
    #[error("Cargo process operation failed at {stage} (OS code {os_code:?})")]
    Process {
        stage: &'static str,
        os_code: Option<i32>,
    },
    #[error("Darwin group inspection failed at {stage}")]
    Inspection { stage: &'static str },
    #[cfg(target_os = "macos")]
    #[error(transparent)]
    NativeInspection(#[from] chinwag_host_process::Error),
    #[error("Cargo verification could not read compiler output")]
    Output,
    #[error("Cargo verification exceeded the compiler output limit")]
    OutputLimit,
    #[error("Cargo verification exceeded the command time limit")]
    Timeout,
}

#[derive(Debug)]
pub struct CommandReport {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed_ms: u128,
}

// The owner moves atomically; a group can never survive without its Child.
struct OwnedProcess {
    owner: Option<OwnedChild>,
}

struct OwnedChild {
    child: Child,
    group: Option<Pid>,
    // Fields drop in declaration order: release the job only after Child cleanup.
    _job: Arc<OwnedSemaphorePermit>,
}

impl OwnedChild {
    fn observe(&mut self, stage: &'static str) -> Result<bool, Error> {
        let group = self.group.ok_or(Error::Process {
            stage: "owned group missing",
            os_code: None,
        })?;
        match waitid(
            WaitId::Pid(group),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(state) => Ok(state.is_some()),
            Err(error) => {
                // Lost identity is terminal: no later Drop may retry this bare ID.
                self.group = None;
                Err(Error::Process {
                    stage,
                    os_code: Some(error.raw_os_error()),
                })
            }
        }
    }

    fn stop_group(&mut self) -> Result<(), Error> {
        if let Some(group) = self.group {
            self.observe("observe before group cleanup")?;
            match kill_process_group(group, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => self.group = None,
                Err(error) => {
                    return Err(Error::Process {
                        stage: "group cleanup",
                        os_code: Some(error.raw_os_error()),
                    });
                }
            }
        }
        Ok(())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.stop_group();
        // No signal follows this reap. Tokio's implicit pid kill is disabled.
        let _ = self.child.try_wait();
    }
}

impl OwnedProcess {
    fn child(&mut self) -> Result<&mut OwnedChild, Error> {
        self.owner.as_mut().ok_or(Error::Process {
            stage: "owned child missing",
            os_code: None,
        })
    }

    async fn wait(&mut self) -> Result<ExitStatus, Error> {
        loop {
            if self.child()?.observe("observe before reap")? {
                if let Err(error) = self.child()?.stop_group() {
                    #[cfg(target_os = "macos")]
                    if matches!(error, Error::Process { os_code: Some(code), .. } if code == rustix::io::Errno::PERM.raw_os_error())
                    {
                        self.inspect_exited_group(
                            Duration::from_secs(2),
                            chinwag_host_process::inspect_exited_group,
                        )
                        .await?;
                    } else {
                        return Err(error);
                    }
                    #[cfg(not(target_os = "macos"))]
                    return Err(error);
                }
                return self
                    .child()?
                    .child
                    .wait()
                    .await
                    .map_err(|error| Error::Process {
                        stage: "reap owned leader",
                        os_code: error.raw_os_error(),
                    });
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    #[cfg(target_os = "macos")]
    async fn inspect_exited_group<F>(&mut self, limit: Duration, inspect: F) -> Result<(), Error>
    where
        F: FnOnce(
                std::num::NonZeroI32,
            )
                -> Result<chinwag_host_process::GroupState, chinwag_host_process::Error>
            + Send
            + 'static,
    {
        let mut owner = self
            .owner
            .take()
            .ok_or_else(|| inspection_failure("owned child missing"))?;
        // There is no await between the transfer and spawning. The worker owns
        // Child, group and the existing job permit, even after cancellation.
        let query = tokio::task::spawn_blocking(move || {
            if !owner.observe("observe before native query")? {
                return Err(inspection_failure("owned leader not exited"));
            }
            let group = owner
                .group
                .ok_or_else(|| inspection_failure("owned group missing"))?;
            let state = inspect(group.as_raw_nonzero());
            if !owner.observe("observe after native query")? {
                return Err(inspection_failure("owned leader no longer exited"));
            }
            match state? {
                chinwag_host_process::GroupState::Quiescent => {
                    owner.group = None;
                    Ok(owner)
                }
                chinwag_host_process::GroupState::Executing => Err(Error::Process {
                    stage: "owned group still executing",
                    os_code: Some(rustix::io::Errno::PERM.raw_os_error()),
                }),
            }
        });
        let owner = timeout(limit, query)
            .await
            .map_err(|_| inspection_failure("native query timeout"))?
            .map_err(|_| inspection_failure("native query worker failed"))??;
        self.owner = Some(owner);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn inspection_failure(stage: &'static str) -> Error {
    Error::Inspection { stage }
}

async fn read_output(mut pipe: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = pipe.read(&mut buffer).await.map_err(|_| Error::Output)?;
        if count == 0 {
            return Ok(output);
        }
        if count > limit.saturating_sub(output.len()) {
            return Err(Error::OutputLimit);
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

pub(crate) async fn execute_guarded(
    command: Command,
    time_limit: Duration,
    output_limit: usize,
    job: Arc<OwnedSemaphorePermit>,
) -> Result<CommandReport, Error> {
    execute_guarded_streams(command, time_limit, output_limit, output_limit, job).await
}

pub(crate) async fn execute_guarded_streams(
    mut command: Command,
    time_limit: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    job: Arc<OwnedSemaphorePermit>,
) -> Result<CommandReport, Error> {
    let start = Instant::now();
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(false)
        .spawn()
        .map_err(|_| Error::Spawn)?;
    let group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(Pid::from_raw)
        .filter(|pid| *pid != Pid::INIT);
    let mut owned = OwnedProcess {
        owner: Some(OwnedChild {
            child,
            group,
            _job: job,
        }),
    };
    if group.is_none() {
        return Err(Error::Process {
            stage: "identify owned leader",
            os_code: None,
        });
    }
    let stdout = owned.child()?.child.stdout.take().ok_or(Error::Output)?;
    let stderr = owned.child()?.child.stderr.take().ok_or(Error::Output)?;
    let (status, stdout, stderr) = timeout(time_limit, async {
        tokio::try_join!(
            owned.wait(),
            read_output(stdout, stdout_limit),
            read_output(stderr, stderr_limit)
        )
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(CommandReport {
        success: status.success(),
        exit_code: status.code(),
        stdout,
        stderr,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

#[cfg(test)]
async fn execute(
    command: Command,
    time_limit: Duration,
    output_limit: usize,
) -> Result<CommandReport, Error> {
    let job = Arc::new(
        Arc::new(Semaphore::new(1))
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?,
    );
    execute_guarded(command, time_limit, output_limit, job).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn artifact_stdout_and_diagnostic_stderr_have_independent_limits() {
        let limit = crate::bundle::MAX_BUNDLE_BYTES;
        for (stdout_bytes, stderr_bytes, succeeds) in
            [(limit, 0, true), (limit + 1, 0, false), (0, 65537, false)]
        {
            let available = Arc::new(Semaphore::new(1));
            let job = Arc::new(available.clone().try_acquire_owned().unwrap());
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                "if [ \"$1\" -gt 0 ]; then /usr/bin/head -c \"$1\" /dev/zero; fi; if [ \"$2\" -gt 0 ]; then /usr/bin/head -c \"$2\" /dev/zero >&2; fi",
                "fixture",
            ]);
            command
                .arg(stdout_bytes.to_string())
                .arg(stderr_bytes.to_string());
            let result =
                execute_guarded_streams(command, Duration::from_secs(10), limit, 65536, job).await;
            if succeeds {
                let report = result.unwrap();
                assert!(report.success, "{report:?}");
                assert_eq!(report.stdout.len(), stdout_bytes);
                assert!(report.stdout.iter().all(|byte| *byte == 0));
                assert!(report.stderr.is_empty());
            } else {
                assert!(matches!(result, Err(Error::OutputLimit)));
            }
            assert_eq!(available.available_permits(), 1);
        }
    }
    #[cfg(target_os = "macos")]
    use std::{fs, path::Path};

    #[cfg(target_os = "macos")]
    struct Fixture {
        group: std::num::NonZeroI32,
        member: std::num::NonZeroI32,
    }

    #[cfg(target_os = "macos")]
    fn descendant(pid_file: &Path) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "sleep 30 & printf '%s %s\\n' \"$!\" \"$$\" > \"$1\"; wait",
            "fixture",
        ]);
        command.arg(pid_file);
        command
    }

    #[cfg(target_os = "macos")]
    async fn read_fixture(path: &Path) -> Fixture {
        timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(value) = fs::read_to_string(path)
                    && value.ends_with('\n')
                {
                    let fields: Vec<_> = value.split_whitespace().collect();
                    assert_eq!(fields.len(), 2, "invalid fixture readiness");
                    let fixture = Fixture {
                        member: fields[0].parse().unwrap(),
                        group: fields[1].parse().unwrap(),
                    };
                    // The original PGID is the unreaped direct child, not merely
                    // a number whose group happens to contain the descendant.
                    assert!(
                        waitid(
                            WaitId::Pid(Pid::from_raw(fixture.group.get()).unwrap()),
                            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                        )
                        .unwrap()
                        .is_none()
                    );
                    assert!(fixture_is_executing(&fixture), "fixture was never live");
                    return fixture;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    #[cfg(target_os = "macos")]
    fn fixture_is_executing(fixture: &Fixture) -> bool {
        chinwag_host_process::fixture_member_is_executing(fixture.group, fixture.member)
            .expect("native fixture observation must succeed")
    }

    #[cfg(target_os = "macos")]
    async fn assert_stopped(fixture: &Fixture) {
        timeout(Duration::from_secs(3), async {
            loop {
                if !fixture_is_executing(fixture) {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("an owned descendant is still executing");
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn cancellation_stops_the_owned_descendant_group() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("descendant.pid");
        let command = descendant(&path);
        let task = tokio::spawn(execute(command, Duration::from_secs(10), 1024));
        let fixture = read_fixture(&path).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_stopped(&fixture).await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg(target_os = "macos")]
    async fn timeout_stops_the_owned_descendant_group() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("descendant.pid");
        let command = descendant(&path);
        let task = tokio::spawn(execute(command, Duration::from_secs(30), 1024));
        let fixture = read_fixture(&path).await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        let result = task.await.unwrap();
        tokio::time::resume();
        assert!(matches!(result, Err(Error::Timeout)));
        assert_stopped(&fixture).await;
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn a_finished_leader_cannot_leave_a_descendant_holding_the_output_pipe() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("descendant.pid");
        let release = directory.path().join("release");
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "sleep 30 & printf '%s %s\\n' \"$!\" \"$$\" > \"$1\"; while [ ! -f \"$2\" ]; do sleep 0.01; done; exit 0",
            "fixture",
        ]);
        command.arg(&path).arg(&release);
        let task = tokio::spawn(execute(command, Duration::from_secs(3), 1024));
        let fixture = read_fixture(&path).await;
        fs::write(release, b"release").unwrap();
        let report = task.await.unwrap().unwrap();
        assert!(report.success);
        assert_stopped(&fixture).await;
    }

    #[cfg(target_os = "macos")]
    async fn exited_owner() -> (OwnedProcess, Arc<Semaphore>, Pid) {
        let available = Arc::new(Semaphore::new(1));
        let job = Arc::new(available.clone().try_acquire_owned().unwrap());
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .process_group(0)
            .kill_on_drop(false)
            .spawn()
            .unwrap();
        let group = Pid::from_raw(i32::try_from(child.id().unwrap()).unwrap()).unwrap();
        let mut owned = OwnedProcess {
            owner: Some(OwnedChild {
                child,
                group: Some(group),
                _job: job,
            }),
        };
        timeout(Duration::from_secs(3), async {
            while !owned.child().unwrap().observe("fixture exit").unwrap() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        (owned, available, group)
    }

    #[cfg(target_os = "macos")]
    fn assert_pin_held(available: &Semaphore, group: Pid) {
        assert_eq!(available.available_permits(), 0);
        assert!(available.try_acquire().is_err());
        assert!(
            waitid(
                WaitId::Pid(group),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .unwrap()
            .is_some()
        );
    }

    #[cfg(target_os = "macos")]
    fn assert_pin_retired(available: &Semaphore, group: Pid) {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while available.available_permits() == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(available.available_permits(), 1, "worker retained the job");
        let _permit = available.try_acquire().unwrap();
        assert_eq!(
            waitid(
                WaitId::Pid(group),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .unwrap_err(),
            rustix::io::Errno::CHILD,
            "worker did not reap its owned leader"
        );
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn native_query_timeout_retains_owned_leader_and_the_same_job_until_worker_ends() {
        let (mut owned, available, group) = exited_owner().await;
        let (release, receive) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let result = owned
                .inspect_exited_group(Duration::from_millis(30), move |group| {
                    let _ = started.send(());
                    receive.recv_timeout(Duration::from_secs(3)).unwrap();
                    chinwag_host_process::inspect_exited_group(group)
                })
                .await;
            assert!(owned.owner.is_none());
            drop(owned);
            result
        });
        ready.await.unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(Error::Inspection {
                stage: "native query timeout",
                ..
            })
        ));
        assert_pin_held(&available, group);
        release.send(()).unwrap();
        assert_pin_retired(&available, group);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn runtime_shutdown_cannot_reap_the_blocked_querys_owned_leader_or_release_its_job() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut owned, available, group) = runtime.block_on(exited_owner());
        let (release, receive) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        runtime.spawn(async move {
            owned
                .inspect_exited_group(Duration::from_secs(30), move |group| {
                    let _ = started.send(());
                    receive.recv_timeout(Duration::from_secs(3)).unwrap();
                    chinwag_host_process::inspect_exited_group(group)
                })
                .await
        });
        runtime.block_on(ready).unwrap();
        runtime.shutdown_background();
        assert_pin_held(&available, group);
        release.send(()).unwrap();
        assert_pin_retired(&available, group);
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn lost_leader_identity_disarms_cleanup_and_drop_never_signals_its_live_sibling() {
        let available = Arc::new(Semaphore::new(1));
        let job = Arc::new(available.clone().try_acquire_owned().unwrap());
        let leader = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .kill_on_drop(false)
            .spawn()
            .unwrap();
        let group = Pid::from_raw(i32::try_from(leader.id().unwrap()).unwrap()).unwrap();
        let mut owner = OwnedChild {
            child: leader,
            group: Some(group),
            _job: job,
        };
        // A second directly owned child pins the group while this test deliberately
        // reaps its old leader. Cleanup uses this child's handle, never a stale ID.
        let mut sibling = Command::new("/bin/sleep")
            .arg("30")
            .process_group(group.as_raw_nonzero().get())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let fixture = Fixture {
            group: group.as_raw_nonzero(),
            member: std::num::NonZeroI32::new(i32::try_from(sibling.id().unwrap()).unwrap())
                .unwrap(),
        };
        assert!(fixture_is_executing(&fixture));
        owner.child.start_kill().unwrap();
        owner.child.wait().await.unwrap();
        assert!(
            matches!(owner.stop_group(), Err(Error::Process { os_code: Some(code), .. }) if code == rustix::io::Errno::CHILD.raw_os_error())
        );
        assert!(owner.group.is_none());
        owner.stop_group().unwrap();
        drop(owner);
        assert!(sibling.try_wait().unwrap().is_none());
        assert!(fixture_is_executing(&fixture));
        assert_eq!(available.available_permits(), 1);
        sibling.start_kill().unwrap();
        sibling.wait().await.unwrap();
        assert_stopped(&fixture).await;
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn executing_or_invalid_native_snapshot_keeps_cleanup_with_the_worker() {
        for injected_error in [
            None,
            Some(chinwag_host_process::Error::Snapshot("empty snapshot")),
            Some(chinwag_host_process::Error::Snapshot("truncated record")),
            Some(chinwag_host_process::Error::Query(Some(1))),
        ] {
            let available = Arc::new(Semaphore::new(1));
            let job = Arc::new(available.clone().try_acquire_owned().unwrap());
            let leader = Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .kill_on_drop(false)
                .spawn()
                .unwrap();
            let group = Pid::from_raw(i32::try_from(leader.id().unwrap()).unwrap()).unwrap();
            let mut owned = OwnedProcess {
                owner: Some(OwnedChild {
                    child: leader,
                    group: Some(group),
                    _job: job,
                }),
            };
            let mut sibling = Command::new("/bin/sleep")
                .arg("30")
                .process_group(group.as_raw_nonzero().get())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let fixture = Fixture {
                group: group.as_raw_nonzero(),
                member: std::num::NonZeroI32::new(i32::try_from(sibling.id().unwrap()).unwrap())
                    .unwrap(),
            };
            assert!(fixture_is_executing(&fixture));
            owned.child().unwrap().child.start_kill().unwrap();
            timeout(Duration::from_secs(3), async {
                while !owned.child().unwrap().observe("fixture exit").unwrap() {
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(
                chinwag_host_process::inspect_exited_group(fixture.group).unwrap(),
                chinwag_host_process::GroupState::Executing
            );
            let was_invalid = injected_error.is_some();
            let result = owned
                .inspect_exited_group(Duration::from_secs(2), move |group| match injected_error {
                    Some(error) => Err(error),
                    None => chinwag_host_process::inspect_exited_group(group),
                })
                .await;
            if was_invalid {
                assert!(matches!(result, Err(Error::NativeInspection(_))));
            } else {
                assert!(matches!(
                    result,
                    Err(Error::Process {
                        stage: "owned group still executing",
                        ..
                    })
                ));
            }
            assert!(owned.owner.is_none());
            assert_pin_retired(&available, group);
            assert_stopped(&fixture).await;
            // Reap only our second direct Child after the worker's group cleanup.
            sibling.wait().await.unwrap();
        }
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn a_malformed_native_snapshot_returns_error_and_retires_its_owner() {
        let (mut owned, available, group) = exited_owner().await;
        let result = owned
            .inspect_exited_group(Duration::from_secs(2), |_| {
                Err(chinwag_host_process::Error::Snapshot(
                    "fixture truncated record",
                ))
            })
            .await;
        assert!(matches!(
            result,
            Err(Error::NativeInspection(
                chinwag_host_process::Error::Snapshot("fixture truncated record")
            ))
        ));
        assert!(owned.owner.is_none());
        assert_pin_retired(&available, group);
    }

    #[tokio::test]
    async fn excessive_output_is_refused_and_failing_commands_return_their_diagnostics() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while :; do printf 12345678; done"]);
        assert!(matches!(
            execute(command, Duration::from_secs(3), 64).await,
            Err(Error::OutputLimit)
        ));
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "printf expected-out; printf expected-error >&2; exit 7",
        ]);
        let report = execute(command, Duration::from_secs(3), 1024)
            .await
            .unwrap();
        assert!(!report.success);
        assert_eq!(report.exit_code, Some(7));
        assert_eq!(report.stdout, b"expected-out");
        assert_eq!(report.stderr, b"expected-error");
    }
}
