// Copyright (c) 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//! Bounded child collection; output is never included in diagnostics.
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use std::{
    io::{self, Read},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
fn nonblocking(stream: &impl std::os::fd::AsFd) -> Result<(), String> {
    let flags = fcntl_getfl(stream).map_err(|_| "child pipe flags unavailable")?;
    fcntl_setfl(stream, flags | OFlags::NONBLOCK)
        .map_err(|_| "child pipe nonblocking setup failed".into())
}
fn collect(
    child: &mut Child,
    stream: &mut impl Read,
    deadline: Instant,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let result = (|| {
        let mut output = Zeroizing::new(Vec::new());
        let mut buffer = Zeroizing::new([0u8; 1024]);
        let mut eof = false;
        loop {
            if Instant::now() >= deadline {
                return Err("credential child deadline exceeded".into());
            }
            if !eof {
                match stream.read(&mut buffer[..]) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        if n > limit.saturating_sub(output.len()) {
                            return Err("credential child output exceeds bound".into());
                        }
                        output.extend_from_slice(&buffer[..n]);
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return Err("credential child stream failed".into()),
                }
            }
            match child
                .try_wait()
                .map_err(|_| "credential child status failed")?
            {
                Some(status) if !status.success() => return Err("credential child failed".into()),
                Some(_) if eof => return Ok(output),
                _ => {}
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        stop(child);
    }
    result
}
pub(crate) fn run(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let deadline = Instant::now() + timeout;
    let mut child = command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| "credential child unavailable")?;
    let Some(mut stream) = child.stdout.take() else {
        stop(&mut child);
        return Err("credential child stream unavailable".into());
    };
    if let Err(error) = nonblocking(&stream) {
        stop(&mut child);
        return Err(error);
    }
    collect(&mut child, &mut stream, deadline, limit)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    fn shell(script: &str) -> Child {
        Command::new("/bin/sh")
            .args(["-c", script])
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    }
    fn assert_reaped(child: &mut Child) {
        let status = child
            .try_wait()
            .unwrap()
            .expect("child must be terminated and reaped");
        assert_eq!(status.signal(), Some(9));
        assert_eq!(child.wait().unwrap(), status);
    }
    #[test]
    fn deadline_handles_blocked_pipe_and_eof_before_child_exit() {
        for script in ["exec /bin/sleep 10", "exec 1>&-; exec /bin/sleep 10"] {
            let mut child = shell(script);
            let mut stream = child.stdout.take().unwrap();
            nonblocking(&stream).unwrap();
            let start = Instant::now();
            let error = collect(
                &mut child,
                &mut stream,
                start + Duration::from_millis(80),
                4096,
            )
            .unwrap_err();
            assert!(error.contains("deadline"));
            assert!(start.elapsed() < Duration::from_secs(2));
            assert_reaped(&mut child);
        }
    }
    #[test]
    fn excess_output_kills_and_reaps_child() {
        let mut child = shell("printf public-fixture-output; exec /bin/sleep 10");
        let mut stream = child.stdout.take().unwrap();
        nonblocking(&stream).unwrap();
        assert!(
            collect(
                &mut child,
                &mut stream,
                Instant::now() + Duration::from_secs(2),
                8
            )
            .unwrap_err()
            .contains("bound")
        );
        assert_reaped(&mut child);
    }
    #[test]
    fn injected_read_error_kills_and_reaps_child() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("public injected failure"))
            }
        }
        let mut child = shell("exec /bin/sleep 10");
        assert!(
            collect(
                &mut child,
                &mut Broken,
                Instant::now() + Duration::from_secs(2),
                4096
            )
            .unwrap_err()
            .contains("stream failed")
        );
        assert_reaped(&mut child);
    }
    #[test]
    fn successful_output_is_capped_and_environment_is_minimal() {
        let output = run(
            Command::new("/bin/sh").args(["-c", "printf public-fixture-output"]),
            Duration::from_secs(2),
            4096,
        )
        .unwrap();
        assert_eq!(&output[..], b"public-fixture-output");
        let output = run(
            Command::new("/usr/bin/env").env("UNRELATED_PARENT_VALUE", "public-fixture"),
            Duration::from_secs(2),
            4096,
        )
        .unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        assert!(text.contains("LANG=C"));
        assert!(text.contains("LC_ALL=C"));
        assert!(!text.contains("UNRELATED_PARENT_VALUE"));
        assert_eq!(text.lines().count(), 2);
    }
}
