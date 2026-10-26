//! Darwin child-only directory actions. No shell, parent chdir, or signals.
//!
//! The caller owns validation of the directory, program and explicit environment.
//! Retain the child and operation guard until its exact wait result is known.

use std::ffi::{CStr, CString};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

const _: () = assert!(libc::POSIX_SPAWN_CLOEXEC_DEFAULT == 0x4000);

pub struct SpawnStdio<'a> {
    pub input: BorrowedFd<'a>,
    pub output: BorrowedFd<'a>,
    pub error: BorrowedFd<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

/// An exclusively waited child. Dropping it neither signals nor reaps it.
#[must_use = "retain the child until its original terminal result is resolved"]
pub struct OwnedChild {
    pid: libc::pid_t,
    state: WaitState,
}

enum WaitState {
    Active,
    Terminal(Exit),
    /// Ownership or status is uncertain. This is not proof of an exited child.
    Quarantined(WaitFailure),
}

#[derive(Clone, Copy)]
enum WaitFailure {
    Os(i32),
    Kind(io::ErrorKind),
}

impl WaitFailure {
    fn from_error(error: &io::Error) -> Self {
        match error.raw_os_error() {
            Some(code) => Self::Os(code),
            None => Self::Kind(error.kind()),
        }
    }
    fn error(self) -> io::Error {
        match self {
            Self::Os(code) => io::Error::from_raw_os_error(code),
            Self::Kind(kind) => kind.into(),
        }
    }
}

impl OwnedChild {
    pub fn pid(&self) -> u32 {
        self.pid as u32
    }

    /// Cache a terminal result. A non-interruption error or unexpected status
    /// instead quarantines polling; retain that outcome as unknown, not exited.
    #[allow(unsafe_code)]
    pub fn try_wait(&mut self) -> io::Result<Option<Exit>> {
        // SAFETY: this token is constructed only from our successful spawn and
        // is not clonable. The caller must not let another waiter reap its PID.
        // status is a writable initialized integer; WNOHANG never signals.
        self.poll_with(|pid| {
            let mut status = 0;
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok((result, status))
            }
        })
    }

    fn poll_with(
        &mut self,
        mut wait: impl FnMut(libc::pid_t) -> io::Result<(libc::pid_t, i32)>,
    ) -> io::Result<Option<Exit>> {
        match self.state {
            WaitState::Terminal(exit) => return Ok(Some(exit)),
            WaitState::Quarantined(error) => return Err(error.error()),
            WaitState::Active => {}
        }
        let (result, status) = loop {
            match wait(self.pid) {
                Ok(observation) => break observation,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    let failure = WaitFailure::from_error(&error);
                    self.state = WaitState::Quarantined(failure);
                    return Err(failure.error());
                }
            }
        };
        if result == 0 {
            return Ok(None);
        }
        if result != self.pid {
            self.state = WaitState::Quarantined(WaitFailure::Kind(io::ErrorKind::InvalidData));
            return Err(io::ErrorKind::InvalidData.into());
        }
        let exit = if libc::WIFEXITED(status) {
            Exit::Code(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            Exit::Signal(libc::WTERMSIG(status))
        } else {
            // A traced stop can report the PID without reaping it. Quarantine
            // the unknown observation, do not label it terminal or poll again.
            self.state = WaitState::Quarantined(WaitFailure::Kind(io::ErrorKind::InvalidData));
            return Err(io::ErrorKind::InvalidData.into());
        };
        self.state = WaitState::Terminal(exit);
        Ok(Some(exit))
    }
}

fn result(code: libc::c_int) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

#[allow(unsafe_code)]
fn duplicate(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: the borrow keeps the source live. F_DUPFD_CLOEXEC creates a new
    // exclusively owned descriptor >=3 and changes no flag on the original.
    let copy = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful fcntl above created this descriptor for us.
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

struct Actions(libc::posix_spawn_file_actions_t);
impl Actions {
    #[allow(unsafe_code)]
    fn new() -> io::Result<Self> {
        let mut raw = MaybeUninit::uninit();
        // SAFETY: raw points to sufficient writable storage. Only a zero return
        // initializes it; no assume_init or destroy happens on failure.
        result(unsafe { libc::posix_spawn_file_actions_init(raw.as_mut_ptr()) })?;
        Ok(Self(unsafe { raw.assume_init() }))
    }
}
impl Drop for Actions {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: Actions exists only after successful init, is not copied, and
        // is destroyed once after the synchronous posix_spawn call returns.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}

struct Attributes(libc::posix_spawnattr_t);
impl Attributes {
    #[allow(unsafe_code)]
    fn new() -> io::Result<Self> {
        let mut raw = MaybeUninit::uninit();
        // SAFETY: same successful-initialization rule as Actions above.
        result(unsafe { libc::posix_spawnattr_init(raw.as_mut_ptr()) })?;
        Ok(Self(unsafe { raw.assume_init() }))
    }
}
impl Drop for Attributes {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: uniquely initialized attributes, no pointer retained by spawn.
        unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
    }
}

/// Spawn an absolute program with argv[0] set to that program and only `env`.
///
/// Directory and stdio descriptors are borrowed, duplicated with CLOEXEC, used
/// in child-only file actions and closed there before exec. No parent directory
/// or original descriptor flags change. A timeout policy belongs to the caller;
/// it must retain this handle and its operation guard on an unknown outcome.
#[allow(unsafe_code)]
pub fn spawn_at(
    program: &CStr,
    args: &[CString],
    env: &[CString],
    directory: BorrowedFd<'_>,
    stdio: SpawnStdio<'_>,
) -> io::Result<OwnedChild> {
    if program.to_bytes().first() != Some(&b'/') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let cwd = duplicate(directory)?;
    let sources = [
        duplicate(stdio.input)?,
        duplicate(stdio.output)?,
        duplicate(stdio.error)?,
    ];
    let mut actions = Actions::new()?;
    let mut attributes = Attributes::new()?;
    // SAFETY: initialized actions/attributes, all source descriptors are unique,
    // owned, >=3, and kept live until spawn returns. Child fchdir happens before
    // any source is closed. dup2 targets only 0..2, so no source is overwritten.
    // CLOEXEC_DEFAULT closes ambient descriptors not explicitly inherited.
    unsafe {
        result(libc::posix_spawn_file_actions_addfchdir_np(
            &mut actions.0,
            cwd.as_raw_fd(),
        ))?;
        for (target, fd) in sources.iter().enumerate() {
            result(libc::posix_spawn_file_actions_adddup2(
                &mut actions.0,
                fd.as_raw_fd(),
                target as i32,
            ))?;
        }
        for fd in std::iter::once(&cwd).chain(sources.iter()) {
            result(libc::posix_spawn_file_actions_addclose(
                &mut actions.0,
                fd.as_raw_fd(),
            ))?;
        }
        result(libc::posix_spawnattr_setflags(
            &mut attributes.0,
            libc::POSIX_SPAWN_CLOEXEC_DEFAULT as i16,
        ))?;
    }
    let mut argv: Vec<*mut libc::c_char> = std::iter::once(program.as_ptr().cast_mut())
        .chain(args.iter().map(|s| s.as_ptr().cast_mut()))
        .collect();
    argv.push(std::ptr::null_mut());
    let mut environment: Vec<*mut libc::c_char> =
        env.iter().map(|s| s.as_ptr().cast_mut()).collect();
    environment.push(std::ptr::null_mut());
    let mut pid = 0;
    // SAFETY: all C strings and null-terminated pointer arrays remain live and
    // unmodified through this synchronous call. POSIX does not modify argv/env
    // strings despite its pointer types. Both opaque objects are initialized;
    // pid is writable. A zero result provides our one new child PID.
    result(unsafe {
        libc::posix_spawn(
            &mut pid,
            program.as_ptr(),
            &actions.0,
            &attributes.0,
            argv.as_ptr(),
            environment.as_ptr(),
        )
    })?;
    // Successful posix_spawn guarantees a positive child PID. Return its token
    // immediately; no fallible work after success may lose ownership.
    Ok(OwnedChild {
        pid,
        state: WaitState::Active,
    })
}

#[cfg(test)]
#[path = "owned_spawn_tests.rs"]
mod tests;
