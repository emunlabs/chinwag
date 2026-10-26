use super::*;
use std::fs::{self, File};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    input: File,
    output: File,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let input = File::open("/dev/null").unwrap();
        let output = File::create(root.join("output")).unwrap();
        Self {
            _temporary: temporary,
            root,
            input,
            output,
        }
    }
    fn stdio(&self) -> SpawnStdio<'_> {
        SpawnStdio {
            input: self.input.as_fd(),
            output: self.output.as_fd(),
            error: self.output.as_fd(),
        }
    }
    fn output(&self) -> String {
        fs::read_to_string(self.root.join("output")).unwrap()
    }
}

fn strings(items: &[&str]) -> Vec<CString> {
    items.iter().map(|s| CString::new(*s).unwrap()).collect()
}

fn wait(child: &mut OwnedChild) -> Exit {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "original child still owned; do not replay"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn helper(fixture: &Fixture, directory: &File, env: &[CString]) -> OwnedChild {
    let executable = CString::new(
        std::env::current_exe()
            .unwrap()
            .as_os_str()
            .as_encoded_bytes(),
    )
    .unwrap();
    spawn_at(
        &executable,
        &strings(&[
            "--ignored",
            "--exact",
            "owned_spawn::tests::fixture_child",
            "--nocapture",
        ]),
        env,
        directory.as_fd(),
        fixture.stdio(),
    )
    .unwrap()
}

#[test]
#[ignore = "controlled subprocess fixture; not independent coverage"]
fn fixture_child() {
    match std::env::var("CHINWAG_SPAWN_TEST").unwrap().as_str() {
        "inspect" => {
            assert_eq!(
                std::env::var("PAYLOAD").unwrap(),
                "literal spaces = preserved"
            );
            assert!(std::env::var_os("HOME").is_none());
            let current = std::env::current_dir().unwrap();
            let metadata = fs::metadata(current).unwrap();
            let ambient: i32 = std::env::var("AMBIENT_FD").unwrap().parse().unwrap();
            assert!(fs::metadata(format!("/dev/fd/{ambient}")).is_err());
            println!("INSPECT_OK {} {}", metadata.dev(), metadata.ino());
        }
        "exit" => std::process::exit(23),
        "wait" => {
            fs::write("started", std::process::id().to_string()).unwrap();
            let start = Instant::now();
            while !Path::new("release").exists() {
                if start.elapsed() > Duration::from_secs(5) {
                    std::process::exit(90);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        _ => panic!("invalid controlled fixture mode"),
    }
}

#[allow(unsafe_code)]
fn flags(file: &File) -> i32 {
    // SAFETY: query only this still-owned fixture descriptor.
    let value = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    assert!(value >= 0);
    value
}

#[allow(unsafe_code)]
fn ambient(file: &File) -> OwnedFd {
    // SAFETY: create a new owned NON-CLOEXEC descriptor for this public fixture,
    // without changing the original. The child must not inherit it.
    let value = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 200) };
    assert!(value >= 200);
    unsafe { OwnedFd::from_raw_fd(value) }
}

#[test]
fn child_cwd_and_explicit_environment_do_not_change_parent_or_leak_ambient_fd() {
    let fixture = Fixture::new();
    let directory = File::open(&fixture.root).unwrap();
    let before = std::env::current_dir().unwrap();
    let original_flags = flags(&directory);
    assert_ne!(original_flags & libc::FD_CLOEXEC, 0);
    let ambient = ambient(&fixture.output);
    let env = strings(&[
        "CHINWAG_SPAWN_TEST=inspect",
        "PAYLOAD=literal spaces = preserved",
        &format!("AMBIENT_FD={}", ambient.as_raw_fd()),
    ]);
    let mut child = helper(&fixture, &directory, &env);
    let pid = child.pid();
    assert_eq!(wait(&mut child), Exit::Code(0));
    assert_eq!(child.try_wait().unwrap(), Some(Exit::Code(0)));
    assert_eq!(child.pid(), pid);
    assert_eq!(flags(&directory), original_flags);
    assert_eq!(std::env::current_dir().unwrap(), before);
    let meta = directory.metadata().unwrap();
    assert!(
        fixture
            .output()
            .contains(&format!("INSPECT_OK {} {}", meta.dev(), meta.ino()))
    );
}

#[test]
fn stock_git_writes_only_the_moved_directory_through_child_fchdir() {
    let fixture = Fixture::new();
    let original = fixture.root.join("original");
    let moved = fixture.root.join("moved");
    fs::create_dir(&original).unwrap();
    fs::write(
        original.join("staged.config"),
        b"[unrelated]\n\tkeep = fixture\n",
    )
    .unwrap();
    let directory = File::open(&original).unwrap();
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    let sentinel = b"replacement must survive\n";
    fs::write(original.join("staged.config"), sentinel).unwrap();
    let env = strings(&[
        "PATH=/usr/bin:/bin",
        &format!("HOME={}", fixture.root.display()),
        "LC_ALL=C",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_CONFIG_SYSTEM=/dev/null",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_CONFIG_COUNT=0",
        "GIT_TERMINAL_PROMPT=0",
    ]);
    let mut child = spawn_at(
        c"/usr/bin/git",
        &strings(&[
            "-c",
            "protocol.allow=never",
            "config",
            "--file",
            "staged.config",
            "--no-includes",
            "--add",
            "gpg.format",
            "ssh",
        ]),
        &env,
        directory.as_fd(),
        fixture.stdio(),
    )
    .unwrap();
    assert_eq!(wait(&mut child), Exit::Code(0), "{}", fixture.output());
    assert!(
        fs::read_to_string(moved.join("staged.config"))
            .unwrap()
            .contains("format = ssh")
    );
    assert_eq!(fs::read(original.join("staged.config")).unwrap(), sentinel);
}

#[test]
fn exit_status_is_cached_and_invalid_program_or_directory_cannot_create_a_handle() {
    let fixture = Fixture::new();
    let directory = File::open(&fixture.root).unwrap();
    let mut child = helper(&fixture, &directory, &strings(&["CHINWAG_SPAWN_TEST=exit"]));
    assert_eq!(wait(&mut child), Exit::Code(23));
    assert_eq!(child.try_wait().unwrap(), Some(Exit::Code(23)));
    for (program, expected) in [(c"/usr/bin/true", 0), (c"/usr/bin/false", 1)] {
        let mut child = spawn_at(program, &[], &[], directory.as_fd(), fixture.stdio()).unwrap();
        assert_eq!(wait(&mut child), Exit::Code(expected));
    }
    let mut child = spawn_at(
        c"/usr/bin/printf",
        &strings(&["%s", "literal spaces = preserved"]),
        &[],
        directory.as_fd(),
        fixture.stdio(),
    )
    .unwrap();
    assert_eq!(wait(&mut child), Exit::Code(0));
    assert!(fixture.output().ends_with("literal spaces = preserved"));
    let error = spawn_at(c"relative", &[], &[], directory.as_fd(), fixture.stdio())
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let error = spawn_at(
        c"/chinwag/nonexistent/program",
        &[],
        &[],
        directory.as_fd(),
        fixture.stdio(),
    )
    .err()
    .unwrap();
    assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
    let error = spawn_at(
        c"/usr/bin/git",
        &[],
        &[],
        fixture.output.as_fd(),
        fixture.stdio(),
    )
    .err()
    .unwrap();
    assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR));
}

#[test]
fn pending_child_is_retained_and_resolved_as_the_same_pid_without_resubmission() {
    let fixture = Fixture::new();
    let directory = File::open(&fixture.root).unwrap();
    let mut child = helper(&fixture, &directory, &strings(&["CHINWAG_SPAWN_TEST=wait"]));
    let pid = child.pid();
    let start = Instant::now();
    while !fixture.root.join("started").exists() {
        assert!(start.elapsed() < Duration::from_secs(3));
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        fs::read_to_string(fixture.root.join("started")).unwrap(),
        pid.to_string()
    );
    for _ in 0..3 {
        assert_eq!(child.try_wait().unwrap(), None);
        assert_eq!(child.pid(), pid);
    }
    fs::write(fixture.root.join("release"), b"explicit fixture release").unwrap();
    assert_eq!(wait(&mut child), Exit::Code(0));
    assert_eq!(child.pid(), pid);
}

#[test]
fn unexpected_nonterminal_status_quarantines_without_a_second_wait() {
    // Deterministic wait seam, not an OS ptrace/stop or proof of reaping.
    let mut child = OwnedChild {
        pid: 42,
        state: WaitState::Active,
    };
    let stopped = (libc::SIGSTOP << 8) | 0x7f;
    assert!(libc::WIFSTOPPED(stopped));
    assert!(!libc::WIFEXITED(stopped));
    let error = child
        .poll_with(|pid| {
            assert_eq!(pid, 42);
            Ok((pid, stopped))
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(matches!(child.state, WaitState::Quarantined(_)));
    let error = child
        .poll_with(|_| panic!("must not wait after an uncertain observation"))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn lost_child_error_is_cached_without_polling_a_possibly_recycled_pid() {
    let mut child = OwnedChild {
        pid: 42,
        state: WaitState::Active,
    };
    let error = child
        .poll_with(|pid| {
            assert_eq!(pid, 42);
            Err(io::Error::from_raw_os_error(libc::ECHILD))
        })
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
    let error = child
        .poll_with(|_| panic!("must not repeat wait after ECHILD"))
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
}

#[test]
fn interruption_repeats_only_the_same_wait_then_caches_the_terminal_result() {
    let mut child = OwnedChild {
        pid: 42,
        state: WaitState::Active,
    };
    let mut calls = 0;
    assert_eq!(
        child
            .poll_with(|pid| {
                assert_eq!(pid, 42);
                calls += 1;
                if calls == 1 {
                    Err(io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Ok((pid, 0))
                }
            })
            .unwrap(),
        Some(Exit::Code(0))
    );
    assert_eq!(calls, 2);
    assert_eq!(
        child
            .poll_with(|_| panic!("terminal cache must avoid another wait"))
            .unwrap(),
        Some(Exit::Code(0))
    );
}
