#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const INPUT: &str = "public-stage1-stdio-marker\n";

struct Fixture {
    root: PathBuf,
    image: PathBuf,
    digest: String,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let base = chinwag_test_fixtures::namespace("CHINWAG_STAGE1_FIXTURES");
        let base = base.as_path();
        assert!(base.is_absolute());
        let root = tempfile::Builder::new()
            .prefix(label)
            .tempdir_in(base)
            .unwrap()
            .keep();
        fs::create_dir(root.join("target")).unwrap();
        fs::create_dir(root.join("target/release")).unwrap();
        let image = root.join("target/release/chinwag");
        fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o500)).unwrap();
        let digest = format!("{:x}", Sha256::digest(fs::read(&image).unwrap()));
        Self {
            root,
            image,
            digest,
        }
    }

    fn arguments(&self, target: &[&str]) -> Vec<String> {
        let mut args = vec![
            "stage1-exec".to_owned(),
            self.root.to_str().unwrap().to_owned(),
            self.digest.clone(),
            "--".to_owned(),
        ];
        args.extend(target.iter().map(|s| (*s).to_owned()));
        args
    }

    fn run(&self, args: Vec<String>) -> (u32, std::process::ExitStatus, String, String) {
        let file = |name: &str| {
            OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .mode(0o600)
                .open(self.root.join(name))
                .unwrap()
        };
        let mut input = file("input");
        input.write_all(INPUT.as_bytes()).unwrap();
        drop(input);
        let stdout = file("stdout");
        let stderr = file("stderr");
        let mut child = Command::new(env!("CARGO_BIN_EXE_chinwag-seed"))
            .args(args)
            .env("CHINWAG_STAGE1_MUST_NOT_LEAK", "public-test-value")
            .stdin(Stdio::from(File::open(self.root.join("input")).unwrap()))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        let pid = child.id();
        fs::write(self.root.join("original-child-pid"), pid.to_string()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                // This is only this test's still-owned, unreaped direct child.
                child.kill().unwrap();
                let status = child.wait().unwrap();
                panic!("fresh stage1 child {pid} timed out; owned wait {status}");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let read = |name: &str| {
            let mut bytes = Vec::new();
            File::open(self.root.join(name))
                .unwrap()
                .take(65537)
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(bytes.len() <= 65536);
            String::from_utf8(bytes).unwrap()
        };
        let out = read("stdout");
        let err = read("stderr");
        fs::write(self.root.join("original-exit"), status.to_string()).unwrap();
        (pid, status, out, err)
    }

    fn refused(&self, args: Vec<String>, reason: &str) {
        let (_, status, out, err) = self.run(args);
        assert_eq!(status.code(), Some(1), "{status}: {out} {err}");
        assert!(out.is_empty(), "refused image produced stdout: {out}");
        assert!(err.contains(reason), "{err}");
    }
}

#[test]
#[ignore = "only invoked as the fresh replacement image"]
fn stage1_payload() {
    let mut input = String::new();
    std::io::stdin()
        .take(1024)
        .read_to_string(&mut input)
        .unwrap();
    assert_eq!(input, INPUT);
    assert_eq!(std::env::var("PATH").unwrap(), "/usr/bin:/bin");
    assert_eq!(std::env::var("LC_ALL").unwrap(), "C");
    assert_eq!(std::env::vars_os().count(), 2);
    println!(
        "STAGE1_REPLACED pid={} cwd={} clean_env=true stdin=true",
        std::process::id(),
        std::env::current_dir().unwrap().display()
    );
}

#[test]
fn replacement_preserves_original_pid_cwd_and_stdio_and_clears_environment() {
    let f = Fixture::new("replace-");
    let args = f.arguments(&[
        "--ignored",
        "--exact",
        "stage1_payload",
        "--nocapture",
        "--test-threads=1",
    ]);
    let (pid, status, out, err) = f.run(args);
    assert!(status.success(), "{status}: {out} {err}");
    assert!(err.is_empty(), "{err}");
    let expected = format!(
        "STAGE1_REPLACED pid={pid} cwd={} clean_env=true stdin=true",
        std::env::current_dir().unwrap().display()
    );
    assert!(out.contains(&expected), "{out}");
    assert!(out.contains("1 passed"), "{out}");
}

#[test]
fn mismatched_digest_refuses_without_executing_the_image() {
    let f = Fixture::new("wrong-hash-");
    let mut args = f.arguments(&[]);
    args[2] = "0".repeat(64);
    f.refused(args, "does not match the expected digest");
}

#[test]
fn final_symlink_and_hardlink_are_refused() {
    let f = Fixture::new("final-symlink-");
    fs::rename(&f.image, f.root.join("original-image")).unwrap();
    symlink("../../original-image", &f.image).unwrap();
    f.refused(f.arguments(&[]), "single-link regular executable");
    let f = Fixture::new("hardlink-");
    fs::hard_link(&f.image, f.root.join("second-name")).unwrap();
    f.refused(f.arguments(&[]), "single-link regular executable");
}

#[test]
fn symlinked_or_writable_release_directory_is_refused() {
    let f = Fixture::new("directory-symlink-");
    fs::rename(f.root.join("target/release"), f.root.join("saved-release")).unwrap();
    symlink("../saved-release", f.root.join("target/release")).unwrap();
    f.refused(
        f.arguments(&[]),
        "directory could not be opened or is unsafe",
    );
    let f = Fixture::new("directory-writable-");
    fs::set_permissions(
        f.root.join("target/release"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    f.refused(
        f.arguments(&[]),
        "directory could not be opened or is unsafe",
    );
}

#[test]
fn non_executable_mode_is_refused() {
    let f = Fixture::new("not-executable-");
    fs::set_permissions(&f.image, fs::Permissions::from_mode(0o400)).unwrap();
    f.refused(f.arguments(&[]), "single-link regular executable");
}

#[test]
fn relative_workspace_bad_digest_and_argument_overflow_are_refused() {
    let f = Fixture::new("relative-path-");
    let mut args = f.arguments(&[]);
    args[1] = "relative-workspace".to_owned();
    f.refused(args, "absolute, normal workspace path");
    let f = Fixture::new("bad-digest-");
    let mut args = f.arguments(&[]);
    args[2] = "X".repeat(64);
    f.refused(args, "64 lowercase SHA-256");
    let f = Fixture::new("too-many-arguments-");
    let mut args = f.arguments(&[]);
    args.extend(std::iter::repeat_n("arg".to_owned(), 33));
    f.refused(args, "arguments exceed their bounds");
}

#[test]
fn returned_exec_error_is_terminal_without_running_another_image() {
    let mut f = Fixture::new("exec-error-");
    fs::set_permissions(&f.image, fs::Permissions::from_mode(0o600)).unwrap();
    // A recognized shebang with a nonexistent absolute interpreter causes the
    // platform exec operation to return ENOENT. No private executable is used.
    let bytes = format!("#!{}/absent-interpreter\n", f.root.display());
    fs::write(&f.image, &bytes).unwrap();
    fs::set_permissions(&f.image, fs::Permissions::from_mode(0o500)).unwrap();
    f.digest = format!("{:x}", Sha256::digest(bytes.as_bytes()));
    f.refused(f.arguments(&[]), "exec returned an error");
}
