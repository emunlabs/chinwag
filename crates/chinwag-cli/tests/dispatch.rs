#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const ALIASES: [(&str, &str); 5] = [
    ("chinwag", "chinwag"),
    ("git-chinwag", "git chinwag"),
    ("git-emun", "git emun"),
    ("gh-chinwag", "gh chinwag"),
    ("gh-emun", "gh emun"),
];

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = loop {
            let n = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("chinwag-cli-{}-{n}", std::process::id()));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create fixture: {error}"),
            }
        };
        fs::create_dir(root.join("aliases")).unwrap();
        fs::create_dir(root.join("work")).unwrap();
        fs::create_dir(root.join("work/.git")).unwrap();
        fs::write(
            root.join("work/.git/config"),
            b"fixture config must survive\n",
        )
        .unwrap();
        fs::write(root.join("work/marker"), b"fixture content must survive\n").unwrap();
        for (name, _) in ALIASES {
            let link = root.join("aliases").join(name);
            symlink(env!("CARGO_BIN_EXE_chinwag"), &link).unwrap();
            assert_eq!(
                fs::canonicalize(link).unwrap(),
                fs::canonicalize(env!("CARGO_BIN_EXE_chinwag")).unwrap()
            );
        }
        Self { root }
    }

    fn run(&self, alias: &str, args: &[&str]) -> Output {
        Command::new(self.root.join("aliases").join(alias))
            .args(args)
            .current_dir(self.root.join("work"))
            .env_clear()
            .output()
            .unwrap()
    }

    fn with_argv0(&self, program: &OsStr, args: &[OsString]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_chinwag"))
            .arg0(program)
            .args(args)
            .current_dir(self.root.join("work"))
            .env_clear()
            .output()
            .unwrap()
    }

    fn snapshot(&self) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        fn visit(root: &Path, path: &Path, entries: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
            if path.is_dir() {
                entries.push((path.strip_prefix(root).unwrap().to_owned(), None));
                for entry in fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), entries);
                }
            } else {
                entries.push((
                    path.strip_prefix(root).unwrap().to_owned(),
                    Some(fs::read(path).unwrap()),
                ));
            }
        }
        let work = self.root.join("work");
        let mut entries = Vec::new();
        visit(&work, &work, &mut entries);
        entries.sort();
        entries
    }
}

#[test]
fn all_five_names_use_one_binary_and_their_own_usage() {
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    for (alias, display) in ALIASES {
        for args in [&[][..], &["--help"][..]] {
            let output = fixture.run(alias, args);
            assert_eq!(output.status.code(), Some(0));
            assert_eq!(
                output.stdout,
                format!(
                    "Usage: {display} [--help | --version]\n       {display} init --help\n       {display} mcp-serve --repo <absolute-path> [--transport stdio|http]\n       {display} configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nLocal Git SSH signing and an offline store for a new repository.\n"
                )
                .as_bytes()
            );
            assert!(output.stderr.is_empty());
        }
        let output = fixture.run(alias, &["--version"]);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"chinwag 0.1.0 (uncommitted candidate)\n");
        assert!(output.stderr.is_empty());
    }
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn unavailable_commands_and_extra_arguments_fail_without_mutating_the_workspace() {
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    for (alias, _) in ALIASES {
        for args in [
            &["--unknown"][..],
            &["--help", "init"][..],
            &["--version", "extra"][..],
            &[""][..],
        ] {
            let output = fixture.run(alias, args);
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert_eq!(output.stderr, b"chinwag: not_in_this_candidate\n");
        }
        for command in ["mcp-serve", "configure-editor"] {
            let output = fixture.run(alias, &[command]);
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert_eq!(output.stderr, b"chinwag: invalid_arguments\n");
        }
    }
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn path_basename_selects_the_invocation() {
    let fixture = Fixture::new();
    for (alias, display) in ALIASES {
        let name = Path::new("/synthetic/parent").join(alias);
        let output = fixture.with_argv0(name.as_os_str(), &["--help".into()]);
        assert_eq!(output.status.code(), Some(0));
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .starts_with(&format!("Usage: {display} "))
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn unknown_and_non_utf8_program_names_fail_with_static_errors() {
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    for program in [
        OsString::from("/synthetic/private-caller"),
        OsString::from(""),
        OsString::from("/"),
        OsString::from_vec(vec![0xff, b'x']),
    ] {
        let output = fixture.with_argv0(&program, &["--help".into()]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"chinwag: unknown_invocation\n");
    }
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn non_utf8_argument_is_rejected_without_echoing_or_mutating() {
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    let output = fixture.with_argv0(
        OsStr::new("chinwag"),
        &[OsString::from_vec(vec![0xff, b'x'])],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"chinwag: not_in_this_candidate\n");
    assert_eq!(fixture.snapshot(), before);
}
