#![forbid(unsafe_code)]

use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process::{Command, Stdio},
};

struct Fixture {
    root: PathBuf,
    recipe: PathBuf,
}

impl Fixture {
    fn new(label: &str, body: &str) -> Self {
        let base = chinwag_test_fixtures::serialized_namespace(
            "CHINWAG_STAGE1_BUILD_FIXTURES",
            &std::env::temp_dir(),
        );
        let base = base.as_path();
        assert!(base.is_absolute());
        let root = tempfile::Builder::new()
            .prefix(label)
            .tempdir_in(base)
            .unwrap()
            .keep();
        for name in ["src", "target", "cache", "native"] {
            fs::create_dir(root.join(name)).unwrap();
        }
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='chinwag-cli'\nversion='0.0.0'\nedition='2024'\n[[bin]]\nname='chinwag'\npath='src/main.rs'\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"chinwag-cli\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        fs::write(root.join("src/main.rs"), body).unwrap();
        let rustc = chinwag_test_fixtures::rustc();
        let recipe = root.join("recipe.json");
        fs::write(
            &recipe,
            serde_json::to_vec_pretty(&json!({
                "workspace": root,
                "toolchain": rustc.parent().unwrap(),
                "cache": root.join("cache"),
                "native_inputs": root.join("native"),
                "rustflags": "",
                "expected_sha256": "0".repeat(64),
                "arguments": []
            }))
            .unwrap(),
        )
        .unwrap();
        Self { root, recipe }
    }

    fn run(&self) -> (std::process::ExitStatus, String, String) {
        let create = |name: &str| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.root.join(name))
                .unwrap()
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_chinwag-seed"))
            .arg("stage1-build-exec")
            .arg(&self.recipe)
            .stdin(Stdio::null())
            .stdout(Stdio::from(create("stdout")))
            .stderr(Stdio::from(create("stderr")))
            .spawn()
            .unwrap();
        let pid = child.id();
        fs::write(self.root.join("original-child-pid"), pid.to_string()).unwrap();
        // Retain this seed Child through its original wait. Killing the seed
        // could orphan its owned Cargo group. The outer once-only operator
        // retains its lock and records UNKNOWN if this test never returns.
        let status = child.wait().unwrap();
        fs::write(self.root.join("original-exit"), status.to_string()).unwrap();
        let read = |name: &str| {
            let f = File::open(self.root.join(name)).unwrap();
            assert!(f.metadata().unwrap().len() <= 1024 * 1024);
            fs::read_to_string(self.root.join(name)).unwrap()
        };
        (status, read("stdout"), read("stderr"))
    }
}

#[test]
fn actual_failed_cargo_build_does_not_attempt_exec() {
    let f = Fixture::new("compile-refusal-", "fn main( {\n");
    let (status, out, err) = f.run();
    assert_eq!(status.code(), Some(1), "{status}: {out} {err}");
    assert!(out.is_empty(), "{out}");
    assert!(
        err.contains("stage1 release build failed; no exec attempted"),
        "{err}"
    );
    assert!(!f.root.join("target/release/chinwag").exists());
}

#[test]
fn actual_successful_cargo_build_still_checks_image_digest_before_exec() {
    let f = Fixture::new(
        "digest-refusal-",
        "fn main() { println!(\"RAN_IMAGE\"); }\n",
    );
    let (status, out, err) = f.run();
    assert_eq!(status.code(), Some(1), "{status}: {out} {err}");
    assert!(out.is_empty(), "refused image executed: {out}");
    assert!(err.contains("does not match the expected digest"), "{err}");
    assert!(f.root.join("target/release/chinwag").is_file());
}

#[test]
fn virtual_workspace_build_selects_only_cli_package() {
    let f = Fixture::new(
        "package-selection-",
        "fn main() { println!(\"SELECTED_CLI\"); }\n",
    );
    let cli_manifest = fs::read_to_string(f.root.join("Cargo.toml")).unwrap();
    fs::create_dir(f.root.join("cli")).unwrap();
    fs::rename(f.root.join("src"), f.root.join("cli/src")).unwrap();
    fs::write(f.root.join("cli/Cargo.toml"), cli_manifest).unwrap();
    fs::create_dir_all(f.root.join("decoy/src")).unwrap();
    fs::write(
        f.root.join("Cargo.toml"),
        "[workspace]\nmembers=['cli','decoy']\nresolver='3'\n",
    )
    .unwrap();
    fs::write(
        f.root.join("decoy/Cargo.toml"),
        "[package]\nname='decoy'\nversion='0.0.0'\nedition='2024'\n[[bin]]\nname='chinwag'\npath='src/main.rs'\n",
    )
    .unwrap();
    fs::write(f.root.join("decoy/src/main.rs"), "fn broken( {\n").unwrap();
    fs::write(
        f.root.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"chinwag-cli\"\nversion = \"0.0.0\"\n\n[[package]]\nname = \"decoy\"\nversion = \"0.0.0\"\n",
    )
    .unwrap();
    let (status, out, err) = f.run();
    assert_eq!(status.code(), Some(1), "{status}: {out} {err}");
    assert!(out.is_empty(), "refused image executed: {out}");
    assert!(err.contains("does not match the expected digest"), "{err}");
    assert!(!err.contains("could not compile `decoy`"), "{err}");
    assert!(f.root.join("target/release/chinwag").is_file());
}
