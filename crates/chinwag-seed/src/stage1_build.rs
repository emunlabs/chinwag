//! Original bootstrap build followed by the existing checked exec component.
//! The operator admits the source tree, toolchain, cache, native archive and
//! compiler flags. Cargo/build scripts are trusted code, not sandboxed here.
//! This command does not decide release, history, signing or Genesis gates.

use chinwag_seed::cargo::CargoVerifier;
use rustix::fs::{Mode, OFlags, open};
use serde::Deserialize;
use std::{
    convert::Infallible,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    workspace: PathBuf,
    toolchain: PathBuf,
    cache: PathBuf,
    native_inputs: PathBuf,
    rustflags: String,
    expected_sha256: String,
    arguments: Vec<String>,
}

pub(super) fn build_and_replace(
    recipe_path: &Path,
) -> Result<Infallible, Box<dyn std::error::Error>> {
    let fd = open(
        recipe_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err("stage1 build recipe must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err("stage1 build recipe exceeds 16384 bytes".into());
    }
    let recipe: Recipe = serde_json::from_slice(&bytes)?;
    if [
        &recipe.workspace,
        &recipe.toolchain,
        &recipe.cache,
        &recipe.native_inputs,
    ]
    .iter()
    .any(|path| !path.is_absolute())
    {
        return Err("stage1 build recipe paths must be absolute".into());
    }
    let builder = CargoVerifier::new(
        &recipe.workspace,
        &recipe.toolchain,
        &recipe.cache,
        &recipe.workspace.join("target"),
    )?;
    // No MCP server or other seed worker is started on this main branch.
    // Drop the runtime before any exec attempt. Drop also waits for any
    // blocking cleanup worker retained by the existing owned-process code.
    let result = {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(builder.build_release(&recipe.native_inputs, &recipe.rustflags))
    };
    let report = result?;
    // Compiler output remains diagnostic stderr; replacement owns stdout.
    std::io::stderr().write_all(&report.stdout)?;
    std::io::stderr().write_all(&report.stderr)?;
    if !report.success {
        return Err("stage1 release build failed; no exec attempted".into());
    }
    let never = super::stage1::replace(
        &recipe.workspace,
        &recipe.expected_sha256,
        &recipe.arguments,
    )?;
    match never {}
}
