#![forbid(unsafe_code)]
use std::env;
use std::error::Error;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=CHINWAG_PRIVATE_CRSQL_INPUTS");
    if env::var("TARGET")? != "aarch64-apple-darwin" {
        return Err(
            "Private native artifact supports only aarch64-apple-darwin; WASM is unimplemented"
                .into(),
        );
    }
    let root = PathBuf::from(
        env::var_os("CHINWAG_PRIVATE_CRSQL_INPUTS")
            .ok_or("CHINWAG_PRIVATE_CRSQL_INPUTS is required for this private build experiment")?,
    );
    if !root.is_absolute() {
        return Err("Private native artifact directory must be absolute".into());
    }
    let directory = root.symlink_metadata()?;
    if !directory.is_dir() || directory.mode() & 0o7777 != 0o700 {
        return Err("Private native artifact directory must be a regular 0700 directory".into());
    }
    // The operator verifies and records actual source/object/archive hashes
    // before and after Cargo. This build script does not claim provenance alone.
    let archive = root.join("libchinwag_private_crsql.a");
    let metadata = archive.symlink_metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.mode() & 0o7777 != 0o400
    {
        return Err("Private native archive must be a nonempty single-link 0400 file".into());
    }
    let directory_text = root.to_str().ok_or("Private artifact path must be UTF8")?;
    if directory_text.contains(['\n', '\r']) {
        return Err("Line breaks in Cargo link path".into());
    }
    println!("cargo:rustc-link-search=native={directory_text}");
    println!("cargo:rustc-link-lib=static=chinwag_private_crsql");
    println!("cargo:rerun-if-changed={}", archive.display());
    Ok(())
}
