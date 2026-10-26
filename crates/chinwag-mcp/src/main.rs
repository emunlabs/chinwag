//! Thin private fixture driver for the callable Rust context library.
#![forbid(unsafe_code)]
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    let [_, command, path] = args.as_slice() else {
        return Err("Expected serve-private-repository and one existing initialized private repository path".into());
    };
    if command != "serve-private-repository" {
        return Err("Unknown private fixture command".into());
    }
    chinwag_mcp_private_anchored::run_private_repository_stdio(path.into())
}
