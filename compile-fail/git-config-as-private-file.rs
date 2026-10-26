#![allow(dead_code)]
#[path = "../crates/confirmed-initial/src/checked_close.rs"]
mod checked_close;
#[path = "../crates/confirmed-initial/src/fs.rs"]
mod fs;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
fn cannot_mix(file: fs::GitConfigFile) {
    let _ = fs::FileId::read(&file);
}
fn main() {}
