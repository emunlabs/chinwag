use chinwag_signing::PrivateDirectory;
fn raw(directory: &PrivateDirectory) {
    let _ = directory.as_fd();
}
fn main() {}
