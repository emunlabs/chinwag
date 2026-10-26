//! Only unsafe boundary: consume a valid owned FD and never retry its raw number.
use std::{
    fs::File,
    os::fd::{IntoRawFd, OwnedFd},
};
pub(crate) fn fd(fd: OwnedFd) -> Result<(), &'static str> {
    let raw = fd.into_raw_fd();
    // Ownership was consumed, so neither Drop nor this function may close twice,
    // even if the OS reports EINTR/EIO. No success receipt follows an error.
    unsafe { rustix::io::try_close(raw) }.map_err(|_| "checked_close")
}
pub(crate) fn file(file: File) -> Result<(), &'static str> {
    fd(file.into())
}
