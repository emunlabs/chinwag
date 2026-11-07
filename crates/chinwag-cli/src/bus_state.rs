//! Bounded diagnostic state replacement. This file grants no bus/task authority.
#![forbid(unsafe_code)]

use crate::bus_identity::BusDirectory;
use rustix::fs::{Mode, OFlags, RenameFlags, openat, renameat, renameat_with};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

const STATE_NAME: &str = "daemon.json";
pub const MAX_DAEMON_STATE_BYTES: usize = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    Oversize,
    Directory,
    UnsafeState,
    Changed,
    Readback,
    TempSequence,
    Io(std::io::ErrorKind),
}
impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("diagnostic daemon state unavailable or replacement uncertain")
    }
}
impl std::error::Error for StateError {}
type Result<T> = std::result::Result<T, StateError>;
fn io(error: std::io::Error) -> StateError {
    StateError::Io(error.kind())
}
fn os(error: rustix::io::Errno) -> StateError {
    io(error.into())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    id: (u64, u64),
    uid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    regular: bool,
}
impl Stamp {
    fn read(file: &File) -> Result<Self> {
        let m = file.metadata().map_err(io)?;
        let stamp = Self {
            id: (m.dev(), m.ino()),
            uid: m.uid(),
            mode: m.mode() & 0o7777,
            nlink: m.nlink(),
            len: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
            regular: m.is_file(),
        };
        stamp.profile()?;
        Ok(stamp)
    }
    fn profile(&self) -> Result<()> {
        if !self.regular
            || self.uid != rustix::process::geteuid().as_raw()
            || !matches!(self.mode, 0o600 | 0o644)
            || self.nlink != 1
            || self.len > MAX_DAEMON_STATE_BYTES as u64
        {
            return Err(StateError::UnsafeState);
        }
        Ok(())
    }
}
struct ObservedState {
    file: File,
    stamp: Stamp,
}
fn observe(directory: &BusDirectory, name: &str) -> Result<Option<ObservedState>> {
    let fd = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) if error == rustix::io::Errno::LOOP => return Err(StateError::UnsafeState),
        Err(error) => return Err(os(error)),
    };
    let file = File::from(fd);
    let stamp = Stamp::read(&file)?;
    Ok(Some(ObservedState { file, stamp }))
}
fn verify_original(directory: &BusDirectory, original: Option<&ObservedState>) -> Result<()> {
    directory.verify().map_err(|_| StateError::Directory)?;
    let current = observe(directory, STATE_NAME)?;
    match (original, current) {
        (None, None) => Ok(()),
        (Some(original), Some(current))
            if Stamp::read(&original.file)? == original.stamp
                && current.stamp == original.stamp =>
        {
            Ok(())
        }
        _ => Err(StateError::Changed),
    }
}
fn verify_temp(directory: &BusDirectory, name: &str, file: &File, expected: Stamp) -> Result<()> {
    directory.verify().map_err(|_| StateError::Directory)?;
    let named = observe(directory, name)?.ok_or(StateError::Changed)?;
    if Stamp::read(file)? != expected || named.stamp != expected || expected.mode != 0o600 {
        return Err(StateError::Changed);
    }
    Ok(())
}

struct StateWriter {
    directory: BusDirectory,
    #[cfg(test)]
    before_rename: Option<Box<dyn FnOnce()>>,
}
impl StateWriter {
    fn open(root: &Path) -> Result<Self> {
        Ok(Self {
            directory: BusDirectory::open(root).map_err(|_| StateError::Directory)?,
            #[cfg(test)]
            before_rename: None,
        })
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_DAEMON_STATE_BYTES {
            return Err(StateError::Oversize);
        }
        self.directory.verify().map_err(|_| StateError::Directory)?;
        // Unsafe existing names are rejected before even creating a temporary
        // file. In particular, a dangling symlink is not treated as absence.
        let original = observe(&self.directory, STATE_NAME)?;
        verify_original(&self.directory, original.as_ref())?;
        let sequence = TEMP_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| StateError::TempSequence)?;
        let temp_name = format!("daemon-state.{}.{}.tmp", std::process::id(), sequence);
        let mut temp = File::from(
            openat(
                &self.directory,
                temp_name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(os)?,
        );
        let empty = Stamp::read(&temp)?;
        if empty.mode != 0o600 || empty.len != 0 {
            return Err(StateError::UnsafeState);
        }
        temp.write_all(bytes).map_err(io)?;
        temp.sync_all().map_err(io)?;
        let written = Stamp::read(&temp)?;
        if written.id != empty.id || written.len != bytes.len() as u64 {
            return Err(StateError::Changed);
        }
        #[cfg(test)]
        if let Some(hook) = self.before_rename.take() {
            hook();
        }
        verify_temp(&self.directory, &temp_name, &temp, written)?;
        verify_original(&self.directory, original.as_ref())?;
        if original.is_some() {
            renameat(
                &self.directory,
                temp_name.as_str(),
                &self.directory,
                STATE_NAME,
            )
            .map_err(os)?;
        } else {
            // Atomically refuse a name that appeared after the absent check.
            renameat_with(
                &self.directory,
                temp_name.as_str(),
                &self.directory,
                STATE_NAME,
                RenameFlags::NOREPLACE,
            )
            .map_err(os)?;
        }
        self.directory.sync().map_err(|_| StateError::Directory)?;
        let installed = Stamp::read(&temp)?;
        if installed.id != written.id
            || installed.mode != 0o600
            || installed.len != bytes.len() as u64
        {
            return Err(StateError::Changed);
        }
        verify_temp(&self.directory, STATE_NAME, &temp, installed)?;
        temp.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut readback = vec![0; bytes.len()];
        temp.read_exact(&mut readback).map_err(io)?;
        if readback != bytes {
            return Err(StateError::Readback);
        }
        verify_temp(&self.directory, STATE_NAME, &temp, installed)
        // On any error the private temporary/installed bytes remain as
        // observed. No unlink, chmod, truncate, retry or repair follows.
    }
}

/// Atomically replace diagnostic state with a fresh private0600 file. Existing
/// legitimate owned0600/0644 single-link state is accepted; its mode is not
/// copied. No key is opened and no caller-selected filename is accepted.
///
/// Descriptor/namespace checks are observations, not hostile same-UID atomic
/// compare-and-swap containment. A post-rename error is uncertain, not rollback.
pub fn write_daemon_state_bytes(root: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_DAEMON_STATE_BYTES {
        return Err(StateError::Oversize);
    }
    StateWriter::open(root)?.write(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus_identity::load_or_create_daemon_secret;
    use std::{
        fs,
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        path::PathBuf,
    };
    use subtle::ConstantTimeEq;
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    fn fixture() -> (TempDir, PathBuf) {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        BusDirectory::open(&root).unwrap();
        (temp, root)
    }
    fn state(root: &Path) -> PathBuf {
        root.join(".chinwag/bus/daemon.json")
    }
    fn key(root: &Path) -> PathBuf {
        root.join(".chinwag/bus/daemon_secret.key")
    }
    fn private_file(path: &Path, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    fn no_temp(root: &Path) -> bool {
        fs::read_dir(root.join(".chinwag/bus"))
            .unwrap()
            .all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("daemon-state.")
            })
    }

    #[test]
    fn state_create_and_atomic_replacement_are_exact_private_and_leave_key_absent() {
        let (_temp, root) = fixture();
        write_daemon_state_bytes(&root, b"first diagnostic bytes").unwrap();
        let first = File::open(state(&root)).unwrap();
        let before = first.metadata().unwrap();
        write_daemon_state_bytes(&root, b"second diagnostic bytes").unwrap();
        let after = fs::symlink_metadata(state(&root)).unwrap();
        assert_eq!(fs::read(state(&root)).unwrap(), b"second diagnostic bytes");
        assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(
            (after.mode() & 0o7777, after.nlink(), after.uid()),
            (0o600, 1, rustix::process::geteuid().as_raw())
        );
        assert!(!key(&root).exists());
        assert!(no_temp(&root));
    }
    #[test]
    fn state_owned_0644_is_replaced_with_0600_without_chmod_on_old_inode() {
        let (_temp, root) = fixture();
        private_file(&state(&root), b"old");
        fs::set_permissions(state(&root), fs::Permissions::from_mode(0o644)).unwrap();
        let old = File::open(state(&root)).unwrap();
        write_daemon_state_bytes(&root, b"new").unwrap();
        assert_eq!(old.metadata().unwrap().mode() & 0o7777, 0o644);
        assert_eq!(fs::metadata(state(&root)).unwrap().mode() & 0o7777, 0o600);
        assert!(no_temp(&root));
    }
    #[test]
    fn still_dangling_state_symlink_refuses_without_creating_target_or_temp() {
        let (_temp, root) = fixture();
        symlink("daemon_secret.key", state(&root)).unwrap();
        assert_eq!(
            write_daemon_state_bytes(&root, b"diagnostic state"),
            Err(StateError::UnsafeState)
        );
        assert!(!key(&root).exists());
        assert!(
            fs::symlink_metadata(state(&root))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(no_temp(&root));
    }
    #[test]
    fn dangling_state_link_created_before_key_creation_never_clobbers_owned_key() {
        let (_temp, root) = fixture();
        symlink("daemon_secret.key", state(&root)).unwrap();
        assert!(!key(&root).exists());
        let _opaque = load_or_create_daemon_secret(&root).unwrap();
        let before = Zeroizing::new(fs::read(key(&root)).unwrap());
        assert_eq!(
            write_daemon_state_bytes(&root, b"diagnostic state"),
            Err(StateError::UnsafeState)
        );
        let after = Zeroizing::new(fs::read(key(&root)).unwrap());
        assert!(
            bool::from(before.as_slice().ct_eq(after.as_slice())),
            "owned fixture key unexpectedly changed"
        );
        assert!(
            fs::symlink_metadata(state(&root))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(no_temp(&root));
    }
    #[test]
    fn state_hardlink_to_owned_key_refuses_without_overwrite_or_cleanup() {
        let (_temp, root) = fixture();
        let _opaque = load_or_create_daemon_secret(&root).unwrap();
        fs::hard_link(key(&root), state(&root)).unwrap();
        let before = Zeroizing::new(fs::read(key(&root)).unwrap());
        assert_eq!(
            write_daemon_state_bytes(&root, b"diagnostic state"),
            Err(StateError::UnsafeState)
        );
        let after = Zeroizing::new(fs::read(key(&root)).unwrap());
        assert!(
            bool::from(before.as_slice().ct_eq(after.as_slice())),
            "owned fixture key unexpectedly changed"
        );
        assert_eq!(fs::metadata(key(&root)).unwrap().nlink(), 2);
        assert!(no_temp(&root));
    }
    #[test]
    fn state_unsafe_mode_directory_and_wrong_owner_profile_refuse() {
        for mode in [0o660, 0o666, 0o700, 0o4600] {
            let (_temp, root) = fixture();
            private_file(&state(&root), b"retain");
            fs::set_permissions(state(&root), fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                write_daemon_state_bytes(&root, b"new"),
                Err(StateError::UnsafeState)
            );
            assert_eq!(fs::read(state(&root)).unwrap(), b"retain");
            assert!(no_temp(&root));
        }
        let (_temp, root) = fixture();
        fs::create_dir(state(&root)).unwrap();
        assert!(write_daemon_state_bytes(&root, b"new").is_err());
        assert!(no_temp(&root));
        let own = root.join("owned-profile");
        private_file(&own, b"");
        let mut stamp = Stamp::read(&File::open(own).unwrap()).unwrap();
        stamp.uid = stamp.uid.wrapping_add(1);
        assert_eq!(stamp.profile(), Err(StateError::UnsafeState));
    }
    #[test]
    fn state_oversize_refuses_before_directories_and_exact_bound_roundtrips() {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        assert_eq!(
            write_daemon_state_bytes(&root, &vec![0; MAX_DAEMON_STATE_BYTES + 1]),
            Err(StateError::Oversize)
        );
        assert!(!root.join(".chinwag").exists());
        let maximum = vec![b'x'; MAX_DAEMON_STATE_BYTES];
        write_daemon_state_bytes(&root, &maximum).unwrap();
        assert_eq!(fs::read(state(&root)).unwrap(), maximum);
    }
    #[test]
    fn state_target_replacement_during_write_refuses_without_overwriting_changed_name() {
        let (_temp, root) = fixture();
        private_file(&state(&root), b"original");
        let mut writer = StateWriter::open(&root).unwrap();
        let changed = root.clone();
        writer.before_rename = Some(Box::new(move || {
            fs::rename(state(&changed), changed.join(".chinwag/bus/old-state")).unwrap();
            private_file(&state(&changed), b"separate replacement");
        }));
        assert_eq!(writer.write(b"new bytes"), Err(StateError::Changed));
        assert_eq!(fs::read(state(&root)).unwrap(), b"separate replacement");
        assert_eq!(
            fs::read(root.join(".chinwag/bus/old-state")).unwrap(),
            b"original"
        );
    }
    #[test]
    fn state_bus_directory_replacement_is_refused_before_rename() {
        let (_temp, root) = fixture();
        let mut writer = StateWriter::open(&root).unwrap();
        let changed = root.clone();
        writer.before_rename = Some(Box::new(move || {
            fs::rename(
                changed.join(".chinwag/bus"),
                changed.join(".chinwag/old-bus"),
            )
            .unwrap();
            fs::create_dir(changed.join(".chinwag/bus")).unwrap();
            fs::set_permissions(
                changed.join(".chinwag/bus"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }));
        assert_eq!(writer.write(b"new bytes"), Err(StateError::Directory));
        assert!(!state(&root).exists());
        assert!(!root.join(".chinwag/old-bus/daemon.json").exists());
    }
}
