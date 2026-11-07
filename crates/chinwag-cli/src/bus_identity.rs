//! Private daemon identity persistence, not enrollment or remote K2 authority.
#![forbid(unsafe_code)]

use iroh::{EndpointId, SecretKey};
use rand::{TryRngCore, rngs::OsRng};
use rustix::fs::{Mode, OFlags, fsync, mkdirat, openat};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsFd, BorrowedFd},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const KEY_NAME: &str = "daemon_secret.key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    InvalidPath,
    UnsafeDirectory,
    UnsafeKeyFile,
    Changed,
    Randomness,
    Io(std::io::ErrorKind),
}
impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Detailed local error codes contain no key material. Untrusted callers
        // receive one generic message rather than a validation oracle.
        f.write_str("daemon identity unavailable")
    }
}
impl std::error::Error for IdentityError {}
type Result<T> = std::result::Result<T, IdentityError>;
fn io(error: std::io::Error) -> IdentityError {
    IdentityError::Io(error.kind())
}
fn os(error: rustix::io::Errno) -> IdentityError {
    io(error.into())
}
fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}
fn checked_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(IdentityError::InvalidPath);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryState {
    id: (u64, u64),
    uid: u32,
    mode: u32,
}
impl DirectoryState {
    fn read(file: &File) -> Result<Self> {
        let metadata = file.metadata().map_err(io)?;
        let mode = metadata.mode() & 0o7777;
        if !metadata.is_dir()
            || metadata.uid() != uid()
            || mode & 0o7022 != 0
            || mode & 0o500 != 0o500
        {
            return Err(IdentityError::UnsafeDirectory);
        }
        Ok(Self {
            id: (metadata.dev(), metadata.ino()),
            uid: metadata.uid(),
            mode,
        })
    }
}
struct Directory {
    file: File,
    state: DirectoryState,
}
impl Directory {
    fn root(path: &Path) -> Result<Self> {
        checked_path(path)?;
        let mut file = File::open("/").map_err(io)?;
        for component in path.components() {
            if let Component::Normal(name) = component {
                file = File::from(
                    openat(
                        &file,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(os)?,
                );
            }
        }
        let state = DirectoryState::read(&file)?;
        Ok(Self { file, state })
    }
    fn below(parent: &Self, name: &str) -> Result<Self> {
        let file = File::from(
            openat(
                &parent.file,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(os)?,
        );
        let state = DirectoryState::read(&file)?;
        Ok(Self { file, state })
    }
    fn private_child(parent: &Self, name: &str) -> Result<Self> {
        match Self::below(parent, name) {
            Ok(directory) => return Ok(directory),
            Err(IdentityError::Io(std::io::ErrorKind::NotFound)) => {}
            Err(error) => return Err(error),
        }
        match mkdirat(&parent.file, name, Mode::from_raw_mode(0o700)) {
            Ok(()) => fsync(&parent.file).map_err(os)?,
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(os(error)),
        }
        Self::below(parent, name)
    }
    fn verify(&self, observed: &Self) -> Result<()> {
        if DirectoryState::read(&self.file)? != self.state || observed.state != self.state {
            return Err(IdentityError::Changed);
        }
        Ok(())
    }
}
/// Retained physical bus-directory observations. Opening this guard does not
/// load a key and supplies no signing, source or remote-admission authority.
pub(crate) struct BusDirectory {
    path: PathBuf,
    root: Directory,
    chinwag: Directory,
    bus: Directory,
}
impl BusDirectory {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let root = Directory::root(path)?;
        let chinwag = Directory::private_child(&root, ".chinwag")?;
        let bus = Directory::private_child(&chinwag, "bus")?;
        let directories = Self {
            path: path.into(),
            root,
            chinwag,
            bus,
        };
        directories.verify()?;
        Ok(directories)
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.root.verify(&Directory::root(&self.path)?)?;
        self.chinwag
            .verify(&Directory::below(&self.root, ".chinwag")?)?;
        self.bus.verify(&Directory::below(&self.chinwag, "bus")?)
    }
    pub(crate) fn sync(&self) -> Result<()> {
        self.verify()?;
        fsync(&self.bus.file).map_err(os)?;
        fsync(&self.chinwag.file).map_err(os)?;
        fsync(&self.root.file).map_err(os)?;
        self.verify()
    }
}
impl AsFd for BusDirectory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.bus.file.as_fd()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct KeyState {
    id: (u64, u64),
    uid: u32,
    mode: u32,
    nlink: u64,
    length: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    regular: bool,
}
impl KeyState {
    fn read(file: &File) -> Result<Self> {
        let m = file.metadata().map_err(io)?;
        Ok(Self {
            id: (m.dev(), m.ino()),
            uid: m.uid(),
            mode: m.mode() & 0o7777,
            nlink: m.nlink(),
            length: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
            regular: m.is_file(),
        })
    }
    fn profile(&self) -> Result<()> {
        if !self.regular
            || self.uid != uid()
            || self.nlink != 1
            || !matches!(self.mode, 0o400 | 0o600)
        {
            return Err(IdentityError::UnsafeKeyFile);
        }
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        self.profile()?;
        if self.length != 32 {
            return Err(IdentityError::UnsafeKeyFile);
        }
        Ok(())
    }
}

fn read_existing(directories: &BusDirectory) -> Result<Option<(SecretKey, KeyState)>> {
    directories.verify()?;
    let fd = match openat(
        &directories.bus.file,
        KEY_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) => return Err(os(error)),
    };
    let mut file = File::from(fd);
    let before = KeyState::read(&file)?;
    before.validate()?;
    let mut seed = Zeroizing::new([0u8; 32]);
    file.read_exact(&mut *seed).map_err(io)?;
    let after = KeyState::read(&file)?;
    after.validate()?;
    let named = File::from(
        openat(
            &directories.bus.file,
            KEY_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(os)?,
    );
    let named = KeyState::read(&named)?;
    named.validate()?;
    directories.verify()?;
    if before != after || named != before {
        return Err(IdentityError::Changed);
    }
    Ok(Some((SecretKey::from_bytes(&seed), before)))
}

/// Preserve an existing private, regular, single-link 32-byte identity, or
/// create one from the fallible OS CSPRNG. Errors retain files as observed:
/// no rotation, truncation, chmod, cleanup or repair is attempted.
///
/// Filesystem checks are retained-descriptor observations, not atomic same-UID
/// containment. A successfully loaded old key has unknown entropy provenance;
/// this function supplies neither enrollment nor production K2 trust.
pub fn load_or_create_daemon_secret(repo_root: &Path) -> Result<SecretKey> {
    let directories = BusDirectory::open(repo_root)?;
    if let Some((key, _)) = read_existing(&directories)? {
        return Ok(key);
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut *seed)
        .map_err(|_| IdentityError::Randomness)?;
    directories.verify()?;
    let fd = match openat(
        &directories.bus.file,
        KEY_NAME,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => fd,
        Err(error) if error == rustix::io::Errno::EXIST => {
            return read_existing(&directories)?
                .map(|(key, _)| key)
                .ok_or(IdentityError::Changed);
        }
        Err(error) => return Err(os(error)),
    };
    let mut file = File::from(fd);
    let empty = KeyState::read(&file)?;
    empty.profile()?;
    if empty.mode != 0o600 || empty.length != 0 {
        return Err(IdentityError::UnsafeKeyFile);
    }
    file.write_all(&*seed).map_err(io)?;
    file.sync_all().map_err(io)?;
    fsync(&directories.bus.file).map_err(os)?;
    // Persist the complete named path even if another creator supplied an
    // otherwise-valid private directory immediately before this operation.
    fsync(&directories.chinwag.file).map_err(os)?;
    fsync(&directories.root.file).map_err(os)?;
    let written = KeyState::read(&file)?;
    written.validate()?;
    let expected_public = SecretKey::from_bytes(&seed).public();
    let (loaded, observed) = read_existing(&directories)?.ok_or(IdentityError::Changed)?;
    // Only public IDs are compared; temporary seed material is zeroized.
    if observed != written
        || observed.id != empty.id
        || !bool::from(loaded.public().as_bytes().ct_eq(expected_public.as_bytes()))
    {
        return Err(IdentityError::Changed);
    }
    Ok(loaded)
}

fn legacy_public_id(repo_root: &Path) -> Result<EndpointId> {
    checked_path(repo_root)?;
    let mut hasher = Sha256::new();
    hasher.update(b"chinwag-iroh-bus-hub-v1:");
    hasher.update(repo_root.to_string_lossy().as_bytes());
    let mut seed = Zeroizing::new([0u8; 32]);
    hasher.finalize_into((&mut *seed).into());
    Ok(SecretKey::from_bytes(&seed).public())
}

/// Detect the old publicly predictable identity for this exact historical path
/// spelling, without reading or rotating a stored key. `false` is not proof of
/// OS randomness: a moved legacy identity or an unrelated weak key is unbound
/// until separately enrolled. This predicate can only support remote refusal.
pub fn is_known_legacy_public_id(repo_root: &Path, public: &EndpointId) -> Result<bool> {
    Ok(bool::from(
        legacy_public_id(repo_root)?
            .as_bytes()
            .ct_eq(public.as_bytes()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    };
    use tempfile::TempDir;

    fn fixture() -> (TempDir, PathBuf) {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        (temp, root)
    }
    fn key_path(root: &Path) -> PathBuf {
        root.join(".chinwag/bus/daemon_secret.key")
    }
    fn empty_private_store(root: &Path) {
        fs::create_dir(root.join(".chinwag")).unwrap();
        fs::set_permissions(root.join(".chinwag"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join(".chinwag/bus")).unwrap();
        fs::set_permissions(root.join(".chinwag/bus"), fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn fresh_os_generated_public_identities_differ_and_are_not_the_known_path_identity() {
        let (_a, a) = fixture();
        let (_b, b) = fixture();
        let first = load_or_create_daemon_secret(&a).unwrap().public();
        let second = load_or_create_daemon_secret(&b).unwrap().public();
        assert_ne!(first, second);
        assert!(!is_known_legacy_public_id(&a, &first).unwrap());
        assert!(!is_known_legacy_public_id(&b, &second).unwrap());
        for root in [&a, &b] {
            let meta = fs::symlink_metadata(key_path(root)).unwrap();
            assert!(meta.is_file());
            assert_eq!(meta.len(), 32);
            assert_eq!(meta.nlink(), 1);
            assert_eq!(meta.mode() & 0o7777, 0o600);
            for directory in [root.join(".chinwag"), root.join(".chinwag/bus")] {
                assert_eq!(
                    fs::symlink_metadata(directory).unwrap().mode() & 0o7777,
                    0o700
                );
            }
        }
    }
    #[test]
    fn existing_identity_is_stable_without_rotation_or_permission_repair() {
        let (_temp, root) = fixture();
        let public = load_or_create_daemon_secret(&root).unwrap().public();
        let before = fs::symlink_metadata(key_path(&root)).unwrap();
        assert_eq!(
            load_or_create_daemon_secret(&root).unwrap().public(),
            public
        );
        let after = fs::symlink_metadata(key_path(&root)).unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.mtime(),
                before.mtime_nsec()
            ),
            (after.dev(), after.ino(), after.mtime(), after.mtime_nsec())
        );
        fs::set_permissions(key_path(&root), fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            load_or_create_daemon_secret(&root).unwrap().public(),
            public
        );
        assert_eq!(
            fs::symlink_metadata(key_path(&root)).unwrap().mode() & 0o7777,
            0o400
        );
    }
    #[test]
    fn existing_owner_controlled_0755_and_0750_containers_preserve_the_private_identity() {
        let (_temp, root) = fixture();
        let public = load_or_create_daemon_secret(&root).unwrap().public();
        let before = fs::symlink_metadata(key_path(&root)).unwrap();
        for name in [".chinwag", ".chinwag/bus"] {
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(
            load_or_create_daemon_secret(&root).unwrap().public(),
            public
        );
        fs::set_permissions(root.join(".chinwag/bus"), fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            load_or_create_daemon_secret(&root).unwrap().public(),
            public
        );
        let after = fs::symlink_metadata(key_path(&root)).unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.mtime(),
                before.mtime_nsec()
            ),
            (after.dev(), after.ino(), after.mtime(), after.mtime_nsec())
        );
        assert_eq!(after.mode() & 0o7777, 0o600);
        assert_eq!(
            fs::symlink_metadata(root.join(".chinwag")).unwrap().mode() & 0o7777,
            0o755
        );
        assert_eq!(
            fs::symlink_metadata(root.join(".chinwag/bus"))
                .unwrap()
                .mode()
                & 0o7777,
            0o750
        );
    }
    #[test]
    fn malformed_fixture_is_refused_without_overwrite() {
        let (_temp, root) = fixture();
        empty_private_store(&root);
        fs::write(key_path(&root), b"not a valid key").unwrap();
        fs::set_permissions(key_path(&root), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_or_create_daemon_secret(&root).is_err());
        assert_eq!(fs::read(key_path(&root)).unwrap(), b"not a valid key");
    }
    #[test]
    fn symlink_and_hardlink_fixture_keys_are_refused_without_clobber() {
        let (_source, source) = fixture();
        let public = load_or_create_daemon_secret(&source).unwrap().public();
        let (_link, link) = fixture();
        empty_private_store(&link);
        symlink(key_path(&source), key_path(&link)).unwrap();
        assert!(load_or_create_daemon_secret(&link).is_err());
        assert!(
            fs::symlink_metadata(key_path(&link))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            load_or_create_daemon_secret(&source).unwrap().public(),
            public
        );
        let alias = source.join("owned-key-alias");
        fs::hard_link(key_path(&source), &alias).unwrap();
        assert!(load_or_create_daemon_secret(&source).is_err());
        assert_eq!(fs::symlink_metadata(key_path(&source)).unwrap().nlink(), 2);
    }
    #[test]
    fn permissive_fixture_key_or_directory_is_refused_without_chmod() {
        let (_temp, root) = fixture();
        load_or_create_daemon_secret(&root).unwrap();
        fs::set_permissions(key_path(&root), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create_daemon_secret(&root).is_err());
        assert_eq!(
            fs::symlink_metadata(key_path(&root)).unwrap().mode() & 0o7777,
            0o644
        );
        for mode in [0o770, 0o777] {
            let (_other, other) = fixture();
            empty_private_store(&other);
            fs::set_permissions(other.join(".chinwag/bus"), fs::Permissions::from_mode(mode))
                .unwrap();
            assert!(load_or_create_daemon_secret(&other).is_err());
            assert!(!key_path(&other).exists());
            assert_eq!(
                fs::symlink_metadata(other.join(".chinwag/bus"))
                    .unwrap()
                    .mode()
                    & 0o7777,
                mode
            );
        }
    }
    #[test]
    fn directory_symlink_and_key_directory_errors_are_not_repaired() {
        let (_a, a) = fixture();
        let (_b, b) = fixture();
        symlink(&b, a.join(".chinwag")).unwrap();
        assert!(load_or_create_daemon_secret(&a).is_err());
        assert!(!b.join("bus").exists());
        let (_c, c) = fixture();
        empty_private_store(&c);
        fs::create_dir(key_path(&c)).unwrap();
        assert!(load_or_create_daemon_secret(&c).is_err());
        assert!(key_path(&c).is_dir());
    }
    #[test]
    fn wrong_owner_metadata_cannot_pass_the_private_key_profile() {
        let (_temp, root) = fixture();
        load_or_create_daemon_secret(&root).unwrap();
        let file = File::open(key_path(&root)).unwrap();
        let mut state = KeyState::read(&file).unwrap();
        state.uid = state.uid.wrapping_add(1);
        assert!(state.validate().is_err());
    }
    #[test]
    fn known_legacy_detection_exposes_only_public_ids_and_does_not_rotate() {
        let (_temp, root) = fixture();
        let public = legacy_public_id(&root).unwrap();
        assert!(is_known_legacy_public_id(&root, &public).unwrap());
        let (_other, other) = fixture();
        assert!(!is_known_legacy_public_id(&other, &public).unwrap());
        assert!(!root.join(".chinwag").exists());
    }
    #[test]
    fn published_rfc8032_empty_message_public_verification_vector() {
        // RFC 8032 section 7.1, TEST 1: public key/signature only, no seed.
        fn public_bytes<const N: usize>(hex: &str) -> [u8; N] {
            assert_eq!(hex.len(), N * 2);
            let mut out = [0; N];
            for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
                out[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
            }
            out
        }
        let public = EndpointId::from_bytes(&public_bytes(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ))
        .unwrap();
        let signature = iroh::Signature::from_bytes(&public_bytes(concat!(
            "e5564300c360ac729086e2cc806e828a",
            "84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd",
            "25bf5f0595bbe24655141438e7a100b"
        )));
        assert!(public.verify(b"", &signature).is_ok());
        assert!(public.verify(b"changed", &signature).is_err());
    }
}
