//! Held private fixture chain; no path-based SQLite open or CWD changes.
use rustix::{
    fd::OwnedFd,
    fs::{AtFlags, FileType, Mode, OFlags, fstat, open, openat, statat},
    io::Errno,
};
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::fd::{AsFd, BorrowedFd},
    path::{Component, Path},
};

#[path = "fs_query.rs"]
mod query;
pub(super) use query::{QueryArtifact, QueryFile};

pub(super) type Result<T> = std::result::Result<T, &'static str>;
const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DirId {
    pub dev: i32,
    pub ino: u64,
    uid: u32,
    gid: u32,
    mode: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RoleFileId<R> {
    pub dev: i32,
    pub ino: u64,
    uid: u32,
    gid: u32,
    pub mode: u16,
    nlink: u64,
    size: u64,
    modified_and_changed: [i128; 4],
    _role: std::marker::PhantomData<R>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrivateFile {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GitConfig {}
pub(super) type FileId = RoleFileId<PrivateFile>;
pub(super) type GitConfigId = RoleFileId<GitConfig>;
trait FileRole {
    fn accepts(mode: u16) -> bool;
    const LIMIT: usize;
}
impl FileRole for PrivateFile {
    fn accepts(mode: u16) -> bool {
        mode & 0o7777 == 0o600
    }
    const LIMIT: usize = crate::MAX_IMAGE_BYTES;
}
impl FileRole for GitConfig {
    fn accepts(mode: u16) -> bool {
        matches!(mode & 0o7777, 0o600 | 0o640 | 0o644)
    }
    const LIMIT: usize = 65_536;
}
/// Distinct checked role: never accepted by private-file metadata methods.
pub(super) struct GitConfigFile(File);
impl GitConfigFile {
    pub fn rewind_input(&mut self) -> Result<()> {
        self.0.seek(SeekFrom::Start(0)).map_err(|_| "config_seek")?;
        Ok(())
    }
    pub fn input(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
    pub fn close(self) -> Result<()> {
        crate::checked_close::file(self.0)
    }
}
#[derive(PartialEq, Eq)]
pub(super) struct GitConfigImage {
    pub id: GitConfigId,
    pub bytes: Vec<u8>,
}
impl GitConfigId {
    fn read(file: &File) -> Result<Self> {
        role_file_id::<GitConfig>(&fstat(file).map_err(|_| "file_stat")?)
    }
}
impl FileId {
    pub fn read(file: &File) -> Result<Self> {
        file_id(&fstat(file).map_err(|_| "file_stat")?)
    }
}
#[derive(PartialEq, Eq)]
pub(super) struct Image {
    pub id: FileId,
    pub bytes: Vec<u8>,
}
struct Link {
    parent: OwnedFd,
    name: OsString,
    child: DirId,
}
pub(super) struct Anchor {
    links: Vec<Link>,
    pub fd: OwnedFd,
    private_start: usize,
    captured: DirId,
    child_role: Option<ChildDirectory>,
}

fn directory_id(s: &rustix::fs::Stat) -> Result<DirId> {
    if FileType::from_raw_mode(s.st_mode) != FileType::Directory || s.st_mode & 0o022 != 0 {
        return Err("unsafe_directory");
    }
    Ok(DirId {
        dev: s.st_dev,
        ino: s.st_ino,
        uid: s.st_uid,
        gid: s.st_gid,
        mode: s.st_mode,
    })
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ChildDirectory {
    Git,
    PrivateLeaf,
}
impl ChildDirectory {
    fn name(self) -> &'static str {
        match self {
            Self::Git => ".git",
            Self::PrivateLeaf => ".chinwag",
        }
    }
    fn check(self, id: DirId) -> Result<()> {
        match self {
            Self::Git => repository(id),
            Self::PrivateLeaf => private(id),
        }
    }
}
fn repository(id: DirId) -> Result<()> {
    if id.uid != rustix::process::geteuid().as_raw()
        || id.mode & 0o022 != 0
        || id.mode & 0o300 != 0o300
    {
        return Err("unsafe_repository_directory");
    }
    Ok(())
}
fn private(id: DirId) -> Result<()> {
    if id.uid != rustix::process::geteuid().as_raw() || id.mode & 0o7777 != 0o700 {
        return Err("not_private_fixture_directory");
    }
    Ok(())
}
fn file_id(s: &rustix::fs::Stat) -> Result<FileId> {
    role_file_id::<PrivateFile>(s)
}
fn role_file_id<R: FileRole>(s: &rustix::fs::Stat) -> Result<RoleFileId<R>> {
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_uid != rustix::process::geteuid().as_raw()
        || !R::accepts(s.st_mode)
        || s.st_nlink != 1
        || s.st_size < 0
        || s.st_size as u64 > R::LIMIT as u64
    {
        return Err("unsafe_fixture_file");
    }
    Ok(RoleFileId {
        dev: s.st_dev,
        ino: s.st_ino,
        uid: s.st_uid,
        gid: s.st_gid,
        mode: s.st_mode,
        nlink: u64::from(s.st_nlink),
        size: s.st_size as u64,
        _role: std::marker::PhantomData,
        modified_and_changed: [
            i128::from(s.st_mtime),
            i128::from(s.st_mtime_nsec),
            i128::from(s.st_ctime),
            i128::from(s.st_ctime_nsec),
        ],
    })
}
impl Anchor {
    pub fn open_fixture(repo: &Path, child: Option<ChildDirectory>) -> Result<Self> {
        let mut components = repo.components();
        if components.next() != Some(Component::RootDir) {
            return Err("absolute_fixture_required");
        }
        let mut fd = open("/", DIR, Mode::empty()).map_err(|_| "open_root")?;
        let mut links = Vec::new();
        for component in components {
            if links.len() >= 256 {
                return Err("fixture_path_component_limit");
            }
            let Component::Normal(name) = component else {
                return Err("invalid_fixture_component");
            };
            directory_id(&fstat(&fd).map_err(|_| "directory_stat")?)?;
            let next =
                openat(&fd, name, DIR, Mode::empty()).map_err(|_| "open_fixture_component")?;
            let id = directory_id(&fstat(&next).map_err(|_| "directory_stat")?)?;
            links.push(Link {
                parent: fd,
                name: name.into(),
                child: id,
            });
            fd = next;
        }
        let private_start = links.len().checked_sub(1).ok_or("fixture_not_root")?;
        repository(directory_id(&fstat(&fd).map_err(|_| "directory_stat")?)?)?;
        if let Some(role) = child {
            let name = role.name();
            let next = openat(&fd, name, DIR, Mode::empty()).map_err(|_| "open_editor_parent")?;
            let id = directory_id(&fstat(&next).map_err(|_| "directory_stat")?)?;
            role.check(id)?;
            links.push(Link {
                parent: fd,
                name: name.into(),
                child: id,
            });
            fd = next;
        }
        let captured = directory_id(&fstat(&fd).map_err(|_| "directory_stat")?)?;
        let anchor = Self {
            links,
            fd,
            private_start,
            captured,
            child_role: child,
        };
        anchor.check()?;
        Ok(anchor)
    }
    pub fn check(&self) -> Result<DirId> {
        for (index, link) in self.links.iter().enumerate() {
            directory_id(&fstat(&link.parent).map_err(|_| "directory_stat")?)?;
            let named = directory_id(
                &statat(&link.parent, &link.name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| "directory_name_changed")?,
            )?;
            let held = self
                .links
                .get(index + 1)
                .map(|next| &next.parent)
                .unwrap_or(&self.fd);
            let held = directory_id(&fstat(held).map_err(|_| "directory_stat")?)?;
            if named != link.child || held != link.child {
                return Err("directory_identity_changed");
            }
            if index == self.private_start {
                repository(held)?;
            } else if index > self.private_start {
                self.child_role
                    .ok_or("missing_directory_role")?
                    .check(held)?;
            }
        }
        let current = directory_id(&fstat(&self.fd).map_err(|_| "directory_stat")?)?;
        if current != self.captured {
            return Err("directory_identity_changed");
        }
        Ok(current)
    }
    pub fn require_absent(&self, name: &str) -> Result<()> {
        match statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Ok(()),
            _ => Err("operation_artifact_present"),
        }
    }
    pub fn open_git_config(&self) -> Result<GitConfigFile> {
        if self.child_role != Some(ChildDirectory::Git) {
            return Err("git_directory_role_required");
        }
        self.check()?;
        let fd = openat(
            &self.fd,
            "config",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "open_git_config")?;
        let file = File::from(fd);
        GitConfigId::read(&file)?;
        Ok(GitConfigFile(file))
    }
    pub fn identify_git_config(&self, file: &GitConfigFile) -> Result<GitConfigId> {
        if self.child_role != Some(ChildDirectory::Git) {
            return Err("git_directory_role_required");
        }
        self.check()?;
        let before = GitConfigId::read(&file.0)?;
        let named = role_file_id::<GitConfig>(
            &statat(&self.fd, "config", AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| "named_config_metadata")?,
        )?;
        let after = GitConfigId::read(&file.0)?;
        if before != named || before != after {
            return Err("held_named_config_changed");
        }
        Ok(before)
    }
    pub fn read_git_config(&self, file: &mut GitConfigFile) -> Result<GitConfigImage> {
        let before = self.identify_git_config(file)?;
        file.0.seek(SeekFrom::Start(0)).map_err(|_| "config_seek")?;
        let mut bytes = Vec::new();
        (&mut file.0)
            .take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| "read_config")?;
        let after = self.identify_git_config(file)?;
        if before != after || bytes.len() as u64 != before.size {
            return Err("git_config_changed");
        }
        Ok(GitConfigImage { id: before, bytes })
    }
    pub fn open_existing(&self, name: &str) -> Result<File> {
        let fd = openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "open_fixture_file")?;
        let file = File::from(fd);
        FileId::read(&file)?;
        Ok(file)
    }
    pub fn read_held(&self, file: &mut File, name: &str, limit: usize) -> Result<Image> {
        let before = FileId::read(file)?;
        if before.size > limit as u64 || limit > crate::MAX_IMAGE_BYTES {
            return Err("fixture_file_limit");
        }
        file.seek(SeekFrom::Start(0)).map_err(|_| "fixture_seek")?;
        let mut bytes = Vec::new();
        (&mut *file)
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "read_fixture_file")?;
        let after = FileId::read(file)?;
        let named = file_id(
            &statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| "file_name_changed")?,
        )?;
        if before != after || after != named || bytes.len() as u64 != before.size {
            return Err("fixture_file_changed");
        }
        Ok(Image { id: before, bytes })
    }
    pub fn close_all(self) -> Result<usize> {
        let Self { links, fd, .. } = self;
        let mut closed = 0;
        let mut failed = crate::checked_close::fd(fd).is_err();
        if !failed {
            closed += 1;
        }
        for link in links.into_iter().rev() {
            if crate::checked_close::fd(link.parent).is_ok() {
                closed += 1;
            } else {
                failed = true;
            }
        }
        if failed {
            Err("anchor_checked_close")
        } else {
            Ok(closed)
        }
    }
    pub fn identify_named(&self, file: &File, name: &str) -> Result<FileId> {
        let before = FileId::read(file)?;
        let named = file_id(
            &statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| "named_file_metadata")?,
        )?;
        let after = FileId::read(file)?;
        if before != named || before != after {
            return Err("held_named_file_changed");
        }
        Ok(before)
    }
}
