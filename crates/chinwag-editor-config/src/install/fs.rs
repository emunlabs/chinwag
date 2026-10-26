//! Anchors for exclusive private fixtures, with no process CWD changes.
use rustix::{
    fd::OwnedFd,
    fs::{AtFlags, FileType, Mode, OFlags, fstat, open, openat, statat},
    io::Errno,
};
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Component, Path},
};

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
pub(super) struct FileId {
    pub dev: i32,
    pub ino: u64,
    uid: u32,
    gid: u32,
    mode: u16,
    nlink: u64,
    size: u64,
}
impl FileId {
    pub fn read(file: &File) -> Result<Self> {
        file_id(&fstat(file).map_err(|_| "file_stat")?)
    }
    pub fn permissions(self) -> u16 {
        self.mode & 0o7777
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
    policy: Policy,
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
enum Policy {
    Fixture,
    Repository,
    PrivateLeaf,
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
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_uid != rustix::process::geteuid().as_raw()
        || !matches!(s.st_mode & 0o7777, 0o600 | 0o640 | 0o644)
        || s.st_nlink != 1
        || s.st_size < 0
        || s.st_size as u64 > crate::MAX_BYTES as u64
    {
        return Err("unsafe_fixture_file");
    }
    Ok(FileId {
        dev: s.st_dev,
        ino: s.st_ino,
        uid: s.st_uid,
        gid: s.st_gid,
        mode: s.st_mode,
        nlink: u64::from(s.st_nlink),
        size: s.st_size as u64,
    })
}
impl Anchor {
    pub fn open_fixture(repo: &Path, child: Option<&str>) -> Result<Self> {
        Self::open_policy(repo, child, Policy::Fixture)
    }
    pub(super) fn open_repository(repo: &Path, child: Option<&str>) -> Result<Self> {
        Self::open_policy(repo, child, Policy::Repository)
    }
    pub(super) fn open_private(repo: &Path) -> Result<Self> {
        Self::open_policy(repo, Some(".chinwag"), Policy::PrivateLeaf)
    }
    pub fn preserves_target_mode(&self) -> bool {
        self.policy == Policy::Repository
    }
    fn check_file_policy(&self, name: &str, id: FileId) -> Result<()> {
        if (self.policy != Policy::Repository
            || matches!(name, "chinwag-install.intent" | "chinwag-install.completed"))
            && id.permissions() != 0o600
        {
            return Err("unsafe_fixture_file");
        }
        Ok(())
    }
    fn open_policy(repo: &Path, child: Option<&str>, policy: Policy) -> Result<Self> {
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
        let repo_id = directory_id(&fstat(&fd).map_err(|_| "directory_stat")?)?;
        if policy == Policy::Fixture {
            private(repo_id)?;
        } else {
            repository(repo_id)?;
        }
        if let Some(name) = child {
            let next = openat(&fd, name, DIR, Mode::empty()).map_err(|_| "open_editor_parent")?;
            let id = directory_id(&fstat(&next).map_err(|_| "directory_stat")?)?;
            if policy == Policy::Repository {
                repository(id)?;
            } else {
                private(id)?;
            }
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
            policy,
        };
        anchor.check()?;
        Ok(anchor)
    }
    pub(super) fn repository_child(
        mut self,
        name: &'static str,
        guard: &mut super::repository::OuterGuard,
    ) -> Result<Self> {
        if self.policy != Policy::Repository || !matches!(name, ".cursor" | ".codex") {
            return Err("invalid_repository_child");
        }
        self.check()?;
        guard.verify_parent_creation(self.identity(), name)?;
        let created = match statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => {
                guard.before_parent_create()?;
                rustix::fs::mkdirat(&self.fd, name, Mode::from_raw_mode(0o700))
                    .map_err(|_| "editor_parent_creation_unconfirmed")?;
                true
            }
            Ok(_) => false,
            Err(_) => return Err("editor_parent_lookup"),
        };
        let next = openat(&self.fd, name, DIR, Mode::empty()).map_err(|_| "open_editor_parent")?;
        let held = directory_id(&fstat(&next).map_err(|_| "directory_stat")?)?;
        let named = directory_id(
            &statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| "editor_parent_name")?,
        )?;
        if held != named {
            return Err("editor_parent_identity_changed");
        }
        repository(held)?;
        if created {
            private(held)?;
            rustix::fs::fsync(&next).map_err(|_| "new_editor_parent_sync")?;
            rustix::fs::fsync(&self.fd).map_err(|_| "new_editor_parent_entry_sync")?;
        }
        self.check()?;
        guard.verify_parent_creation(self.identity(), name)?;
        self.links.push(Link {
            parent: self.fd,
            name: name.into(),
            child: held,
        });
        self.fd = next;
        self.captured = held;
        self.check()?;
        if created {
            guard.parent_created();
        }
        Ok(self)
    }
    pub(super) fn repository_identity(&self) -> DirId {
        self.links[self.private_start].child
    }
    pub fn identity(&self) -> DirId {
        self.captured
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
                if self.policy == Policy::Fixture {
                    private(held)?;
                } else {
                    repository(held)?;
                }
            } else if index > self.private_start {
                if self.policy == Policy::Repository {
                    repository(held)?;
                } else {
                    private(held)?;
                }
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
    pub fn read(&self, name: &str) -> Result<Option<Image>> {
        self.read_bounded(name, crate::MAX_BYTES)
    }
    pub fn read_bounded(&self, name: &str, limit: usize) -> Result<Option<Image>> {
        let fd = match openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err("open_fixture_file"),
        };
        let mut file = File::from(fd);
        let result = (|| {
            let before = FileId::read(&file)?;
            self.check_file_policy(name, before)?;
            if before.size > limit as u64 || limit > crate::MAX_BYTES {
                return Err("fixture_file_limit");
            }
            let mut bytes = Vec::new();
            (&mut file)
                .take((limit + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| "read_fixture_file")?;
            let after = FileId::read(&file)?;
            let named = file_id(
                &statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| "file_name_changed")?,
            )?;
            if before != after || after != named || bytes.len() as u64 != before.size {
                return Err("fixture_file_changed");
            }
            Ok(Some(Image { id: before, bytes }))
        })();
        let closed = super::checked_close::file(file);
        match (result, closed) {
            (Ok(image), Ok(())) => Ok(image),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
    pub fn close_all(self) -> Result<usize> {
        let Self { links, fd, .. } = self;
        let mut closed = 0;
        let mut failed = super::checked_close::fd(fd).is_err();
        if !failed {
            closed += 1;
        }
        for link in links.into_iter().rev() {
            if super::checked_close::fd(link.parent).is_ok() {
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

    pub fn exclusive(&self, name: &str) -> Result<File> {
        let fd = openat(
            &self.fd,
            name,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "exclusive_fixture_artifact")?;
        Ok(File::from(fd))
    }
    pub fn verify(&self, file: &mut File, name: &str, expected: &[u8]) -> Result<FileId> {
        file.seek(SeekFrom::Start(0)).map_err(|_| "artifact_seek")?;
        let held = FileId::read(file)?;
        self.check_file_policy(name, held)?;
        let named = self.read(name)?.ok_or("artifact_missing")?;
        if held != named.id || named.bytes != expected {
            return Err("artifact_readback_changed");
        }
        Ok(held)
    }
}
