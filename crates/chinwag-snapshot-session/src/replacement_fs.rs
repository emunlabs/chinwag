//! Held private file identities for the original replacement lifetime only.
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

type Result<T> = std::result::Result<T, &'static str>;
const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirId {
    dev: i32,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    dev: i32,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u16,
    nlink: u64,
    size: u64,
    times: [i128; 4],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileId(Stamp);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DetachedId(Stamp);
#[derive(PartialEq, Eq)]
pub(super) struct Image {
    pub id: FileId,
    pub bytes: Vec<u8>,
}
#[derive(PartialEq, Eq)]
pub(super) struct DetachedImage {
    pub id: DetachedId,
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
    repository_index: usize,
    captured: DirId,
}

fn directory_id(stat: &rustix::fs::Stat) -> Result<DirId> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || stat.st_mode & 0o022 != 0 {
        return Err("unsafe_directory");
    }
    Ok(DirId {
        dev: stat.st_dev,
        ino: stat.st_ino,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode,
    })
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
fn stamp(stat: &rustix::fs::Stat, expected_links: u64) -> Result<Stamp> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || u64::from(stat.st_nlink) != expected_links
        || stat.st_size < 0
        || stat.st_size as u64 > crate::MAX_IMAGE_BYTES as u64
    {
        return Err("unsafe_fixture_file");
    }
    Ok(Stamp {
        dev: stat.st_dev,
        ino: stat.st_ino,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode,
        nlink: u64::from(stat.st_nlink),
        size: stat.st_size as u64,
        times: [
            i128::from(stat.st_mtime),
            i128::from(stat.st_mtime_nsec),
            i128::from(stat.st_ctime),
            i128::from(stat.st_ctime_nsec),
        ],
    })
}
impl Stamp {
    fn same_rename_object(self, other: Self) -> bool {
        (
            self.dev,
            self.ino,
            self.uid,
            self.gid,
            self.mode,
            self.size,
            &self.times[..2],
        ) == (
            other.dev,
            other.ino,
            other.uid,
            other.gid,
            other.mode,
            other.size,
            &other.times[..2],
        )
    }
}
impl FileId {
    pub fn observation(self) -> (i32, u64, u64, [i128; 4]) {
        (self.0.dev, self.0.ino, self.0.nlink, self.0.times)
    }
    pub fn read(file: &File) -> Result<Self> {
        Ok(Self(stamp(&fstat(file).map_err(|_| "file_stat")?, 1)?))
    }
    pub fn same_renamed_image(self, other: Self) -> bool {
        self.0.same_rename_object(other.0)
    }
    pub fn same_inode(self, other: Self) -> bool {
        (self.0.dev, self.0.ino) == (other.0.dev, other.0.ino)
    }
    pub fn record(self) -> String {
        let s = self.0;
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            s.dev,
            s.ino,
            s.uid,
            s.gid,
            s.mode,
            s.nlink,
            s.size,
            s.times[0],
            s.times[1],
            s.times[2],
            s.times[3]
        )
    }
}
impl DetachedId {
    pub fn observation(self) -> (i32, u64, u64, [i128; 4]) {
        (self.0.dev, self.0.ino, self.0.nlink, self.0.times)
    }
}
fn bytes(file: &mut File, limit: usize) -> Result<Vec<u8>> {
    if limit > crate::MAX_IMAGE_BYTES {
        return Err("fixture_file_limit");
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| "fixture_seek")?;
    let mut bytes = Vec::new();
    (&mut *file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "read_fixture_file")?;
    if bytes.len() > limit {
        return Err("fixture_file_limit");
    }
    Ok(bytes)
}
impl Anchor {
    pub fn open_fixture(repo: &Path) -> Result<Self> {
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
            let child = directory_id(&fstat(&next).map_err(|_| "directory_stat")?)?;
            links.push(Link {
                parent: fd,
                name: name.into(),
                child,
            });
            fd = next;
        }
        let repository_index = links.len().checked_sub(1).ok_or("fixture_not_root")?;
        repository(directory_id(&fstat(&fd).map_err(|_| "directory_stat")?)?)?;
        let next = openat(&fd, ".chinwag", DIR, Mode::empty()).map_err(|_| "open_private_leaf")?;
        let child = directory_id(&fstat(&next).map_err(|_| "directory_stat")?)?;
        private(child)?;
        links.push(Link {
            parent: fd,
            name: ".chinwag".into(),
            child,
        });
        let anchor = Self {
            links,
            fd: next,
            repository_index,
            captured: child,
        };
        anchor.check()?;
        Ok(anchor)
    }
    pub fn check(&self) -> Result<()> {
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
            if index == self.repository_index {
                repository(held)?;
            } else if index > self.repository_index {
                private(held)?;
            }
        }
        if directory_id(&fstat(&self.fd).map_err(|_| "directory_stat")?)? != self.captured {
            return Err("directory_identity_changed");
        }
        Ok(())
    }
    pub fn require_absent(&self, name: &str) -> Result<()> {
        match statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Ok(()),
            _ => Err("operation_artifact_present"),
        }
    }
    pub fn named_id(&self, name: &str) -> Result<FileId> {
        Ok(FileId(stamp(
            &statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| "file_name_changed")?,
            1,
        )?))
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
    pub fn read_held(&self, file: &mut File, name: &str, limit: usize) -> Result<Image> {
        let before = FileId::read(file)?;
        if before.0.size > limit as u64 {
            return Err("fixture_file_limit");
        }
        let bytes = bytes(file, limit)?;
        let after = FileId::read(file)?;
        if before != after || after != self.named_id(name)? || bytes.len() as u64 != before.0.size {
            return Err("fixture_file_changed");
        }
        Ok(Image { id: after, bytes })
    }
    pub fn verify(&self, file: &mut File, name: &str, expected: &[u8]) -> Result<FileId> {
        let image = self.read_held(file, name, expected.len())?;
        if image.bytes != expected {
            return Err("artifact_literal_changed");
        }
        Ok(image.id)
    }
    pub fn read_detached(&self, file: &mut File, original: &Image) -> Result<DetachedImage> {
        let before = DetachedId(stamp(&fstat(&*file).map_err(|_| "detached_file_stat")?, 0)?);
        if !before.0.same_rename_object(original.id.0) {
            return Err("detached_original_identity_changed");
        }
        let bytes = bytes(file, original.bytes.len())?;
        let after = DetachedId(stamp(&fstat(&*file).map_err(|_| "detached_file_stat")?, 0)?);
        if before != after || bytes != original.bytes {
            return Err("detached_original_changed");
        }
        Ok(DetachedImage { id: after, bytes })
    }
    pub fn close_all(self) -> Result<usize> {
        let Self { links, fd, .. } = self;
        let mut closed = 0;
        let mut failed = false;
        for fd in std::iter::once(fd).chain(links.into_iter().rev().map(|link| link.parent)) {
            if crate::checked_close::fd(fd).is_ok() {
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
}
