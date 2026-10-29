//! Original query files. Observed identities cannot construct an owner.
use super::*;
use rustix::fs::{fchmod, fsync, unlinkat};
use std::io::Write;

#[derive(Clone, Copy)]
pub(crate) enum QueryArtifact {
    Pending,
    Output,
    Error,
}
impl QueryArtifact {
    fn name(self) -> &'static str {
        match self {
            Self::Pending => "chinwag-principal.pending",
            Self::Output => "chinwag-principal.stdout",
            Self::Error => "chinwag-principal.stderr",
        }
    }
}

pub(crate) struct QueryFile {
    file: File,
    artifact: QueryArtifact,
    created: FileId,
}
impl QueryFile {
    pub fn create(anchor: &Anchor, artifact: QueryArtifact, bytes: &[u8]) -> Result<Self> {
        if anchor.child_role != Some(ChildDirectory::Git) {
            return Err("git_directory_role_required");
        }
        anchor.check()?;
        let fd = openat(
            &anchor.fd,
            artifact.name(),
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_retain(0o600),
        )
        .map_err(|_| "query_file_exclusive_create")?;
        // Any subsequent failure leaves the newly occupied name in place.
        fchmod(&fd, Mode::from_bits_retain(0o600)).map_err(|_| "query_file_mode")?;
        let mut file = File::from(fd);
        file.write_all(bytes).map_err(|_| "query_file_write")?;
        file.sync_all().map_err(|_| "query_file_sync")?;
        fsync(&anchor.fd).map_err(|_| "query_parent_sync")?;
        let created = anchor.identify_named(&file, artifact.name())?;
        if anchor.read_held(&mut file, artifact.name(), 65_536)?.bytes != bytes {
            return Err("query_initial_bytes_changed");
        }
        Ok(Self {
            file,
            artifact,
            created,
        })
    }
    pub fn output(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
    pub fn check_instance(&self, anchor: &Anchor) -> Result<()> {
        anchor.check()?;
        let id = anchor.identify_named_live(&self.file, self.artifact.name())?;
        if id.dev != self.created.dev
            || id.ino != self.created.ino
            || id.uid != self.created.uid
            || id.gid != self.created.gid
            || id.mode != self.created.mode
            || id.nlink != self.created.nlink
            || id.size > 65_536
        {
            return Err("original_query_file_changed");
        }
        Ok(())
    }
    pub fn read(&mut self, anchor: &Anchor) -> Result<Image> {
        self.check_instance(anchor)?;
        anchor.read_held(&mut self.file, self.artifact.name(), 65_536)
    }
    /// Only after the original child is known terminal, or never spawned.
    /// The caller supplies the exact image it just inspected, not an owner.
    pub fn release(mut self, anchor: &Anchor, expected: &Image) -> Result<()> {
        self.check_instance(anchor)?;
        if self.read(anchor)? != *expected {
            return Err("query_terminal_image_changed");
        }
        unlinkat(&anchor.fd, self.artifact.name(), AtFlags::empty())
            .map_err(|_| "query_file_unlink")?;
        // Attempt the original descriptor close even if the unlink sync fails.
        let sync = fsync(&anchor.fd).map_err(|_| "query_unlink_sync");
        let close = crate::checked_close::file(self.file);
        sync.and(close)
    }
}
