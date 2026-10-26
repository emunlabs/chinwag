//! Original local repository directory admission; no database or key access.
use crate::fs::{Anchor, ChildDirectory};
use crate::{Refused, refusal};
use std::{marker::PhantomData, path::Path, rc::Rc};

/// Held identity chains only. No Clone, serialization, grant, or public fields.
#[must_use = "Finish this original admission with checked directory closes"]
pub struct RepositoryAdmission {
    git: Anchor,
    private: Anchor,
    _thread: PhantomData<Rc<()>>,
}
impl RepositoryAdmission {
    pub fn open(repo: &Path) -> Result<Self, Refused> {
        let git = Anchor::open_fixture(repo, Some(ChildDirectory::Git)).map_err(refusal)?;
        let private = match Anchor::open_fixture(repo, Some(ChildDirectory::PrivateLeaf)) {
            Ok(anchor) => anchor,
            Err(reason) => {
                git.close_all().map_err(refusal)?;
                return Err(refusal(reason));
            }
        };
        let admission = Self {
            git,
            private,
            _thread: PhantomData,
        };
        if let Err(error) = admission.verify() {
            let closed = admission.finish();
            closed?;
            return Err(error);
        }
        Ok(admission)
    }
    pub fn verify(&self) -> Result<(), Refused> {
        self.git.check().map_err(refusal)?;
        self.private.check().map_err(refusal)?;
        Ok(())
    }
    /// Current held directory identities for comparison with an original live initializer.
    /// These observations grant neither ownership nor cleanup authority.
    pub fn directory_identities(&self) -> Result<[(i32, u64); 3], Refused> {
        self.verify()?;
        let repo = self.git.repository_identity();
        if repo != self.private.repository_identity() {
            return Err(refusal("repository_admission_roots_differ"));
        }
        let git = self.git.check().map_err(refusal)?;
        let private = self.private.check().map_err(refusal)?;
        Ok([
            (repo.dev, repo.ino),
            (git.dev, git.ino),
            (private.dev, private.ino),
        ])
    }
    pub fn finish(self) -> Result<usize, Refused> {
        let verified = self.verify();
        let Self { git, private, .. } = self;
        let git = git.close_all().map_err(refusal);
        let private = private.close_all().map_err(refusal);
        verified?;
        Ok(git? + private?)
    }
}
