//! Original completed store with live signing and repository bindings for one editor handoff.
use super::{
    ConfirmedSigning, CreatedReceipt, FileId, IntegrationFailure, IntegrationOwner,
    LocalInitializationReceipt, MAX_IMAGE_BYTES, checked_close, failed,
};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs::File,
    path::{Path, PathBuf},
};

struct LiveInitialization {
    confirmation: ConfirmedSigning,
    store_file: File,
    store_id: FileId,
}

/// Constructed only by the original initial-store owner. No reconstruction from receipts.
#[must_use = "Finish this original live handoff after the editor outcome; Drop is not completion"]
pub struct InitializationHandoff {
    live: RefCell<LiveInitialization>,
    repo: PathBuf,
    store: CreatedReceipt,
}
impl IntegrationOwner {
    /// Retain the original confirmed signing owner across configuration of one editor.
    pub fn finish_for_editor(mut self) -> Result<InitializationHandoff, IntegrationFailure> {
        self.confirmation
            .verify()
            .map_err(|reason| failed(reason, false))?;
        let store = self
            .owner
            .finish()
            .map_err(|reason| failed(reason, false))?;
        self.confirmation
            .verify()
            .map_err(|reason| failed(reason, true))?;
        let material = self
            .confirmation
            .original
            .material
            .as_ref()
            .ok_or_else(|| failed("material_missing", true))?;
        let mut store_file = material
            .anchor
            .open_existing("state.crdb")
            .map_err(|reason| failed(reason, true))?;
        let image = material
            .anchor
            .read_held(&mut store_file, "state.crdb", MAX_IMAGE_BYTES);
        let image = match image {
            Ok(image) => image,
            Err(reason) => {
                let _ = checked_close::file(store_file);
                let _ = self.confirmation.close_direct();
                return Err(failed(reason, true));
            }
        };
        if image.bytes.len() != store.bytes()
            || <[u8; 32]>::from(Sha256::digest(&image.bytes)) != store.sha256()
        {
            let _ = checked_close::file(store_file);
            let _ = self.confirmation.close_direct();
            return Err(failed("initial_handoff_store_changed", true));
        }
        let repo = self.confirmation.original.repo.clone();
        let handoff = InitializationHandoff {
            live: RefCell::new(LiveInitialization {
                confirmation: self.confirmation,
                store_file,
                store_id: image.id,
            }),
            repo,
            store,
        };
        if let Err(reason) = handoff.verify() {
            let _ = handoff.finish();
            return Err(failed(reason, true));
        }
        Ok(handoff)
    }
}
impl InitializationHandoff {
    /// The original path, retained privately throughout this handoff.
    pub fn repository(&self) -> &Path {
        &self.repo
    }
    /// Observation from the actual completed initial-store callee, never owner reconstruction.
    pub fn store_receipt(&self) -> &CreatedReceipt {
        &self.store
    }
    /// Validate original held files, directory names and completed store bytes.
    pub fn verify(&self) -> Result<(), &'static str> {
        let mut live = self
            .live
            .try_borrow_mut()
            .map_err(|_| "initial_handoff_borrowed")?;
        let LiveInitialization {
            confirmation,
            store_file,
            store_id,
        } = &mut *live;
        confirmation.verify()?;
        let material = confirmation
            .original
            .material
            .as_ref()
            .ok_or("material_missing")?;
        let image = material
            .anchor
            .read_held(store_file, "state.crdb", MAX_IMAGE_BYTES)?;
        if image.id != *store_id
            || image.bytes.len() != self.store.bytes()
            || <[u8; 32]>::from(Sha256::digest(&image.bytes)) != self.store.sha256()
        {
            return Err("initial_handoff_store_changed");
        }
        confirmation.verify()
    }
    /// Compare observations with still-held original directories, before editor mutation.
    pub fn verify_admitted_directories(&self, actual: [(i32, u64); 3]) -> Result<(), &'static str> {
        self.verify()?;
        let live = self
            .live
            .try_borrow()
            .map_err(|_| "initial_handoff_borrowed")?;
        let original = &live.confirmation.original;
        let repo = original.repo_anchor.check()?;
        let git = original.git_anchor.check()?;
        let private = original
            .material
            .as_ref()
            .ok_or("material_missing")?
            .anchor
            .check()?;
        if actual
            != [
                (repo.dev, repo.ino),
                (git.dev, git.ino),
                (private.dev, private.ino),
            ]
        {
            return Err("initial_editor_admission_mismatch");
        }
        Ok(())
    }
    /// A returned editor refusal still requires this checked original release.
    /// All independent close attempts happen even after a validation or close error.
    pub fn finish(self) -> Result<LocalInitializationReceipt, IntegrationFailure> {
        let verified = self.verify();
        let Self { live, store, .. } = self;
        let LiveInitialization {
            confirmation,
            store_file,
            ..
        } = live.into_inner();
        let public_key = confirmation.original.pin;
        let config_sha256 = confirmation.config_sha256();
        let config_state = confirmation.state;
        let proof = confirmation.proof.clone();
        let store_closed = checked_close::file(store_file);
        let confirmation_closed = confirmation.close_direct();
        verified.map_err(|reason| failed(reason, true))?;
        store_closed.map_err(|reason| failed(reason, true))?;
        let directly_owned_checked_fds =
            1 + confirmation_closed.map_err(|reason| failed(reason, true))?;
        Ok(LocalInitializationReceipt {
            public_key,
            config_sha256,
            config_state,
            proof,
            store,
            directly_owned_checked_fds,
        })
    }
}
