//! Private fresh-fixture signing to initial-store handoff. No production CLI.
#![deny(unsafe_code)]
#[cfg(not(target_os = "macos"))]
compile_error!("Private macOS handoff only; WASM is unimplemented");
#[allow(unsafe_code)]
mod checked_close;
mod editor_handoff;
mod fs;
mod principal;
pub use editor_handoff::InitializationHandoff;
pub use principal::{PrincipalFailure, PrincipalLookup, PrincipalState, ResolvedPrincipal};

use chinwag_signing::{
    GitNamespaceProof, InitCoordinator, InitPaths, InitReceipt, PrivateDirectory, Receipt,
    SigningSecret, TxState,
};
use chinwag_snapshot_session_private::initial_create::{
    CreatedReceipt, CreationOwner, fresh_empty_store_image_for_private_fixture,
};
use fs::{Anchor, FileId, GitConfigFile, GitConfigImage};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::File,
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 65_536;
const KEY: &str = "signer";
const ALLOWED: &str = "allowed_signers";

#[derive(Debug)]
pub struct StartFailure(pub &'static str);
impl std::fmt::Display for StartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for StartFailure {}

struct Material {
    anchor: Anchor,
    directory: PrivateDirectory,
    key: File,
    key_id: FileId,
    allowed: File,
    allowed_id: FileId,
}
impl Material {
    fn capture(repo: &Path) -> Result<Self, &'static str> {
        let anchor = Anchor::open_fixture(repo, Some(fs::ChildDirectory::PrivateLeaf))?;
        let directory = PrivateDirectory::open(&repo.join(".chinwag"))
            .map_err(|_| "capture_private_directory")?;
        let key = anchor.open_existing(KEY)?;
        let key_id = anchor.identify_named(&key, KEY)?;
        let allowed = anchor.open_existing(ALLOWED)?;
        let allowed_id = anchor.identify_named(&allowed, ALLOWED)?;
        Ok(Self {
            anchor,
            directory,
            key,
            key_id,
            allowed,
            allowed_id,
        })
    }
}

/// Own this exact coordinator while pending or unknown. No receipt constructor.
#[must_use = "Keep this original signing attempt while its child is pending or unknown"]
pub struct SigningAttempt {
    coordinator: InitCoordinator,
    repo: PathBuf,
    principal: String,
    pin: [u8; 32],
    original_config_mode: u16,
    repo_anchor: Anchor,
    git_anchor: Anchor,
    queried_config: Option<(GitConfigFile, GitConfigImage)>,
    material: Option<Material>,
    capture_error: Option<&'static str>,
    _thread: PhantomData<Rc<()>>,
}
/// Confirmation failure retains the original attempt, including any owned child.
#[must_use = "Retain and observe the same original attempt; do not start another"]
pub struct ConfirmationFailure {
    original: Box<SigningAttempt>,
    reason: &'static str,
}
impl std::fmt::Debug for ConfirmationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmationFailure")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for ConfirmationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}
impl std::error::Error for ConfirmationFailure {}
impl ConfirmationFailure {
    pub fn reason(&self) -> &'static str {
        self.reason
    }
    pub fn receipt(&self) -> InitReceipt {
        self.original.receipt()
    }
    pub fn into_original(self) -> SigningAttempt {
        *self.original
    }
}

impl SigningAttempt {
    /// Fresh Root-private fixture only. No existing-key reuse or caller key path.
    pub fn start_fresh_private_fixture(repo: &Path, principal: &str) -> Result<Self, StartFailure> {
        let repo_anchor = Anchor::open_fixture(repo, None).map_err(StartFailure)?;
        let git_anchor =
            Anchor::open_fixture(repo, Some(fs::ChildDirectory::Git)).map_err(StartFailure)?;
        repo_anchor
            .require_absent(".chinwag")
            .map_err(StartFailure)?;
        // Metadata only before the original signing coordinator takes config.lock.
        let config = git_anchor.open_git_config().map_err(StartFailure)?;
        let original_config_mode = git_anchor
            .identify_git_config(&config)
            .map_err(StartFailure)?
            .mode;
        config.close().map_err(StartFailure)?;
        repo_anchor.check().map_err(StartFailure)?;
        git_anchor.check().map_err(StartFailure)?;
        let secret = SigningSecret::generate().map_err(|_| StartFailure("fixture_entropy"))?;
        let pin = secret.public_bytes();
        let private_leaf = repo.join(".chinwag");
        let paths = InitPaths {
            repo,
            private_leaf: &private_leaf,
            key_name: OsStr::new(KEY),
            allowed_name: OsStr::new(ALLOWED),
            scratch_name: OsStr::new("initial-store-signing"),
            principal,
            child_timeout: Duration::from_secs(2),
        };
        let coordinator = InitCoordinator::start_fresh(paths, &secret);
        drop(secret);
        // Never propagate a capture error by dropping a possibly active coordinator.
        let (material, capture_error) = match Material::capture(repo) {
            Ok(material) => (Some(material), None),
            Err(error) => (None, Some(error)),
        };
        Ok(Self {
            coordinator,
            repo: repo.to_owned(),
            principal: principal.into(),
            pin,
            original_config_mode,
            repo_anchor,
            git_anchor,
            queried_config: None,
            material,
            capture_error,
            _thread: PhantomData,
        })
    }
    /// Consume the one original query result; observed principal text alone
    /// cannot authorize this path or release its original configuration FD.
    pub fn start_discovered(mut resolved: ResolvedPrincipal) -> Result<Self, StartFailure> {
        resolved.preimage.verify().map_err(StartFailure)?;
        resolved
            .preimage
            .repo_anchor
            .require_absent(".chinwag")
            .map_err(StartFailure)?;
        resolved
            .preimage
            .git_anchor
            .require_absent("config.lock")
            .map_err(StartFailure)?;
        let constraint = resolved.preimage.constraint().map_err(StartFailure)?;
        let principal::ResolvedPrincipal {
            repo,
            principal,
            preimage,
            ..
        } = resolved;
        let principal::PrincipalPreimage {
            repo_anchor,
            git_anchor,
            config,
            image,
        } = preimage;
        let original_config_mode = image.id.mode;
        let secret = SigningSecret::generate().map_err(|_| StartFailure("fixture_entropy"))?;
        let pin = secret.public_bytes();
        let private_leaf = repo.join(".chinwag");
        let paths = InitPaths {
            repo: &repo,
            private_leaf: &private_leaf,
            key_name: OsStr::new(KEY),
            allowed_name: OsStr::new(ALLOWED),
            scratch_name: OsStr::new("initial-store-signing"),
            principal: &principal,
            child_timeout: Duration::from_secs(2),
        };
        let coordinator = InitCoordinator::start_fresh_bound(paths, &secret, constraint);
        drop(secret);
        let (material, capture_error) = match Material::capture(&repo) {
            Ok(material) => (Some(material), None),
            Err(error) => (None, Some(error)),
        };
        let mut attempt = Self {
            coordinator,
            repo,
            principal,
            pin,
            original_config_mode,
            repo_anchor,
            git_anchor,
            queried_config: Some((config, image)),
            material,
            capture_error,
            _thread: PhantomData,
        };
        if let Err(error) = attempt.release_admitted_query_preimage() {
            // The original signing child may be running. Keep its coordinator
            // and all remaining original resources even if a checked close fails.
            attempt.capture_error.get_or_insert(error);
        }
        Ok(attempt)
    }
    fn release_admitted_query_preimage(&mut self) -> Result<(), &'static str> {
        let (config, image) = self
            .queried_config
            .as_mut()
            .ok_or("query_preimage_missing")?;
        let InitReceipt::Config { transaction, .. } = self.coordinator.receipt() else {
            return Err("query_preimage_not_admitted");
        };
        let repo = self.repo_anchor.check()?;
        let git = self.git_anchor.check()?;
        let hash: [u8; 32] = Sha256::digest(&image.bytes).into();
        if !matches!(transaction.state, TxState::Pending { .. })
            || transaction.child_pid == 0
            || (transaction.repo_dev, transaction.repo_ino) != (repo.dev, repo.ino)
            || (transaction.git_dev, transaction.git_ino) != (git.dev, git.ino)
            || (transaction.config_dev, transaction.config_ino) != (image.id.dev, image.id.ino)
            || transaction.snapshot_sha256 != hash
            || self.git_anchor.read_git_config(config)? != *image
        {
            return Err("query_preimage_not_admitted");
        }
        let (config, _) = self.queried_config.take().ok_or("query_preimage_missing")?;
        config.close()
    }
    pub fn receipt(&self) -> InitReceipt {
        self.coordinator.receipt()
    }
    /// Observes the same retained coordinator; grants no authority.
    pub fn reason(&self) -> &'static str {
        self.coordinator.reason()
    }
    pub fn poll(&mut self, now: Instant) -> InitReceipt {
        self.coordinator.poll(now)
    }
    pub fn observe_child(&mut self) -> std::io::Result<Option<String>> {
        self.coordinator
            .observe_child()
            .map(|exit| exit.map(|value| format!("{value:?}")))
    }
    fn terminal(&self) -> Result<Receipt, &'static str> {
        let transaction = match self.coordinator.receipt() {
            InitReceipt::Config { transaction, .. } => transaction,
            _ => return Err("original_material_not_confirmed"),
        };
        match transaction.state {
            TxState::Installed | TxState::Unchanged => {}
            TxState::Pending { .. } => return Err("original_child_pending"),
            TxState::ChildUnknown { .. } => return Err("original_child_unknown"),
            _ => return Err("original_config_not_confirmed"),
        }
        let repo = self.repo_anchor.check()?;
        let git = self.git_anchor.check()?;
        if transaction.expected_public != self.pin
            || (transaction.repo_dev, transaction.repo_ino) != (repo.dev, repo.ino)
            || (transaction.git_dev, transaction.git_ino) != (git.dev, git.ino)
        {
            return Err("original_signing_identity_changed");
        }
        Ok(transaction)
    }
    fn verify_material(&mut self) -> Result<GitNamespaceProof, &'static str> {
        self.terminal()?;
        if let Some(error) = self.capture_error {
            return Err(error);
        }
        let material = self.material.as_mut().ok_or("material_missing")?;
        let id = material.anchor.check()?;
        if !material
            .directory
            .matches_directory_identity(id.dev, id.ino)
            .map_err(|_| "private_directory_stat")?
        {
            return Err("private_directory_changed");
        }
        if material.anchor.identify_named(&material.key, KEY)? != material.key_id {
            return Err("signer_metadata_changed");
        }
        let allowed =
            material
                .anchor
                .read_held(&mut material.allowed, ALLOWED, MAX_CONFIG_BYTES)?;
        if allowed.id != material.allowed_id {
            return Err("allowed_metadata_changed");
        }
        let secret = material
            .directory
            .read_existing(OsStr::new(KEY), &self.pin)
            .map_err(|_| "original_fresh_signer_read")?;
        let proof = secret
            .prove_git_namespace()
            .map_err(|_| "original_signature_proof")?;
        drop(secret);
        let expected = format!(
            "{} namespaces=\"git\" {}\n",
            self.principal, proof.public_openssh
        );
        if proof.public != self.pin
            || proof.namespace != "git"
            || allowed.bytes != expected.as_bytes()
            || material.anchor.identify_named(&material.key, KEY)? != material.key_id
        {
            return Err("original_signing_material_changed");
        }
        material.anchor.check()?;
        self.terminal()?;
        Ok(proof)
    }
    fn confirm_inner(
        &mut self,
    ) -> Result<(GitConfigFile, GitConfigImage, GitNamespaceProof, TxState), &'static str> {
        let transaction = self.terminal()?;
        let proof = self.verify_material()?;
        let mut config = self.git_anchor.open_git_config()?;
        let image = self.git_anchor.read_git_config(&mut config)?;
        let (dev, ino, expected) = if transaction.state == TxState::Installed {
            (
                transaction.lock_dev,
                transaction.lock_ino,
                transaction.staged_sha256,
            )
        } else {
            (
                transaction.config_dev,
                transaction.config_ino,
                transaction.snapshot_sha256,
            )
        };
        let hash: [u8; 32] = Sha256::digest(&image.bytes).into();
        if (image.id.dev, image.id.ino) != (dev, ino)
            || hash != expected
            || image.id.mode != self.original_config_mode
        {
            return Err("original_confirmed_config_changed");
        }
        self.verify_material()?;
        Ok((config, image, proof, transaction.state))
    }
    pub fn confirm(mut self) -> Result<ConfirmedSigning, ConfirmationFailure> {
        match self.confirm_inner() {
            Ok((config, image, proof, state)) => Ok(ConfirmedSigning {
                original: self,
                config,
                image,
                proof,
                state,
            }),
            Err(reason) => Err(ConfirmationFailure {
                original: Box::new(self),
                reason,
            }),
        }
    }
    fn close_direct(self) -> Result<usize, &'static str> {
        let Self {
            coordinator,
            repo_anchor,
            git_anchor,
            queried_config,
            material,
            ..
        } = self;
        // Original accepted APIs retain their existing Drop semantics. These
        // drops are not counted as successful checked FD closes.
        drop(coordinator);
        let material = match material {
            Some(Material {
                anchor,
                directory,
                key,
                allowed,
                ..
            }) => {
                drop(directory);
                let key = checked_close::file(key);
                let allowed = checked_close::file(allowed);
                let anchor = anchor.close_all();
                key.and(allowed)
                    .and(anchor)
                    .map(|directories| 2 + directories)
            }
            None => Err("material_missing"),
        };
        // Attempt every independent held close before returning the first error.
        let git = git_anchor.close_all();
        let repo = repo_anchor.close_all();
        let query = match queried_config {
            Some((config, _)) => config.close().map(|()| 1),
            None => Ok(0),
        };
        Ok(material? + git? + repo? + query?)
    }
}

/// Original confirmed signing, bound to one private repo path and live anchors.
#[must_use = "Consume the original confirmation once; presence never remints it"]
pub struct ConfirmedSigning {
    original: SigningAttempt,
    config: GitConfigFile,
    image: GitConfigImage,
    proof: GitNamespaceProof,
    state: TxState,
}
#[derive(Debug)]
pub struct IntegrationFailure {
    pub reason: String,
    pub original_store_callee_completed: bool,
}
impl std::fmt::Display for IntegrationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}
impl std::error::Error for IntegrationFailure {}
fn failed(reason: impl ToString, completed: bool) -> IntegrationFailure {
    IntegrationFailure {
        reason: reason.to_string(),
        original_store_callee_completed: completed,
    }
}
impl ConfirmedSigning {
    pub fn public_key(&self) -> [u8; 32] {
        self.original.pin
    }
    pub fn proof(&self) -> &GitNamespaceProof {
        &self.proof
    }
    pub fn config_state(&self) -> TxState {
        self.state
    }
    pub fn config_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.image.bytes).into()
    }
    fn verify(&mut self) -> Result<(), &'static str> {
        if self.original.terminal()?.state != self.state {
            return Err("confirmation_state_changed");
        }
        self.original.verify_material()?;
        if self.original.git_anchor.read_git_config(&mut self.config)? != self.image {
            return Err("confirmed_config_binding_changed");
        }
        Ok(())
    }
    /// The original repo path is retained privately; no caller destination argument.
    pub fn begin_initial(mut self) -> Result<IntegrationOwner, IntegrationFailure> {
        self.verify().map_err(|e| failed(e, false))?;
        let image = fresh_empty_store_image_for_private_fixture().map_err(|e| failed(e, false))?;
        self.verify().map_err(|e| failed(e, false))?;
        let owner = image
            .begin_private_fixture(&self.original.repo)
            .map_err(|e| failed(e, false))?;
        self.verify().map_err(|e| failed(e, false))?;
        Ok(IntegrationOwner {
            owner,
            confirmation: self,
        })
    }
    fn close_direct(self) -> Result<usize, &'static str> {
        let config = self.config.close();
        let original = self.original.close_direct();
        config?;
        Ok(1 + original?)
    }
}
#[must_use = "Finish this original handoff or retain its empty target and marker"]
pub struct IntegrationOwner {
    owner: CreationOwner,
    confirmation: ConfirmedSigning,
}
/// Only local signing plus initial empty store. No full init, hosted or G-v claim.
#[derive(Debug)]
pub struct LocalInitializationReceipt {
    public_key: [u8; 32],
    config_sha256: [u8; 32],
    config_state: TxState,
    proof: GitNamespaceProof,
    store: CreatedReceipt,
    directly_owned_checked_fds: usize,
}
impl LocalInitializationReceipt {
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    pub fn config_sha256(&self) -> [u8; 32] {
        self.config_sha256
    }
    pub fn config_state(&self) -> TxState {
        self.config_state
    }
    pub fn proof(&self) -> &GitNamespaceProof {
        &self.proof
    }
    pub fn store(&self) -> &CreatedReceipt {
        &self.store
    }
    pub fn directly_owned_checked_fds(&self) -> usize {
        self.directly_owned_checked_fds
    }
}
impl IntegrationOwner {
    pub fn finish(self) -> Result<LocalInitializationReceipt, IntegrationFailure> {
        self.finish_inner(false)
    }
    #[cfg(feature = "private-probe")]
    pub fn refuse_after_store_for_private_probe(
        self,
    ) -> Result<LocalInitializationReceipt, IntegrationFailure> {
        self.finish_inner(true)
    }
    fn finish_inner(
        mut self,
        refuse_after_store: bool,
    ) -> Result<LocalInitializationReceipt, IntegrationFailure> {
        self.confirmation.verify().map_err(|e| failed(e, false))?;
        let store = self.owner.finish().map_err(|e| failed(e, false))?;
        if refuse_after_store {
            return Err(failed(
                "controlled_after_store_callee_before_handoff_receipt",
                true,
            ));
        }
        self.confirmation.verify().map_err(|e| failed(e, true))?;
        let public_key = self.confirmation.original.pin;
        let config_sha256 = Sha256::digest(&self.confirmation.image.bytes).into();
        let config_state = self.confirmation.state;
        let proof = self.confirmation.proof.clone();
        let directly_owned_checked_fds = self
            .confirmation
            .close_direct()
            .map_err(|e| failed(e, true))?;
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

#[cfg(test)]
#[path = "preimage_tests.rs"]
mod preimage_tests;
