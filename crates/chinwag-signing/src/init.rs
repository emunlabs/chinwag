use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, Instant};

use chinwag_host_process::owned_spawn::Exit;

use crate::{
    ConfigPreimageConstraint, ConfigTransaction, Error, PrivateDirectory, Receipt,
    RepoSigningRequest, SigningSecret,
};

pub struct InitPaths<'a> {
    pub repo: &'a Path,
    pub private_leaf: &'a Path,
    pub key_name: &'a OsStr,
    pub allowed_name: &'a OsStr,
    pub scratch_name: &'a OsStr,
    pub principal: &'a str,
    pub child_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitFailure {
    Principal,
    Names,
    Paths,
    Timeout,
    PublicKey,
    Storage(Error),
}

impl InitFailure {
    fn code(self) -> &'static str {
        match self {
            Self::Principal => "init_principal",
            Self::Names => "init_names",
            Self::Paths => "init_paths",
            Self::Timeout => "init_timeout",
            Self::PublicKey => "init_public_key",
            Self::Storage(error) => error.code(),
        }
    }
}

/// The last confirmed creation step, or the next step whose creation is uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitProgress {
    LeafUnconfirmed,
    LeafConfirmed,
    KeyUnconfirmed,
    KeyConfirmed,
    AllowedUnconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitMaterial {
    FreshCreated,
    /// The caller's pin matched the existing key. Config still validates the allowed line.
    ExistingKeyConfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitReceipt {
    Refused {
        expected_public: [u8; 32],
        failure: InitFailure,
    },
    MaterialIncomplete {
        expected_public: [u8; 32],
        progress: InitProgress,
        failure: InitFailure,
    },
    Config {
        material: InitMaterial,
        transaction: Receipt,
    },
}

enum Inner {
    Refused {
        expected_public: [u8; 32],
        failure: InitFailure,
    },
    Incomplete {
        expected_public: [u8; 32],
        progress: InitProgress,
        error: Error,
    },
    Config {
        material: InitMaterial,
        transaction: Box<ConfigTransaction>,
    },
}

#[must_use = "retain while a config child is pending or unknown; poll the same coordinator"]
pub struct InitCoordinator {
    inner: Inner,
}

impl InitCoordinator {
    pub fn start_fresh(paths: InitPaths<'_>, secret: &SigningSecret) -> Self {
        Self::fresh_inner(
            paths,
            secret,
            #[cfg(test)]
            crate::repo::TestHooks::default(),
        )
    }

    pub fn start_fresh_bound(
        paths: InitPaths<'_>,
        secret: &SigningSecret,
        constraint: ConfigPreimageConstraint,
    ) -> Self {
        Self::fresh_constrained_inner(
            paths,
            secret,
            Some(constraint),
            #[cfg(test)]
            crate::repo::TestHooks::default(),
        )
    }

    fn fresh_inner(
        paths: InitPaths<'_>,
        secret: &SigningSecret,
        #[cfg(test)] hooks: crate::repo::TestHooks,
    ) -> Self {
        Self::fresh_constrained_inner(
            paths,
            secret,
            None,
            #[cfg(test)]
            hooks,
        )
    }

    fn fresh_constrained_inner(
        paths: InitPaths<'_>,
        secret: &SigningSecret,
        constraint: Option<ConfigPreimageConstraint>,
        #[cfg(test)] hooks: crate::repo::TestHooks,
    ) -> Self {
        let pin = secret.public_bytes();
        if let Err(failure) = preflight(&paths) {
            return Self::refused(pin, failure);
        }
        if crate::allowed_signers_line(paths.principal, secret).is_err() {
            return Self::refused(pin, InitFailure::PublicKey);
        }
        let directory = match PrivateDirectory::create_new(paths.private_leaf) {
            Ok(directory) => directory,
            Err(Error::CreatedButUnconfirmed) => {
                return Self::incomplete(
                    pin,
                    InitProgress::LeafUnconfirmed,
                    Error::CreatedButUnconfirmed,
                );
            }
            Err(error) => return Self::refused(pin, InitFailure::Storage(error)),
        };
        Self::complete_fresh_bound(
            directory,
            paths,
            secret,
            pin,
            constraint,
            #[cfg(test)]
            hooks,
        )
    }

    #[cfg(test)]
    fn complete_fresh(
        directory: PrivateDirectory,
        paths: InitPaths<'_>,
        secret: &SigningSecret,
        pin: [u8; 32],
        hooks: crate::repo::TestHooks,
    ) -> Self {
        Self::complete_fresh_bound(directory, paths, secret, pin, None, hooks)
    }

    fn complete_fresh_bound(
        directory: PrivateDirectory,
        paths: InitPaths<'_>,
        secret: &SigningSecret,
        pin: [u8; 32],
        constraint: Option<ConfigPreimageConstraint>,
        #[cfg(test)] hooks: crate::repo::TestHooks,
    ) -> Self {
        if let Err(error) = directory.write_new(paths.key_name, secret) {
            let progress = if error == Error::CreatedButUnconfirmed {
                InitProgress::KeyUnconfirmed
            } else {
                InitProgress::LeafConfirmed
            };
            return Self::incomplete(pin, progress, error);
        }
        if let Err(error) =
            directory.write_new_allowed_signers(paths.allowed_name, paths.principal, secret)
        {
            let progress = if error == Error::CreatedButUnconfirmed {
                InitProgress::AllowedUnconfirmed
            } else {
                InitProgress::KeyConfirmed
            };
            return Self::incomplete(pin, progress, error);
        }
        Self::delegate(
            paths,
            pin,
            InitMaterial::FreshCreated,
            constraint,
            #[cfg(test)]
            hooks,
        )
    }

    pub fn start_reuse(paths: InitPaths<'_>, expected_public: &[u8; 32]) -> Self {
        let pin = *expected_public;
        if let Err(failure) = preflight(&paths) {
            return Self::refused(pin, failure);
        }
        let loaded = PrivateDirectory::open(paths.private_leaf)
            .and_then(|directory| directory.read_existing(paths.key_name, &pin));
        let secret = match loaded {
            Ok(secret) => secret,
            Err(error) => return Self::refused(pin, InitFailure::Storage(error)),
        };
        if crate::allowed_signers_line(paths.principal, &secret).is_err() {
            return Self::refused(pin, InitFailure::PublicKey);
        }
        drop(secret);
        Self::delegate(
            paths,
            pin,
            InitMaterial::ExistingKeyConfirmed,
            None,
            #[cfg(test)]
            crate::repo::TestHooks::default(),
        )
    }

    fn delegate(
        paths: InitPaths<'_>,
        pin: [u8; 32],
        material: InitMaterial,
        constraint: Option<ConfigPreimageConstraint>,
        #[cfg(test)] hooks: crate::repo::TestHooks,
    ) -> Self {
        let request = RepoSigningRequest {
            repo: paths.repo,
            private_directory: paths.private_leaf,
            key_name: paths.key_name,
            allowed_name: paths.allowed_name,
            expected_public: &pin,
            principal: paths.principal,
            scratch_name: paths.scratch_name,
            child_timeout: paths.child_timeout,
        };
        let transaction = match constraint {
            Some(constraint) => ConfigTransaction::begin_bound(request, constraint),
            None => {
                #[cfg(test)]
                {
                    ConfigTransaction::begin_with(request, hooks)
                }
                #[cfg(not(test))]
                {
                    ConfigTransaction::begin(request)
                }
            }
        };
        Self {
            inner: Inner::Config {
                material,
                transaction: Box::new(transaction),
            },
        }
    }

    fn refused(expected_public: [u8; 32], failure: InitFailure) -> Self {
        Self {
            inner: Inner::Refused {
                expected_public,
                failure,
            },
        }
    }

    fn incomplete(expected_public: [u8; 32], progress: InitProgress, error: Error) -> Self {
        Self {
            inner: Inner::Incomplete {
                expected_public,
                progress,
                error,
            },
        }
    }

    pub fn receipt(&self) -> InitReceipt {
        match &self.inner {
            Inner::Refused {
                expected_public,
                failure,
            } => InitReceipt::Refused {
                expected_public: *expected_public,
                failure: *failure,
            },
            Inner::Incomplete {
                expected_public,
                progress,
                error,
            } => InitReceipt::MaterialIncomplete {
                expected_public: *expected_public,
                progress: *progress,
                failure: InitFailure::Storage(*error),
            },
            Inner::Config {
                material,
                transaction,
            } => InitReceipt::Config {
                material: *material,
                transaction: transaction.receipt(),
            },
        }
    }

    pub fn reason(&self) -> &'static str {
        match &self.inner {
            Inner::Refused { failure, .. } => failure.code(),
            Inner::Incomplete { error, .. } => error.code(),
            Inner::Config { transaction, .. } => transaction.reason(),
        }
    }

    pub fn poll(&mut self, now: Instant) -> InitReceipt {
        if let Inner::Config { transaction, .. } = &mut self.inner {
            transaction.poll(now);
        }
        self.receipt()
    }

    /// Observe only the same retained unknown child; never advance, install, or clean up.
    pub fn observe_child(&mut self) -> std::io::Result<Option<Exit>> {
        match &mut self.inner {
            Inner::Config { transaction, .. } => transaction.observe_child(),
            Inner::Refused { .. } | Inner::Incomplete { .. } => {
                Err(std::io::ErrorKind::InvalidInput.into())
            }
        }
    }
}

fn preflight(paths: &InitPaths<'_>) -> Result<(), InitFailure> {
    crate::validate_principal(paths.principal).map_err(|_| InitFailure::Principal)?;
    if paths.child_timeout.is_zero() || paths.child_timeout > Duration::from_secs(60) {
        return Err(InitFailure::Timeout);
    }
    for name in [paths.key_name, paths.allowed_name, paths.scratch_name] {
        crate::repo::validate_component(name).map_err(|_| InitFailure::Names)?;
    }
    if paths.key_name == paths.allowed_name
        || paths.key_name == paths.scratch_name
        || paths.allowed_name == paths.scratch_name
    {
        return Err(InitFailure::Names);
    }
    crate::repo::path_text(paths.repo).map_err(|_| InitFailure::Paths)?;
    crate::repo::path_text(paths.private_leaf).map_err(|_| InitFailure::Paths)?;
    Ok(())
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;
