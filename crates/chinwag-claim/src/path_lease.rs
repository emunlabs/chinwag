// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Durable repository/path leases independent of the legacy fixed PR claim policy.
//!
//! A separate, stable lock inode serializes transactions. Rows survive process
//! exits, so a crash never silently grants overlapping writes to a peer.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum PathLeaseError {
    Io(std::io::Error),
    Malformed(String),
    OverlappingClaim(String),
    MissingClaim,
    ReceiptMismatch,
    Quarantined,
}
impl fmt::Display for PathLeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "lease I/O: {e}"),
            Self::Malformed(e) => write!(f, "invalid path lease: {e}"),
            Self::OverlappingClaim(id) => write!(f, "OverlappingClaim: {id}"),
            Self::MissingClaim => f.write_str("lease missing"),
            Self::ReceiptMismatch => f.write_str("lease receipt mismatch"),
            Self::Quarantined => f.write_str("lease quarantined"),
        }
    }
}
impl std::error::Error for PathLeaseError {}
impl From<std::io::Error> for PathLeaseError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
type Result<T> = std::result::Result<T, PathLeaseError>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathLeaseRequest {
    pub claim_id: String,
    pub actor: String,
    pub repository: PathBuf,
    pub roots: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathLeaseRecord {
    pub request: PathLeaseRequest,
    pub state: PathLeaseState,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathLeaseState {
    Active,
    Released,
    Quarantined,
}

pub struct PathLeaseStore {
    root: PathBuf,
}
impl PathLeaseStore {
    pub fn open(root: &Path) -> Result<Self> {
        reject_symlink_components(root)?;
        std::fs::create_dir_all(root)?;
        reject_symlink_components(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            root: root.canonicalize()?,
        })
    }
    fn locked(&self) -> Result<File> {
        let path = self.root.join("path-leases.lock");
        reject_if_symlink(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        file.lock()?;
        Ok(file)
    }
    fn read(&self) -> Result<BTreeMap<String, PathLeaseRecord>> {
        let path = self.root.join("path-leases.v1.json");
        reject_if_symlink(&path)?;
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| PathLeaseError::Malformed(e.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e.into()),
        }
    }
    fn write(&self, rows: &BTreeMap<String, PathLeaseRecord>) -> Result<()> {
        let path = self.root.join("path-leases.v1.json");
        let temp = self.root.join("path-leases.v1.pending");
        // A pending file can only be left by an interrupted prior transaction;
        // replacing it under the stable lock does not release any reservation.
        reject_if_symlink(&temp)?;
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(
            &serde_json::to_vec(rows).map_err(|e| PathLeaseError::Malformed(e.to_string()))?,
        )?;
        file.sync_all()?;
        std::fs::rename(temp, path)?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    pub fn acquire(&self, request: &PathLeaseRequest) -> Result<PathLeaseRecord> {
        validate_request(request)?;
        let _lock = self.locked()?;
        let mut rows = self.read()?;
        if let Some(prior) = rows.get(&request.claim_id) {
            if &prior.request == request && prior.state == PathLeaseState::Active {
                return Ok(prior.clone());
            }
            return Err(PathLeaseError::ReceiptMismatch);
        }
        for prior in rows
            .values()
            .filter(|r| r.state != PathLeaseState::Released)
        {
            validate_request(&prior.request)?;
            if prior.request.repository == request.repository
                && request
                    .roots
                    .iter()
                    .any(|a| prior.request.roots.iter().any(|b| paths_overlap(a, b)))
            {
                return Err(PathLeaseError::OverlappingClaim(
                    prior.request.claim_id.clone(),
                ));
            }
        }
        let row = PathLeaseRecord {
            request: request.clone(),
            state: PathLeaseState::Active,
        };
        rows.insert(request.claim_id.clone(), row.clone());
        self.write(&rows)?;
        Ok(row)
    }
    pub fn verify(&self, receipt: &PathLeaseRecord) -> Result<()> {
        let _lock = self.locked()?;
        let rows = self.read()?;
        let stored = rows
            .get(&receipt.request.claim_id)
            .ok_or(PathLeaseError::MissingClaim)?;
        if stored != receipt {
            return Err(PathLeaseError::ReceiptMismatch);
        }
        match stored.state {
            PathLeaseState::Active => Ok(()),
            PathLeaseState::Quarantined => Err(PathLeaseError::Quarantined),
            PathLeaseState::Released => Err(PathLeaseError::MissingClaim),
        }
    }
    pub fn release(&self, receipt: &PathLeaseRecord, quarantine: bool) -> Result<()> {
        let _lock = self.locked()?;
        let mut rows = self.read()?;
        let stored = rows
            .get_mut(&receipt.request.claim_id)
            .ok_or(PathLeaseError::MissingClaim)?;
        if stored != receipt || stored.state != PathLeaseState::Active {
            return Err(PathLeaseError::ReceiptMismatch);
        }
        stored.state = if quarantine {
            PathLeaseState::Quarantined
        } else {
            PathLeaseState::Released
        };
        self.write(&rows)
    }
    pub fn lookup(&self, id: &str) -> Result<PathLeaseRecord> {
        let _lock = self.locked()?;
        self.read()?
            .get(id)
            .cloned()
            .ok_or(PathLeaseError::MissingClaim)
    }
}

pub fn validate_root(root: &str) -> Result<()> {
    let root = root.strip_suffix("/**").unwrap_or(root);
    if root.contains(['*', '?', '[', ']']) {
        return Err(PathLeaseError::Malformed(
            "only a trailing /** is supported".into(),
        ));
    }
    // Reuse the claim contract's traversal, protected-directory and ASCII rules.
    let mut policy = crate::ClaimPolicy::default();
    policy
        .allow(crate::Pr::Pr01, root)
        .map_err(|e| PathLeaseError::Malformed(e.to_string()))
}
pub fn paths_overlap(a: &str, b: &str) -> bool {
    let a = a.strip_suffix("/**").unwrap_or(a).to_ascii_lowercase();
    let b = b.strip_suffix("/**").unwrap_or(b).to_ascii_lowercase();
    a == b
        || a.strip_prefix(&b)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || b.strip_prefix(&a)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
fn validate_request(request: &PathLeaseRequest) -> Result<()> {
    if request.claim_id.is_empty()
        || request.claim_id.len() > 128
        || !request
            .claim_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || request.actor.is_empty()
        || request.actor.chars().any(char::is_control)
    {
        return Err(PathLeaseError::Malformed("invalid identity".into()));
    }
    reject_symlink_components(&request.repository)?;
    if request.repository.canonicalize()? != request.repository {
        return Err(PathLeaseError::Malformed(
            "repository must be canonical".into(),
        ));
    }
    for candidate in request.repository.ancestors() {
        if candidate.join(".git").exists() || candidate.join(".jj").exists() {
            if candidate != request.repository {
                return Err(PathLeaseError::Malformed(
                    "lease repository must be its repository root".into(),
                ));
            }
            break;
        }
    }
    for root in &request.roots {
        validate_root(root)?;
    }
    Ok(())
}
fn reject_if_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            Err(PathLeaseError::Malformed("symlink lease path".into()))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        reject_if_symlink(&current)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlap_is_path_bounded_and_case_insensitive() {
        assert!(paths_overlap("src/**", "src/lib.rs"));
        assert!(paths_overlap("Src/lib.rs", "src/**"));
        assert!(!paths_overlap("src/**", "src-other/file"));
    }
}
