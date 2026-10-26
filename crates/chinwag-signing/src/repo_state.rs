use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxState {
    Pending { pid: u32 },
    Refused,
    LockHeldElsewhere,
    Unchanged,
    ChildUnknown { pid: u32 },
    StagedRejected,
    OriginalChanged,
    RenameFailed,
    InstallUnconfirmed,
    Installed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub state: TxState,
    pub expected_public: [u8; 32],
    pub repo_dev: i32,
    pub repo_ino: u64,
    pub git_dev: i32,
    pub git_ino: u64,
    pub config_dev: i32,
    pub config_ino: u64,
    pub lock_dev: i32,
    pub lock_ino: u64,
    pub snapshot_sha256: [u8; 32],
    pub staged_sha256: [u8; 32],
    pub child_pid: u32,
    pub reason: &'static str,
}

pub struct RepoSigningRequest<'a> {
    pub repo: &'a Path,
    pub private_directory: &'a Path,
    pub key_name: &'a OsStr,
    pub allowed_name: &'a OsStr,
    pub expected_public: &'a [u8; 32],
    pub principal: &'a str,
    pub scratch_name: &'a OsStr,
    pub child_timeout: Duration,
}
