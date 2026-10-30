//! Explicit owner-local HTTP inbox enrollment and private capability export.
//! No live client configuration, account, model or application is consulted.

use chinwag_bus_client::BusClient;
use chinwag_bus_mcp::{
    InboxServer,
    http::{HttpCapability, HttpInbox, HttpInboxConfig},
};
use chinwag_connector_registry::{
    BindingView, ConnectionId, Destination, NativeRoom, OwnerLocalDecision,
};
use chinwag_connectors::{BuiltinConnector, ConnectorHost};
use rustix::fs::{AtFlags, Mode, OFlags, fchmod, open, openat, statat};
use std::{
    ffi::OsString,
    fs::File,
    io::Write,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const LEASE: Duration = Duration::from_secs(900);
const CLEANUP_BUDGET: Duration = Duration::from_secs(30);
const MAX_DOCUMENT: usize = 4096;

/// Pure syntax validation shared by CLI preflight and held output publication.
/// Filesystem ownership and existing-node checks happen only in the holder.
pub fn validate_capability_path(path: &Path) -> Result<()> {
    let text = path.to_str().ok_or(McpOwnerError::InvalidCapabilityPath)?;
    let normalized: PathBuf = path.components().collect();
    if !path.is_absolute()
        || normalized.as_os_str() != path.as_os_str()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || path.file_name().is_none_or(|name| name.len() > 240)
    {
        return Err(McpOwnerError::InvalidCapabilityPath);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum McpOwnerError {
    #[error("invalid loopback inbox endpoint")]
    InvalidEndpoint,
    #[error(
        "capability file requires a normalized absolute new path in an existing owned directory"
    )]
    InvalidCapabilityPath,
    #[error("capability file already exists; it was not read, changed or reused")]
    CapabilityFileExists,
    #[error("strong randomness is unavailable")]
    RandomUnavailable,
    #[error("owner-local HTTP inbox admission is unavailable")]
    AdmissionUnavailable,
    #[error("private capability export failed; a new file may exist and must not be reused")]
    CapabilityStorage,
    #[error("owner-local HTTP inbox transport is unavailable")]
    TransportUnavailable,
    #[error("HTTP inbox cleanup completion was not observed")]
    CleanupUnobserved,
}

pub type Result<T> = std::result::Result<T, McpOwnerError>;

/// Holds one explicitly admitted transport. Neither this holder nor its errors
/// implement token serialization/debugging. The only token export is the new
/// owner-declared private file; status comes from the held transport snapshot.
pub struct HttpMcpOwner {
    transport: Arc<HttpInbox>,
    enrollment: Enrollment,
}

impl HttpMcpOwner {
    pub async fn start(
        endpoint: &str,
        host: Arc<Mutex<ConnectorHost>>,
        capability_file: &Path,
    ) -> Result<Self> {
        if endpoint.is_empty()
            || endpoint.len() > 256
            || endpoint.trim() != endpoint
            || endpoint.chars().any(char::is_control)
        {
            return Err(McpOwnerError::InvalidEndpoint);
        }
        let endpoint = endpoint.to_owned();
        let output = capability_file.to_owned();
        let (endpoint, file) = tokio::task::spawn_blocking(move || {
            let file = CapabilityOutput::prepare(&output)?;
            // Construct and drop reqwest's blocking client on this worker.
            // URL validation does not perform a bus request.
            let client = BusClient::new(&endpoint).map_err(|_| McpOwnerError::InvalidEndpoint)?;
            Ok::<_, McpOwnerError>((client.normalized_endpoint().to_owned(), file))
        })
        .await
        .map_err(|_| McpOwnerError::InvalidEndpoint)??;
        let mut secret = [0u8; 32];
        let mut connection_nonce = [0u8; 16];
        getrandom::fill(&mut secret).map_err(|_| McpOwnerError::RandomUnavailable)?;
        getrandom::fill(&mut connection_nonce).map_err(|_| McpOwnerError::RandomUnavailable)?;
        let capability = HttpCapability::from_bytes(secret);
        let connection = ConnectionId::new(format!("owner-http-{}", hex(&connection_nonce)))
            .map_err(|_| McpOwnerError::AdmissionUnavailable)?;
        let destination = Destination::new(&endpoint, NativeRoom::Mgmt)
            .map_err(|_| McpOwnerError::AdmissionUnavailable)?;
        let decision = OwnerLocalDecision::new_http_capability(
            "explicit-owner-local-http-enrollment",
            connection.clone(),
            destination,
        )
        .map_err(|_| McpOwnerError::AdmissionUnavailable)?;
        let binding = {
            // Startup never waits on another dispatch's synchronous reader.
            let mut host = host
                .try_lock()
                .map_err(|_| McpOwnerError::AdmissionUnavailable)?;
            host.set_enabled(BuiltinConnector::NativeInbox, true)
                .map_err(|_| McpOwnerError::AdmissionUnavailable)?;
            host.admit_local_inbox(decision, &connection, LEASE, Instant::now())
                .map_err(|_| McpOwnerError::AdmissionUnavailable)?
        };
        let enrollment = Enrollment(Arc::new(GrantCleanup {
            host: host.clone(),
            binding: binding.clone(),
            runtime: tokio::runtime::Handle::current(),
            observed: AtomicBool::new(false),
        }));
        let attempt = async {
            let document = owner_document(&endpoint, capability.token())?;
            tokio::task::spawn_blocking(move || file.write_new(&document, || {}))
                .await
                .map_err(|_| McpOwnerError::CapabilityStorage)??;
            let authority = endpoint
                .strip_prefix("http://")
                .and_then(|origin| origin.strip_suffix('/'))
                .ok_or(McpOwnerError::InvalidEndpoint)?;
            let owner = InboxServer::with_binding(endpoint.clone(), host, binding)
                .await
                .map_err(|_| McpOwnerError::TransportUnavailable)?;
            match HttpInbox::new(
                owner.clone(),
                capability,
                HttpInboxConfig {
                    allowed_authority: authority.to_owned(),
                },
            ) {
                Ok(transport) => Ok(Arc::new(transport)),
                Err(_) => {
                    owner.request_close();
                    let _ = owner.shutdown().await;
                    Err(McpOwnerError::TransportUnavailable)
                }
            }
        }
        .await;
        match attempt {
            Ok(transport) => Ok(Self {
                transport,
                enrollment,
            }),
            Err(error) => {
                enrollment.0.revoke().await?;
                Err(error)
            }
        }
    }

    pub fn transport(&self) -> Arc<HttpInbox> {
        self.transport.clone()
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.transport.request_close();
        let drained = self.transport.shutdown().await;
        let revoked = self.enrollment.0.revoke().await;
        drained.map_err(|_| McpOwnerError::CleanupUnobserved)?;
        revoked
    }
}

impl Drop for HttpMcpOwner {
    fn drop(&mut self) {
        // Immediate transport fence only. Actual drain/revocation is observed
        // by shutdown, never claimed merely because cleanup was scheduled.
        self.transport.request_close();
    }
}

struct GrantCleanup {
    host: Arc<Mutex<ConnectorHost>>,
    binding: BindingView,
    runtime: tokio::runtime::Handle,
    observed: AtomicBool,
}

impl GrantCleanup {
    fn try_revoke(&self) -> Result<bool> {
        if self.observed.load(Ordering::Acquire) {
            return Ok(true);
        }
        match self.host.try_lock() {
            Ok(mut host) => {
                host.revoke(self.binding.grant)
                    .map_err(|_| McpOwnerError::CleanupUnobserved)?;
                self.observed.store(true, Ordering::Release);
                Ok(true)
            }
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Poisoned(_)) => Err(McpOwnerError::CleanupUnobserved),
        }
    }

    async fn revoke(&self) -> Result<()> {
        let deadline = Instant::now() + CLEANUP_BUDGET;
        loop {
            if self.try_revoke()? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(McpOwnerError::CleanupUnobserved);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

struct Enrollment(Arc<GrantCleanup>);

impl Drop for Enrollment {
    fn drop(&mut self) {
        if matches!(self.0.try_revoke(), Ok(true)) {
            return;
        }
        let cleanup = self.0.clone();
        let _cleanup = self.0.runtime.spawn(async move {
            let _ = cleanup.revoke().await;
        });
    }
}

fn owner_document(endpoint: &str, token: &str) -> Result<Vec<u8>> {
    let mut document = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "chinwag-owner-http-mcp/v1",
        "url": format!("{}api/mcp", endpoint),
        "headers": {"Authorization": format!("Bearer {token}")},
        "room": "#mgmt",
        "lease_seconds": 900
    }))
    .map_err(|_| McpOwnerError::CapabilityStorage)?;
    document.push(b'\n');
    if document.len() > MAX_DOCUMENT {
        return Err(McpOwnerError::CapabilityStorage);
    }
    Ok(document)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct CapabilityOutput {
    parent: File,
    parent_path: PathBuf,
    name: OsString,
}

impl CapabilityOutput {
    fn prepare(path: &Path) -> Result<Self> {
        validate_capability_path(path)?;
        let parent_path = path
            .parent()
            .ok_or(McpOwnerError::InvalidCapabilityPath)?
            .to_owned();
        let name = path
            .file_name()
            .filter(|name| name.len() <= 240)
            .ok_or(McpOwnerError::InvalidCapabilityPath)?
            .to_owned();
        let parent = owned_parent(&parent_path)?;
        match statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(McpOwnerError::CapabilityFileExists),
            Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err(McpOwnerError::CapabilityStorage),
        }
        Ok(Self {
            parent,
            parent_path,
            name,
        })
    }

    fn write_new(&self, document: &[u8], before_verify: impl FnOnce()) -> Result<()> {
        if document.is_empty() || document.len() > MAX_DOCUMENT {
            return Err(McpOwnerError::CapabilityStorage);
        }
        let mut file: File = openat(
            &self.parent,
            &self.name,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                McpOwnerError::CapabilityFileExists
            } else {
                McpOwnerError::CapabilityStorage
            }
        })?
        .into();
        fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|_| McpOwnerError::CapabilityStorage)?;
        file.write_all(document)
            .map_err(|_| McpOwnerError::CapabilityStorage)?;
        file.sync_all()
            .map_err(|_| McpOwnerError::CapabilityStorage)?;
        before_verify();
        let before = file
            .metadata()
            .map_err(|_| McpOwnerError::CapabilityStorage)?;
        if !before.is_file()
            || before.uid() != rustix::process::geteuid().as_raw()
            || before.mode() & 0o777 != 0o600
            || before.nlink() != 1
            || before.len() != document.len() as u64
        {
            return Err(McpOwnerError::CapabilityStorage);
        }
        let mut actual = vec![0u8; document.len() + 1];
        let mut count = 0;
        loop {
            let read = file
                .read_at(&mut actual[count..], count as u64)
                .map_err(|_| McpOwnerError::CapabilityStorage)?;
            if read == 0 {
                break;
            }
            count += read;
            if count > document.len() {
                return Err(McpOwnerError::CapabilityStorage);
            }
        }
        let after = file
            .metadata()
            .map_err(|_| McpOwnerError::CapabilityStorage)?;
        if count != document.len()
            || &actual[..count] != document
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || before.mode() != after.mode()
            || before.nlink() != after.nlink()
        {
            return Err(McpOwnerError::CapabilityStorage);
        }
        let named = statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| McpOwnerError::CapabilityStorage)?;
        let current_parent = owned_parent(&self.parent_path)?;
        let parent = self
            .parent
            .metadata()
            .map_err(|_| McpOwnerError::CapabilityStorage)?;
        let current = current_parent
            .metadata()
            .map_err(|_| McpOwnerError::CapabilityStorage)?;
        if named.st_dev as u64 != after.dev()
            || named.st_ino != after.ino()
            || parent.dev() != current.dev()
            || parent.ino() != current.ino()
        {
            return Err(McpOwnerError::CapabilityStorage);
        }
        self.parent
            .sync_all()
            .map_err(|_| McpOwnerError::CapabilityStorage)
    }
}

fn owned_parent(path: &Path) -> Result<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory: File = open("/", flags, Mode::empty())
        .map_err(|_| McpOwnerError::InvalidCapabilityPath)?
        .into();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, flags, Mode::empty())
                    .map_err(|_| McpOwnerError::InvalidCapabilityPath)?
                    .into()
            }
            _ => return Err(McpOwnerError::InvalidCapabilityPath),
        }
    }
    let metadata = directory
        .metadata()
        .map_err(|_| McpOwnerError::InvalidCapabilityPath)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
        return Err(McpOwnerError::InvalidCapabilityPath);
    }
    Ok(directory)
}

#[cfg(test)]
mod tests;
