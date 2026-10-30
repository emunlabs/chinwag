//! Owner-triggered, host-local artifact export. This module never installs a
//! client, changes its configuration, starts a process or contacts an endpoint.

mod zip;

use crate::mcp_binary::{PinnedMcpBinary, VerifiedMcpBinary};
use chinwag_native_launch::FixedMcpConfig;
use rustix::fs::{
    AtFlags, Dir, Mode, OFlags, RenameFlags, fchmod, mkdirat, open, openat, renameat_with, statat,
    unlinkat,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::Write,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const PLUGIN_MANIFEST: &str = "plugin.json";
const PLUGIN_CONFIG: &str = "mcp.json";
static NEXT_STAGE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    ClaudeMcpb,
    AntigravityPlugin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExportError {
    #[error("connector artifact export requires macOS")]
    UnsupportedPlatform,
    #[error("invalid fixed native inbox configuration")]
    InvalidConfiguration,
    #[error("the exact owned native MCP binary is unavailable or changed")]
    BinaryUnavailable,
    #[error("output requires a normalized absolute new path in an existing owned directory")]
    InvalidOutput,
    #[error("output already exists; no existing artifact was replaced")]
    OutputExists,
    #[error("connector artifact storage failed; no client action was performed")]
    Storage,
    #[error("artifact publication could not be confirmed; output may exist; do not overwrite it")]
    PublicationUncertain,
}

/// An export receipt describes bytes, not client installation or connection.
#[derive(Debug, Serialize)]
pub struct ExportReceipt {
    pub schema: &'static str,
    pub state: &'static str,
    pub format: ExportFormat,
    pub output: PathBuf,
    pub artifact_sha256: String,
    pub digest_kind: &'static str,
    pub artifact_bytes: u64,
    pub entry_count: u8,
    pub binary_sha256: String,
    pub binary_bytes: u64,
    pub endpoint: String,
    pub room: &'static str,
    pub lease_seconds: u16,
    pub host_local: bool,
    pub client_acceptance: &'static str,
}

/// Only owner CLI/host code creates this value. It has no deserialization or
/// configurable argv, room, lease, environment, hook or installer interface.
pub struct ConnectorExport {
    format: ExportFormat,
    config: FixedMcpConfig,
    binary: PinnedMcpBinary,
}

impl ConnectorExport {
    pub fn new(format: ExportFormat, binary: &Path, bus_origin: &str) -> Result<Self, ExportError> {
        if !cfg!(target_os = "macos") {
            return Err(ExportError::UnsupportedPlatform);
        }
        let config = FixedMcpConfig::new(binary, bus_origin)
            .map_err(|_| ExportError::InvalidConfiguration)?;
        let binary = PinnedMcpBinary::open(binary).map_err(|_| ExportError::BinaryUnavailable)?;
        Ok(Self {
            format,
            config,
            binary,
        })
    }

    /// Stages only fixed output entries and publishes without replacement. The
    /// parent must already exist; exporting never creates a directory tree.
    pub fn export_new(&self, output: &Path) -> Result<ExportReceipt, ExportError> {
        self.export_prepared(output, || {})
    }

    fn export_prepared(
        &self,
        output: &Path,
        before_publication: impl FnOnce(),
    ) -> Result<ExportReceipt, ExportError> {
        self.export_with_hooks(output, before_publication, || {})
    }

    fn export_with_hooks(
        &self,
        output: &Path,
        before_publication: impl FnOnce(),
        after_publication: impl FnOnce(),
    ) -> Result<ExportReceipt, ExportError> {
        let (parent_path, name) = output_parts(output, self.format)?;
        let parent = owned_directory(&parent_path)?;
        require_absent(&parent, &name)?;
        let snapshot = self
            .binary
            .verified_snapshot()
            .map_err(|_| ExportError::BinaryUnavailable)?;
        if snapshot.path() != Path::new(self.config.command()) {
            return Err(ExportError::BinaryUnavailable);
        }
        let binary_sha256 = hex(&snapshot.sha256());
        let binary_bytes = snapshot.bytes().len() as u64;
        let prepared = self.prepare(&snapshot)?;
        drop(snapshot);
        let artifact_bytes = prepared.byte_count();
        let artifact_sha256 = prepared.digest();
        let digest_kind = match self.format {
            ExportFormat::ClaudeMcpb => "sha256-file",
            ExportFormat::AntigravityPlugin => "sha256-fixed-directory-v1",
        };
        let mut stage = Stage::create(&parent, self.format, &prepared)?;
        stage.write()?;
        before_publication();
        self.binary
            .revalidate()
            .map_err(|_| ExportError::BinaryUnavailable)?;
        let current_parent = owned_directory(&parent_path)?;
        if !same_file(&parent, &current_parent)? {
            return Err(ExportError::InvalidOutput);
        }
        stage.verify(OsStr::new(&stage.name))?;
        renameat_with(&parent, &stage.name, &parent, &name, RenameFlags::NOREPLACE).map_err(
            |error| {
                if error == rustix::io::Errno::EXIST {
                    ExportError::OutputExists
                } else {
                    ExportError::Storage
                }
            },
        )?;
        stage.published = true;
        after_publication();
        parent
            .sync_all()
            .map_err(|_| ExportError::PublicationUncertain)?;
        stage
            .verify(&name)
            .map_err(|_| ExportError::PublicationUncertain)?;
        let published_parent =
            owned_directory(&parent_path).map_err(|_| ExportError::PublicationUncertain)?;
        if !same_file(&parent, &published_parent).map_err(|_| ExportError::PublicationUncertain)? {
            return Err(ExportError::PublicationUncertain);
        }
        Ok(ExportReceipt {
            schema: "chinwag-connector-export/v1",
            state: "exported",
            format: self.format,
            output: output.to_owned(),
            artifact_sha256,
            digest_kind,
            artifact_bytes,
            entry_count: 2,
            binary_sha256,
            binary_bytes,
            endpoint: self.config.endpoint().to_owned(),
            room: "#mgmt",
            lease_seconds: 900,
            host_local: true,
            client_acceptance: "unverified",
        })
    }

    fn prepare(&self, snapshot: &VerifiedMcpBinary) -> Result<Prepared, ExportError> {
        match self.format {
            ExportFormat::ClaudeMcpb => {
                let manifest = json_bytes(&serde_json::json!({
                    "manifest_version": "0.3",
                    "name": self.config.server_name(),
                    "display_name": "Chinwag inbox",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "Read the native Chinwag mgmt inbox on this computer.",
                    "author": {"name": "Chinwag"},
                    "server": {
                        "type": "binary",
                        "entry_point": zip::BINARY_NAME,
                        "mcp_config": {
                            "command": "${__dirname}/server/chinwag-bus-mcp",
                            "args": self.config.args()
                        }
                    },
                    "compatibility": {"platforms": ["darwin"]}
                }))?;
                Ok(Prepared::Archive(
                    zip::encode(&manifest, snapshot.bytes()).map_err(|_| ExportError::Storage)?,
                ))
            }
            ExportFormat::AntigravityPlugin => Ok(Prepared::Directory {
                manifest: json_bytes(&serde_json::json!({
                    "name": "chinwag-native-inbox",
                    "displayName": "Chinwag inbox",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "Read the native Chinwag mgmt inbox on this computer."
                }))?,
                config: json_bytes(&serde_json::json!({
                    "mcpServers": {
                        "mgmt": {"command": self.config.command(), "args": self.config.args()}
                    }
                }))?,
            }),
        }
    }
}

enum Prepared {
    Archive(Vec<u8>),
    Directory { manifest: Vec<u8>, config: Vec<u8> },
}

impl Prepared {
    fn byte_count(&self) -> u64 {
        match self {
            Self::Archive(bytes) => bytes.len() as u64,
            Self::Directory { manifest, config } => (manifest.len() + config.len()) as u64,
        }
    }

    fn digest(&self) -> String {
        match self {
            Self::Archive(bytes) => hex(&Sha256::digest(bytes)),
            Self::Directory { manifest, config } => {
                // Domain-separated, fixed-order length-prefixed file bytes.
                let mut hash = Sha256::new();
                hash.update(b"chinwag-fixed-plugin-directory/v1\0");
                for (name, bytes) in [(PLUGIN_MANIFEST, manifest), (PLUGIN_CONFIG, config)] {
                    hash.update((name.len() as u32).to_le_bytes());
                    hash.update(name.as_bytes());
                    hash.update((bytes.len() as u64).to_le_bytes());
                    hash.update(bytes);
                }
                hex(&hash.finalize())
            }
        }
    }
}

fn json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, ExportError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| ExportError::Storage)?;
    bytes.push(b'\n');
    if bytes.len() > zip::MAX_MANIFEST_BYTES {
        return Err(ExportError::Storage);
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn output_parts(output: &Path, format: ExportFormat) -> Result<(PathBuf, OsString), ExportError> {
    let text = output.to_str().ok_or(ExportError::InvalidOutput)?;
    let normalized: PathBuf = output.components().collect();
    if !output.is_absolute()
        || normalized.as_os_str() != output.as_os_str()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || output
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || (format == ExportFormat::ClaudeMcpb && output.extension() != Some(OsStr::new("mcpb")))
    {
        return Err(ExportError::InvalidOutput);
    }
    let name = output.file_name().ok_or(ExportError::InvalidOutput)?;
    if name.len() > 240 || name.to_string_lossy().starts_with(".chinwag-export-") {
        return Err(ExportError::InvalidOutput);
    }
    Ok((
        output
            .parent()
            .ok_or(ExportError::InvalidOutput)?
            .to_owned(),
        name.to_owned(),
    ))
}

fn owned_directory(path: &Path) -> Result<File, ExportError> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory: File = open("/", flags, Mode::empty())
        .map_err(|_| ExportError::InvalidOutput)?
        .into();
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, flags, Mode::empty())
                    .map_err(|_| ExportError::InvalidOutput)?
                    .into();
            }
            _ => return Err(ExportError::InvalidOutput),
        }
    }
    let metadata = directory.metadata().map_err(|_| ExportError::Storage)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(ExportError::InvalidOutput);
    }
    Ok(directory)
}

fn require_absent(directory: &File, name: &OsStr) -> Result<(), ExportError> {
    match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Err(ExportError::OutputExists),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(_) => Err(ExportError::Storage),
    }
}

fn same_file(left: &File, right: &File) -> Result<bool, ExportError> {
    let left = left.metadata().map_err(|_| ExportError::Storage)?;
    let right = right.metadata().map_err(|_| ExportError::Storage)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

struct Stage<'a> {
    parent: &'a File,
    name: String,
    node: File,
    children: Vec<File>,
    prepared: &'a Prepared,
    format: ExportFormat,
    published: bool,
}

impl<'a> Stage<'a> {
    fn create(
        parent: &'a File,
        format: ExportFormat,
        prepared: &'a Prepared,
    ) -> Result<Self, ExportError> {
        let name = format!(
            ".chinwag-export-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        );
        let node = match format {
            ExportFormat::ClaudeMcpb => create_file(parent, &name, Mode::RUSR | Mode::WUSR)?,
            ExportFormat::AntigravityPlugin => {
                mkdirat(parent, &name, Mode::RWXU).map_err(|_| ExportError::Storage)?;
                match openat(
                    parent,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(fd) => fd.into(),
                    // Without an opened held node, ownership of the current
                    // name cannot be established for cleanup.
                    Err(_) => return Err(ExportError::Storage),
                }
            }
        };
        Ok(Self {
            parent,
            name,
            node,
            children: Vec::new(),
            prepared,
            format,
            published: false,
        })
    }

    fn write(&mut self) -> Result<(), ExportError> {
        match self.prepared {
            Prepared::Archive(bytes) => self
                .node
                .write_all(bytes)
                .map_err(|_| ExportError::Storage)?,
            Prepared::Directory { manifest, config } => {
                for (name, bytes) in [(PLUGIN_MANIFEST, manifest), (PLUGIN_CONFIG, config)] {
                    let mut file = create_file(
                        &self.node,
                        name,
                        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
                    )?;
                    file.write_all(bytes).map_err(|_| ExportError::Storage)?;
                    file.sync_all().map_err(|_| ExportError::Storage)?;
                    self.children.push(file);
                }
            }
        }
        self.node.sync_all().map_err(|_| ExportError::Storage)
    }

    /// Verify names against held nodes and compare actual bounded bytes with
    /// the fixed prepared artifact. A pathname check alone cannot detect an
    /// in-place edit, and a held descriptor alone cannot prove what is named.
    fn verify(&self, name: &OsStr) -> Result<(), ExportError> {
        let named = named_node(
            self.parent,
            name,
            &self.node,
            self.format == ExportFormat::AntigravityPlugin,
        )?;
        match self.prepared {
            Prepared::Archive(bytes) => verify_bytes(&named, bytes, 0o600)?,
            Prepared::Directory { manifest, config } => {
                let before = self.node.metadata().map_err(|_| ExportError::Storage)?;
                if !before.is_dir()
                    || before.uid() != rustix::process::geteuid().as_raw()
                    || before.mode() & 0o7777 != 0o700
                    || self.children.len() != 2
                {
                    return Err(ExportError::Storage);
                }
                let mut seen = [false; 2];
                for entry in Dir::read_from(&self.node).map_err(|_| ExportError::Storage)? {
                    let entry = entry.map_err(|_| ExportError::Storage)?;
                    let index = match entry.file_name().to_bytes() {
                        b"." | b".." => continue,
                        b"plugin.json" => 0,
                        b"mcp.json" => 1,
                        _ => return Err(ExportError::Storage),
                    };
                    if seen[index] {
                        return Err(ExportError::Storage);
                    }
                    seen[index] = true;
                }
                if seen != [true, true] {
                    return Err(ExportError::Storage);
                }
                for (index, (child, bytes)) in
                    [(PLUGIN_MANIFEST, manifest), (PLUGIN_CONFIG, config)]
                        .into_iter()
                        .enumerate()
                {
                    let named_child =
                        named_node(&self.node, OsStr::new(child), &self.children[index], false)?;
                    verify_bytes(&named_child, bytes, 0o644)?;
                    named_node(&self.node, OsStr::new(child), &self.children[index], false)?;
                }
                if !unchanged(
                    &before,
                    &self.node.metadata().map_err(|_| ExportError::Storage)?,
                ) {
                    return Err(ExportError::Storage);
                }
            }
        }
        named_node(
            self.parent,
            name,
            &self.node,
            self.format == ExportFormat::AntigravityPlugin,
        )?;
        Ok(())
    }
}

impl Drop for Stage<'_> {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // Preserve any replaced node, changed bytes, foreign child or incomplete
        // staging output. Cleanup is restricted to a complete untouched stage.
        if self.verify(OsStr::new(&self.name)).is_err() {
            return;
        }
        if self.format == ExportFormat::AntigravityPlugin {
            for name in [PLUGIN_MANIFEST, PLUGIN_CONFIG] {
                let _ = unlinkat(&self.node, name, AtFlags::empty());
            }
            let _ = unlinkat(self.parent, &self.name, AtFlags::REMOVEDIR);
        } else {
            let _ = unlinkat(self.parent, &self.name, AtFlags::empty());
        }
    }
}

fn create_file(directory: &File, name: &str, mode: Mode) -> Result<File, ExportError> {
    let file: File = openat(
        directory,
        name,
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK,
        mode,
    )
    .map_err(|_| ExportError::Storage)?
    .into();
    fchmod(&file, mode).map_err(|_| ExportError::Storage)?;
    Ok(file)
}

fn named_node(
    parent: &File,
    name: &OsStr,
    held: &File,
    directory: bool,
) -> Result<File, ExportError> {
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    let named: File = openat(parent, name, flags, Mode::empty())
        .map_err(|_| ExportError::Storage)?
        .into();
    if !same_file(held, &named)? {
        return Err(ExportError::Storage);
    }
    Ok(named)
}

fn verify_bytes(file: &File, expected: &[u8], mode: u32) -> Result<(), ExportError> {
    let before = file.metadata().map_err(|_| ExportError::Storage)?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o7777 != mode
        || before.nlink() != 1
        || before.len() != expected.len() as u64
    {
        return Err(ExportError::Storage);
    }
    let mut buffer = [0u8; 16384];
    let mut offset = 0;
    while offset < expected.len() {
        let end = expected.len().min(offset + buffer.len());
        let count = file
            .read_at(&mut buffer[..end - offset], offset as u64)
            .map_err(|_| ExportError::Storage)?;
        if count == 0 || buffer[..count] != expected[offset..offset + count] {
            return Err(ExportError::Storage);
        }
        offset += count;
    }
    if file
        .read_at(&mut buffer[..1], offset as u64)
        .map_err(|_| ExportError::Storage)?
        != 0
        || !unchanged(&before, &file.metadata().map_err(|_| ExportError::Storage)?)
    {
        return Err(ExportError::Storage);
    }
    Ok(())
}

fn unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && (before.mtime(), before.mtime_nsec()) == (after.mtime(), after.mtime_nsec())
        && (before.ctime(), before.ctime_nsec()) == (after.ctime(), after.ctime_nsec())
}

#[cfg(test)]
mod tests;
