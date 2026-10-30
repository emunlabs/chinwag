#![cfg(target_os = "macos")]

use super::*;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

const ORIGIN: &str = "http://127.0.0.1:44345";
const BINARY_BYTES: &[u8] = b"\xcf\xfa\xed\xfeowned-rust-fixture";

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    binary: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let binary = root.join("chinwag-bus-mcp");
        fs::write(&binary, BINARY_BYTES).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            _temporary: temporary,
            root,
            binary,
        }
    }

    fn exporter(&self, format: ExportFormat) -> ConnectorExport {
        ConnectorExport::new(format, &self.binary, ORIGIN).unwrap()
    }

    fn assert_no_stage(&self) {
        assert!(fs::read_dir(&self.root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".chinwag-export-")
        }));
    }
}

struct ZipEntry {
    name: String,
    bytes: Vec<u8>,
    mode: u32,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// Fixture-only central-directory inspection independently cross-checks local
/// records, permissions, CRCs, offsets, sizes and the exact archive boundary.
fn entries(bytes: &[u8]) -> Vec<ZipEntry> {
    let end = bytes.len() - 22;
    assert_eq!(&bytes[end..end + 4], b"PK\x05\x06");
    assert_eq!(u16_at(bytes, end + 4), 0);
    assert_eq!(u16_at(bytes, end + 6), 0);
    assert_eq!(u16_at(bytes, end + 8), 2);
    assert_eq!(u16_at(bytes, end + 10), 2);
    assert_eq!(u16_at(bytes, end + 20), 0);
    let start = u32_at(bytes, end + 16) as usize;
    assert_eq!(start + u32_at(bytes, end + 12) as usize, end);
    let mut cursor = start;
    let mut extracted = Vec::new();
    let mut next_local = 0;
    for _ in 0..2 {
        assert_eq!(&bytes[cursor..cursor + 4], b"PK\x01\x02");
        assert_eq!(u16_at(bytes, cursor + 4), (3 << 8) | 20);
        assert_eq!(u16_at(bytes, cursor + 6), 20);
        assert_eq!(u16_at(bytes, cursor + 8), 0x0800);
        assert_eq!(u16_at(bytes, cursor + 10), 0);
        assert_eq!(u16_at(bytes, cursor + 12), 0);
        assert_eq!(u16_at(bytes, cursor + 14), 0x21);
        let checksum = u32_at(bytes, cursor + 16);
        let size = u32_at(bytes, cursor + 20) as usize;
        assert_eq!(size, u32_at(bytes, cursor + 24) as usize);
        let name_len = u16_at(bytes, cursor + 28) as usize;
        assert_eq!(u16_at(bytes, cursor + 30), 0);
        assert_eq!(u16_at(bytes, cursor + 32), 0);
        assert_eq!(u16_at(bytes, cursor + 34), 0);
        let mode = u32_at(bytes, cursor + 38) >> 16;
        let local = u32_at(bytes, cursor + 42) as usize;
        assert_eq!(local, next_local);
        let name = &bytes[cursor + 46..cursor + 46 + name_len];
        assert_eq!(&bytes[local..local + 4], b"PK\x03\x04");
        assert_eq!(u16_at(bytes, local + 6), 0x0800);
        assert_eq!(u16_at(bytes, local + 8), 0);
        assert_eq!(u32_at(bytes, local + 14), checksum);
        assert_eq!(u32_at(bytes, local + 18) as usize, size);
        assert_eq!(u32_at(bytes, local + 22) as usize, size);
        assert_eq!(u16_at(bytes, local + 26) as usize, name_len);
        assert_eq!(u16_at(bytes, local + 28), 0);
        assert_eq!(&bytes[local + 30..local + 30 + name_len], name);
        let data_start = local + 30 + name_len;
        let data_end = data_start + size;
        assert!(data_end <= start);
        let data = bytes[data_start..data_end].to_vec();
        assert_eq!(crc32fast::hash(&data), checksum);
        extracted.push(ZipEntry {
            name: String::from_utf8(name.to_vec()).unwrap(),
            bytes: data,
            mode,
        });
        next_local = data_end;
        cursor += 46 + name_len;
    }
    assert_eq!(next_local, start);
    assert_eq!(cursor, end);
    extracted
}

#[test]
fn stored_zip_has_only_fixed_entries_valid_offsets_modes_and_known_crc() {
    let archive = zip::encode(b"{}\n", b"123456789").unwrap();
    let parsed = entries(&archive);
    assert_eq!(parsed[0].name, "manifest.json");
    assert_eq!(parsed[0].bytes, b"{}\n");
    assert_eq!(parsed[0].mode, 0o100644);
    assert_eq!(parsed[1].name, "server/chinwag-bus-mcp");
    assert_eq!(parsed[1].bytes, b"123456789");
    assert_eq!(parsed[1].mode, 0o100755);
    let binary_local = 30 + "manifest.json".len() + 3;
    assert_eq!(u32_at(&archive, binary_local + 14), 0xcbf4_3926);
    assert_eq!(archive, zip::encode(b"{}\n", b"123456789").unwrap());
    assert!(zip::encode(&[], b"1").is_err());
    assert!(zip::encode(b"{}", &[]).is_err());
    assert!(zip::encode(&vec![0; zip::MAX_MANIFEST_BYTES + 1], b"1").is_err());
}

#[test]
fn claude_export_is_a_real_two_entry_unsigned_binary_package() {
    let fixture = Fixture::new();
    let exporter = fixture.exporter(ExportFormat::ClaudeMcpb);
    let output = fixture.root.join("inbox.mcpb");
    let receipt = exporter.export_new(&output).unwrap();
    let bytes = fs::read(&output).unwrap();
    let parsed = entries(&bytes);
    let manifest: Value = serde_json::from_slice(&parsed[0].bytes).unwrap();
    assert_eq!(manifest["manifest_version"], "0.3");
    assert_eq!(manifest["name"], "chinwag-native-inbox-mgmt");
    assert_eq!(manifest["author"], json!({"name":"Chinwag"}));
    assert_eq!(
        manifest["server"],
        json!({
            "type":"binary",
            "entry_point":"server/chinwag-bus-mcp",
            "mcp_config": {
                "command":"${__dirname}/server/chinwag-bus-mcp",
                "args":["--bus-url",format!("{ORIGIN}/"),"--allow-room","#mgmt","--lease-seconds","900"]
            }
        })
    );
    assert_eq!(manifest["compatibility"], json!({"platforms":["darwin"]}));
    assert_eq!(manifest.as_object().unwrap().len(), 8);
    assert_eq!(parsed[1].bytes, BINARY_BYTES);
    assert_eq!(parsed[1].mode, 0o100755);
    assert_eq!(receipt.artifact_sha256, hex(&Sha256::digest(&bytes)));
    assert_eq!(receipt.artifact_bytes, bytes.len() as u64);
    assert_eq!(receipt.binary_sha256, hex(&Sha256::digest(BINARY_BYTES)));
    assert_eq!(receipt.binary_bytes, BINARY_BYTES.len() as u64);
    assert_eq!(receipt.entry_count, 2);
    assert_eq!(receipt.client_acceptance, "unverified");
    assert_eq!(receipt.digest_kind, "sha256-file");
    assert!(receipt.host_local);
    assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
    let second = fixture.root.join("inbox-second.mcpb");
    let second_receipt = exporter.export_new(&second).unwrap();
    assert_eq!(fs::read(second).unwrap(), bytes);
    assert_eq!(second_receipt.artifact_sha256, receipt.artifact_sha256);
    fixture.assert_no_stage();
}

#[test]
fn antigravity_export_is_exact_local_plugin_not_private_client_configuration() {
    let fixture = Fixture::new();
    let exporter = fixture.exporter(ExportFormat::AntigravityPlugin);
    let output = fixture.root.join("plugin-export");
    let receipt = exporter.export_new(&output).unwrap();
    let mut names: Vec<_> = fs::read_dir(&output)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [OsString::from("mcp.json"), OsString::from("plugin.json")]
    );
    let manifest_raw = fs::read(output.join("plugin.json")).unwrap();
    let config_raw = fs::read(output.join("mcp.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_raw).unwrap();
    let config: Value = serde_json::from_slice(&config_raw).unwrap();
    assert_eq!(
        manifest,
        json!({
            "name":"chinwag-native-inbox", "displayName":"Chinwag inbox",
            "version":env!("CARGO_PKG_VERSION"),
            "description":"Read the native Chinwag mgmt inbox on this computer."
        })
    );
    assert_eq!(
        config,
        json!({"mcpServers":{"mgmt":{
            "command":fixture.binary.to_str().unwrap(),
            "args":["--bus-url",format!("{ORIGIN}/"),"--allow-room","#mgmt","--lease-seconds","900"]
        }}})
    );
    assert!(
        !String::from_utf8(config_raw.clone())
            .unwrap()
            .contains("${")
    );
    assert_eq!(
        receipt.artifact_bytes,
        (manifest_raw.len() + config_raw.len()) as u64
    );
    assert_eq!(receipt.digest_kind, "sha256-fixed-directory-v1");
    assert_eq!(receipt.artifact_sha256.len(), 64);
    assert_eq!(receipt.room, "#mgmt");
    assert_eq!(receipt.lease_seconds, 900);
    assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(output.join("mcp.json")).unwrap().mode() & 0o777,
        0o644
    );
    let second = exporter
        .export_new(&fixture.root.join("plugin-export-second"))
        .unwrap();
    assert_eq!(second.artifact_sha256, receipt.artifact_sha256);
    fixture.assert_no_stage();
}

#[test]
fn preexisting_files_directories_links_and_fifo_are_preserved_without_opening() {
    let fixture = Fixture::new();
    let file = fixture.root.join("existing.mcpb");
    fs::write(&file, b"original bytes").unwrap();
    let link = fixture.root.join("link.mcpb");
    symlink(&file, &link).unwrap();
    let fifo = fixture.root.join("fifo.mcpb");
    let fifo_c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // Only a temporary fixture filesystem node; no subprocess or client API.
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    for output in [&file, &link, &fifo] {
        assert_eq!(
            fixture
                .exporter(ExportFormat::ClaudeMcpb)
                .export_new(output)
                .unwrap_err(),
            ExportError::OutputExists
        );
    }
    assert_eq!(fs::read(&file).unwrap(), b"original bytes");
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let directory = fixture.root.join("existing-plugin");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("keep"), b"never replace").unwrap();
    assert_eq!(
        fixture
            .exporter(ExportFormat::AntigravityPlugin)
            .export_new(&directory)
            .unwrap_err(),
        ExportError::OutputExists
    );
    assert_eq!(fs::read(directory.join("keep")).unwrap(), b"never replace");
    fixture.assert_no_stage();
}

#[test]
fn late_destination_conflicts_preserve_existing_bytes_and_remove_only_staging() {
    for format in [ExportFormat::ClaudeMcpb, ExportFormat::AntigravityPlugin] {
        let fixture = Fixture::new();
        let output = fixture.root.join(if format == ExportFormat::ClaudeMcpb {
            "late.mcpb"
        } else {
            "late-plugin"
        });
        let result = fixture.exporter(format).export_prepared(&output, || {
            if format == ExportFormat::ClaudeMcpb {
                fs::write(&output, b"late original").unwrap();
            } else {
                fs::create_dir(&output).unwrap();
                fs::write(output.join("keep"), b"late original").unwrap();
            }
        });
        assert_eq!(result.unwrap_err(), ExportError::OutputExists);
        assert_eq!(
            fs::read(if format == ExportFormat::ClaudeMcpb {
                output
            } else {
                output.join("keep")
            })
            .unwrap(),
            b"late original"
        );
        fixture.assert_no_stage();
    }
}

#[test]
fn binary_changes_before_or_after_staging_cannot_publish_an_artifact() {
    for late in [false, true] {
        let fixture = Fixture::new();
        let exporter = fixture.exporter(ExportFormat::ClaudeMcpb);
        let output = fixture.root.join("changed.mcpb");
        let replace = || {
            fs::rename(&fixture.binary, fixture.root.join("old-binary")).unwrap();
            fs::write(&fixture.binary, BINARY_BYTES).unwrap();
            fs::set_permissions(&fixture.binary, fs::Permissions::from_mode(0o755)).unwrap();
        };
        let result = if late {
            exporter.export_prepared(&output, replace)
        } else {
            replace();
            exporter.export_new(&output)
        };
        assert_eq!(result.unwrap_err(), ExportError::BinaryUnavailable);
        assert!(!output.exists());
        assert_eq!(fs::read(&fixture.binary).unwrap(), BINARY_BYTES);
        fixture.assert_no_stage();
    }
}

#[test]
fn output_scope_rejects_aliases_unsafe_parent_and_lexical_escape() {
    let fixture = Fixture::new();
    let alias = fixture.root.join("alias");
    symlink(&fixture.root, &alias).unwrap();
    let unsafe_parent = fixture.root.join("writable");
    fs::create_dir(&unsafe_parent).unwrap();
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
    for output in [
        PathBuf::from("relative.mcpb"),
        fixture.root.join("../escape.mcpb"),
        fixture.root.join("./dot.mcpb"),
        fixture.root.join("wrong.zip"),
        alias.join("aliased.mcpb"),
        unsafe_parent.join("unsafe.mcpb"),
        fixture.root.join("missing-parent/out.mcpb"),
    ] {
        assert_eq!(
            fixture
                .exporter(ExportFormat::ClaudeMcpb)
                .export_new(&output)
                .unwrap_err(),
            ExportError::InvalidOutput
        );
    }
    assert!(!fixture.root.join("aliased.mcpb").exists());
    fixture.assert_no_stage();
}

#[test]
fn replaced_output_parent_does_not_redirect_publication_or_cleanup() {
    let fixture = Fixture::new();
    let parent = fixture.root.join("owned");
    let moved = fixture.root.join("moved");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let output = parent.join("inbox.mcpb");
    let result = fixture
        .exporter(ExportFormat::ClaudeMcpb)
        .export_prepared(&output, || {
            fs::rename(&parent, &moved).unwrap();
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(parent.join("keep"), b"replacement directory").unwrap();
        });
    assert_eq!(result.unwrap_err(), ExportError::InvalidOutput);
    assert!(!output.exists());
    assert_eq!(
        fs::read(parent.join("keep")).unwrap(),
        b"replacement directory"
    );
    assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
}

#[test]
fn shared_configuration_and_pin_reject_untrusted_inputs_before_export() {
    let fixture = Fixture::new();
    for endpoint in [
        "https://127.0.0.1:1",
        "http://example.com",
        "http://127.0.0.1:1/path",
        "http://127.0.0.1:1/%2e",
        "http://user@127.0.0.1:1",
    ] {
        assert!(matches!(
            ConnectorExport::new(ExportFormat::ClaudeMcpb, &fixture.binary, endpoint),
            Err(ExportError::InvalidConfiguration)
        ));
    }
    let script = fixture.root.join("script");
    fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        ConnectorExport::new(ExportFormat::ClaudeMcpb, &script, ORIGIN),
        Err(ExportError::BinaryUnavailable)
    ));
    fs::set_permissions(&fixture.binary, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        ConnectorExport::new(ExportFormat::ClaudeMcpb, &fixture.binary, ORIGIN),
        Err(ExportError::BinaryUnavailable)
    ));
    fixture.assert_no_stage();
}

fn staged_path(root: &Path) -> PathBuf {
    let stages: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".chinwag-export-")
        })
        .collect();
    assert_eq!(stages.len(), 1);
    stages[0].clone()
}

#[test]
fn stage_tampering_archive_replacement_is_preserved_without_publication() {
    let fixture = Fixture::new();
    let output = fixture.root.join("replaced.mcpb");
    let saved = fixture.root.join("saved-original.mcpb");
    let mut replacement = None;
    let result = fixture
        .exporter(ExportFormat::ClaudeMcpb)
        .export_prepared(&output, || {
            let stage = staged_path(&fixture.root);
            fs::rename(&stage, &saved).unwrap();
            fs::write(&stage, b"foreign archive replacement").unwrap();
            replacement = Some(stage);
        });
    assert_eq!(result.unwrap_err(), ExportError::Storage);
    assert!(!output.exists());
    assert_eq!(
        fs::read(replacement.unwrap()).unwrap(),
        b"foreign archive replacement"
    );
    assert!(fs::read(saved).unwrap().starts_with(b"PK"));
}

#[test]
fn stage_tampering_archive_same_inode_bytes_are_preserved_without_publication() {
    let fixture = Fixture::new();
    let output = fixture.root.join("tampered.mcpb");
    let mut tampered = None;
    let result = fixture
        .exporter(ExportFormat::ClaudeMcpb)
        .export_prepared(&output, || {
            let stage = staged_path(&fixture.root);
            let mut bytes = fs::read(&stage).unwrap();
            bytes[0] ^= 1;
            fs::write(&stage, &bytes).unwrap();
            tampered = Some((stage, bytes));
        });
    assert_eq!(result.unwrap_err(), ExportError::Storage);
    assert!(!output.exists());
    let (stage, bytes) = tampered.unwrap();
    assert_eq!(fs::read(stage).unwrap(), bytes);
}

#[test]
fn stage_tampering_plugin_directory_replacement_is_preserved_without_publication() {
    let fixture = Fixture::new();
    let output = fixture.root.join("replaced-plugin");
    let saved = fixture.root.join("saved-original-plugin");
    let mut replacement = None;
    let result = fixture
        .exporter(ExportFormat::AntigravityPlugin)
        .export_prepared(&output, || {
            let stage = staged_path(&fixture.root);
            fs::rename(&stage, &saved).unwrap();
            fs::create_dir(&stage).unwrap();
            fs::write(stage.join("keep"), b"foreign directory replacement").unwrap();
            replacement = Some(stage);
        });
    assert_eq!(result.unwrap_err(), ExportError::Storage);
    assert!(!output.exists());
    assert_eq!(
        fs::read(replacement.unwrap().join("keep")).unwrap(),
        b"foreign directory replacement"
    );
    assert!(saved.join(PLUGIN_MANIFEST).is_file());
    assert!(saved.join(PLUGIN_CONFIG).is_file());
}

#[test]
fn stage_tampering_plugin_content_extra_child_and_link_are_preserved() {
    for kind in ["content", "extra", "link", "mode"] {
        let fixture = Fixture::new();
        let output = fixture.root.join("tampered-plugin");
        let mut stage_path = None;
        let result = fixture
            .exporter(ExportFormat::AntigravityPlugin)
            .export_prepared(&output, || {
                let stage = staged_path(&fixture.root);
                match kind {
                    "content" => {
                        fs::write(stage.join(PLUGIN_CONFIG), b"foreign configuration").unwrap()
                    }
                    "extra" => fs::write(stage.join("keep"), b"foreign extra child").unwrap(),
                    "link" => {
                        fs::remove_file(stage.join(PLUGIN_CONFIG)).unwrap();
                        symlink(&fixture.binary, stage.join(PLUGIN_CONFIG)).unwrap();
                    }
                    "mode" => fs::set_permissions(
                        stage.join(PLUGIN_CONFIG),
                        fs::Permissions::from_mode(0o777),
                    )
                    .unwrap(),
                    _ => unreachable!(),
                }
                stage_path = Some(stage);
            });
        assert_eq!(result.unwrap_err(), ExportError::Storage, "{kind}");
        assert!(!output.exists());
        let stage = stage_path.unwrap();
        assert!(stage.join(PLUGIN_MANIFEST).exists());
        match kind {
            "content" => assert_eq!(
                fs::read(stage.join(PLUGIN_CONFIG)).unwrap(),
                b"foreign configuration"
            ),
            "extra" => assert_eq!(
                fs::read(stage.join("keep")).unwrap(),
                b"foreign extra child"
            ),
            "link" => assert!(
                fs::symlink_metadata(stage.join(PLUGIN_CONFIG))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            ),
            "mode" => assert_eq!(
                fs::metadata(stage.join(PLUGIN_CONFIG)).unwrap().mode() & 0o777,
                0o777
            ),
            _ => unreachable!(),
        }
    }
}

#[test]
fn stage_tampering_after_publication_is_uncertain_and_preserves_actual_output() {
    for format in [ExportFormat::ClaudeMcpb, ExportFormat::AntigravityPlugin] {
        let fixture = Fixture::new();
        let output = fixture.root.join(if format == ExportFormat::ClaudeMcpb {
            "published.mcpb"
        } else {
            "published-plugin"
        });
        let saved = fixture.root.join("published-original");
        let result = fixture.exporter(format).export_with_hooks(
            &output,
            || {},
            || {
                fs::rename(&output, &saved).unwrap();
                if format == ExportFormat::ClaudeMcpb {
                    fs::write(&output, b"foreign published archive").unwrap();
                } else {
                    fs::create_dir(&output).unwrap();
                    fs::write(output.join("keep"), b"foreign published plugin").unwrap();
                }
            },
        );
        assert_eq!(result.unwrap_err(), ExportError::PublicationUncertain);
        if format == ExportFormat::ClaudeMcpb {
            assert_eq!(fs::read(&output).unwrap(), b"foreign published archive");
            assert!(fs::read(&saved).unwrap().starts_with(b"PK"));
        } else {
            assert_eq!(
                fs::read(output.join("keep")).unwrap(),
                b"foreign published plugin"
            );
            assert!(saved.join(PLUGIN_CONFIG).is_file());
        }
        fixture.assert_no_stage();
    }
}

#[test]
fn stage_tampering_published_same_inode_content_is_uncertain_without_cleanup() {
    for format in [ExportFormat::ClaudeMcpb, ExportFormat::AntigravityPlugin] {
        let fixture = Fixture::new();
        let output = fixture.root.join(if format == ExportFormat::ClaudeMcpb {
            "published-tampered.mcpb"
        } else {
            "published-tampered-plugin"
        });
        let target = if format == ExportFormat::ClaudeMcpb {
            output.clone()
        } else {
            output.join(PLUGIN_CONFIG)
        };
        let result = fixture.exporter(format).export_with_hooks(
            &output,
            || {},
            || {
                fs::write(&target, b"foreign published bytes").unwrap();
            },
        );
        assert_eq!(result.unwrap_err(), ExportError::PublicationUncertain);
        assert_eq!(fs::read(target).unwrap(), b"foreign published bytes");
        fixture.assert_no_stage();
    }
}

#[test]
fn stage_tampering_published_parent_change_cannot_acknowledge_old_output_path() {
    let fixture = Fixture::new();
    let parent = fixture.root.join("owned-parent");
    let moved = fixture.root.join("moved-parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let output = parent.join("published.mcpb");
    let result = fixture
        .exporter(ExportFormat::ClaudeMcpb)
        .export_with_hooks(
            &output,
            || {},
            || {
                fs::rename(&parent, &moved).unwrap();
                fs::create_dir(&parent).unwrap();
                fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
                fs::write(parent.join("keep"), b"foreign parent replacement").unwrap();
            },
        );
    assert_eq!(result.unwrap_err(), ExportError::PublicationUncertain);
    assert!(!output.exists());
    assert_eq!(
        fs::read(parent.join("keep")).unwrap(),
        b"foreign parent replacement"
    );
    assert!(
        fs::read(moved.join("published.mcpb"))
            .unwrap()
            .starts_with(b"PK")
    );
}
