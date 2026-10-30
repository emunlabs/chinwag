//! A two-entry Stored ZIP encoder, not a general archive implementation.

pub(super) const MANIFEST_NAME: &str = "manifest.json";
pub(super) const BINARY_NAME: &str = "server/chinwag-bus-mcp";
pub(super) const MAX_MANIFEST_BYTES: usize = 16 * 1024;
pub(super) const MAX_BINARY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct InvalidZipBounds;

struct Entry<'a> {
    name: &'static str,
    data: &'a [u8],
    mode: u32,
    checksum: u32,
    offset: u32,
}

/// All paths and permissions are constants. No directories, links, compression,
/// extra fields, comments, data descriptors or ZIP64 records are accepted.
pub(super) fn encode(manifest: &[u8], binary: &[u8]) -> Result<Vec<u8>, InvalidZipBounds> {
    if manifest.is_empty()
        || manifest.len() > MAX_MANIFEST_BYTES
        || binary.is_empty()
        || binary.len() > MAX_BINARY_BYTES
    {
        return Err(InvalidZipBounds);
    }
    let capacity = manifest
        .len()
        .checked_add(binary.len())
        .and_then(|n| n.checked_add(1024))
        .ok_or(InvalidZipBounds)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| InvalidZipBounds)?;
    let mut entries = [
        Entry {
            name: MANIFEST_NAME,
            data: manifest,
            mode: 0o100644,
            checksum: crc32fast::hash(manifest),
            offset: 0,
        },
        Entry {
            name: BINARY_NAME,
            data: binary,
            mode: 0o100755,
            checksum: crc32fast::hash(binary),
            offset: 0,
        },
    ];
    for entry in &mut entries {
        entry.offset = u32::try_from(output.len()).map_err(|_| InvalidZipBounds)?;
        let length = u32::try_from(entry.data.len()).map_err(|_| InvalidZipBounds)?;
        output.extend_from_slice(b"PK\x03\x04");
        u16_le(&mut output, 20); // Version needed: ZIP 2.0.
        u16_le(&mut output, 0x0800); // UTF-8 paths; no other flags.
        u16_le(&mut output, 0); // Stored, with no compression.
        u16_le(&mut output, 0); // Fixed DOS time.
        u16_le(&mut output, 0x0021); // 1980-01-01, the minimum DOS date.
        u32_le(&mut output, entry.checksum);
        u32_le(&mut output, length);
        u32_le(&mut output, length);
        u16_le(&mut output, entry.name.len() as u16);
        u16_le(&mut output, 0);
        output.extend_from_slice(entry.name.as_bytes());
        output.extend_from_slice(entry.data);
    }
    let central_offset = u32::try_from(output.len()).map_err(|_| InvalidZipBounds)?;
    for entry in &entries {
        let length = u32::try_from(entry.data.len()).map_err(|_| InvalidZipBounds)?;
        output.extend_from_slice(b"PK\x01\x02");
        u16_le(&mut output, (3 << 8) | 20); // Unix creator, ZIP 2.0.
        u16_le(&mut output, 20);
        u16_le(&mut output, 0x0800);
        u16_le(&mut output, 0);
        u16_le(&mut output, 0);
        u16_le(&mut output, 0x0021);
        u32_le(&mut output, entry.checksum);
        u32_le(&mut output, length);
        u32_le(&mut output, length);
        u16_le(&mut output, entry.name.len() as u16);
        u16_le(&mut output, 0); // No extra field.
        u16_le(&mut output, 0); // No comment.
        u16_le(&mut output, 0); // Single disk.
        u16_le(&mut output, 0);
        u32_le(&mut output, entry.mode << 16);
        u32_le(&mut output, entry.offset);
        output.extend_from_slice(entry.name.as_bytes());
    }
    let central_size = u32::try_from(output.len())
        .map_err(|_| InvalidZipBounds)?
        .checked_sub(central_offset)
        .ok_or(InvalidZipBounds)?;
    output.extend_from_slice(b"PK\x05\x06");
    u16_le(&mut output, 0);
    u16_le(&mut output, 0);
    u16_le(&mut output, 2);
    u16_le(&mut output, 2);
    u32_le(&mut output, central_size);
    u32_le(&mut output, central_offset);
    u16_le(&mut output, 0);
    Ok(output)
}

fn u16_le(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn u32_le(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}
