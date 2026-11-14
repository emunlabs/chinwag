//! Deterministic POSIX USTAR `.tar.gz` packager, archive reader, and 512x512 RGB PNG icon encoder.
#![forbid(unsafe_code)]

use crate::PackError;
use flate2::{Compression, Crc, GzBuilder, read::GzDecoder, write::ZlibEncoder};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Component, Path},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub bytes: Vec<u8>,
    pub executable: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BundleTree {
    files: BTreeMap<String, FileEntry>,
}

impl BundleTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_file(
        &mut self,
        relative_path: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<(), PackError> {
        self.insert_entry(relative_path, bytes, false)
    }

    pub fn insert_entry(
        &mut self,
        relative_path: impl Into<String>,
        bytes: Vec<u8>,
        executable: bool,
    ) -> Result<(), PackError> {
        let rel = relative_path.into();
        validate_archive_path(&rel)?;
        if self.files.contains_key(&rel) {
            return Err(PackError::Archive {
                detail: format!("duplicate bundle path `{rel}`"),
            });
        }
        self.files.insert(rel, FileEntry { bytes, executable });
        Ok(())
    }

    pub fn files(&self) -> &BTreeMap<String, FileEntry> {
        &self.files
    }

    /// Encode this `BundleTree` into a byte-for-byte deterministic POSIX USTAR `.tar.gz` archive:
    /// - Sorted lexicographically by path (`BTreeMap`)
    /// - Explicit directory entries (`0755`) emitted before child files (`0644` / `0755`)
    /// - `mtime = 0`, `uid = 0`, `gid = 0`, `uname = ""`, `gname = ""`
    /// - Gzip header `mtime = 0`, `OS = 3` (Unix), `Compression::best()`
    pub fn to_deterministic_tar_gz(&self) -> Result<Vec<u8>, PackError> {
        let mut tar_bytes = Vec::new();
        let mut emitted_dirs = BTreeSet::new();

        for (rel_path, entry) in &self.files {
            let parts: Vec<&str> = rel_path.split('/').collect();
            for depth in 1..parts.len() {
                let mut dir_path = parts[..depth].join("/");
                dir_path.push('/');
                if emitted_dirs.insert(dir_path.clone()) {
                    let hdr = build_ustar_header(&dir_path, 0o755, 0, b'5')?;
                    tar_bytes.extend_from_slice(&hdr);
                }
            }
            let mode = if entry.executable { 0o755 } else { 0o644 };
            let hdr = build_ustar_header(rel_path, mode, entry.bytes.len() as u64, b'0')?;
            tar_bytes.extend_from_slice(&hdr);
            tar_bytes.extend_from_slice(&entry.bytes);
            let rem = entry.bytes.len() % 512;
            if rem != 0 {
                tar_bytes.resize(tar_bytes.len() + (512 - rem), 0);
            }
        }

        // Two 512-byte zero blocks terminate the POSIX tar stream.
        tar_bytes.resize(tar_bytes.len() + 1024, 0);

        let mut gz = GzBuilder::new()
            .mtime(0)
            .operating_system(3)
            .write(Vec::new(), Compression::best());
        gz.write_all(&tar_bytes).map_err(|e| PackError::Archive {
            detail: format!("gzip encode failed: {e}"),
        })?;
        gz.finish().map_err(|e| PackError::Archive {
            detail: format!("gzip finish failed: {e}"),
        })
    }
}

/// Decompress and parse a deterministic POSIX USTAR `.tar.gz` archive back into `(path -> bytes)`,
/// enforcing normalized `mtime == 0`, `uid == 0`, `gid == 0`, and path traversal safety.
pub fn unpack_deterministic_tar_gz(archive: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, PackError> {
    if archive.len() < 10 {
        return Err(PackError::Archive {
            detail: "gzip archive truncated".into(),
        });
    }
    // Verify gzip header mtime (bytes 4..8) == 0 and OS byte (byte 9) == 3
    if archive[4..8] != [0, 0, 0, 0] || archive[9] != 3 {
        return Err(PackError::Archive {
            detail: "gzip header lacks normalized mtime=0 or OS=3".into(),
        });
    }

    let mut decoder = GzDecoder::new(archive);
    let mut tar = Vec::new();
    decoder
        .read_to_end(&mut tar)
        .map_err(|e| PackError::Archive {
            detail: format!("gzip decode failed: {e}"),
        })?;
    if tar.len() % 512 != 0 || tar.len() < 1024 {
        return Err(PackError::Archive {
            detail: "decompressed tar stream is not 512-byte block aligned".into(),
        });
    }

    let mut out = BTreeMap::new();
    let mut offset = 0usize;
    let mut prev_name: Option<String> = None;

    while offset + 512 <= tar.len() {
        let block = &tar[offset..offset + 512];
        offset += 512;
        if block.iter().all(|b| *b == 0) {
            break;
        }
        verify_ustar_checksum(block)?;
        let typeflag = block[156];
        let name = extract_ustar_path(block)?;
        let uid = parse_octal(&block[108..116])?;
        let gid = parse_octal(&block[116..124])?;
        let size = parse_octal(&block[124..136])? as usize;
        let mtime = parse_octal(&block[136..148])?;
        if uid != 0 || gid != 0 || mtime != 0 {
            return Err(PackError::Archive {
                detail: format!("non-normalized uid/gid/mtime on tar entry `{name}`"),
            });
        }
        if let Some(prev) = &prev_name
            && name <= *prev
        {
            return Err(PackError::Archive {
                detail: format!("tar entries out of canonical sort order: `{prev}` then `{name}`"),
            });
        }
        prev_name = Some(name.clone());

        match typeflag {
            b'5' => {
                if size != 0 {
                    return Err(PackError::Archive {
                        detail: format!("directory entry `{name}` has non-zero size"),
                    });
                }
                let trimmed = name.trim_end_matches('/');
                validate_archive_path(trimmed)?;
            }
            b'0' | 0 => {
                validate_archive_path(&name)?;
                if offset + size > tar.len() {
                    return Err(PackError::Archive {
                        detail: format!("tar entry `{name}` exceeds archive bounds"),
                    });
                }
                let payload = tar[offset..offset + size].to_vec();
                let blocks = size.div_ceil(512);
                offset += blocks * 512;
                if out.insert(name.clone(), payload).is_some() {
                    return Err(PackError::Archive {
                        detail: format!("duplicate file `{name}` in archive"),
                    });
                }
            }
            other => {
                return Err(PackError::Archive {
                    detail: format!("forbidden tar entry type `{other}` on `{name}`"),
                });
            }
        }
    }

    Ok(out)
}

/// Render a deterministic `size x size` 24-bit RGB PNG icon (`color_type = 2`, 8-bit depth)
/// depicting the Chinwag ring & three-node coordination motif.
pub fn render_deterministic_icon_png(
    size: u32,
    primary_rgb: [u8; 3],
    accent_rgb: [u8; 3],
) -> Result<Vec<u8>, PackError> {
    let mut raw_scanlines = Vec::with_capacity((size as usize) * (1 + (size as usize) * 3));
    let center = (size as i64) / 2;
    let ring_outer = (size as i64) * 32 / 100;
    let ring_inner = (size as i64) * 26 / 100;
    let dot_r2 = ((size as i64) * 45 / 1000).pow(2);
    let dot_y = (size as i64) * 46 / 100;
    let dot_xs = [(size as i64) * 37 / 100, center, (size as i64) * 63 / 100];
    let bar_y_min = (size as i64) * 60 / 100;
    let bar_y_max = (size as i64) * 64 / 100;
    let bar_x_min = (size as i64) * 35 / 100;
    let bar_x_max = (size as i64) * 65 / 100;

    for y in 0..size {
        raw_scanlines.push(0u8); // Filter type 0 (None)
        let yi = y as i64;
        let dy = yi - center;
        for x in 0..size {
            let xi = x as i64;
            let dx = xi - center;
            let dist2 = dx * dx + dy * dy;
            let in_ring = dist2 <= ring_outer * ring_outer && dist2 >= ring_inner * ring_inner;
            let in_bar = yi >= bar_y_min && yi <= bar_y_max && xi >= bar_x_min && xi <= bar_x_max;
            let mut pixel = if in_ring || in_bar {
                accent_rgb
            } else {
                primary_rgb
            };
            for (idx, dot_x) in dot_xs.iter().enumerate() {
                let ddx = xi - *dot_x;
                let ddy = yi - dot_y;
                if ddx * ddx + ddy * ddy <= dot_r2 {
                    pixel = if idx == 1 {
                        accent_rgb
                    } else {
                        [0xF8, 0xFA, 0xFC]
                    };
                }
            }
            raw_scanlines.extend_from_slice(&pixel);
        }
    }

    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::best());
    zlib.write_all(&raw_scanlines)
        .map_err(|e| PackError::Archive {
            detail: format!("PNG zlib encode failed: {e}"),
        })?;
    let idat_payload = zlib.finish().map_err(|e| PackError::Archive {
        detail: format!("PNG zlib finish failed: {e}"),
    })?;

    let mut png = Vec::with_capacity(64 + idat_payload.len());
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&size.to_be_bytes());
    ihdr[4..8].copy_from_slice(&size.to_be_bytes());
    ihdr[8] = 8; // bit depth 8
    ihdr[9] = 2; // truecolor RGB
    ihdr[10] = 0; // deflate compression
    ihdr[11] = 0; // adaptive filtering
    ihdr[12] = 0; // non-interlaced
    write_png_chunk(&mut png, b"IHDR", &ihdr);
    write_png_chunk(&mut png, b"IDAT", &idat_payload);
    write_png_chunk(&mut png, b"IEND", &[]);

    Ok(png)
}

/// Verify PNG signature, `IHDR` dimensions (`expected_size x expected_size`), and every chunk CRC32.
pub fn verify_png_dimensions_and_crc(png: &[u8], expected_size: u32) -> Result<(), PackError> {
    if png.len() < 33 || &png[0..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(PackError::Archive {
            detail: "invalid PNG file signature".into(),
        });
    }
    let mut pos = 8usize;
    let mut saw_ihdr = false;
    let mut saw_iend = false;
    while pos + 12 <= png.len() {
        let len = u32::from_be_bytes([png[pos], png[pos + 1], png[pos + 2], png[pos + 3]]) as usize;
        let chunk_type = &png[pos + 4..pos + 8];
        let data_start = pos + 8;
        let data_end = data_start
            .checked_add(len)
            .ok_or_else(|| PackError::Archive {
                detail: "PNG chunk length overflow".into(),
            })?;
        if data_end + 4 > png.len() {
            return Err(PackError::Archive {
                detail: "PNG chunk truncated".into(),
            });
        }
        let expected_crc = u32::from_be_bytes([
            png[data_end],
            png[data_end + 1],
            png[data_end + 2],
            png[data_end + 3],
        ]);
        let mut crc = Crc::new();
        crc.update(&png[pos + 4..data_end]);
        if crc.sum() != expected_crc {
            return Err(PackError::Archive {
                detail: "PNG chunk CRC mismatch".into(),
            });
        }
        if chunk_type == b"IHDR" {
            if len != 13 {
                return Err(PackError::Archive {
                    detail: "PNG IHDR must be 13 bytes".into(),
                });
            }
            let w = u32::from_be_bytes([
                png[data_start],
                png[data_start + 1],
                png[data_start + 2],
                png[data_start + 3],
            ]);
            let h = u32::from_be_bytes([
                png[data_start + 4],
                png[data_start + 5],
                png[data_start + 6],
                png[data_start + 7],
            ]);
            if w != expected_size || h != expected_size {
                return Err(PackError::Archive {
                    detail: format!(
                        "PNG icon dimensions {w}x{h} do not match required {expected_size}x{expected_size}"
                    ),
                });
            }
            saw_ihdr = true;
        } else if chunk_type == b"IEND" {
            saw_iend = true;
            pos = data_end + 4;
            break;
        }
        pos = data_end + 4;
    }
    if !saw_ihdr || !saw_iend || pos != png.len() {
        return Err(PackError::Archive {
            detail: "incomplete or trailing bytes in PNG icon".into(),
        });
    }
    Ok(())
}

fn write_png_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
    let mut crc = Crc::new();
    crc.update(chunk_type);
    crc.update(data);
    out.extend_from_slice(&crc.sum().to_be_bytes());
}

fn validate_archive_path(rel: &str) -> Result<(), PackError> {
    let p = Path::new(rel);
    if rel.is_empty()
        || rel.len() > 200
        || rel.starts_with('/')
        || rel.ends_with('/')
        || rel.contains('\\')
        || rel.contains('\0')
        || p.components().any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(PackError::Archive {
            detail: format!("invalid archive relative path `{rel}`"),
        });
    }
    Ok(())
}

fn build_ustar_header(
    path: &str,
    mode: u32,
    size: u64,
    typeflag: u8,
) -> Result<[u8; 512], PackError> {
    let mut block = [0u8; 512];
    let (prefix, name) = split_ustar_path(path)?;
    block[0..name.len()].copy_from_slice(name.as_bytes());
    write_octal(&mut block[100..108], u64::from(mode), 7);
    write_octal(&mut block[108..116], 0, 7); // uid = 0
    write_octal(&mut block[116..124], 0, 7); // gid = 0
    write_octal(&mut block[124..136], size, 11);
    write_octal(&mut block[136..148], 0, 11); // mtime = 0
    block[148..156].fill(b' ');
    block[156] = typeflag;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    if !prefix.is_empty() {
        block[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    }

    let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
    let checksum_str = format!("{sum:06o}\0 ");
    block[148..156].copy_from_slice(checksum_str.as_bytes());
    Ok(block)
}

fn split_ustar_path(path: &str) -> Result<(&str, &str), PackError> {
    if path.len() <= 100 {
        return Ok(("", path));
    }
    for (idx, ch) in path.char_indices() {
        if ch == '/' {
            let prefix = &path[..idx];
            let name = &path[idx + 1..];
            if prefix.len() <= 155 && !name.is_empty() && name.len() <= 100 {
                return Ok((prefix, name));
            }
        }
    }
    Err(PackError::Archive {
        detail: format!("path `{path}` exceeds POSIX USTAR 155+100 byte limit"),
    })
}

fn write_octal(dest: &mut [u8], val: u64, digits: usize) {
    let formatted = format!("{val:0digits$o}");
    dest[..digits].copy_from_slice(&formatted.as_bytes()[..digits]);
    dest[digits] = 0;
}

fn verify_ustar_checksum(block: &[u8]) -> Result<(), PackError> {
    if &block[257..263] != b"ustar\0" {
        return Err(PackError::Archive {
            detail: "missing POSIX USTAR magic".into(),
        });
    }
    let stored = parse_octal(&block[148..156])?;
    let mut sum = 0u64;
    for (idx, byte) in block.iter().enumerate() {
        if (148..156).contains(&idx) {
            sum += u64::from(b' ');
        } else {
            sum += u64::from(*byte);
        }
    }
    if stored != sum {
        return Err(PackError::Archive {
            detail: "tar header checksum mismatch".into(),
        });
    }
    Ok(())
}

fn extract_ustar_path(block: &[u8]) -> Result<String, PackError> {
    let name = c_str_slice(&block[0..100])?;
    let prefix = c_str_slice(&block[345..500])?;
    if prefix.is_empty() {
        Ok(name.to_owned())
    } else {
        Ok(format!("{prefix}/{name}"))
    }
}

fn c_str_slice(bytes: &[u8]) -> Result<&str, PackError> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).map_err(|e| PackError::Archive {
        detail: format!("non-UTF-8 tar header string: {e}"),
    })
}

fn parse_octal(bytes: &[u8]) -> Result<u64, PackError> {
    let trimmed = c_str_slice(bytes)?.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(trimmed, 8).map_err(|e| PackError::Archive {
        detail: format!("invalid octal field `{trimmed}`: {e}"),
    })
}
