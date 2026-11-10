// Copyright (c) 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{Event, Manifest, digest, duckdb_ffi::DuckDb, model::MAX_INPUT};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::Path,
};
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
pub(crate) fn literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}
pub fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = crate::namespace::open_checked(path, false)?;
    let m = file.metadata().map_err(error)?;
    if !m.is_file() || m.nlink() != 1 || m.len() > MAX_INPUT {
        return Err("input is not a bounded regular nonlinked file".into());
    }
    let mut out = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_INPUT + 1)
        .read_to_end(&mut out)
        .map_err(error)?;
    if out.len() as u64 > MAX_INPUT {
        return Err("input grew past bound".into());
    }
    Ok(out)
}
pub(crate) fn private_dir(path: &Path) -> Result<(), String> {
    let directory = crate::namespace::open_checked(path, true)?;
    let m = directory.metadata().map_err(error)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.mode() & 0o777 != 0o700 {
        return Err("dataset directory must be a physical mode0700 directory".into());
    }
    Ok(())
}
fn immutable(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = crate::namespace::create_file(path)?;
    f.write_all(bytes).map_err(error)?;
    f.sync_all().map_err(error)
}
pub fn events(path: &Path) -> Result<Vec<Event>, String> {
    events_bytes(&read_bounded(path)?)
}
pub(crate) fn events_bytes(data: &[u8]) -> Result<Vec<Event>, String> {
    if data.len() as u64 > MAX_INPUT {
        return Err("input outside byte bound".into());
    }
    let text = std::str::from_utf8(data).map_err(error)?;
    let mut ids = BTreeSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let e: Event = serde_json::from_str(line).map_err(error)?;
        e.validate()?;
        if !ids.insert(e.id.clone()) {
            return Err("duplicate event id".into());
        }
        out.push(e);
    }
    if out.is_empty() || out.len() > 10000 {
        return Err("event count outside archive bound".into());
    }
    Ok(out)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dataset {
    manifest: Manifest,
    jsonl_sha256: String,
    parquet_sha256: String,
}
pub(crate) fn connect(path: &Path) -> Result<DuckDb, String> {
    let db = DuckDb::open(path)?;
    db.execute("SET autoinstall_known_extensions=false; SET autoload_known_extensions=false; SET memory_limit='128MB'; SET threads=1;")?;
    Ok(db)
}
pub fn ingest(manifest: &Manifest, input: &Path, root: &Path) -> Result<serde_json::Value, String> {
    manifest.validate()?;
    let source = events(input)?;
    let mut canonical = String::new();
    for event in &source {
        canonical.push_str(&manifest.approve(event)?);
        canonical.push('\n');
    }
    if canonical.len() as u64 > MAX_INPUT {
        return Err("canonical batch exceeds limit".into());
    }
    private_dir(root)?;
    if fs::read_dir(root).map_err(error)?.next().is_some() {
        return Err("dataset root must be empty; archives are immutable".into());
    }
    crate::namespace::mkdir_private(&root.join("objects"))?;
    crate::namespace::mkdir_private(&root.join("cache"))?;
    let jsonl_sha256 = digest(canonical.as_bytes());
    immutable(
        &root.join("objects").join(format!("{jsonl_sha256}.jsonl")),
        canonical.as_bytes(),
    )?;
    let parquet = root.join("objects").join(format!("{jsonl_sha256}.parquet"));
    let db = connect(&root.join("cache/catalog.duckdb"))?;
    db.execute(
        "CREATE TABLE events(id VARCHAR PRIMARY KEY,ts VARCHAR,body VARCHAR,event_json VARCHAR);",
    )?;
    for event in &source {
        db.execute(&format!(
            "INSERT INTO events VALUES ({},{},{},{});",
            literal(&event.id),
            literal(&event.timestamp_utc),
            literal(&event.text),
            literal(&event.canonical()?)
        ))?;
    }
    db.execute(&format!("SET allowed_paths=[{}]; SET enable_external_access=false; COPY events TO {} (FORMAT PARQUET);",literal(parquet.to_str().ok_or("nonUTF8 path")?),literal(parquet.to_str().ok_or("nonUTF8 path")?)))?;
    let parquet_sha256 = digest(&read_bounded(&parquet)?);
    let dataset = Dataset {
        manifest: manifest.clone(),
        jsonl_sha256: jsonl_sha256.clone(),
        parquet_sha256: parquet_sha256.clone(),
    };
    immutable(
        &root.join("dataset.json"),
        &serde_json::to_vec(&dataset).map_err(error)?,
    )?;
    Ok(
        serde_json::json!({"ok":true,"classification":"derived_context","events":source.len(),"jsonl_sha256":jsonl_sha256,"parquet_sha256":parquet_sha256,"cloud_upload":"not_performed"}),
    )
}
pub struct Archive {
    db: DuckDb,
    manifest: Manifest,
}
impl Archive {
    pub fn open(root: &Path) -> Result<Self, String> {
        private_dir(root)?;
        private_dir(&root.join("objects"))?;
        private_dir(&root.join("cache"))?;
        let ds: Dataset =
            serde_json::from_slice(&read_bounded(&root.join("dataset.json"))?).map_err(error)?;
        ds.manifest.validate()?;
        for h in [&ds.jsonl_sha256, &ds.parquet_sha256] {
            if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid object digest".into());
            }
        }
        let jsonl = root
            .join("objects")
            .join(format!("{}.jsonl", ds.jsonl_sha256));
        let parquet = root
            .join("objects")
            .join(format!("{}.parquet", ds.jsonl_sha256));
        if digest(&read_bounded(&jsonl)?) != ds.jsonl_sha256
            || digest(&read_bounded(&parquet)?) != ds.parquet_sha256
        {
            return Err("immutable object digest mismatch".into());
        }
        for e in events(&jsonl)? {
            ds.manifest.approve(&e)?;
        }
        let db = connect(Path::new(":memory:"))?;
        db.execute(&format!("SET allowed_paths=[{}]; SET enable_external_access=false; CREATE TABLE events AS SELECT * FROM read_parquet({});",literal(parquet.to_str().ok_or("nonUTF8 path")?),literal(parquet.to_str().ok_or("nonUTF8 path")?)))?;
        Ok(Self {
            db,
            manifest: ds.manifest,
        })
    }
    pub fn search(&self, query: &str, limit: usize) -> Result<serde_json::Value, String> {
        if query.is_empty() || query.len() > 256 || !(1..=20).contains(&limit) {
            return Err("search requires1..256bytes and limit1..20".into());
        }
        let rows=self.db.query_rows_varchar(&format!("SELECT event_json FROM events WHERE contains(lower(body),lower({})) ORDER BY ts,id LIMIT {limit}",literal(query)))?;
        let mut out = Vec::new();
        for row in rows {
            let event: Event = serde_json::from_str(&row[0]).map_err(error)?;
            self.manifest.approve(&event)?;
            out.push(serde_json::json!({"id":event.id,"timestamp_utc":event.timestamp_utc,"role":event.role,"channel":event.channel,"snippet":event.text.chars().take(200).collect::<String>(),"supersedes":event.supersedes}));
        }
        Ok(serde_json::json!({"classification":"derived_context","results":out}))
    }
    pub fn read_event(&self, id: &str) -> Result<Event, String> {
        if !crate::model::token(id) {
            return Err("invalid event id".into());
        }
        let rows = self.db.query_rows_varchar(&format!(
            "SELECT event_json FROM events WHERE id={} LIMIT 1",
            literal(id)
        ))?;
        let row = rows.first().ok_or("event not found")?;
        let event: Event = serde_json::from_str(&row[0]).map_err(error)?;
        self.manifest.approve(&event)?;
        Ok(event)
    }
}
