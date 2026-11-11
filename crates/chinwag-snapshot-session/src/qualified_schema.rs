//! Fixed V2 observation schema. V1 admission and its factory remain unchanged.
#![forbid(unsafe_code)]

use crate::{
    Error, Result, Rows, SessionError, Value, native::Connection, qualified::RecordFamily,
};
use std::ffi::CStr;

pub(crate) const SCHEMA_VERSION: i32 = 2;

const fn sql(bytes: &'static [u8]) -> &'static CStr {
    match CStr::from_bytes_with_nul(bytes) {
        Ok(sql) => sql,
        Err(_) => panic!("invalid fixed qualified SQL"),
    }
}

pub(crate) struct FamilyTable {
    pub name: &'static str,
    pub replicated: bool,
    pub ddl: &'static CStr,
    pub insert: &'static CStr,
    pub by_identity: &'static CStr,
    pub by_variant: &'static CStr,
    pub by_logical_key: &'static CStr,
}

// Non-key CRR columns are nullable on purpose. A partially replicated row is
// held by the typed loader; empty source identities are never qualified defaults.
macro_rules! family {
    ($name:literal, $replicated:literal) => {
        FamilyTable {
            name: $name,
            replicated: $replicated,
            ddl: sql(concat!("CREATE TABLE ", $name, "(id TEXT PRIMARY KEY NOT NULL,workspace_id TEXT,observation_id TEXT,record_sha256 BLOB,total_length BLOB,part_count INTEGER,logical_key BLOB,family INTEGER)\0").as_bytes()),
            insert: sql(concat!("INSERT INTO ", $name, "(id,workspace_id,observation_id,record_sha256,total_length,part_count,logical_key,family) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)\0").as_bytes()),
            by_identity: sql(concat!("SELECT id,workspace_id,observation_id,record_sha256,total_length,part_count,logical_key,family FROM ", $name, " WHERE workspace_id=?1 AND observation_id=?2 ORDER BY id LIMIT 2\0").as_bytes()),
            by_variant: sql(concat!("SELECT id,workspace_id,observation_id,record_sha256,total_length,part_count,logical_key,family FROM ", $name, " WHERE id=?1\0").as_bytes()),
            by_logical_key: sql(concat!("SELECT DISTINCT observation_id FROM ", $name, " WHERE workspace_id=?1 AND logical_key=?2 AND observation_id>?3 ORDER BY observation_id LIMIT ?4\0").as_bytes()),
        }
    };
}

pub(crate) const FAMILIES: [FamilyTable; 9] = [
    family!("task_sources", true),
    family!("task_projection", true),
    family!("task_dependency_edges", true),
    family!("task_events", true),
    family!("task_message_bindings", true),
    family!("task_assignments", true),
    family!("task_acceptances", true),
    family!("source_write_intents", false),
    family!("scheduler_admissions", false),
];

pub(crate) fn family_table(family: RecordFamily) -> &'static FamilyTable {
    use RecordFamily::*;
    &FAMILIES[match family {
        Source => 0,
        Projection => 1,
        Dependency => 2,
        Event => 3,
        Message => 4,
        Assignment => 5,
        Acceptance => 6,
        SourceWriteIntent => 7,
        SchedulerAdmission => 8,
    }]
}

pub(crate) const OBSERVATION_CHUNKS_DDL: &CStr = c"CREATE TABLE qualified_observation_chunks(id TEXT PRIMARY KEY NOT NULL,record_key TEXT,ordinal INTEGER,bytes BLOB)";
pub(crate) const LOCAL_CHUNKS_DDL: &CStr = c"CREATE TABLE qualified_local_chunks(id TEXT PRIMARY KEY NOT NULL,record_key TEXT NOT NULL,ordinal INTEGER NOT NULL,bytes BLOB NOT NULL)";
pub(crate) const REF_DDL: &CStr = c"CREATE TABLE qualified_task_refs(id TEXT PRIMARY KEY NOT NULL,record_key TEXT NOT NULL,ordinal INTEGER NOT NULL,canonical BLOB NOT NULL,task_ref_sha256 BLOB NOT NULL,workspace_id TEXT NOT NULL,repo_id TEXT NOT NULL,task_source_id TEXT NOT NULL,source_generation BLOB NOT NULL,canonical_task_path TEXT NOT NULL,task_id TEXT NOT NULL,task_spec_sha256 BLOB NOT NULL,task_status_rev BLOB NOT NULL,file_cas_rev BLOB NOT NULL,baseline_algorithm TEXT NOT NULL,baseline_bytes BLOB NOT NULL)";
pub(crate) const ORIGINAL_DDL: &CStr = c"CREATE TABLE qualified_originals(id TEXT PRIMARY KEY NOT NULL,original_key BLOB NOT NULL,family INTEGER NOT NULL,workspace_id TEXT NOT NULL,record_key TEXT NOT NULL,record_sha256 BLOB NOT NULL,binding_sha256 BLOB NOT NULL)";
pub(crate) const QUARANTINE_DDL: &CStr = c"CREATE TABLE qualified_quarantine(id TEXT PRIMARY KEY NOT NULL,identity BLOB NOT NULL,record_key TEXT NOT NULL,record_sha256 BLOB NOT NULL,family INTEGER NOT NULL,workspace_id TEXT NOT NULL,observation_id TEXT NOT NULL,total_length BLOB NOT NULL,part_count INTEGER NOT NULL,logical_key BLOB NOT NULL,original_key BLOB)";
pub(crate) const MIGRATION_DDL: &CStr = c"CREATE TABLE qualified_migrations(id TEXT PRIMARY KEY NOT NULL,workspace_id TEXT NOT NULL,operation_id TEXT NOT NULL,request_sha256 BLOB NOT NULL,from_version INTEGER NOT NULL,to_version INTEGER NOT NULL,outcome TEXT NOT NULL)";
pub(crate) const LEGACY_DDL: &CStr = c"CREATE TABLE qualified_legacy_associations(id TEXT PRIMARY KEY NOT NULL,workspace_id TEXT NOT NULL,legacy_thread_id TEXT NOT NULL,legacy_message_id TEXT NOT NULL,association_id TEXT NOT NULL,legacy_sha256 BLOB NOT NULL,migration_operation_id TEXT NOT NULL,association BLOB NOT NULL,association_sha256 BLOB NOT NULL,inferred_legacy INTEGER NOT NULL)";

pub(crate) const OBSERVATION_PARTS: &CStr = c"SELECT ordinal,bytes FROM qualified_observation_chunks WHERE record_key=?1 ORDER BY ordinal LIMIT 5";
pub(crate) const LOCAL_PARTS: &CStr = c"SELECT ordinal,bytes FROM qualified_local_chunks WHERE record_key=?1 ORDER BY ordinal LIMIT 5";
pub(crate) const INSERT_OBSERVATION_PART: &CStr =
    c"INSERT INTO qualified_observation_chunks(id,record_key,ordinal,bytes) VALUES(?1,?2,?3,?4)";
pub(crate) const INSERT_LOCAL_PART: &CStr =
    c"INSERT INTO qualified_local_chunks(id,record_key,ordinal,bytes) VALUES(?1,?2,?3,?4)";
pub(crate) const REFS: &CStr = c"SELECT ordinal,canonical,task_ref_sha256,workspace_id,repo_id,task_source_id,source_generation,canonical_task_path,task_id,task_spec_sha256,task_status_rev,file_cas_rev,baseline_algorithm,baseline_bytes FROM qualified_task_refs WHERE record_key=?1 ORDER BY ordinal LIMIT 3";
pub(crate) const INSERT_REF: &CStr = c"INSERT INTO qualified_task_refs(id,record_key,ordinal,canonical,task_ref_sha256,workspace_id,repo_id,task_source_id,source_generation,canonical_task_path,task_id,task_spec_sha256,task_status_rev,file_cas_rev,baseline_algorithm,baseline_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)";

/// Caller must hold the one migration transaction after validating its V1 owner.
pub(crate) fn upgrade_v1(native: &Connection) -> Result<()> {
    for table in &FAMILIES {
        native.query(table.ddl, &[])?;
        if table.replicated {
            register_crr(native, table.name)?;
        }
    }
    native.query(OBSERVATION_CHUNKS_DDL, &[])?;
    register_crr(native, "qualified_observation_chunks")?;
    for ddl in [
        LOCAL_CHUNKS_DDL,
        REF_DDL,
        ORIGINAL_DDL,
        QUARANTINE_DDL,
        MIGRATION_DDL,
        LEGACY_DDL,
    ] {
        native.query(ddl, &[])?;
    }
    native.query(c"PRAGMA user_version=2", &[])?;
    Ok(())
}

fn register_crr(native: &Connection, table: &'static str) -> Result<()> {
    if native.query(
        c"SELECT crsql_as_crr('main', ?1)",
        &[Value::Text(table.into())],
    )? != vec![vec![Value::Text("OK".into())]]
    {
        return Err(Error::Contract("Unexpected qualified CRR registration"));
    }
    Ok(())
}

fn template_schema() -> Result<Rows> {
    let native = Connection::open_template_memory()?;
    let outcome = crate::initialize_schema(&native)
        .and_then(|()| crate::transaction(&native, || upgrade_v1(&native)))
        .and_then(|()| crate::schema_objects(&native));
    crate::finish(native, outcome)
}

pub(crate) fn validate_v2(native: &Connection) -> Result<()> {
    crate::check_engine(native)?;
    if native.query(c"PRAGMA application_id", &[])?
        != vec![vec![Value::Integer(i64::from(
            crate::schema::APPLICATION_ID,
        ))]]
        || native.query(c"PRAGMA user_version", &[])?
            != vec![vec![Value::Integer(i64::from(SCHEMA_VERSION))]]
        || crate::schema_objects(native)? != template_schema()?
    {
        return Err(Error::Contract("Qualified V2 schema fingerprint differs"));
    }
    if crate::site_id(native)? != crate::metadata_site(native)? {
        return Err(Error::Contract("Qualified V2 site metadata differs"));
    }
    Ok(())
}

fn check_header(image: &[u8]) -> std::result::Result<(), &'static str> {
    if image.len() < 100 || image.len() > crate::MAX_IMAGE_BYTES {
        return Err("Qualified snapshot header size");
    }
    let h = &image[..100];
    if &h[..16] != b"SQLite format 3\0" {
        return Err("Qualified snapshot header magic");
    }
    let page = match u16::from_be_bytes([h[16], h[17]]) {
        1 => 65536,
        value => usize::from(value),
    };
    let word = |n: usize| u32::from_be_bytes([h[n], h[n + 1], h[n + 2], h[n + 3]]);
    if !(512..=65536).contains(&page)
        || !page.is_power_of_two()
        || !image.len().is_multiple_of(page)
        || h[18..20] != [1, 1]
        || h[21..24] != [64, 32, 32]
        || word(44) != 4
        || word(56) != 1
        || word(60) != SCHEMA_VERSION as u32
        || word(68) != crate::schema::APPLICATION_ID as u32
    {
        return Err("Qualified snapshot format/version/application");
    }
    Ok(())
}

pub(crate) fn open_v2_image(
    image: &[u8],
) -> std::result::Result<(Connection, crate::native::BootstrapReceipt), SessionError> {
    check_header(image).map_err(SessionError::Header)?;
    let (native, bootstrap) =
        Connection::open_image_for_probe(image, false).map_err(SessionError::Native)?;
    let native = native.ok_or(SessionError::Contract("No qualified native owner"))?;
    let validation = validate_v2(&native).and_then(|()| {
        if bootstrap.calls != 1
            || bootstrap.deserialize_code != Some(0)
            || bootstrap.extension_code != Some(0)
            || bootstrap.open_code != 0
            || bootstrap.cancelled_temporary != 1
            || bootstrap.restored_original != 0
            || bootstrap.failed_open_checked_closed
        {
            return Err(Error::Contract("Unexpected qualified bootstrap lifecycle"));
        }
        Ok(())
    });
    if let Err(error) = validation {
        return crate::finish(native, Err(error)).map_err(SessionError::Native);
    }
    Ok((native, bootstrap))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p010_schema_foundation_is_real_v2_and_only_observations_are_crrs() {
        let native = Connection::open_template_memory().unwrap();
        let outcome = (|| -> Result<()> {
            crate::initialize_schema(&native)?;
            let v1_schema = crate::schema_objects(&native)?;
            // Derive the extension's actual fixed schema suffixes from an
            // existing CRR, rather than querying an invented status function.
            let crr_suffixes: Vec<String> = v1_schema
                .iter()
                .filter_map(|row| match row.as_slice() {
                    [Value::Text(_), Value::Text(name), _, _] => name
                        .strip_prefix("threads")
                        .filter(|suffix| suffix.contains("crsql"))
                        .map(str::to_owned),
                    _ => None,
                })
                .collect();
            assert!(
                !crr_suffixes.is_empty(),
                "real V1 CRR objects: {v1_schema:?}"
            );
            crate::transaction(&native, || upgrade_v1(&native))?;
            validate_v2(&native)?;
            let v2_schema = crate::schema_objects(&native)?;
            assert!(
                v1_schema.iter().all(|row| v2_schema.contains(row)),
                "V2 must preserve every original V1 schema object"
            );
            let names: Vec<&str> = v2_schema
                .iter()
                .filter_map(|row| match row.as_slice() {
                    [_, Value::Text(name), _, _] => Some(name.as_str()),
                    _ => None,
                })
                .collect();
            for table in &FAMILIES {
                assert!(names.contains(&table.name));
                for suffix in &crr_suffixes {
                    let derived = format!("{}{suffix}", table.name);
                    assert_eq!(
                        names.contains(&derived.as_str()),
                        table.replicated,
                        "actual CRR object membership for {derived}"
                    );
                }
            }
            for suffix in &crr_suffixes {
                assert!(names.contains(&format!("qualified_observation_chunks{suffix}").as_str()));
                for local in [
                    "qualified_local_chunks",
                    "qualified_task_refs",
                    "qualified_originals",
                    "qualified_quarantine",
                    "qualified_migrations",
                    "qualified_legacy_associations",
                ] {
                    assert!(names.contains(&local));
                    assert!(!names.contains(&format!("{local}{suffix}").as_str()));
                }
            }
            // Header/version checks and the exact V1 schema remain strict.
            let image = native.export_image_for_original_writer()?;
            assert!(crate::check_header(&image).is_err());
            assert!(check_header(&image).is_ok());
            println!(
                "real schema V1 objects={}, V2 objects={}, measured CRR suffixes={crr_suffixes:?}, seven new families plus chunks replicated; local journals/indexes remain local",
                v1_schema.len(),
                v2_schema.len()
            );
            Ok(())
        })();
        crate::finish(native, outcome).unwrap();
    }
}
