//! Private read-only API for one held file snapshot and its in-memory CRSQL owner.
#![deny(unsafe_code)]
#[cfg(not(target_os = "macos"))]
compile_error!("Only private macOS native snapshot sessions are verified; WASM is unimplemented");
#[allow(unsafe_code)]
mod checked_close;
mod create_fs;
pub mod initial_create;
#[allow(unsafe_code)]
mod native;
pub mod replacement;
mod replacement_fs;
mod schema;
mod types;
use chinwag_snapshot_read_owner_private::{ReadOwner, ReadReceipt, Refused};
use native::Connection;
pub use types::{Error, FiniteReal, Result, Rows, Value};

pub const MAX_ROWS: usize = 4096;
pub const MAX_VALUE_BYTES: usize = 65_536;
pub const MAX_QUERY_BYTES: usize = 1_048_576;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeCounts {
    pub opens: u64,
    pub checked_closes: u64,
}
/// Diagnostic process-local call counts, never cleanup or write authority.
pub fn native_counts_for_private_probe() -> NativeCounts {
    native::counts()
}
#[derive(Debug, PartialEq)]
pub struct ThreadContext {
    pub thread: Rows,
    pub messages: Rows,
    pub pins: Rows,
}
#[derive(Debug)]
pub enum SessionError {
    Header(&'static str),
    Native(Error),
    Owner(Refused),
    Contract(&'static str),
}
impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header(s) | Self::Contract(s) => f.write_str(s),
            Self::Native(e) => e.fmt(f),
            Self::Owner(e) => write!(f, "file owner: {}", e.reason),
        }
    }
}
impl std::error::Error for SessionError {}
type SessionResult<T> = std::result::Result<T, SessionError>;
/// Fields and ownership never escape. Drop retains the file marker; no receipt.
#[must_use = "Explicitly finish this original session or retain its marker; never replay an uncertain session"]
pub struct SnapshotSession {
    native: Option<Connection>,
    owner: Option<ReadOwner>,
    bootstrap: native::BootstrapReceipt,
}
#[derive(Debug)]
pub struct SessionReceipt {
    file: ReadReceipt,
    before_file_release: NativeCounts,
    owner_verified_after_native_close: bool,
}
impl SessionReceipt {
    pub fn file(&self) -> &ReadReceipt {
        &self.file
    }
    pub fn native_before_file_release(&self) -> NativeCounts {
        self.before_file_release
    }
    pub fn owner_verified_after_native_close(&self) -> bool {
        self.owner_verified_after_native_close
    }
}
impl SnapshotSession {
    pub fn from_owner(owner: ReadOwner) -> SessionResult<Self> {
        check_header(owner.image()).map_err(SessionError::Header)?;
        let expected = template_schema().map_err(SessionError::Native)?;
        let (connection, bootstrap) =
            Connection::open_image_for_probe(owner.image(), false).map_err(SessionError::Native)?;
        let connection = connection.ok_or(SessionError::Contract("No imported native owner"))?;
        let validation = (|| {
            check_engine(&connection)?;
            if connection.query(c"PRAGMA application_id", &[])?
                != vec![vec![Value::Integer(i64::from(schema::APPLICATION_ID))]]
                || connection.query(c"PRAGMA user_version", &[])?
                    != vec![vec![Value::Integer(i64::from(schema::SCHEMA_VERSION))]]
                || schema_objects(&connection)? != expected
            {
                return Err(Error::Contract(
                    "Snapshot header/schema fingerprint differs from pinned template",
                ));
            }
            if site_id(&connection)? != metadata_site(&connection)? {
                return Err(Error::Contract("Snapshot cached and metadata site differ"));
            }
            if bootstrap.calls != 1
                || bootstrap.deserialize_code != Some(0)
                || bootstrap.extension_code != Some(0)
                || bootstrap.open_code != 0
                || bootstrap.cancelled_temporary != 1
                || bootstrap.restored_original != 0
                || bootstrap.failed_open_checked_closed
            {
                return Err(Error::Contract("Unexpected bootstrap lifecycle receipt"));
            }
            Ok(())
        })();
        if let Err(error) = validation {
            return finish(connection, Err(error)).map_err(SessionError::Native);
        }
        Ok(Self {
            native: Some(connection),
            owner: Some(owner),
            bootstrap,
        })
    }
    fn connection(&self) -> SessionResult<&Connection> {
        self.native
            .as_ref()
            .ok_or(SessionError::Contract("Session native owner missing"))
    }
    pub fn site_id(&self) -> SessionResult<[u8; 16]> {
        site_id(self.connection()?).map_err(SessionError::Native)
    }
    pub fn schema_objects(&self) -> SessionResult<Rows> {
        schema_objects(self.connection()?).map_err(SessionError::Native)
    }
    pub fn callback_api_was_null(&self) -> bool {
        self.bootstrap.api_was_null
    }
    pub fn context(&self, thread_id: &str) -> SessionResult<ThreadContext> {
        let connection = self.connection()?;
        let values = texts(&[thread_id]).map_err(SessionError::Native)?;
        Ok(ThreadContext {
            thread: connection.query(c"SELECT id,repo_id,branch_ref,title,created_at_ms,updated_at_ms FROM threads WHERE id=?1 ORDER BY id", &values).map_err(SessionError::Native)?,
            messages: connection.query(c"SELECT id,thread_id,author_key_id,role,body,created_at_ms FROM messages WHERE thread_id=?1 ORDER BY id", &values).map_err(SessionError::Native)?,
            pins: connection.query(c"SELECT id,thread_id,file_path,symbol_hash,source_commit,body,created_at_ms FROM context_pins WHERE thread_id=?1 ORDER BY id", &values).map_err(SessionError::Native)?,
        })
    }
    pub fn tombstones(&self) -> SessionResult<Rows> {
        self.connection()?
            .query(
                c"SELECT id,repo_id,branch_ref,source_commit,file_path,symbol_hash,attempted_action,failure,reason,alternative,evidence_hash,created_at_ms FROM tombstones ORDER BY created_at_ms DESC, id",
                &[],
            )
            .map_err(SessionError::Native)
    }
    pub fn verified_invariants(&self) -> SessionResult<Rows> {
        self.connection()?
            .query(
                c"SELECT id,repo_id,branch_ref,source_commit,file_path,symbol_hash,invariant,ci_run_id,ci_receipt_hash,verified_at_ms FROM verified_invariants ORDER BY verified_at_ms DESC, id",
                &[],
            )
            .map_err(SessionError::Native)
    }
    pub fn all_pins(&self) -> SessionResult<Rows> {
        self.connection()?
            .query(
                c"SELECT id,thread_id,file_path,symbol_hash,source_commit,body,created_at_ms FROM context_pins ORDER BY created_at_ms DESC, id",
                &[],
            )
            .map_err(SessionError::Native)
    }
    pub fn crdb_stats(&self) -> SessionResult<Rows> {
        self.connection()?
            .query(
                c"SELECT (SELECT count(*) FROM threads), (SELECT count(*) FROM messages), (SELECT count(*) FROM context_pins), (SELECT count(*) FROM tombstones), (SELECT count(*) FROM verified_invariants), crsql_db_version()",
                &[],
            )
            .map_err(SessionError::Native)
    }
    pub fn finish(mut self) -> SessionResult<SessionReceipt> {
        let mut native = self
            .native
            .take()
            .ok_or(SessionError::Contract("Session native owner missing"))?;
        native.close().map_err(SessionError::Native)?;
        let before_file_release = native::counts();
        let mut owner = self
            .owner
            .take()
            .ok_or(SessionError::Contract("Session file owner missing"))?;
        owner.verify_unchanged().map_err(SessionError::Owner)?;
        let file = owner.finish_read().map_err(SessionError::Owner)?;
        Ok(SessionReceipt {
            file,
            before_file_release,
            owner_verified_after_native_close: true,
        })
    }
}
fn check_header(image: &[u8]) -> std::result::Result<(), &'static str> {
    if image.len() < 100 || image.len() > MAX_IMAGE_BYTES {
        return Err("Snapshot header size");
    }
    let h = &image[..100];
    if &h[..16] != b"SQLite format 3\0" {
        return Err("Snapshot header magic");
    }
    let page = match u16::from_be_bytes([h[16], h[17]]) {
        1 => 65536,
        value => usize::from(value),
    };
    if !(512..=65536).contains(&page)
        || !page.is_power_of_two()
        || !image.len().is_multiple_of(page)
        || h[18..20] != [1, 1]
        || h[21..24] != [64, 32, 32]
    {
        return Err("Snapshot page format or journal mode");
    }
    let word = |n: usize| u32::from_be_bytes([h[n], h[n + 1], h[n + 2], h[n + 3]]);
    if word(44) != 4
        || word(56) != 1
        || word(60) != schema::SCHEMA_VERSION as u32
        || word(68) != schema::APPLICATION_ID as u32
    {
        return Err("Snapshot schema format, encoding, version, or application ID");
    }
    Ok(())
}
fn site_id(connection: &Connection) -> Result<[u8; 16]> {
    site_query(connection, c"SELECT crsql_site_id()")
}
fn metadata_site(connection: &Connection) -> Result<[u8; 16]> {
    site_query(
        connection,
        c"SELECT site_id FROM crsql_site_id WHERE ordinal=0",
    )
}
fn site_query(connection: &Connection, query: &std::ffi::CStr) -> Result<[u8; 16]> {
    match connection.query(query, &[])?.as_slice() {
        [row] => match row.as_slice() {
            [Value::Blob(bytes)] => bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::Contract("Site length")),
            _ => Err(Error::Contract("Site type")),
        },
        _ => Err(Error::Contract("Site row count")),
    }
}
fn template_schema() -> Result<Rows> {
    let native = Connection::open_template_memory()?;
    let outcome = initialize_schema(&native).and_then(|()| schema_objects(&native));
    finish(native, outcome)
}
fn texts(values: &[&str]) -> Result<Vec<Value>> {
    values
        .iter()
        .map(|value| {
            if value.len() > MAX_VALUE_BYTES {
                Err(Error::Contract("Private SQL value limit"))
            } else {
                Ok(Value::Text((*value).into()))
            }
        })
        .collect()
}
fn check_engine(native: &Connection) -> Result<()> {
    if native.query(
        c"SELECT sqlite_version(),sqlite_compileoption_used('THREADSAFE=1')",
        &[],
    )? != vec![vec![Value::Text("3.42.0".into()), Value::Integer(1)]]
    {
        return Err(Error::Contract("Unexpected engine version or thread mode"));
    }
    Ok(())
}
fn initialize_schema(native: &Connection) -> Result<()> {
    check_engine(native)?;
    transaction(native, || {
        for table in &schema::TABLES {
            native.query(table.ddl, &[])?;
            if native.query(
                c"SELECT crsql_as_crr(?1)",
                &[Value::Text(table.name.into())],
            )? != vec![vec![Value::Text("OK".into())]]
            {
                return Err(Error::Contract("Unexpected CRR registration result"));
            }
        }
        for (pragma, value) in [
            ("application_id", schema::APPLICATION_ID),
            ("user_version", schema::SCHEMA_VERSION),
        ] {
            let sql = std::ffi::CString::new(format!("PRAGMA {pragma}={value}"))
                .map_err(|_| Error::Contract("NUL in fixed header SQL"))?;
            native.query(&sql, &[])?;
        }
        Ok(())
    })
}
fn schema_objects(native: &Connection) -> Result<Rows> {
    native.query(
        c"SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name,sql",
        &[],
    )
}
fn finish<T>(mut native: Connection, outcome: Result<T>) -> Result<T> {
    match (outcome, native.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(Error::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}
fn transaction<T>(native: &Connection, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    native.query(c"BEGIN", &[])?;
    let mut guard = Rollback {
        connection: native,
        pending: true,
    };
    match operation().and_then(|value| {
        native.query(c"COMMIT", &[])?;
        Ok(value)
    }) {
        Ok(value) => {
            guard.pending = false;
            Ok(value)
        }
        Err(operation) => {
            let rollback = native.query(c"ROLLBACK", &[]);
            guard.pending = false;
            match rollback {
                Ok(_) => Err(operation),
                Err(cleanup) => Err(Error::Rollback {
                    operation: Box::new(operation),
                    cleanup: Box::new(cleanup),
                }),
            }
        }
    }
}
struct Rollback<'a> {
    connection: &'a Connection,
    pending: bool,
}
impl Drop for Rollback<'_> {
    fn drop(&mut self) {
        if self.pending {
            let _ = self.connection.query(c"ROLLBACK", &[]);
        }
    }
}
