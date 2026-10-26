// Native FFI boundary. No Rust allocation is handed to C.
use crate::types::{Error, FiniteReal, Result, Rows, Value};
use std::cell::Cell;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::marker::PhantomData;
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

type Handle = *mut c_void;
type Destructor = Option<unsafe extern "C" fn(Handle)>;
type Extension = unsafe extern "C" fn(Handle, *mut *mut c_char, *const c_void) -> c_int;
type ErasedExtension = unsafe extern "C" fn();
unsafe extern "C" {
    fn sqlite3_initialize() -> c_int;
    fn sqlite3_auto_extension(entry: ErasedExtension) -> c_int;
    fn sqlite3_cancel_auto_extension(entry: ErasedExtension) -> c_int;
    fn sqlite3_crsqlite_init(db: Handle, error: *mut *mut c_char, api: *const c_void) -> c_int;
    fn sqlite3_threadsafe() -> c_int;
    fn sqlite3_open_v2(
        path: *const c_char,
        db: *mut Handle,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    fn sqlite3_db_readonly(db: Handle, name: *const c_char) -> c_int;
    fn sqlite3_close(db: Handle) -> c_int;
    fn sqlite3_close_v2(db: Handle) -> c_int;
    fn sqlite3_serialize(db: Handle, name: *const c_char, size: *mut i64, flags: u32) -> *mut u8;
    fn sqlite3_deserialize(
        db: Handle,
        name: *const c_char,
        data: *mut u8,
        size: i64,
        capacity: i64,
        flags: u32,
    ) -> c_int;
    fn sqlite3_malloc64(size: u64) -> *mut c_void;
    fn sqlite3_free(allocation: *mut c_void);
    fn sqlite3_errmsg(db: Handle) -> *const c_char;
    fn sqlite3_prepare_v2(
        db: Handle,
        sql: *const c_char,
        n: c_int,
        stmt: *mut Handle,
        tail: *mut *const c_char,
    ) -> c_int;
    fn sqlite3_bind_parameter_count(stmt: Handle) -> c_int;
    fn sqlite3_bind_null(stmt: Handle, index: c_int) -> c_int;
    fn sqlite3_bind_int64(stmt: Handle, index: c_int, value: i64) -> c_int;
    fn sqlite3_bind_double(stmt: Handle, index: c_int, value: f64) -> c_int;
    fn sqlite3_bind_text(
        stmt: Handle,
        index: c_int,
        value: *const c_char,
        length: c_int,
        drop: Destructor,
    ) -> c_int;
    fn sqlite3_bind_blob(
        stmt: Handle,
        index: c_int,
        value: *const c_void,
        length: c_int,
        drop: Destructor,
    ) -> c_int;
    fn sqlite3_step(stmt: Handle) -> c_int;
    fn sqlite3_finalize(stmt: Handle) -> c_int;
    fn sqlite3_column_count(stmt: Handle) -> c_int;
    fn sqlite3_column_type(stmt: Handle, index: c_int) -> c_int;
    fn sqlite3_column_int64(stmt: Handle, index: c_int) -> i64;
    fn sqlite3_column_double(stmt: Handle, index: c_int) -> f64;
    fn sqlite3_column_text(stmt: Handle, index: c_int) -> *const u8;
    fn sqlite3_column_blob(stmt: Handle, index: c_int) -> *const c_void;
    fn sqlite3_column_bytes(stmt: Handle, index: c_int) -> c_int;
}
struct InitState {
    blocked: bool,
}
static OPEN_CALLS: AtomicU64 = AtomicU64::new(0);
static CHECKED_CLOSES: AtomicU64 = AtomicU64::new(0);
pub(crate) fn counts() -> crate::NativeCounts {
    crate::NativeCounts {
        opens: OPEN_CALLS.load(Ordering::SeqCst),
        checked_closes: CHECKED_CLOSES.load(Ordering::SeqCst),
    }
}
static INITIALIZE: Mutex<InitState> = Mutex::new(InitState { blocked: false });
thread_local! {
    static IMAGE_BOOTSTRAP: Cell<*mut BootstrapContext> = const { Cell::new(ptr::null_mut()) };
}
struct BootstrapContext {
    allocation: Option<Allocation>,
    size: i64,
    refuse_before_import: bool,
    calls: u32,
    deserialize_code: Option<c_int>,
    extension_code: Option<c_int>,
    api_was_null: bool,
}
#[derive(Debug)]
pub(crate) struct BootstrapReceipt {
    pub calls: u32,
    pub deserialize_code: Option<c_int>,
    pub extension_code: Option<c_int>,
    pub api_was_null: bool,
    pub open_code: c_int,
    pub cancelled_temporary: c_int,
    pub restored_original: c_int,
    pub failed_open_checked_closed: bool,
}
// The pinned header requires erasing this documented three-argument C entry
// to void(*)(void). SQLite casts it back before calling; never invoke erased.
fn erase(entry: Extension) -> ErasedExtension {
    unsafe { std::mem::transmute::<Extension, ErasedExtension>(entry) }
}
// No Rust allocations, indexing, panicking locks, or fallible destructors here.
// Both profiles use panic=abort; no unwind crosses this C ABI. A process abort
// yields no restoration/close receipt. The pointer lives through synchronous open.
unsafe extern "C" fn import_before_extension(
    db: Handle,
    error: *mut *mut c_char,
    api: *const c_void,
) -> c_int {
    let context = match IMAGE_BOOTSTRAP.try_with(Cell::get) {
        Ok(pointer) if !pointer.is_null() && !db.is_null() => pointer,
        _ => return 1,
    };
    if unsafe { (*context).calls } != 0 {
        return 1;
    }
    unsafe {
        (*context).calls = 1;
        (*context).api_was_null = api.is_null();
    }
    if unsafe { (*context).refuse_before_import } {
        return 4;
    }
    let allocation = match unsafe { (*context).allocation.take() } {
        Some(allocation) => allocation,
        None => return 1,
    };
    let pointer = allocation.0.as_ptr();
    // FREEONCLOSE owns this SQLite allocation on ordinary failure too. The
    // bounded size and valid handle satisfy deserialize's ownership contract.
    std::mem::forget(allocation);
    let code = unsafe {
        sqlite3_deserialize(
            db,
            c"main".as_ptr(),
            pointer,
            (*context).size,
            crate::MAX_IMAGE_BYTES as i64,
            1,
        )
    };
    unsafe { (*context).deserialize_code = Some(code) };
    if code != 0 {
        return code;
    }
    // Forward the exact opaque table received from SQLite, including NULL in
    // this OMIT_LOAD_EXTENSION build. No fabricated sqlite3_api_routines.
    let code = unsafe { sqlite3_crsqlite_init(db, error, api) };
    unsafe { (*context).extension_code = Some(code) };
    code
}
pub(crate) struct Connection {
    handle: Option<NonNull<c_void>>,
    _owner_thread: PhantomData<Rc<()>>,
}
impl Connection {
    pub(crate) fn open_template_memory() -> Result<Self> {
        // MEMORY and CREATE apply only to this literal private in-memory name.
        Self::open(c":memory:", 2 | 4 | 0x80, false)
    }
    fn open(path: &CStr, access: c_int, readonly: bool) -> Result<Self> {
        let _initialize = INITIALIZE
            .lock()
            .map_err(|_| Error::Contract("Native init mutex poisoned"))?;
        if _initialize.blocked {
            return Err(Error::Contract("Native bootstrap state blocked"));
        }
        if unsafe { sqlite3_threadsafe() } != 1 {
            return Err(Error::Contract("Expected THREADSAFE=1"));
        }
        let mut raw = ptr::null_mut();
        let code = unsafe {
            OPEN_CALLS.fetch_add(1, Ordering::SeqCst);
            sqlite3_open_v2(
                path.as_ptr(),
                &mut raw,
                access | 0x00010000 | 0x01000000,
                ptr::null(),
            )
        };
        let connection = Self {
            handle: NonNull::new(raw),
            _owner_thread: PhantomData,
        };
        if connection.handle.is_none() {
            return Err(Error::Sqlite {
                code,
                message: "Open returned no handle".into(),
            });
        }
        connection.check(code)?;
        if unsafe { sqlite3_db_readonly(connection.raw()?, c"main".as_ptr()) }
            != i32::from(readonly)
        {
            return Err(Error::Contract("Unexpected database access mode"));
        }
        Ok(connection)
    }
    fn raw(&self) -> Result<Handle> {
        self.handle.map(NonNull::as_ptr).ok_or(Error::Closed)
    }
    /// Same bounded SQLite allocator path, reachable only after the original
    /// typed writer's transaction/site/schema checks. No public byte exporter.
    pub(crate) fn export_image_for_original_writer(&self) -> Result<Vec<u8>> {
        self.export_empty_image_for_factory()
    }
    pub(crate) fn export_empty_image_for_factory(&self) -> Result<Vec<u8>> {
        let db = self.raw()?;
        let mut size = -1;
        // NOCOPY returns a borrowed pointer or NULL and still reports the size.
        // It is never freed or exposed to Rust callers.
        let _borrowed = unsafe { sqlite3_serialize(db, c"main".as_ptr(), &mut size, 1) };
        if size <= 0 || size > crate::MAX_IMAGE_BYTES as i64 {
            return Err(Error::Contract("Private image size limit"));
        }
        let expected = size;
        let raw = unsafe { sqlite3_serialize(db, c"main".as_ptr(), &mut size, 0) };
        let allocation =
            Allocation(NonNull::new(raw).ok_or(Error::Contract("Image export allocation failed"))?);
        if size != expected {
            return Err(Error::Contract("Image size changed during export"));
        }
        // The successful SQLite copy owns exactly `size` initialized bytes.
        Ok(unsafe { std::slice::from_raw_parts(allocation.0.as_ptr(), size as usize) }.to_vec())
    }
    /// Root-generated private image only, one serialized logical replica revival.
    /// No production user path, hostile image, or parallel SQLite caller contract.
    pub(crate) fn open_image_for_probe(
        image: &[u8],
        refuse_before_import: bool,
    ) -> Result<(Option<Self>, BootstrapReceipt)> {
        if image.is_empty() || image.len() > crate::MAX_IMAGE_BYTES {
            return Err(Error::Contract("Private image size limit"));
        }
        let mut initialize = INITIALIZE
            .lock()
            .map_err(|_| Error::Contract("Native init mutex poisoned"))?;
        if initialize.blocked {
            return Err(Error::Contract("Native bootstrap state blocked"));
        }
        if unsafe { sqlite3_threadsafe() } != 1 || unsafe { sqlite3_initialize() } != 0 {
            initialize.blocked = true;
            return Err(Error::Contract("Native bootstrap initialization failed"));
        }
        let raw = unsafe { sqlite3_malloc64(crate::MAX_IMAGE_BYTES as u64) }.cast::<u8>();
        let allocation =
            Allocation(NonNull::new(raw).ok_or(Error::Contract("Image import allocation failed"))?);
        // The new SQLite allocation is disjoint from the borrowed Rust bytes.
        unsafe {
            ptr::copy_nonoverlapping(image.as_ptr(), allocation.0.as_ptr(), image.len());
        }
        let mut context = BootstrapContext {
            allocation: Some(allocation),
            size: image.len() as i64,
            refuse_before_import,
            calls: 0,
            deserialize_code: None,
            extension_code: None,
            api_was_null: false,
        };
        let context_pointer = &raw mut context;
        let installed = IMAGE_BOOTSTRAP.try_with(|slot| {
            if slot.get().is_null() {
                slot.set(context_pointer);
                true
            } else {
                false
            }
        });
        if installed != Ok(true) {
            initialize.blocked = true;
            return Err(Error::Contract("Bootstrap context unavailable or occupied"));
        }
        let original = erase(sqlite3_crsqlite_init);
        let temporary = erase(import_before_extension);
        let removed = unsafe { sqlite3_cancel_auto_extension(original) };
        if removed != 1 {
            let _ = IMAGE_BOOTSTRAP.try_with(|slot| slot.set(ptr::null_mut()));
            initialize.blocked = true;
            return Err(Error::Contract("Expected original auto-extension missing"));
        }
        // No Rust allocation/error propagation between registry removal and
        // explicit restoration: every returned path passes the scalar cleanup.
        let registered = unsafe { sqlite3_auto_extension(temporary) };
        let mut raw = ptr::null_mut();
        let code = if registered == 0 {
            unsafe {
                OPEN_CALLS.fetch_add(1, Ordering::SeqCst);
                sqlite3_open_v2(
                    c":memory:".as_ptr(),
                    &mut raw,
                    2 | 4 | 0x80 | 0x00010000 | 0x01000000,
                    ptr::null(),
                )
            }
        } else {
            registered
        };
        let cancelled = unsafe { sqlite3_cancel_auto_extension(temporary) };
        let cleared = IMAGE_BOOTSTRAP
            .try_with(|slot| slot.replace(ptr::null_mut()) == context_pointer)
            == Ok(true);
        let restored = unsafe { sqlite3_auto_extension(original) };
        let registry_ok = cancelled == i32::from(registered == 0) && cleared && restored == 0;
        if !registry_ok {
            initialize.blocked = true;
        }
        let valid = registered == 0
            && context.calls == 1
            && ((refuse_before_import
                && code == 4
                && context.deserialize_code.is_none()
                && context.extension_code.is_none())
                || (!refuse_before_import
                    && code == 0
                    && context.deserialize_code == Some(0)
                    && context.extension_code == Some(0)));
        if !valid {
            initialize.blocked = true;
        }
        let mut receipt = BootstrapReceipt {
            calls: context.calls,
            deserialize_code: context.deserialize_code,
            extension_code: context.extension_code,
            api_was_null: context.api_was_null,
            open_code: code,
            cancelled_temporary: cancelled,
            restored_original: restored,
            failed_open_checked_closed: false,
        };
        let accepted = registry_ok && valid && !refuse_before_import && !raw.is_null();
        if accepted {
            let connection = Self {
                handle: NonNull::new(raw),
                _owner_thread: PhantomData,
            };
            drop(initialize);
            let outcome = if unsafe { sqlite3_db_readonly(raw, c"main".as_ptr()) } == 0 {
                Ok(())
            } else {
                Err(Error::Contract("Imported memory access mode"))
            };
            return match outcome {
                Ok(()) => Ok((Some(connection), receipt)),
                Err(error) => crate::finish(connection, Err(error)),
            };
        }
        // Failed opens may not have CRSQL at all. Only finalize if its exact
        // initialization returned OK; then close every non-NULL raw handle.
        if !raw.is_null() {
            let closed = if context.extension_code == Some(0) {
                let mut connection = Self {
                    handle: NonNull::new(raw),
                    _owner_thread: PhantomData,
                };
                connection.close()
            } else {
                let close_code = unsafe { sqlite3_close(raw) };
                if close_code == 0 {
                    CHECKED_CLOSES.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                } else {
                    // Failure remains a failure; close_v2 is no success receipt.
                    unsafe { sqlite3_close_v2(raw) };
                    Err(Error::Contract(
                        "Uninitialized failed-open checked close failed",
                    ))
                }
            };
            if let Err(error) = closed {
                initialize.blocked = true;
                return Err(error);
            }
            receipt.failed_open_checked_closed = true;
        }
        if registry_ok && valid && refuse_before_import && receipt.failed_open_checked_closed {
            Ok((None, receipt))
        } else {
            initialize.blocked = true;
            Err(Error::Contract(
                "Bootstrap open or explicit restoration failed",
            ))
        }
    }
    fn check(&self, code: c_int) -> Result<()> {
        if code == 0 {
            return Ok(());
        }
        let raw = self.raw()?;
        let pointer = unsafe { sqlite3_errmsg(raw) };
        let message = if pointer.is_null() {
            "No SQLite error text".into()
        } else {
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned()
        };
        Err(Error::Sqlite { code, message })
    }
    pub(crate) fn query(&self, sql: &CStr, parameters: &[Value]) -> Result<Rows> {
        let db = self.raw()?;
        let mut raw = ptr::null_mut();
        let mut tail = ptr::null();
        let code = unsafe { sqlite3_prepare_v2(db, sql.as_ptr(), -1, &mut raw, &mut tail) };
        let statement = Statement {
            handle: NonNull::new(raw),
            connection: self,
            _parameters: parameters,
        };
        self.check(code)?;
        let handle = statement.raw()?;
        if !tail.is_null() && unsafe { *tail } != 0 {
            return Err(Error::Contract("Multiple SQL statements"));
        }
        if unsafe { sqlite3_bind_parameter_count(handle) } as usize != parameters.len() {
            return Err(Error::Contract("Parameter count mismatch"));
        }
        for (offset, value) in parameters.iter().enumerate() {
            let index =
                c_int::try_from(offset + 1).map_err(|_| Error::Contract("Too many parameters"))?;
            let code = unsafe {
                match value {
                    Value::Null => sqlite3_bind_null(handle, index),
                    Value::Integer(value) => sqlite3_bind_int64(handle, index, *value),
                    Value::Real(value) => sqlite3_bind_double(handle, index, value.get()),
                    Value::Text(value) => sqlite3_bind_text(
                        handle,
                        index,
                        value.as_ptr().cast(),
                        length(value.len())?,
                        None,
                    ),
                    Value::Blob(value) => sqlite3_bind_blob(
                        handle,
                        index,
                        value.as_ptr().cast(),
                        length(value.len())?,
                        None,
                    ),
                }
            };
            self.check(code)?;
        }
        // SQLITE_STATIC bindings borrow parameters until Statement has finalized.
        let mut rows = Vec::new();
        let mut total_bytes = 0usize;
        loop {
            let code = unsafe { sqlite3_step(handle) };
            if code == 101 {
                break;
            }
            if code != 100 {
                self.check(code)?;
                return Err(Error::Contract("Unexpected successful step code"));
            }
            if rows.len() == crate::MAX_ROWS {
                return Err(Error::Contract("Private query row limit"));
            }
            let mut row = Vec::new();
            for index in 0..unsafe { sqlite3_column_count(handle) } {
                let value = match unsafe { sqlite3_column_type(handle, index) } {
                    1 => Value::Integer(unsafe { sqlite3_column_int64(handle, index) }),
                    2 => Value::Real(FiniteReal::new(unsafe {
                        sqlite3_column_double(handle, index)
                    })?),
                    kind @ (3 | 4) => {
                        let pointer = if kind == 3 {
                            unsafe { sqlite3_column_text(handle, index) }
                        } else {
                            unsafe { sqlite3_column_blob(handle, index) }.cast()
                        };
                        let size = unsafe { sqlite3_column_bytes(handle, index) };
                        if size < 0 || (pointer.is_null() && (size != 0 || kind == 3)) {
                            return Err(Error::Contract("Invalid SQLite column buffer"));
                        }
                        if size as usize > crate::MAX_VALUE_BYTES {
                            return Err(Error::Contract("Private SQL value limit"));
                        }
                        let bytes = if size == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(pointer, size as usize) }.to_vec()
                        };
                        if kind == 3 {
                            Value::Text(
                                String::from_utf8(bytes)
                                    .map_err(|_| Error::Contract("Invalid UTF8 TEXT"))?,
                            )
                        } else {
                            Value::Blob(bytes)
                        }
                    }
                    5 => Value::Null,
                    _ => return Err(Error::Contract("Unknown SQLite column type")),
                };
                total_bytes += match &value {
                    Value::Text(v) => v.len(),
                    Value::Blob(v) => v.len(),
                    _ => 8,
                };
                if total_bytes > crate::MAX_QUERY_BYTES {
                    return Err(Error::Contract("Private query byte limit"));
                }
                row.push(value);
            }
            rows.push(row);
        }
        statement.finish()?;
        Ok(rows)
    }
    pub(crate) fn close(&mut self) -> Result<()> {
        let raw = self.raw()?;
        if self.query(c"SELECT crsql_finalize()", &[])?
            != vec![vec![Value::Text("finalized".into())]]
        {
            return Err(Error::Contract("Unexpected CRSQL finalize result"));
        }
        let code = unsafe { sqlite3_close(raw) };
        self.check(code)?;
        CHECKED_CLOSES.fetch_add(1, Ordering::SeqCst);
        self.handle = None;
        Ok(())
    }
}
struct Allocation(NonNull<u8>);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            sqlite3_free(self.0.as_ptr().cast());
        }
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        if self.handle.is_some() {
            // Best-effort cleanup is not an explicit close success receipt.
            let _ = self.query(c"SELECT crsql_finalize()", &[]);
            if let Some(raw) = self.handle.take() {
                unsafe {
                    sqlite3_close_v2(raw.as_ptr());
                }
            }
        }
    }
}
struct Statement<'connection, 'parameters> {
    handle: Option<NonNull<c_void>>,
    connection: &'connection Connection,
    _parameters: &'parameters [Value],
}
impl Statement<'_, '_> {
    fn raw(&self) -> Result<Handle> {
        self.handle
            .map(NonNull::as_ptr)
            .ok_or(Error::Contract("No prepared statement"))
    }
    fn finish(mut self) -> Result<()> {
        let raw = self
            .handle
            .take()
            .ok_or(Error::Contract("Statement already finalized"))?;
        self.connection
            .check(unsafe { sqlite3_finalize(raw.as_ptr()) })
    }
}
impl Drop for Statement<'_, '_> {
    fn drop(&mut self) {
        if let Some(raw) = self.handle.take() {
            unsafe {
                sqlite3_finalize(raw.as_ptr());
            }
        }
    }
}
fn length(size: usize) -> Result<c_int> {
    c_int::try_from(size).map_err(|_| Error::Contract("SQL value exceeds C ABI length"))
}
