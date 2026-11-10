// Copyright (c) 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
// Reused from chinwag-training-lake/src/duckdb_ffi.rs; limited to archive needs.
use std::ffi::{CStr, CString, c_char, c_void};
use std::path::Path;
use std::ptr;

pub type IdxT = u64;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DuckDbState {
    DuckDBSuccess = 0,
    DuckDBError = 1,
}

#[repr(C)]
pub struct DuckDbResult {
    pub deprecated_column_count: IdxT,
    pub deprecated_row_count: IdxT,
    pub deprecated_rows_changed: IdxT,
    pub deprecated_columns: *mut c_void,
    pub deprecated_error_message: *mut c_char,
    pub internal_data: *mut c_void,
}

impl Default for DuckDbResult {
    fn default() -> Self {
        Self {
            deprecated_column_count: 0,
            deprecated_row_count: 0,
            deprecated_rows_changed: 0,
            deprecated_columns: ptr::null_mut(),
            deprecated_error_message: ptr::null_mut(),
            internal_data: ptr::null_mut(),
        }
    }
}

pub type DuckDbDatabase = *mut c_void;
pub type DuckDbConnection = *mut c_void;

#[link(name = "duckdb")]
unsafe extern "C" {
    pub fn duckdb_open(path: *const c_char, out_database: *mut DuckDbDatabase) -> DuckDbState;
    pub fn duckdb_close(database: *mut DuckDbDatabase);
    pub fn duckdb_connect(
        database: DuckDbDatabase,
        out_connection: *mut DuckDbConnection,
    ) -> DuckDbState;
    pub fn duckdb_disconnect(connection: *mut DuckDbConnection);
    pub fn duckdb_query(
        connection: DuckDbConnection,
        query: *const c_char,
        out_result: *mut DuckDbResult,
    ) -> DuckDbState;
    pub fn duckdb_destroy_result(result: *mut DuckDbResult);
    pub fn duckdb_result_error(result: *mut DuckDbResult) -> *const c_char;
    pub fn duckdb_row_count(result: *mut DuckDbResult) -> IdxT;
    pub fn duckdb_column_count(result: *mut DuckDbResult) -> IdxT;
    pub fn duckdb_value_varchar(result: *mut DuckDbResult, col: IdxT, row: IdxT) -> *mut c_char;
    pub fn duckdb_free(ptr: *mut c_void);
}

pub struct DuckDb {
    db: DuckDbDatabase,
    conn: DuckDbConnection,
}

impl DuckDb {
    pub fn open(path: &Path) -> Result<Self, String> {
        let path_str = path
            .to_str()
            .ok_or_else(|| "Invalid UTF-8 path for DuckDB database".to_string())?;
        let c_path = CString::new(path_str).map_err(|e| format!("CString error: {e}"))?;
        let mut db: DuckDbDatabase = ptr::null_mut();
        let state = unsafe { duckdb_open(c_path.as_ptr(), &mut db) };
        if state != DuckDbState::DuckDBSuccess || db.is_null() {
            return Err(format!("duckdb_open failed for {}", path.display()));
        }
        let mut conn: DuckDbConnection = ptr::null_mut();
        let conn_state = unsafe { duckdb_connect(db, &mut conn) };
        if conn_state != DuckDbState::DuckDBSuccess || conn.is_null() {
            unsafe { duckdb_close(&mut db) };
            return Err(format!("duckdb_connect failed for {}", path.display()));
        }
        Ok(Self { db, conn })
    }

    pub fn execute(&self, sql: &str) -> Result<(), String> {
        let c_sql = CString::new(sql).map_err(|e| format!("SQL CString error: {e}"))?;
        let mut res = DuckDbResult::default();
        let state = unsafe { duckdb_query(self.conn, c_sql.as_ptr(), &mut res) };
        if state != DuckDbState::DuckDBSuccess {
            let err_msg = unsafe {
                let ptr = duckdb_result_error(&mut res);
                if ptr.is_null() {
                    "Unknown DuckDB query error".to_string()
                } else {
                    CStr::from_ptr(ptr).to_string_lossy().into_owned()
                }
            };
            unsafe { duckdb_destroy_result(&mut res) };
            return Err(format!("DuckDB SQL error: {err_msg}"));
        }
        unsafe { duckdb_destroy_result(&mut res) };
        Ok(())
    }

    pub fn query_rows_varchar(&self, sql: &str) -> Result<Vec<Vec<String>>, String> {
        let c_sql = CString::new(sql).map_err(|e| format!("SQL CString error: {e}"))?;
        let mut res = DuckDbResult::default();
        let state = unsafe { duckdb_query(self.conn, c_sql.as_ptr(), &mut res) };
        if state != DuckDbState::DuckDBSuccess {
            let err_msg = unsafe {
                let ptr = duckdb_result_error(&mut res);
                if ptr.is_null() {
                    "Unknown DuckDB query error".to_string()
                } else {
                    CStr::from_ptr(ptr).to_string_lossy().into_owned()
                }
            };
            unsafe { duckdb_destroy_result(&mut res) };
            return Err(format!("DuckDB SQL error: {err_msg}"));
        }
        let rows = unsafe { duckdb_row_count(&mut res) };
        let cols = unsafe { duckdb_column_count(&mut res) };
        let mut out = Vec::with_capacity(rows as usize);
        for r in 0..rows {
            let mut row_vec = Vec::with_capacity(cols as usize);
            for c in 0..cols {
                let val_str = unsafe {
                    let ptr = duckdb_value_varchar(&mut res, c, r);
                    if ptr.is_null() {
                        String::new()
                    } else {
                        let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
                        duckdb_free(ptr as *mut c_void);
                        s
                    }
                };
                row_vec.push(val_str);
            }
            out.push(row_vec);
        }
        unsafe { duckdb_destroy_result(&mut res) };
        Ok(out)
    }
}

impl Drop for DuckDb {
    fn drop(&mut self) {
        unsafe {
            if !self.conn.is_null() {
                duckdb_disconnect(&mut self.conn);
            }
            if !self.db.is_null() {
                duckdb_close(&mut self.db);
            }
        }
    }
}
