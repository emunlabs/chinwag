//! Draft schema for a private fixture experiment; not a product migration.
#![forbid(unsafe_code)]
use std::ffi::CStr;

pub const APPLICATION_ID: i32 = i32::from_be_bytes(*b"CHWG");
pub const SCHEMA_VERSION: i32 = 1;
pub struct Table {
    pub name: &'static str,
    pub ddl: &'static CStr,
}

// All references are data, not SQL foreign keys: the pinned CRR validator rejects
// declared foreign keys. Non-key NOT NULL columns have explicit defaults.
pub const TABLES: [Table; 8] = [
    Table {
        name: "threads",
        ddl: c"CREATE TABLE threads(
            id TEXT PRIMARY KEY NOT NULL,
            repo_id TEXT NOT NULL DEFAULT '',
            branch_ref TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            created_at_ms INTEGER NOT NULL DEFAULT 0,
            updated_at_ms INTEGER NOT NULL DEFAULT 0)",
    },
    Table {
        name: "messages",
        ddl: c"CREATE TABLE messages(
            id TEXT PRIMARY KEY NOT NULL,
            thread_id TEXT NOT NULL DEFAULT '',
            author_key_id TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            body TEXT NOT NULL DEFAULT '',
            created_at_ms INTEGER NOT NULL DEFAULT 0)",
    },
    Table {
        name: "context_pins",
        ddl: c"CREATE TABLE context_pins(
            id TEXT PRIMARY KEY NOT NULL,
            thread_id TEXT NOT NULL DEFAULT '',
            file_path TEXT NOT NULL DEFAULT '',
            symbol_hash TEXT NOT NULL DEFAULT '',
            source_commit TEXT NOT NULL DEFAULT '',
            body TEXT NOT NULL DEFAULT '',
            created_at_ms INTEGER NOT NULL DEFAULT 0)",
    },
    // Replicated observations never mint grants or replace the accepted owner.
    Table {
        name: "agent_claims",
        ddl: c"CREATE TABLE agent_claims(
            id TEXT PRIMARY KEY NOT NULL,
            file_path TEXT NOT NULL DEFAULT '',
            symbol_hash TEXT NOT NULL DEFAULT '',
            owner_key_id TEXT NOT NULL DEFAULT '',
            authority_event_hash TEXT NOT NULL DEFAULT '',
            observed_at_ms INTEGER NOT NULL DEFAULT 0)",
    },
    Table {
        name: "leases",
        ddl: c"CREATE TABLE leases(
            id TEXT PRIMARY KEY NOT NULL,
            claim_id TEXT NOT NULL DEFAULT '',
            owner_key_id TEXT NOT NULL DEFAULT '',
            authority_event_hash TEXT NOT NULL DEFAULT '',
            observed_expires_at_ms INTEGER NOT NULL DEFAULT 0,
            observed_at_ms INTEGER NOT NULL DEFAULT 0)",
    },
    Table {
        name: "flight_checkpoints",
        ddl: c"CREATE TABLE flight_checkpoints(
            id TEXT PRIMARY KEY NOT NULL,
            thread_id TEXT NOT NULL DEFAULT '',
            agent_key_id TEXT NOT NULL DEFAULT '',
            branch_ref TEXT NOT NULL DEFAULT '',
            parent_step_id TEXT NOT NULL DEFAULT '',
            snapshot_oid TEXT NOT NULL DEFAULT '',
            tool_digest TEXT NOT NULL DEFAULT '',
            receipt_hash TEXT NOT NULL DEFAULT '',
            created_at_ms INTEGER NOT NULL DEFAULT 0)",
    },
    // Storage definitions do not implement rewind, AST selection or injection.
    Table {
        name: "tombstones",
        ddl: c"CREATE TABLE tombstones(
            id TEXT PRIMARY KEY NOT NULL,
            repo_id TEXT NOT NULL DEFAULT '',
            branch_ref TEXT NOT NULL DEFAULT '',
            source_commit TEXT NOT NULL DEFAULT '',
            file_path TEXT NOT NULL DEFAULT '',
            symbol_hash TEXT NOT NULL DEFAULT '',
            attempted_action TEXT NOT NULL DEFAULT '',
            failure TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            alternative TEXT NOT NULL DEFAULT '',
            evidence_hash TEXT NOT NULL DEFAULT '',
            created_at_ms INTEGER NOT NULL DEFAULT 0)",
    },
    // A row is not proof of CI. Verified consumption requires a future CI gate.
    Table {
        name: "verified_invariants",
        ddl: c"CREATE TABLE verified_invariants(
            id TEXT PRIMARY KEY NOT NULL,
            repo_id TEXT NOT NULL DEFAULT '',
            branch_ref TEXT NOT NULL DEFAULT '',
            source_commit TEXT NOT NULL DEFAULT '',
            file_path TEXT NOT NULL DEFAULT '',
            symbol_hash TEXT NOT NULL DEFAULT '',
            invariant TEXT NOT NULL DEFAULT '',
            ci_run_id TEXT NOT NULL DEFAULT '',
            ci_receipt_hash TEXT NOT NULL DEFAULT '',
            verified_at_ms INTEGER NOT NULL DEFAULT 0)",
    },
];
