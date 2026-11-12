// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Cloudflare R2 / S3 Parquet + DuckDB (`httpfs`) Encrypted Message Archive with Cleartext
//! Searchable Routing Metadata (`sender_seat`, `recipient_seat`, `timestamp_utc`, `room`, `task_id`),
//! Encrypted `acu_ciphertext` BLOB Column (`CHWGAEAD` wrapping `CHWGACU2`), Hybrid Active-Channel RAM Cache
//! (`active_channel_cache`), and Off-UI-Thread CISO Forensic Decryption (`SharedFatClientArchiveHandle`).

use crate::AcuError;
use crate::acu::{acu_partial_decrypt_at_epoch, revoke_and_rerandomize};
use crate::aead::{DEFAULT_MESSAGE_ARCHIVE_ID, EncryptedCiPayload, is_valid_metadata_token};
use crate::keys::{SeatSecretKey, is_valid_seat_id};
use crate::protocol::{
    AcuShareRequest, AllowedSignersRegistry, CisoAcuFatClient, DEFAULT_CISO_ACU_ID,
};
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

const ARCHIVE_ROW_SIG_DOMAIN: &[u8] = b"chinwag-parquet-archive-row/v3";

/// Default DuckDB background worker thread cap on the CISO/developer fat client so GPUI / local
/// web workbench UI rendering threads are never starved.
pub const DEFAULT_DUCKDB_THREADS: u8 = 2;

/// Default DuckDB RAM cap on the CISO/developer fat client.
pub const DEFAULT_DUCKDB_MEMORY_LIMIT: &str = "1GB";

/// Default number of recent messages cached per active room in RAM (`active_channel_cache`).
pub const DEFAULT_ACTIVE_CHANNEL_PAGE_SIZE: usize = 50;

/// Hive-partitioned key for Cloudflare R2 / S3 Parquet message archives:
/// `org_id=<org_id>/year=<YYYY>/month=<MM>/day=<DD>/archive.parquet`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HivePartitionKey {
    /// Organization / tenant identifier.
    pub org_id: String,
    /// Four-digit UTC year (e.g., `2026`).
    pub year: u16,
    /// Two-digit UTC month (`1..=12`).
    pub month: u8,
    /// Two-digit UTC day (`1..=31`).
    pub day: u8,
}

impl HivePartitionKey {
    /// Create and validate a [`HivePartitionKey`].
    pub fn new(org_id: impl Into<String>, year: u16, month: u8, day: u8) -> Result<Self, AcuError> {
        let org_id = org_id.into();
        if !is_safe_storage_token(&org_id) || !(1..=12).contains(&month) || !(1..=31).contains(&day)
        {
            return Err(AcuError::InvalidMetadata);
        }
        Ok(Self {
            org_id,
            year,
            month,
            day,
        })
    }

    /// Format the S3-compatible Cloudflare R2 URI for this Hive partition:
    /// `s3://{bucket}/org_id={org_id}/year={year:04}/month={month:02}/day={day:02}/archive.parquet`.
    pub fn s3_parquet_uri(&self, bucket: &str) -> Result<String, AcuError> {
        if !is_safe_storage_token(bucket) || !is_safe_storage_token(&self.org_id) {
            return Err(AcuError::InvalidMetadata);
        }
        Ok(format!(
            "s3://{bucket}/org_id={}/year={:04}/month={:02}/day={:02}/archive.parquet",
            self.org_id, self.year, self.month, self.day
        ))
    }

    /// Format the native DuckDB `r2://` URI for this Hive partition:
    /// `r2://{bucket}/org_id={org_id}/year={year:04}/month={month:02}/day={day:02}/archive.parquet`.
    pub fn r2_parquet_uri(&self, bucket: &str) -> Result<String, AcuError> {
        if !is_safe_storage_token(bucket) || !is_safe_storage_token(&self.org_id) {
            return Err(AcuError::InvalidMetadata);
        }
        Ok(format!(
            "r2://{bucket}/org_id={}/year={:04}/month={:02}/day={:02}/archive.parquet",
            self.org_id, self.year, self.month, self.day
        ))
    }

    /// Format the Hive-partitioned wildcard URI across all dates for an organization on S3/R2:
    /// `s3://{bucket}/org_id={org_id}/year=*/month=*/day=*/*.parquet`.
    pub fn s3_glob_uri(bucket: &str, org_id: &str) -> Result<String, AcuError> {
        if !is_safe_storage_token(bucket) || !is_safe_storage_token(org_id) {
            return Err(AcuError::InvalidMetadata);
        }
        Ok(format!(
            "s3://{bucket}/org_id={org_id}/year=*/month=*/day=*/*.parquet"
        ))
    }
}

/// A single row in the Cloudflare R2 Parquet Message Archive table.
///
/// Routing metadata columns (`message_id`, `timestamp_utc`, `sender_seat`, `recipient_seat`,
/// `room`, `task_id`, `policy_epoch`, `rerandomized_by_seat`, `ed25519_sig`) are stored in cleartext Parquet columns
/// for sub-second DuckDB predicate pushdown and min/max row-group pruning, while the message
/// body is sealed inside the `acu_ciphertext` BLOB column (`CHWGAEAD` / `CHWGACU2`) under
/// `ACU AND (Recipient OR Archive)` with zero cleartext basis commitments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedMessageRow {
    /// Unique message identifier.
    pub message_id: String,
    /// UTC timestamp in milliseconds since Unix epoch.
    pub timestamp_utc: u64,
    /// Original sender seat identifier (immutable across post-revocation rerandomization).
    pub sender_seat: String,
    /// Recipient seat identifier (e.g., `"GEMINI-PM"` or `"branch:8687872"`).
    pub recipient_seat: String,
    /// Bus room / channel name (e.g., `"#eng"` or `"#ci"`).
    pub room: String,
    /// Associated ticket or task identifier (e.g., `"CHWG-101"`).
    pub task_id: String,
    /// Current ACU policy epoch of `acu_ciphertext`.
    pub policy_epoch: u64,
    /// Optional CISO ACU seat that re-signed this row after in-place `revoke_and_rerandomize`.
    pub rerandomized_by_seat: Option<String>,
    /// Ed25519 signature over the canonical row metadata and `SHA-256(acu_ciphertext)`.
    pub ed25519_sig: Vec<u8>,
    /// Deterministic binary serialization (`EncryptedCiPayload::to_bytes`) of the message payload.
    pub acu_ciphertext: Vec<u8>,
}

impl ArchivedMessageRow {
    /// Verify the cleartext `ed25519_sig` over the row metadata and `SHA-256(acu_ciphertext)`
    /// against `.chinwag/allowed_signers` BEFORE attempting pairing or AEAD decryption.
    pub fn verify_row_signature(&self, registry: &AllowedSignersRegistry) -> Result<(), AcuError> {
        if self.ed25519_sig.len() != 64 {
            return Err(AcuError::SignatureVerificationFailed("archive_row_sig_len"));
        }
        let verifying_seat = self
            .rerandomized_by_seat
            .as_deref()
            .unwrap_or(&self.sender_seat);
        let signer_rec = registry.get_any(verifying_seat)?;
        let preimage = Self::signing_preimage(
            &self.message_id,
            self.timestamp_utc,
            &self.sender_seat,
            &self.recipient_seat,
            &self.room,
            &self.task_id,
            self.policy_epoch,
            self.rerandomized_by_seat.as_deref(),
            &self.acu_ciphertext,
        );
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.ed25519_sig);
        let sig = Signature::from_bytes(&sig_bytes);
        signer_rec
            .ed25519_verifying_key
            .verify_strict(&preimage, &sig)
            .map_err(|_| AcuError::SignatureVerificationFailed("archive_row"))
    }

    /// Prune `revoked_seat_ids` and cryptographically rerandomize this archived row's
    /// `acu_ciphertext` BLOB in-place using the ACU operator's `acu_sk` (verifying the existing
    /// row signature first so tampered metadata cannot be laundered, unsealing and re-sealing
    /// `basis_commitments` with fresh randomness at `policy_epoch + 1`, preserving `sender_seat`,
    /// and re-signing with `re_signer_ed25519_sk`).
    pub fn revoke_and_rerandomize_in_place(
        &mut self,
        acu_sk: &SeatSecretKey,
        revoked_seat_ids: &[&str],
        registry: &AllowedSignersRegistry,
        re_signer_seat_id: &str,
        re_signer_ed25519_sk: &SigningKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), AcuError> {
        self.verify_row_signature(registry)?;
        let signer_rec = registry.get_active(re_signer_seat_id)?;
        if signer_rec.ed25519_verifying_key != re_signer_ed25519_sk.verifying_key() {
            return Err(AcuError::SignatureVerificationFailed("re_signer_mismatch"));
        }
        let _acu_rec = registry.get_active(acu_sk.seat_id())?;
        let mut payload = EncryptedCiPayload::from_bytes(&self.acu_ciphertext)?;
        let active_keys = registry.active_acu_keys();
        revoke_and_rerandomize(
            &mut payload.acu_ciphertext,
            acu_sk,
            revoked_seat_ids,
            &active_keys,
            rng,
        )?;
        let new_epoch = payload.acu_ciphertext.policy_epoch;
        let new_ciphertext = payload.to_bytes();
        let preimage = Self::signing_preimage(
            &self.message_id,
            self.timestamp_utc,
            &self.sender_seat,
            &self.recipient_seat,
            &self.room,
            &self.task_id,
            new_epoch,
            Some(re_signer_seat_id),
            &new_ciphertext,
        );
        let sig: Signature = re_signer_ed25519_sk.sign(&preimage);
        self.policy_epoch = new_epoch;
        self.acu_ciphertext = new_ciphertext;
        self.rerandomized_by_seat = Some(re_signer_seat_id.to_string());
        self.ed25519_sig = sig.to_bytes().to_vec();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn signing_preimage(
        message_id: &str,
        timestamp_utc: u64,
        sender_seat: &str,
        recipient_seat: &str,
        room: &str,
        task_id: &str,
        policy_epoch: u64,
        rerandomized_by_seat: Option<&str>,
        acu_ciphertext: &[u8],
    ) -> Vec<u8> {
        let blob_hash = Sha256::digest(acu_ciphertext);
        let mut out = Vec::new();
        out.extend_from_slice(ARCHIVE_ROW_SIG_DOMAIN);
        push_len_prefixed(&mut out, message_id.as_bytes());
        out.extend_from_slice(&timestamp_utc.to_be_bytes());
        push_len_prefixed(&mut out, sender_seat.as_bytes());
        push_len_prefixed(&mut out, recipient_seat.as_bytes());
        push_len_prefixed(&mut out, room.as_bytes());
        push_len_prefixed(&mut out, task_id.as_bytes());
        out.extend_from_slice(&policy_epoch.to_be_bytes());
        match rerandomized_by_seat {
            Some(re_signer) => {
                out.push(1u8);
                push_len_prefixed(&mut out, re_signer.as_bytes());
            }
            None => out.push(0u8),
        }
        out.extend_from_slice(&blob_hash);
        out
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Cleartext metadata predicate filter for DuckDB `read_parquet` queries over Cloudflare R2 / S3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveSearchFilter {
    /// Organization identifier for Hive partition pruning (`org_id=...`).
    pub org_id: String,
    /// Optional exact match on `sender_seat`.
    pub sender_seat: Option<String>,
    /// Optional exact match on `recipient_seat`.
    pub recipient_seat: Option<String>,
    /// Optional exact match on `room` (e.g., `"#eng"`).
    pub room: Option<String>,
    /// Optional exact match on `task_id` (e.g., `"CHWG-101"`).
    pub task_id: Option<String>,
    /// Optional inclusive lower bound on `timestamp_utc`.
    pub timestamp_start_utc: Option<u64>,
    /// Optional inclusive upper bound on `timestamp_utc`.
    pub timestamp_end_utc: Option<u64>,
    /// Maximum number of rows to return (`1..=1000`, defaults to `50`).
    pub limit: usize,
}

impl ArchiveSearchFilter {
    /// Create a new metadata filter for `org_id` with default `limit = 50`.
    #[must_use]
    pub fn new(org_id: impl Into<String>) -> Self {
        Self {
            org_id: org_id.into(),
            sender_seat: None,
            recipient_seat: None,
            room: None,
            task_id: None,
            timestamp_start_utc: None,
            timestamp_end_utc: None,
            limit: DEFAULT_ACTIVE_CHANNEL_PAGE_SIZE,
        }
    }
}

/// DuckDB `httpfs` + Cloudflare R2 (S3-compatible API) configuration with UI-thread resource caps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuckDbArchiveConfig {
    /// R2 / S3 bucket name (e.g., `"chinwag-archive"`).
    pub bucket: String,
    /// Cloudflare account ID for R2 (e.g., `"cf-acct-99887766"`).
    pub r2_account_id: Option<String>,
    /// S3-compatible endpoint host (`"<account_id>.r2.cloudflarestorage.com"`).
    pub s3_endpoint: String,
    /// S3 region (`"auto"` for Cloudflare R2).
    pub s3_region: String,
    /// Maximum DuckDB worker threads (`SET threads = 2;`) to protect GUI responsiveness.
    pub threads: u8,
    /// Maximum DuckDB RAM allocation (`SET memory_limit = '1GB';`).
    pub memory_limit: String,
}

impl DuckDbArchiveConfig {
    /// Primary constructor for **Cloudflare R2** using R2's S3-compatible API
    /// (`<account_id>.r2.cloudflarestorage.com`, `s3_region = 'auto'`, `threads = 2`, `memory_limit = '1GB'`).
    pub fn cloudflare_r2(
        account_id: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Result<Self, AcuError> {
        let account_id = account_id.into();
        let bucket = bucket.into();
        if !is_safe_storage_token(&account_id) || !is_safe_storage_token(&bucket) {
            return Err(AcuError::InvalidMetadata);
        }
        let s3_endpoint = format!("{account_id}.r2.cloudflarestorage.com");
        Ok(Self {
            bucket,
            r2_account_id: Some(account_id),
            s3_endpoint,
            s3_region: "auto".to_string(),
            threads: DEFAULT_DUCKDB_THREADS,
            memory_limit: DEFAULT_DUCKDB_MEMORY_LIMIT.to_string(),
        })
    }

    /// Generate the DuckDB session initialization SQL enforcing background thread/memory limits
    /// and configuring `httpfs` for Cloudflare R2's S3-compatible API.
    pub fn to_httpfs_init_sql(&self) -> Result<String, AcuError> {
        if self.threads == 0
            || !is_safe_storage_token(&self.memory_limit)
            || !is_safe_storage_token(&self.s3_region)
            || !is_safe_storage_token(&self.s3_endpoint)
        {
            return Err(AcuError::InvalidMetadata);
        }
        Ok(format!(
            "SET threads = {};\nSET memory_limit = '{}';\nINSTALL httpfs;\nLOAD httpfs;\nSET s3_region = '{}';\nSET s3_endpoint = '{}';\nSET s3_url_style = 'path';",
            self.threads, self.memory_limit, self.s3_region, self.s3_endpoint
        ))
    }

    /// Generate the parameterized DuckDB `read_parquet` SQL query and positional bind parameters
    /// (`$1`, `$2`, ...) pushing metadata predicates down into Parquet row-group headers.
    pub fn build_read_parquet_query(
        &self,
        filter: &ArchiveSearchFilter,
    ) -> Result<(String, Vec<String>), AcuError> {
        let glob_uri = HivePartitionKey::s3_glob_uri(&self.bucket, &filter.org_id)?;
        let limit = filter.limit.clamp(1, 1000);

        let mut clauses = Vec::new();
        let mut params = Vec::new();

        if let Some(ref sender) = filter.sender_seat {
            params.push(sender.clone());
            clauses.push(format!("sender_seat = ${}", params.len()));
        }
        if let Some(ref recipient) = filter.recipient_seat {
            params.push(recipient.clone());
            clauses.push(format!("recipient_seat = ${}", params.len()));
        }
        if let Some(ref room) = filter.room {
            params.push(room.clone());
            clauses.push(format!("room = ${}", params.len()));
        }
        if let Some(ref task_id) = filter.task_id {
            params.push(task_id.clone());
            clauses.push(format!("task_id = ${}", params.len()));
        }
        if let Some(start_ts) = filter.timestamp_start_utc {
            params.push(start_ts.to_string());
            clauses.push(format!("timestamp_utc >= ${}", params.len()));
        }
        if let Some(end_ts) = filter.timestamp_end_utc {
            params.push(end_ts.to_string());
            clauses.push(format!("timestamp_utc <= ${}", params.len()));
        }

        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!("\nWHERE {}", clauses.join(" AND "))
        };

        let sql = format!(
            "SELECT message_id, timestamp_utc, sender_seat, recipient_seat, room, task_id, policy_epoch, ed25519_sig, acu_ciphertext\nFROM read_parquet('{glob_uri}', hive_partitioning = true){where_sql}\nORDER BY timestamp_utc DESC\nLIMIT {limit};"
        );
        Ok((sql, params))
    }

    /// **Hybrid Active-Channel Cache (Step 1 SQL):** Generate the DuckDB SQL to populate the
    /// in-memory `active_channel_cache` temp table when a user first clicks a channel (`room`).
    pub fn build_populate_active_channel_cache_sql(
        &self,
        org_id: &str,
        room: &str,
        limit: usize,
    ) -> Result<(String, Vec<String>), AcuError> {
        let glob_uri = HivePartitionKey::s3_glob_uri(&self.bucket, org_id)?;
        let clamped_limit = limit.clamp(1, 1000);
        let sql = format!(
            "CREATE TEMP TABLE IF NOT EXISTS active_channel_cache AS\nSELECT message_id, timestamp_utc, sender_seat, recipient_seat, room, task_id, policy_epoch, ed25519_sig, acu_ciphertext\nFROM read_parquet('{glob_uri}', hive_partitioning = true)\nWHERE room = $1\nORDER BY timestamp_utc DESC\nLIMIT {clamped_limit};"
        );
        Ok((sql, vec![room.to_string()]))
    }

    /// **Hybrid Active-Channel Cache (Step 3 SQL):** Generate the DuckDB cursor-paginated SQL
    /// when the user scrolls up past the oldest cached message (`timestamp_utc < before_timestamp_utc`).
    pub fn build_scroll_older_chunk_sql(
        &self,
        org_id: &str,
        room: &str,
        before_timestamp_utc: u64,
        limit: usize,
    ) -> Result<(String, Vec<String>), AcuError> {
        let glob_uri = HivePartitionKey::s3_glob_uri(&self.bucket, org_id)?;
        let clamped_limit = limit.clamp(1, 1000);
        let sql = format!(
            "SELECT message_id, timestamp_utc, sender_seat, recipient_seat, room, task_id, policy_epoch, ed25519_sig, acu_ciphertext\nFROM read_parquet('{glob_uri}', hive_partitioning = true)\nWHERE room = $1 AND timestamp_utc < $2\nORDER BY timestamp_utc DESC\nLIMIT {clamped_limit};"
        );
        Ok((
            sql,
            vec![room.to_string(), before_timestamp_utc.to_string()],
        ))
    }
}

/// Indicates whether a channel window query was served in `0` network hops from the
/// fat client's in-RAM `active_channel_cache` or fetched via an R2 Parquet Range query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheHit {
    /// Served in `0` network hops from the fat client's in-RAM `active_channel_cache`.
    ActiveChannelRamCache,
    /// Fetched from Cloudflare R2 Parquet storage and merged into `active_channel_cache`.
    R2ParquetRangeFetch,
}

/// Decrypted message record returned strictly in RAM to the CISO / recipient fat client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedArchiveRecord {
    /// Message identifier.
    pub message_id: String,
    /// UTC timestamp.
    pub timestamp_utc: u64,
    /// Sender seat identifier.
    pub sender_seat: String,
    /// Recipient seat identifier.
    pub recipient_seat: String,
    /// Bus room / channel.
    pub room: String,
    /// Associated task or ticket ID.
    pub task_id: String,
    /// Policy epoch at the time of decryption.
    pub policy_epoch: u64,
    /// Decrypted plaintext bytes (held strictly in RAM; never written back to disk).
    pub plaintext: Vec<u8>,
}

/// Hive-partitioned Parquet Archive engine + Hybrid Active-Channel RAM Cache (`active_channel_cache`).
#[derive(Clone, Debug, Default)]
pub struct AcuParquetArchiveStore {
    partitions: BTreeMap<HivePartitionKey, Vec<ArchivedMessageRow>>,
    active_channel_cache: BTreeMap<(String, String), Vec<ArchivedMessageRow>>,
}

impl AcuParquetArchiveStore {
    /// Create a new empty archive store + active-channel cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encrypt a bus message or CI/CD alert under the canonical Zero-Plaintext-At-Rest policy
    /// (`ACU AND (recipient_seat OR archive:vault)`), sealing basis commitments exclusively under `pk_ACU`,
    /// serialize to `acu_ciphertext` (`CHWGAEAD` / `CHWGACU3`), sign cleartext routing metadata +
    /// `SHA-256(acu_ciphertext)` with `sender_ed25519_sk`, and append to its R2 Hive partition.
    #[allow(clippy::too_many_arguments)]
    pub fn append_signed_message(
        &mut self,
        partition: HivePartitionKey,
        message_id: impl Into<String>,
        timestamp_utc: u64,
        sender_seat: impl Into<String>,
        recipient_seat: impl Into<String>,
        room: impl Into<String>,
        task_id: impl Into<String>,
        plaintext: &[u8],
        sender_ed25519_sk: &SigningKey,
        registry: &AllowedSignersRegistry,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<ArchivedMessageRow, AcuError> {
        let message_id = message_id.into();
        let sender_seat = sender_seat.into();
        let recipient_seat = recipient_seat.into();
        let room = room.into();
        let task_id = task_id.into();

        if !is_valid_metadata_token(&message_id)
            || !is_valid_seat_id(&sender_seat)
            || !is_valid_seat_id(&recipient_seat)
            || !is_valid_metadata_token(&room)
            || !is_valid_metadata_token(&task_id)
        {
            return Err(AcuError::InvalidMetadata);
        }

        // Verify sender is active in .chinwag/allowed_signers and matches sender_ed25519_sk.
        let sender_rec = registry.get_active(&sender_seat)?;
        if sender_rec.ed25519_verifying_key != sender_ed25519_sk.verifying_key() {
            return Err(AcuError::SignatureVerificationFailed("sender_key_mismatch"));
        }

        let acu_rec = registry.get_active(DEFAULT_CISO_ACU_ID)?;
        let recipient_rec = registry.get_active(&recipient_seat)?;
        let archive_rec = registry.get_active(DEFAULT_MESSAGE_ARCHIVE_ID)?;

        let encrypted_payload = EncryptedCiPayload::encrypt_with_acu_and_archive(
            plaintext,
            &acu_rec.acu_public_key,
            &recipient_rec.acu_public_key,
            &archive_rec.acu_public_key,
            &partition.org_id,
            &task_id,
            rng,
        )?;

        let policy_epoch = encrypted_payload.acu_ciphertext.policy_epoch;
        let acu_ciphertext = encrypted_payload.to_bytes();

        let preimage = ArchivedMessageRow::signing_preimage(
            &message_id,
            timestamp_utc,
            &sender_seat,
            &recipient_seat,
            &room,
            &task_id,
            policy_epoch,
            None,
            &acu_ciphertext,
        );
        let sig: Signature = sender_ed25519_sk.sign(&preimage);

        let row = ArchivedMessageRow {
            message_id,
            timestamp_utc,
            sender_seat,
            recipient_seat,
            room,
            task_id,
            policy_epoch,
            rerandomized_by_seat: None,
            ed25519_sig: sig.to_bytes().to_vec(),
            acu_ciphertext,
        };

        self.partitions
            .entry(partition)
            .or_default()
            .push(row.clone());
        Ok(row)
    }

    /// Execute a fast cleartext metadata search across Hive partitions (`sender_seat`,
    /// `recipient_seat`, `room`, `task_id`, `timestamp_utc` range) without touching or
    /// decrypting any `acu_ciphertext` BLOBs.
    #[must_use]
    pub fn search_metadata(&self, filter: &ArchiveSearchFilter) -> Vec<&ArchivedMessageRow> {
        let mut matches: Vec<&ArchivedMessageRow> = self
            .partitions
            .iter()
            .filter(|(part, _)| part.org_id == filter.org_id)
            .flat_map(|(_, rows)| rows.iter())
            .filter(|row| {
                filter
                    .sender_seat
                    .as_ref()
                    .is_none_or(|s| &row.sender_seat == s)
                    && filter
                        .recipient_seat
                        .as_ref()
                        .is_none_or(|r| &row.recipient_seat == r)
                    && filter.room.as_ref().is_none_or(|rm| &row.room == rm)
                    && filter.task_id.as_ref().is_none_or(|t| &row.task_id == t)
                    && filter
                        .timestamp_start_utc
                        .is_none_or(|start| row.timestamp_utc >= start)
                    && filter
                        .timestamp_end_utc
                        .is_none_or(|end| row.timestamp_utc <= end)
            })
            .collect();

        matches.sort_by_key(|b| std::cmp::Reverse(b.timestamp_utc));
        matches.truncate(filter.limit.clamp(1, 1000));
        matches
    }

    /// **Hybrid Active-Channel Cache (`active_channel_cache`):**
    /// - Serves cached channels in `0` network hops or fetches/paginates from R2 Parquet partitions.
    pub fn load_channel_window(
        &mut self,
        org_id: &str,
        room: &str,
        before_timestamp_utc: Option<u64>,
        limit: usize,
    ) -> (CacheHit, Vec<ArchivedMessageRow>) {
        let clamped_limit = limit.clamp(1, 1000);
        let cache_key = (org_id.to_string(), room.to_string());

        if before_timestamp_utc.is_none()
            && let Some(cached) = self.active_channel_cache.get(&cache_key)
        {
            let slice: Vec<ArchivedMessageRow> =
                cached.iter().take(clamped_limit).cloned().collect();
            return (CacheHit::ActiveChannelRamCache, slice);
        }

        let mut filter = ArchiveSearchFilter::new(org_id);
        filter.room = Some(room.to_string());
        filter.limit = clamped_limit;
        if let Some(cursor_ts) = before_timestamp_utc {
            filter.timestamp_end_utc = Some(cursor_ts.saturating_sub(1));
        }

        let fetched: Vec<ArchivedMessageRow> =
            self.search_metadata(&filter).into_iter().cloned().collect();

        let entry = self.active_channel_cache.entry(cache_key).or_default();
        for row in &fetched {
            if !entry
                .iter()
                .any(|existing| existing.message_id == row.message_id)
            {
                entry.push(row.clone());
            }
        }
        entry.sort_by_key(|b| std::cmp::Reverse(b.timestamp_utc));

        (CacheHit::R2ParquetRangeFetch, fetched)
    }

    /// Mutate an archived row in-place by `message_id` (used for testing tampering rejection
    /// or in-place `revoke_and_rerandomize` rotation on stored Parquet rows).
    pub fn update_row_by_id(
        &mut self,
        message_id: &str,
        mutate: impl FnOnce(&mut ArchivedMessageRow),
    ) -> bool {
        for rows in self.partitions.values_mut() {
            for row in rows.iter_mut() {
                if row.message_id == message_id {
                    mutate(row);
                    self.active_channel_cache.clear();
                    return true;
                }
            }
        }
        false
    }

    /// Execute a CISO forensic investigation query:
    /// 1. Filters Parquet rows using cleartext metadata predicates (`search_metadata`).
    /// 2. Verifies each matching row's `ed25519_sig` against `.chinwag/allowed_signers` (Verify-Before-Decrypt).
    /// 3. Deserializes the `acu_ciphertext` BLOB (`EncryptedCiPayload::from_bytes`, requiring `CHWGACU3`).
    /// 4. Requests $D_{\text{ACU}}$ from `ciso_acu.authorize_archive_investigation(...)` (logging
    ///    `AcuAuditDecision::GrantedArchiveInvestigation`).
    /// 5. Combines $D_{\text{ACU}} + D_{\text{Archive}}$ strictly via [`crate::acu::acu_verify_partial_share`]
    ///    (zero cleartext basis commitments) in RAM and returns the decrypted records.
    pub fn ciso_investigate_and_decrypt(
        &self,
        filter: &ArchiveSearchFilter,
        investigation_ticket: &str,
        ciso_acu: &mut CisoAcuFatClient,
        archive_ed25519_sk: &SigningKey,
        archive_acu_sk: &SeatSecretKey,
        registry: &AllowedSignersRegistry,
    ) -> Result<Vec<DecryptedArchiveRecord>, AcuError> {
        let matching_rows = self.search_metadata(filter);
        let active_keys = registry.active_acu_keys();
        let mut out = Vec::with_capacity(matching_rows.len());

        for row in matching_rows {
            // 1. Verify-Before-Decrypt: check Ed25519 signature over row metadata + SHA256(acu_ciphertext).
            row.verify_row_signature(registry)?;

            // 2. Deserialize EncryptedCiPayload from the `acu_ciphertext` BLOB column.
            let payload = EncryptedCiPayload::from_bytes(&row.acu_ciphertext)?;
            if payload.acu_ciphertext.policy_epoch != row.policy_epoch {
                return Err(AcuError::EpochMismatch {
                    expected: row.policy_epoch,
                    actual: payload.acu_ciphertext.policy_epoch,
                });
            }

            // Locate the ACU row and Archive Unit row inside `payload.acu_ciphertext.rows`.
            let acu_row = payload
                .acu_ciphertext
                .rows
                .iter()
                .find(|r| r.seat_id == DEFAULT_CISO_ACU_ID)
                .ok_or_else(|| AcuError::UnknownSeat(DEFAULT_CISO_ACU_ID.to_string()))?
                .clone();

            let archive_row = payload
                .acu_ciphertext
                .rows
                .iter()
                .find(|r| r.seat_id == DEFAULT_MESSAGE_ARCHIVE_ID)
                .ok_or_else(|| AcuError::UnknownSeat(DEFAULT_MESSAGE_ARCHIVE_ID.to_string()))?;

            // 3. Request partial decryption share D_ACU from CISO ACU fat client over iroh.
            let req = AcuShareRequest::create_signed(
                format!("forensic-{}-{}", investigation_ticket, row.message_id),
                DEFAULT_MESSAGE_ARCHIVE_ID,
                DEFAULT_CISO_ACU_ID,
                &filter.org_id,
                &row.task_id,
                payload.acu_ciphertext.policy_epoch,
                payload.acu_ciphertext.clone(),
                acu_row.clone(),
                row.timestamp_utc,
                archive_ed25519_sk,
            );
            let resp = ciso_acu.authorize_archive_investigation(
                &req,
                DEFAULT_MESSAGE_ARCHIVE_ID,
                investigation_ticket,
                registry,
            )?;
            resp.verify_by_agent(&acu_row, registry)?;

            // 4. Compute Archive Unit's partial decryption share D_Archive and combine in RAM.
            let d_archive = acu_partial_decrypt_at_epoch(
                archive_row,
                archive_acu_sk,
                payload.acu_ciphertext.policy_epoch,
            );
            let plaintext = payload.decrypt(&[resp.partial_share, d_archive], &active_keys)?;

            out.push(DecryptedArchiveRecord {
                message_id: row.message_id.clone(),
                timestamp_utc: row.timestamp_utc,
                sender_seat: row.sender_seat.clone(),
                recipient_seat: row.recipient_seat.clone(),
                room: row.room.clone(),
                task_id: row.task_id.clone(),
                policy_epoch: row.policy_epoch,
                plaintext,
            });
        }

        Ok(out)
    }
}

/// Thread-safe handle wrapping [`AcuParquetArchiveStore`] and [`CisoAcuFatClient`] so the
/// GPUI / local web workbench UI thread can offload blocking DuckDB R2 Range queries and
/// BLS12-381 pairing math onto a background OS thread (`std::thread::spawn` / `spawn_blocking`).
#[derive(Clone)]
pub struct SharedFatClientArchiveHandle {
    store: Arc<Mutex<AcuParquetArchiveStore>>,
    ciso_acu: Arc<Mutex<CisoAcuFatClient>>,
}

impl SharedFatClientArchiveHandle {
    /// Wrap an archive store and CISO ACU fat client in a thread-safe handle.
    #[must_use]
    pub fn new(store: AcuParquetArchiveStore, ciso_acu: CisoAcuFatClient) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            ciso_acu: Arc::new(Mutex::new(ciso_acu)),
        }
    }

    /// Offload a metadata search + BLS12-381 pairing decryption investigation onto a dedicated
    /// background worker thread so the fat client's GUI rendering thread never drops a frame.
    #[must_use]
    pub fn spawn_blocking_investigation(
        &self,
        filter: ArchiveSearchFilter,
        investigation_ticket: String,
        archive_ed25519_sk: SigningKey,
        archive_acu_sk: Arc<SeatSecretKey>,
        registry: AllowedSignersRegistry,
    ) -> JoinHandle<Result<Vec<DecryptedArchiveRecord>, AcuError>> {
        let store = Arc::clone(&self.store);
        let ciso_acu = Arc::clone(&self.ciso_acu);

        thread::spawn(move || {
            let store_guard = store
                .lock()
                .map_err(|_| AcuError::SerializationError("archive store mutex poisoned"))?;
            let mut acu_guard = ciso_acu
                .lock()
                .map_err(|_| AcuError::SerializationError("ciso acu mutex poisoned"))?;

            store_guard.ciso_investigate_and_decrypt(
                &filter,
                &investigation_ticket,
                &mut acu_guard,
                &archive_ed25519_sk,
                &archive_acu_sk,
                &registry,
            )
        })
    }

    /// Load a channel window via the thread-safe handle.
    pub fn load_channel_window(
        &self,
        org_id: &str,
        room: &str,
        before_timestamp_utc: Option<u64>,
        limit: usize,
    ) -> Result<(CacheHit, Vec<ArchivedMessageRow>), AcuError> {
        let mut store_guard = self
            .store
            .lock()
            .map_err(|_| AcuError::SerializationError("archive store mutex poisoned"))?;
        Ok(store_guard.load_channel_window(org_id, room, before_timestamp_utc, limit))
    }

    /// Append a signed message using the OS CSPRNG (`OsRng`).
    #[allow(clippy::too_many_arguments)]
    pub fn append_signed_message_os_rng(
        &self,
        partition: HivePartitionKey,
        message_id: impl Into<String>,
        timestamp_utc: u64,
        sender_seat: impl Into<String>,
        recipient_seat: impl Into<String>,
        room: impl Into<String>,
        task_id: impl Into<String>,
        plaintext: &[u8],
        sender_ed25519_sk: &SigningKey,
        registry: &AllowedSignersRegistry,
    ) -> Result<ArchivedMessageRow, AcuError> {
        let mut store_guard = self
            .store
            .lock()
            .map_err(|_| AcuError::SerializationError("archive store mutex poisoned"))?;
        store_guard.append_signed_message(
            partition,
            message_id,
            timestamp_utc,
            sender_seat,
            recipient_seat,
            room,
            task_id,
            plaintext,
            sender_ed25519_sk,
            registry,
            &mut OsRng,
        )
    }
}

fn is_safe_storage_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}
