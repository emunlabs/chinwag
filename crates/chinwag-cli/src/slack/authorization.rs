// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Browser-assisted OAuth v2 + PKCE + `K1` seat binding and Coordinator `K2`-signed grant
//! exchange (`0600` regular files, zero symlinks, zero `argv` secrets per `ROG-580`,
//! zero fabricated workspace defaults per `INV-CUSTOMER-CONFIGURABLE-NO-HARDCODING-01`).

use crate::slack::emitter::{RelayDispatchTarget, send_http_post};
use chinwag_slack_contract::{
    ApprovedHttpsUrl, AuthorizationRef, CanonicalU64, Ed25519KeyPairSigner, KeyFingerprint,
    OpaqueOrgId, OpaqueRef, OrgAdminPasskeyAttestationV1, SCHEMA_VERSION_V1, Signature64,
    VerificationPolicyV1, decode_bounded_json, domain_separated_jcs_signing_input, to_jcs_bytes,
    verify_ed25519_strict, verify_passkey_attestation,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use url::Url;
use zeroize::Zeroizing;

pub const K1_CONNECT_EXCHANGE_DOMAIN: &[u8] = b"chinwag.slack.connect_exchange.v1\0";
pub const K2_CONNECT_GRANT_DOMAIN: &[u8] = b"chinwag.slack.connect_binding.v1\0";

const FORBIDDEN_ARGV_FLAGS: &[&str] = &[
    "--token",
    "--bot-token",
    "--user-token",
    "--secret",
    "--client-secret",
    "--signing-secret",
    "--api-key",
    "--bearer",
    "--pkce-verifier",
];

const SECRET_TOKEN_PREFIXES: &[&str] = &[
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xapp-",
    "xwfp-",
    "chwg_",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "sk-",
    "AIza",
    "AKIA",
    "eyJ",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedMetadataMode {
    StrictZk,
    RichSymbols,
}

impl RequestedMetadataMode {
    pub fn parse_flag(raw: &str) -> Option<Self> {
        match raw {
            "strict_zk" => Some(Self::StrictZk),
            "rich_symbols" => Some(Self::RichSymbols),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StrictZk => "strict_zk",
            Self::RichSymbols => "rich_symbols",
        }
    }
}

fn deserialize_disallow_null_passkey<'de, D>(
    deserializer: D,
) -> Result<Option<Box<OrgAdminPasskeyAttestationV1>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    OrgAdminPasskeyAttestationV1::deserialize(deserializer).map(|v| Some(Box::new(v)))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SlackBindingState {
    NotConnected,
    Pending {
        challenge_id: OpaqueRef,
        org_id: OpaqueOrgId,
        connect_origin: String,
        verification_url: String,
        pkce_code_challenge: String,
        k1_key_id: KeyFingerprint,
        requested_mode: RequestedMetadataMode,
        expires_at_ms: CanonicalU64,
    },
    Connected {
        org_id: OpaqueOrgId,
        team_id: OpaqueRef,
        installation_ref: OpaqueRef,
        authorization_ref: AuthorizationRef,
        k1_key_id: KeyFingerprint,
        coordinator_k2_pubkey: KeyFingerprint,
        metadata_mode: RequestedMetadataMode,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_disallow_null_passkey"
        )]
        passkey_attestation: Option<Box<OrgAdminPasskeyAttestationV1>>,
        authorization_epoch: CanonicalU64,
        connected_at_ms: CanonicalU64,
    },
    Revoked {
        org_id: OpaqueOrgId,
        reason: String,
        revoked_at_ms: CanonicalU64,
    },
}

/// Signed request sent from CLI (`K1`) to `{connect_origin}/api/slack/connect/exchange`
/// carrying the single-use `pkce_code_verifier` inside the TLS/loopback body (never in `argv`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectExchangeProofPayloadV1 {
    pub schema_version: u16,
    pub challenge_id: OpaqueRef,
    pub org_id: OpaqueOrgId,
    pub callback_ref: OpaqueRef,
    pub pkce_code_verifier: String,
    pub k1_key_id: KeyFingerprint,
    pub requested_mode: RequestedMetadataMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConnectExchangeRequestV1 {
    pub payload: ConnectExchangeProofPayloadV1,
    pub k1_signature: Signature64,
}

/// Coordinator-issued installation binding grant signed under `K2` (`chinwag.slack.connect_binding.v1\0`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectBindingGrantV1 {
    pub schema_version: u16,
    pub challenge_id: OpaqueRef,
    pub org_id: OpaqueOrgId,
    pub team_id: OpaqueRef,
    pub installation_ref: OpaqueRef,
    pub authorization_ref: AuthorizationRef,
    pub k1_key_id: KeyFingerprint,
    pub pkce_code_challenge: String,
    pub metadata_mode: RequestedMetadataMode,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null_passkey"
    )]
    pub passkey_attestation: Option<Box<OrgAdminPasskeyAttestationV1>>,
    pub authorization_epoch: CanonicalU64,
    pub issued_at_ms: CanonicalU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConnectBindingGrantV1 {
    pub grant: ConnectBindingGrantV1,
    pub coordinator_k2_pubkey: KeyFingerprint,
    pub coordinator_k2_signature: Signature64,
}

#[derive(Debug)]
pub enum ConnectExchangeOutcome {
    Connected(Box<SlackBindingState>),
    AuthDeniedOrRevoked(String),
    TempUnavailable(String),
}

#[derive(Debug)]
pub enum AuthStateError {
    ArgvSecretRejected,
    UnsafePath(&'static str),
    InvalidConfig(String),
    Io(String),
}

impl std::fmt::Display for AuthStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArgvSecretRejected => write!(
                f,
                "secrets and tokens are strictly forbidden in CLI argv (ROG-580); use browser-assisted `chinwag slack connect`"
            ),
            Self::UnsafePath(msg) => write!(f, "unsafe Slack state path refused: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "invalid Slack binding configuration: {msg}"),
            Self::Io(msg) => write!(f, "Slack state I/O error: {msg}"),
        }
    }
}

fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Scans CLI arguments and rejects any flag or value that looks like a pasted token or secret (`ROG-580`).
/// Never echoes the rejected token value in error messages.
pub fn guard_zero_argv_secrets(args: &[String]) -> Result<(), AuthStateError> {
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        for flag in FORBIDDEN_ARGV_FLAGS {
            if lower == *flag || lower.starts_with(&format!("{flag}=")) {
                return Err(AuthStateError::ArgvSecretRejected);
            }
        }
        if lower.contains("bearer ") {
            return Err(AuthStateError::ArgvSecretRejected);
        }
        let candidates = match arg.split_once('=') {
            Some((_, rhs)) => [arg.as_str(), rhs],
            None => [arg.as_str(), ""],
        };
        for cand in candidates {
            if cand.is_empty() {
                continue;
            }
            for prefix in SECRET_TOKEN_PREFIXES {
                if cand.starts_with(prefix) {
                    return Err(AuthStateError::ArgvSecretRejected);
                }
            }
        }
    }
    Ok(())
}

pub fn ensure_safe_state_dir(dir: &Path) -> Result<(), AuthStateError> {
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|e| AuthStateError::Io(e.to_string()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| AuthStateError::Io(e.to_string()))?;
    }
    let meta = fs::symlink_metadata(dir).map_err(|e| AuthStateError::Io(e.to_string()))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(AuthStateError::UnsafePath(
            "state directory must not be a symlink",
        ));
    }
    if (meta.permissions().mode() & 0o077) != 0 {
        return Err(AuthStateError::UnsafePath(
            "state directory must have 0700 permissions",
        ));
    }
    Ok(())
}

pub fn verify_not_symlink_if_exists(path: &Path) -> Result<bool, AuthStateError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(AuthStateError::UnsafePath(
                    "state or key file must be a regular non-symlink file",
                ));
            }
            if (meta.permissions().mode() & 0o077) != 0 {
                return Err(AuthStateError::UnsafePath(
                    "state or key file must have 0600 permissions",
                ));
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(AuthStateError::Io(e.to_string())),
    }
}

pub fn write_atomic_0600(
    dir: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<PathBuf, AuthStateError> {
    ensure_safe_state_dir(dir)?;
    let target = dir.join(file_name);
    let _ = verify_not_symlink_if_exists(&target)?;

    let mut nonce = [0u8; 8];
    rand::rng().fill_bytes(&mut nonce);
    let tmp_name = format!(".{file_name}.tmp.{}", hex::encode(nonce));
    let tmp_path = dir.join(tmp_name);

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| AuthStateError::Io(e.to_string()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| AuthStateError::Io(e.to_string()))?;
    drop(f);

    fs::rename(&tmp_path, &target).map_err(|e| AuthStateError::Io(e.to_string()))?;
    Ok(target)
}

const KEY_FILE_NAME: &str = "slack_k1_seed.bin";
const BINDING_FILE_NAME: &str = "slack_binding.json";
const PKCE_VERIFIER_FILE_NAME: &str = "slack_pkce_verifier.bin";

pub fn load_or_create_k1_signer(state_dir: &Path) -> Result<Ed25519KeyPairSigner, AuthStateError> {
    ensure_safe_state_dir(state_dir)?;
    let key_path = state_dir.join(KEY_FILE_NAME);
    if verify_not_symlink_if_exists(&key_path)? {
        let mut raw = Zeroizing::new(Vec::with_capacity(32));
        OpenOptions::new()
            .read(true)
            .open(&key_path)
            .and_then(|mut f| f.read_to_end(&mut raw))
            .map_err(|e| AuthStateError::Io(e.to_string()))?;
        if raw.len() != 32 {
            return Err(AuthStateError::InvalidConfig(
                "slack_k1_seed.bin must be exactly 32 bytes".to_owned(),
            ));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&raw);
        return Ok(Ed25519KeyPairSigner::from_seed_bytes(&seed));
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *seed);
    write_atomic_0600(state_dir, KEY_FILE_NAME, &*seed)?;
    Ok(Ed25519KeyPairSigner::from_seed_bytes(&seed))
}

pub fn load_binding_state(state_dir: &Path) -> Result<SlackBindingState, AuthStateError> {
    ensure_safe_state_dir(state_dir)?;
    let path = state_dir.join(BINDING_FILE_NAME);
    if !verify_not_symlink_if_exists(&path)? {
        return Ok(SlackBindingState::NotConnected);
    }
    let bytes = fs::read(&path).map_err(|e| AuthStateError::Io(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| AuthStateError::InvalidConfig(e.to_string()))
}

pub fn save_binding_state(
    state_dir: &Path,
    state: &SlackBindingState,
) -> Result<(), AuthStateError> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| AuthStateError::InvalidConfig(e.to_string()))?;
    write_atomic_0600(state_dir, BINDING_FILE_NAME, &bytes)?;
    Ok(())
}

pub fn pkce_s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64url_no_pad(&digest)
}

fn base64url_no_pad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        }
    }
    out
}

fn validate_connect_url(raw: &str, allow_loopback_http: bool) -> Result<String, AuthStateError> {
    let parsed = Url::parse(raw).map_err(|e| AuthStateError::InvalidConfig(e.to_string()))?;
    match parsed.scheme() {
        "https" => {
            let approved = ApprovedHttpsUrl::parse(raw)
                .map_err(|e| AuthStateError::InvalidConfig(e.to_string()))?;
            Ok(approved.as_str().to_owned())
        }
        "http" if allow_loopback_http => {
            let host = parsed.host_str().unwrap_or("");
            if (host != "127.0.0.1" && host != "localhost" && host != "::1")
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
            {
                return Err(AuthStateError::InvalidConfig(
                    "plain HTTP connect origin is restricted strictly to loopback test endpoints"
                        .to_owned(),
                ));
            }
            Ok(raw.to_owned())
        }
        _ => Err(AuthStateError::InvalidConfig(
            "HTTPS connect origin required for Slack OAuth handoff".to_owned(),
        )),
    }
}

fn read_pkce_verifier(state_dir: &Path) -> Result<Zeroizing<String>, AuthStateError> {
    let path = state_dir.join(PKCE_VERIFIER_FILE_NAME);
    if !verify_not_symlink_if_exists(&path)? {
        return Err(AuthStateError::InvalidConfig(
            "missing local PKCE code_verifier state file".to_owned(),
        ));
    }
    let mut raw = Zeroizing::new(Vec::with_capacity(64));
    OpenOptions::new()
        .read(true)
        .open(&path)
        .and_then(|mut f| f.read_to_end(&mut raw))
        .map_err(|e| AuthStateError::Io(e.to_string()))?;
    let verifier_str = std::str::from_utf8(&raw)
        .map_err(|_| AuthStateError::InvalidConfig("invalid UTF-8 in PKCE verifier".to_owned()))?
        .trim()
        .to_owned();
    if verifier_str.len() < 43 || verifier_str.len() > 128 {
        return Err(AuthStateError::InvalidConfig(
            "PKCE code_verifier length outside RFC 7636 [43, 128] bounds".to_owned(),
        ));
    }
    Ok(Zeroizing::new(verifier_str))
}

/// Overwrites the existing `slack_pkce_verifier.bin` regular-file inode in place with zeros,
/// flushes via `sync_all()`, and unlinks the directory entry — propagating any I/O or inode
/// mismatch error fail-closed instead of allocating a replacement temp inode.
pub fn scrub_and_remove_pkce_verifier(state_dir: &Path) -> Result<(), AuthStateError> {
    ensure_safe_state_dir(state_dir)?;
    let path = state_dir.join(PKCE_VERIFIER_FILE_NAME);
    let lstat_meta = match fs::symlink_metadata(&path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(AuthStateError::UnsafePath(
                    "PKCE verifier file must be a regular non-symlink file",
                ));
            }
            if (meta.permissions().mode() & 0o077) != 0 {
                return Err(AuthStateError::UnsafePath(
                    "PKCE verifier file must have 0600 permissions",
                ));
            }
            meta
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(AuthStateError::Io(e.to_string())),
    };

    let mut f = OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(|e| AuthStateError::Io(e.to_string()))?;
    let open_meta = f
        .metadata()
        .map_err(|e| AuthStateError::Io(e.to_string()))?;
    if open_meta.ino() != lstat_meta.ino() || open_meta.dev() != lstat_meta.dev() {
        return Err(AuthStateError::UnsafePath(
            "PKCE verifier inode changed during scrub",
        ));
    }
    let scrub_len = usize::try_from(open_meta.len())
        .unwrap_or(128)
        .clamp(128, 4096);
    let zeros = vec![0u8; scrub_len];
    f.seek(SeekFrom::Start(0))
        .and_then(|_| f.write_all(&zeros))
        .and_then(|()| f.sync_all())
        .map_err(|e| AuthStateError::Io(e.to_string()))?;
    drop(f);
    fs::remove_file(&path).map_err(|e| AuthStateError::Io(e.to_string()))?;
    Ok(())
}

/// Initiates a browser-assisted OAuth v2 + PKCE + `K1` seat challenge without touching tokens in CLI.
pub fn begin_browser_oauth_handoff(
    state_dir: &Path,
    connect_base_url: &str,
    allow_loopback_http: bool,
    org_id: OpaqueOrgId,
    requested_mode: RequestedMetadataMode,
    now_ms: u64,
) -> Result<SlackBindingState, AuthStateError> {
    let trimmed = connect_base_url.trim_end_matches('/');
    let validated_origin = validate_connect_url(trimmed, allow_loopback_http)?;

    let signer = load_or_create_k1_signer(state_dir)?;
    let mut verifier_bytes = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *verifier_bytes);
    let verifier = Zeroizing::new(base64url_no_pad(&*verifier_bytes));
    write_atomic_0600(state_dir, PKCE_VERIFIER_FILE_NAME, verifier.as_bytes())?;

    let pkce_code_challenge = pkce_s256_challenge(&verifier);

    let mut ch_rand = [0u8; 8];
    rand::rng().fill_bytes(&mut ch_rand);
    let challenge_id = OpaqueRef::parse(format!("ch_{}", hex::encode(ch_rand)))
        .map_err(|e| AuthStateError::InvalidConfig(e.to_string()))?;

    let verification_url = validate_connect_url(
        &format!(
            "{validated_origin}/connect/slack/start?org={}&challenge={}&pkce={}&mode={}&k1={}",
            org_id.as_str(),
            challenge_id.as_str(),
            pkce_code_challenge,
            requested_mode.as_str(),
            signer.public_fingerprint().to_prefixed_string(),
        ),
        allow_loopback_http,
    )?;

    let pending = SlackBindingState::Pending {
        challenge_id,
        org_id,
        connect_origin: validated_origin,
        verification_url,
        pkce_code_challenge,
        k1_key_id: signer.public_fingerprint(),
        requested_mode,
        expires_at_ms: CanonicalU64::new(now_ms.saturating_add(600_000)),
    };
    save_binding_state(state_dir, &pending)?;
    Ok(pending)
}

/// Signs a Coordinator `K2` installation binding grant (used by Coordinator and loopback conformance tests).
pub fn sign_connect_binding_grant(
    k2_signer: &Ed25519KeyPairSigner,
    grant: ConnectBindingGrantV1,
) -> Result<SignedConnectBindingGrantV1, AuthStateError> {
    if grant.schema_version != SCHEMA_VERSION_V1 {
        return Err(AuthStateError::InvalidConfig(
            "unsupported ConnectBindingGrantV1 schema_version".to_owned(),
        ));
    }
    let (_, signing_input) = domain_separated_jcs_signing_input(K2_CONNECT_GRANT_DOMAIN, &grant)
        .map_err(|e| AuthStateError::InvalidConfig(e.to_string()))?;
    let sig = k2_signer.sign_raw_domain_payload(&signing_input);
    Ok(SignedConnectBindingGrantV1 {
        grant,
        coordinator_k2_pubkey: k2_signer.public_fingerprint(),
        coordinator_k2_signature: sig,
    })
}

/// Redeems a pending browser OAuth challenge against `{connect_origin}/api/slack/connect/exchange`
/// using the local `0600` PKCE `code_verifier` + `K1` Ed25519 signature, verifies the Coordinator's
/// `K2` Ed25519 signature on the returned workspace installation binding, scrubs the single-use PKCE
/// verifier on success/denial, and persists `SlackBindingState::Connected` with zero fabricated defaults.
#[allow(clippy::too_many_arguments)]
pub fn exchange_pkce_challenge_with_coordinator(
    state_dir: &Path,
    challenge_id_arg: &str,
    callback_ref: OpaqueRef,
    expected_coordinator_k2: &KeyFingerprint,
    trusted_admin_passkey: Option<&KeyFingerprint>,
    allow_loopback_http: bool,
    timeout_ms: u64,
    now_ms: u64,
) -> Result<ConnectExchangeOutcome, AuthStateError> {
    let current = load_binding_state(state_dir)?;
    let SlackBindingState::Pending {
        challenge_id,
        org_id,
        connect_origin,
        pkce_code_challenge,
        k1_key_id,
        requested_mode,
        expires_at_ms,
        ..
    } = current
    else {
        return Err(AuthStateError::InvalidConfig(
            "no pending browser OAuth challenge to complete".to_owned(),
        ));
    };

    if challenge_id.as_str() != challenge_id_arg {
        return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
            "OAuth challenge mismatch".to_owned(),
        ));
    }
    if expires_at_ms.get() <= now_ms {
        scrub_and_remove_pkce_verifier(state_dir)?;
        return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
            "OAuth challenge expired".to_owned(),
        ));
    }

    let signer = load_or_create_k1_signer(state_dir)?;
    if !ct_eq_bytes(signer.public_fingerprint().as_bytes(), k1_key_id.as_bytes()) {
        return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
            "local K1 key does not match pending challenge K1 fingerprint".to_owned(),
        ));
    }

    let verifier = read_pkce_verifier(state_dir)?;
    let derived_challenge = pkce_s256_challenge(&verifier);
    if !ct_eq_bytes(derived_challenge.as_bytes(), pkce_code_challenge.as_bytes()) {
        scrub_and_remove_pkce_verifier(state_dir)?;
        return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
            "local PKCE code_verifier does not match pending S256 challenge".to_owned(),
        ));
    }

    let mut payload = ConnectExchangeProofPayloadV1 {
        schema_version: SCHEMA_VERSION_V1,
        challenge_id: challenge_id.clone(),
        org_id: org_id.clone(),
        callback_ref,
        pkce_code_verifier: (*verifier).clone(),
        k1_key_id: k1_key_id.clone(),
        requested_mode,
    };
    let (_, k1_input) = domain_separated_jcs_signing_input(K1_CONNECT_EXCHANGE_DOMAIN, &payload)
        .map_err(|e| AuthStateError::InvalidConfig(e.to_string()))?;
    let k1_signature = signer.sign_raw_domain_payload(&k1_input);
    let signed_req = SignedConnectExchangeRequestV1 {
        payload: payload.clone(),
        k1_signature,
    };
    let req_bytes = Zeroizing::new(
        to_jcs_bytes(&signed_req).map_err(|e| AuthStateError::InvalidConfig(e.to_string()))?,
    );
    // Wipe temporary copy in struct
    payload.pkce_code_verifier = String::new();

    let endpoint_url = format!(
        "{}/api/slack/connect/exchange",
        connect_origin.trim_end_matches('/')
    );
    let target = RelayDispatchTarget {
        endpoint_url,
        allow_loopback_http,
        timeout_ms,
    };

    let (status, _retry, resp_body) =
        match send_http_post(&target, challenge_id.as_str(), None, &req_bytes) {
            Ok(tuple) => tuple,
            Err(err) => {
                // Keep Pending + PKCE verifier intact so operator can retry once network recovers
                return Ok(ConnectExchangeOutcome::TempUnavailable(err));
            }
        };

    match status {
        200..=299 => {
            let signed_grant: SignedConnectBindingGrantV1 =
                decode_bounded_json(resp_body.as_bytes(), 16_384).map_err(|_| {
                    AuthStateError::InvalidConfig(
                        "malformed Coordinator connect grant payload".to_owned(),
                    )
                })?;

            if signed_grant.grant.schema_version != SCHEMA_VERSION_V1 {
                scrub_and_remove_pkce_verifier(state_dir)?;
                return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
                    "unsupported Coordinator connect grant schema version".to_owned(),
                ));
            }
            if !ct_eq_bytes(
                signed_grant.coordinator_k2_pubkey.as_bytes(),
                expected_coordinator_k2.as_bytes(),
            ) {
                scrub_and_remove_pkce_verifier(state_dir)?;
                return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
                    "Coordinator K2 public key is not trusted".to_owned(),
                ));
            }

            let (_, grant_signing_input) =
                domain_separated_jcs_signing_input(K2_CONNECT_GRANT_DOMAIN, &signed_grant.grant)
                    .map_err(|e| AuthStateError::InvalidConfig(e.to_string()))?;
            if verify_ed25519_strict(
                expected_coordinator_k2,
                &grant_signing_input,
                &signed_grant.coordinator_k2_signature,
            )
            .is_err()
            {
                scrub_and_remove_pkce_verifier(state_dir)?;
                return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
                    "Coordinator K2 Ed25519 signature verification failed".to_owned(),
                ));
            }

            let g = signed_grant.grant;
            if g.challenge_id != challenge_id
                || g.org_id != org_id
                || !ct_eq_bytes(g.k1_key_id.as_bytes(), k1_key_id.as_bytes())
                || !ct_eq_bytes(
                    g.pkce_code_challenge.as_bytes(),
                    pkce_code_challenge.as_bytes(),
                )
            {
                scrub_and_remove_pkce_verifier(state_dir)?;
                return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
                    "Coordinator grant challenge/org/K1/PKCE binding mismatch".to_owned(),
                ));
            }

            if g.metadata_mode == RequestedMetadataMode::RichSymbols {
                let Some(att) = g.passkey_attestation.as_deref() else {
                    scrub_and_remove_pkce_verifier(state_dir)?;
                    return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
                        "rich_symbols mode requires OrgAdminPasskeyAttestationV1".to_owned(),
                    ));
                };
                let Some(expected_admin_passkey) = trusted_admin_passkey else {
                    scrub_and_remove_pkce_verifier(state_dir)?;
                    return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
                        "rich_symbols mode requires --admin-passkey-pubkey or CHINWAG_SLACK_ADMIN_PASSKEY_PUBKEY"
                            .to_owned(),
                    ));
                };
                let passkey_policy = VerificationPolicyV1 {
                    trusted_admin_passkey_keys: Some(vec![expected_admin_passkey.clone()]),
                    now_ms: Some(now_ms),
                    expected_authorization_epoch: Some(g.authorization_epoch.get()),
                    ..VerificationPolicyV1::default()
                };
                if att.grant.org_id != org_id
                    || verify_passkey_attestation(att, &passkey_policy).is_err()
                {
                    scrub_and_remove_pkce_verifier(state_dir)?;
                    return Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(
                        "invalid, untrusted, or expired OrgAdminPasskeyAttestationV1 on connect grant"
                            .to_owned(),
                    ));
                }
            }

            scrub_and_remove_pkce_verifier(state_dir)?;
            let connected = SlackBindingState::Connected {
                org_id: g.org_id,
                team_id: g.team_id,
                installation_ref: g.installation_ref,
                authorization_ref: g.authorization_ref,
                k1_key_id: g.k1_key_id,
                coordinator_k2_pubkey: signed_grant.coordinator_k2_pubkey,
                metadata_mode: g.metadata_mode,
                passkey_attestation: g.passkey_attestation,
                authorization_epoch: g.authorization_epoch,
                connected_at_ms: CanonicalU64::new(now_ms),
            };
            save_binding_state(state_dir, &connected)?;
            Ok(ConnectExchangeOutcome::Connected(Box::new(connected)))
        }
        401 | 403 | 410 => {
            scrub_and_remove_pkce_verifier(state_dir)?;
            let reason = format!("Coordinator rejected PKCE/K1 connect exchange (HTTP {status})");
            let revoked = SlackBindingState::Revoked {
                org_id,
                reason: reason.clone(),
                revoked_at_ms: CanonicalU64::new(now_ms),
            };
            save_binding_state(state_dir, &revoked)?;
            Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(reason))
        }
        429 | 500..=599 => Ok(ConnectExchangeOutcome::TempUnavailable(format!(
            "Coordinator temporarily unavailable during PKCE exchange (HTTP {status})"
        ))),
        other => Err(AuthStateError::InvalidConfig(format!(
            "unexpected HTTP {other} from Coordinator connect exchange"
        ))),
    }
}
