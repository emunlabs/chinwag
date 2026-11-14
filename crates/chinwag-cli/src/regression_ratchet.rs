// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Self-ratcheting behavioral regressions & secret-scrubbed RFC-8785 cassettes
//! (`CHWG-0251` · `INV-CI-BEHAVIORAL-RATCHET-01` & `INV-CI-ZERO-SECRET-LEAK-01`).
//!
//! Promotes negative architectural tombstones (`chinwag memory tombstone --promote-regression`
//! and `chinwag regression add`) into deterministic, git-tracked specs:
//! - `.chinwag/regressions/<id>.json` (`BehavioralRegressionSpecV1`)
//! - `.chinwag/cassettes/<id>.json` (`TombstoneCassetteV1`)
//!
//! Replays them offline at `$0` cost via `chinwag regression verify`.
#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, openat, statat};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

pub const INV_BEHAVIORAL_RATCHET: &str = "INV-CI-BEHAVIORAL-RATCHET-01";
pub const INV_ZERO_SECRET_LEAK: &str = "INV-CI-ZERO-SECRET-LEAK-01";
pub const REDACTED_MARKER: &str = "[REDACTED_SECRET]";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TombstoneCassetteV1 {
    pub schema: String,
    pub invariant: String,
    pub zero_secret_leak_invariant: String,
    pub id: String,
    pub source_commit: String,
    pub file_scope: String,
    pub attempted_action: String,
    pub observed_failure: String,
    pub kill_reason: String,
    pub verified_alternative: String,
    pub forbidden_patterns: Vec<String>,
    pub required_patterns: Vec<String>,
    pub secret_redactions_applied: usize,
    pub replay_mode: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehavioralRegressionSpecV1 {
    pub schema: String,
    pub invariant: String,
    pub id: String,
    pub directive: String,
    pub source_commit: String,
    pub file_scope: String,
    pub reason: String,
    pub alternative: String,
    pub forbidden_patterns: Vec<String>,
    pub required_patterns: Vec<String>,
    pub cassette_rel_path: String,
    pub cassette_jcs_sha256: String,
}

#[derive(Clone, Debug)]
pub struct PromoteRegressionInput<'a> {
    pub id: &'a str,
    pub source_commit: &'a str,
    pub file_scope: &'a str,
    pub attempted_action: &'a str,
    pub failure: &'a str,
    pub reason: &'a str,
    pub alternative: &'a str,
    pub forbidden_patterns: Vec<String>,
    pub required_patterns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromoteRegressionReceipt {
    pub ok: bool,
    pub invariant: String,
    pub zero_secret_leak_invariant: String,
    pub id: String,
    pub regression_path: String,
    pub cassette_path: String,
    pub spec_jcs_sha256: String,
    pub cassette_jcs_sha256: String,
    pub secret_redactions_applied: usize,
    pub payload_sha256_hex: String,
    pub runner_ed25519_pk_hex: String,
    pub runner_ed25519_sig_hex: String,
}

impl PromoteRegressionReceipt {
    fn canonical_signing_bytes(&self) -> Result<Vec<u8>, String> {
        let unsigned = json!({
            "cassette_jcs_sha256": self.cassette_jcs_sha256,
            "cassette_path": self.cassette_path,
            "id": self.id,
            "invariant": self.invariant,
            "ok": self.ok,
            "regression_path": self.regression_path,
            "secret_redactions_applied": self.secret_redactions_applied,
            "spec_jcs_sha256": self.spec_jcs_sha256,
            "zero_secret_leak_invariant": self.zero_secret_leak_invariant,
        });
        to_rfc8785_jcs_string(&unsigned).map(String::into_bytes)
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        let canonical = self.canonical_signing_bytes()?;
        if self.payload_sha256_hex != sha256_hex(&canonical) {
            return Err("PromoteRegressionReceipt payload_sha256_hex mismatch".to_owned());
        }
        verify_ed25519_jcs_signature(
            &canonical,
            &self.runner_ed25519_pk_hex,
            &self.runner_ed25519_sig_hex,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionFailureV1 {
    pub id: String,
    pub invariant: String,
    pub target: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionVerifyReportV1 {
    pub ok: bool,
    pub schema: String,
    pub invariant: String,
    pub passed: bool,
    pub specs_verified: usize,
    pub cassettes_verified: usize,
    pub scoped_files_checked: usize,
    pub failures: Vec<RegressionFailureV1>,
    pub payload_sha256_hex: String,
    pub runner_ed25519_pk_hex: String,
    pub runner_ed25519_sig_hex: String,
}

impl RegressionVerifyReportV1 {
    fn canonical_signing_bytes(&self) -> Result<Vec<u8>, String> {
        let failures_val =
            serde_json::to_value(&self.failures).map_err(|e| format!("serialize failures: {e}"))?;
        let unsigned = json!({
            "cassettes_verified": self.cassettes_verified,
            "failures": failures_val,
            "invariant": self.invariant,
            "ok": self.ok,
            "passed": self.passed,
            "schema": self.schema,
            "scoped_files_checked": self.scoped_files_checked,
            "specs_verified": self.specs_verified,
        });
        to_rfc8785_jcs_string(&unsigned).map(String::into_bytes)
    }

    fn build_signed(
        passed: bool,
        specs_verified: usize,
        cassettes_verified: usize,
        scoped_files_checked: usize,
        failures: Vec<RegressionFailureV1>,
    ) -> Result<Self, String> {
        let (pk_hex, signing_key) = generate_ephemeral_ed25519()?;
        let mut report = Self {
            ok: passed,
            schema: "RegressionVerifyReportV1".to_owned(),
            invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
            passed,
            specs_verified,
            cassettes_verified,
            scoped_files_checked,
            failures,
            payload_sha256_hex: String::new(),
            runner_ed25519_pk_hex: pk_hex,
            runner_ed25519_sig_hex: String::new(),
        };
        let canonical = report.canonical_signing_bytes()?;
        report.payload_sha256_hex = sha256_hex(&canonical);
        let sig: Signature = signing_key.sign(&canonical);
        report.runner_ed25519_sig_hex = hex_encode_bytes(&sig.to_bytes());
        report.verify_signature()?;
        Ok(report)
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        if self.schema != "RegressionVerifyReportV1" {
            return Err(format!("unexpected schema `{}`", self.schema));
        }
        let canonical = self.canonical_signing_bytes()?;
        if self.payload_sha256_hex != sha256_hex(&canonical) {
            return Err("RegressionVerifyReportV1 payload_sha256_hex mismatch".to_owned());
        }
        verify_ed25519_jcs_signature(
            &canonical,
            &self.runner_ed25519_pk_hex,
            &self.runner_ed25519_sig_hex,
        )
    }
}

fn generate_ephemeral_ed25519() -> Result<(String, SigningKey), String> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    rand::rng().fill_bytes(&mut *seed);
    if seed.iter().all(|&b| b == 0) {
        return Err("CSPRNG returned all-zero seed".to_owned());
    }
    let sk = SigningKey::from_bytes(&seed);
    let pk_hex = hex_encode_bytes(&sk.verifying_key().to_bytes());
    Ok((pk_hex, sk))
}

fn verify_ed25519_jcs_signature(
    canonical: &[u8],
    pk_hex: &str,
    sig_hex: &str,
) -> Result<(), String> {
    let pk_bytes = hex_decode_fixed::<32>(pk_hex)?;
    let sig_bytes = hex_decode_fixed::<64>(sig_hex)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| format!("invalid Ed25519 pk: {e}"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(canonical, &sig)
        .map_err(|e| format!("Ed25519 signature verification failed: {e}"))
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_fixed<const N: usize>(raw: &str) -> Result<[u8; N], String> {
    if raw.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, raw.len()));
    }
    let mut out = [0_u8; N];
    let bytes = raw.as_bytes();
    for (idx, slot) in out.iter_mut().enumerate() {
        let hi = match bytes[idx * 2] {
            b'0'..=b'9' => bytes[idx * 2] - b'0',
            b'a'..=b'f' => bytes[idx * 2] - b'a' + 10,
            b'A'..=b'F' => bytes[idx * 2] - b'A' + 10,
            other => return Err(format!("invalid hex byte 0x{other:02x}")),
        };
        let lo = match bytes[idx * 2 + 1] {
            b'0'..=b'9' => bytes[idx * 2 + 1] - b'0',
            b'a'..=b'f' => bytes[idx * 2 + 1] - b'a' + 10,
            b'A'..=b'F' => bytes[idx * 2 + 1] - b'A' + 10,
            other => return Err(format!("invalid hex byte 0x{other:02x}")),
        };
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

pub fn validate_regression_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 128 {
        return Err("regression id must be 1..=128 ASCII characters".to_owned());
    }
    if id.starts_with('.') || id.ends_with('.') || id.contains("..") {
        return Err(format!("invalid regression id `{id}`"));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "regression id `{id}` may only contain [A-Za-z0-9._-]"
        ));
    }
    Ok(())
}

/// Scrubs bearer tokens, API keys, PEM blocks, JWTs, AWS keys, GitHub PATs, and
/// secret assignments before writing git-tracked `.chinwag/regressions` or `.chinwag/cassettes`.
pub fn scrub_secrets(input: &str) -> (String, usize) {
    let mut redactions = 0_usize;
    let mut text = input.to_owned();

    // 1. Scrub PEM private-key armor blocks.
    let pem_begin = concat!("-----", "BEGIN ");
    let pem_priv = concat!("PRIVATE", " KEY-----");
    let pem_end = concat!("-----", "END ");
    while let Some(start) = text.find(pem_begin) {
        let rest = &text[start..];
        if let Some(hdr_end) = rest.find(pem_priv) {
            let search_from = start + hdr_end + pem_priv.len();
            if let Some(end_rel) = text[search_from..].find(pem_end) {
                let after_end = search_from + end_rel;
                let tail_len = text[after_end..]
                    .find("-----")
                    .and_then(|i| {
                        let r = &text[after_end + i + 5..];
                        r.find("-----").map(|j| i + 5 + j + 5)
                    })
                    .unwrap_or_else(|| text.len() - after_end);
                text.replace_range(start..after_end + tail_len, REDACTED_MARKER);
                redactions += 1;
                continue;
            }
        }
        break;
    }

    // 2. Scrub `Bearer <ws+><token>`, `Basic <ws+><token>`, and `Authorization: token <ws+><token>`
    //    case-insensitively across single or multiple spaces/tabs.
    text = scrub_auth_schemes(&text, &mut redactions);

    // 3. Token-by-token & multi-occurrence `key=value` / `header: value` scan per line.
    let mut rebuilt = String::with_capacity(text.len());
    for (line_idx, line) in text.split('\n').enumerate() {
        if line_idx > 0 {
            rebuilt.push('\n');
        }
        rebuilt.push_str(&scrub_line_tokens(line, &mut redactions));
    }

    (rebuilt, redactions)
}

fn is_cred_value_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b'/' | b'=' | b'~')
}

fn scrub_auth_schemes(input: &str, redactions: &mut usize) -> String {
    let mut text = input.to_owned();

    // First scrub `Authorization: token <ws+><pat>` (case-insensitive).
    let mut cursor = 0;
    while cursor < text.len() {
        let lower = text[cursor..].to_ascii_lowercase();
        let Some(rel) = lower.find("authorization") else {
            break;
        };
        let hdr_start = cursor + rel;
        let after_hdr = hdr_start + "authorization".len();
        let ws1 = text[after_hdr..]
            .bytes()
            .take_while(|b| matches!(b, b' ' | b'\t'))
            .count();
        if text[after_hdr + ws1..].starts_with(':') {
            let after_colon = after_hdr + ws1 + 1;
            let ws2 = text[after_colon..]
                .bytes()
                .take_while(|b| matches!(b, b' ' | b'\t'))
                .count();
            let scheme_start = after_colon + ws2;
            if text[scheme_start..]
                .get(..5)
                .is_some_and(|s| s.eq_ignore_ascii_case("token"))
            {
                let after_scheme = scheme_start + 5;
                let ws3 = text[after_scheme..]
                    .bytes()
                    .take_while(|b| matches!(b, b' ' | b'\t'))
                    .count();
                if ws3 >= 1 {
                    let val_start = after_scheme + ws3;
                    let val_len = text[val_start..]
                        .bytes()
                        .take_while(|&b| is_cred_value_byte(b))
                        .count();
                    if val_len >= 8 && !text[val_start..].starts_with("[REDACTED") {
                        text.replace_range(val_start..val_start + val_len, REDACTED_MARKER);
                        *redactions += 1;
                        cursor = val_start + REDACTED_MARKER.len();
                        continue;
                    }
                }
            }
        }
        cursor = after_hdr;
    }

    // Next scrub `Bearer <ws+><tok>` and `Basic <ws+><tok>` (case-insensitive, word-bounded).
    for scheme_kw in ["bearer", "basic"] {
        let mut pos = 0;
        while pos < text.len() {
            let lower = text[pos..].to_ascii_lowercase();
            let Some(rel) = lower.find(scheme_kw) else {
                break;
            };
            let kw_start = pos + rel;
            let prev_is_word = kw_start > 0 && is_token_char(text.as_bytes()[kw_start - 1]);
            let after_kw = kw_start + scheme_kw.len();
            let ws_len = text[after_kw..]
                .bytes()
                .take_while(|b| matches!(b, b' ' | b'\t'))
                .count();
            if !prev_is_word && ws_len >= 1 {
                let val_start = after_kw + ws_len;
                let val_len = text[val_start..]
                    .bytes()
                    .take_while(|&b| is_cred_value_byte(b))
                    .count();
                if val_len >= 8 && !text[val_start..].starts_with("[REDACTED") {
                    text.replace_range(val_start..val_start + val_len, REDACTED_MARKER);
                    *redactions += 1;
                    pos = val_start + REDACTED_MARKER.len();
                    continue;
                }
            }
            pos = after_kw;
        }
    }

    text
}

const SENSITIVE_KEY_HINTS: &[&str] = &[
    "x-api-key",
    "api_key",
    "api-key",
    "apikey",
    "secret_key",
    "secret-key",
    "private_key",
    "private-key",
    "access_token",
    "access-token",
    "refresh_token",
    "refresh-token",
    "auth_token",
    "auth-token",
    "client_secret",
    "client-secret",
    "set-cookie",
    "authorization",
    "cookie",
    "password",
    "passwd",
];

fn scrub_line_tokens(line: &str, redactions: &mut usize) -> String {
    // Advance across ALL occurrences of each sensitive key hint on the line so prose mentions
    // earlier on the line (`"Rotated api_key because api_key=..."`) never shadow real secrets.
    let lower = line.to_ascii_lowercase();
    for key_hint in SENSITIVE_KEY_HINTS {
        let mut search_from = 0;
        while search_from < lower.len() {
            let Some(rel) = lower[search_from..].find(key_hint) else {
                break;
            };
            let pos = search_from + rel;
            let after_key = pos + key_hint.len();
            let tail = &line[after_key..];
            let trimmed = tail.trim_start_matches([' ', '\t', '"', '\'']);
            if let Some(rest) = trimmed
                .strip_prefix('=')
                .or_else(|| trimmed.strip_prefix(':'))
            {
                let val_trimmed = rest.trim_start_matches([' ', '\t', '"', '\'']);
                let val_len = val_trimmed
                    .bytes()
                    .take_while(|b| {
                        !b.is_ascii_whitespace()
                            && !matches!(b, b'"' | b'\'' | b',' | b';' | b')' | b'}' | b']')
                    })
                    .count();
                if val_len >= 8 && !val_trimmed.starts_with("[REDACTED") {
                    let val_offset = line.len() - val_trimmed.len();
                    let mut out = String::new();
                    out.push_str(&scrub_line_tokens(&line[..pos], redactions));
                    out.push_str(&line[pos..val_offset]);
                    out.push_str(REDACTED_MARKER);
                    out.push_str(&scrub_line_tokens(&val_trimmed[val_len..], redactions));
                    *redactions += 1;
                    return out;
                }
            }
            search_from = after_key;
        }
    }

    // Scan contiguous token runs for credential prefixes, JWTs (`eyJ...`), and secret tokens.
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        if is_token_char(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_token_char(bytes[i]) {
                i += 1;
            }
            let tok = &line[start..i];
            if looks_like_secret_token(tok) {
                out.push_str(REDACTED_MARKER);
                *redactions += 1;
            } else {
                out.push_str(tok);
            }
        } else {
            let ch = line[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
}

pub fn looks_like_secret_token(tok: &str) -> bool {
    if tok == REDACTED_MARKER || tok.starts_with("sha256:") || tok.starts_with("blake3:") {
        return false;
    }
    let phantom_prefix = concat!("chwg", "_phantom_");
    if tok.starts_with(phantom_prefix) && tok.len() >= phantom_prefix.len() + 6 {
        return true;
    }
    for prefix in [
        concat!("sk", "-ant-"),
        concat!("sk", "-proj-"),
        concat!("sk", "-live-"),
        concat!("sk", "-"),
        concat!("xa", "i-"),
        concat!("gh", "p_"),
        concat!("gh", "o_"),
        concat!("gh", "u_"),
        concat!("gh", "s_"),
        concat!("gh", "r_"),
        concat!("github", "_pat_"),
        concat!("xox", "b-"),
        concat!("xox", "p-"),
        concat!("xox", "a-"),
        concat!("xox", "r-"),
        concat!("AI", "za"),
        concat!("wh", "sec_"),
        concat!("rk_", "live_"),
    ] {
        if tok.starts_with(prefix) && tok.len() >= prefix.len() + 12 {
            return true;
        }
    }
    if tok.starts_with(concat!("AK", "IA"))
        && tok.len() == 20
        && tok
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return true;
    }
    // Three-segment JWT (`eyJ<header>.eyJ<payload>.<sig>`).
    if tok.starts_with("eyJ") {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() == 3
            && parts[0].len() >= 8
            && parts[1].starts_with("eyJ")
            && parts[2].len() >= 8
        {
            return true;
        }
    }
    false
}

/// RFC-8785 JSON Canonicalization Scheme (JCS) deterministic serializer:
/// sorts object keys by UTF-16 code units with compact separators and standard JSON string escaping.
pub fn to_rfc8785_jcs_string(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_jcs_value(value, &mut out)?;
    Ok(out)
}

fn write_jcs_value(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err("RFC-8785 JCS forbids non-finite numbers".to_owned());
                }
                if f == 0.0 {
                    out.push('0');
                } else {
                    out.push_str(&serde_json::to_string(&n).map_err(|e| e.to_string())?);
                }
            }
        }
        Value::String(s) => {
            write_jcs_string(s, out);
        }
        Value::Array(arr) => {
            out.push('[');
            for (idx, item) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_jcs_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            write_jcs_object(map, out)?;
        }
    }
    Ok(())
}

fn write_jcs_object(map: &Map<String, Value>, out: &mut String) -> Result<(), String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    out.push('{');
    for (idx, key) in keys.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        write_jcs_string(key, out);
        out.push(':');
        if let Some(val) = map.get(*key) {
            write_jcs_value(val, out)?;
        }
    }
    out.push('}');
    Ok(())
}

fn write_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn ensure_safe_subdir(parent: &Path, leaf: &str) -> Result<PathBuf, String> {
    let pst = statat(CWD, parent, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| format!("stat {}: {e}", parent.display()))?;
    if FileType::from_raw_mode(pst.st_mode) != FileType::Directory {
        return Err(format!(
            "refusing symlink or non-directory `{}`",
            parent.display()
        ));
    }
    let dir = parent.join(leaf);
    if let Ok(st) = statat(CWD, &dir, AtFlags::SYMLINK_NOFOLLOW) {
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
            return Err(format!(
                "refusing symlink/non-directory `{}`",
                dir.display()
            ));
        }
    } else {
        fs::create_dir(&dir).map_err(|e| format!("create_dir {}: {e}", dir.display()))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {}: {e}", dir.display()))?;
    }
    Ok(dir)
}

pub(crate) fn ensure_regular_file_no_follow(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let pst = statat(CWD, parent, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("stat parent `{}`: {e}", parent.display()))?;
        if FileType::from_raw_mode(pst.st_mode) != FileType::Directory {
            return Err(format!(
                "refusing non-directory or symlink parent `{}`",
                parent.display()
            ));
        }
    }
    let st = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| format!("stat `{}`: {e}", path.display()))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(format!(
            "refusing symlink or non-regular file `{}`",
            path.display()
        ));
    }
    if st.st_nlink > 1 {
        return Err(format!(
            "refusing hardlinked file `{}` (nlink={})",
            path.display(),
            st.st_nlink
        ));
    }
    Ok(())
}

pub(crate) fn ensure_parent_dir_chain_no_follow(parent: &Path) -> Result<(), String> {
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    for comp in parent.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(format!(
                "refusing `..` traversal in output directory `{}`",
                parent.display()
            ));
        }
    }
    let mut missing_leaves = Vec::new();
    let mut cursor = parent;
    loop {
        if let Ok(st) = statat(CWD, cursor, AtFlags::SYMLINK_NOFOLLOW) {
            if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
                return Err(format!(
                    "refusing symlink or non-directory ancestor `{}`",
                    cursor.display()
                ));
            }
            break;
        }
        let Some(name) = cursor.file_name() else {
            return Err(format!("missing root directory for `{}`", parent.display()));
        };
        missing_leaves.push(name.to_os_string());
        let Some(next_parent) = cursor.parent() else {
            break;
        };
        cursor = if next_parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            next_parent
        };
    }

    let mut build = if cursor.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        cursor.to_path_buf()
    };
    for seg in missing_leaves.into_iter().rev() {
        build.push(seg);
        if let Ok(st) = statat(CWD, &build, AtFlags::SYMLINK_NOFOLLOW) {
            if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
                return Err(format!(
                    "refusing symlink or non-directory `{}`",
                    build.display()
                ));
            }
        } else {
            fs::create_dir(&build).map_err(|e| format!("create_dir {}: {e}", build.display()))?;
            fs::set_permissions(&build, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("chmod {}: {e}", build.display()))?;
        }
    }
    Ok(())
}

pub(crate) fn write_regular_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_parent_dir_chain_no_follow(parent)?;

    if let Ok(st) = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW) {
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return Err(format!(
                "refusing symlink or non-regular target `{}`",
                path.display()
            ));
        }
        if st.st_nlink > 1 {
            return Err(format!(
                "refusing hardlinked target `{}` (nlink={})",
                path.display(),
                st.st_nlink
            ));
        }
    }

    let mut nonce = [0_u8; 8];
    rand::rng().fill_bytes(&mut nonce);
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("reg"),
        std::process::id(),
        hex_encode_bytes(&nonce)
    ));
    let owned_fd = openat(
        CWD,
        &tmp,
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| format!("open {}: {e}", tmp.display()))?;
    let mut file = fs::File::from(owned_fd);
    let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("write {}: {e}", tmp.display()));
    }
    drop(file);
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename {}: {e}", path.display())
    })
}

/// Scrubs secrets and emits deterministic RFC-8785 JCS `.chinwag/regressions/<id>.json`
/// and `.chinwag/cassettes/<id>.json` (`TombstoneCassetteV1`).
pub fn promote_tombstone_regression(
    repo_root: &Path,
    input: &PromoteRegressionInput<'_>,
) -> Result<PromoteRegressionReceipt, String> {
    validate_regression_id(input.id)?;
    let chinwag_dir = ensure_safe_subdir(repo_root, ".chinwag")?;
    let regressions_dir = ensure_safe_subdir(&chinwag_dir, "regressions")?;
    let cassettes_dir = ensure_safe_subdir(&chinwag_dir, "cassettes")?;

    let (clean_commit, r1) = scrub_secrets(input.source_commit);
    let (clean_scope, r2) = scrub_secrets(input.file_scope);
    let (clean_act, r3) = scrub_secrets(input.attempted_action);
    let (clean_fail, r4) = scrub_secrets(input.failure);
    let (clean_reason, r5) = scrub_secrets(input.reason);
    let (clean_alt, r6) = scrub_secrets(input.alternative);

    let mut total_redactions = r1 + r2 + r3 + r4 + r5 + r6;

    let mut forbidden_patterns = Vec::new();
    for pat in &input.forbidden_patterns {
        let (c, r) = scrub_secrets(pat.trim());
        total_redactions += r;
        if !c.is_empty() && c != REDACTED_MARKER {
            forbidden_patterns.push(c);
        }
    }
    forbidden_patterns.sort();
    forbidden_patterns.dedup();

    let mut required_patterns = Vec::new();
    for pat in &input.required_patterns {
        let (c, r) = scrub_secrets(pat.trim());
        total_redactions += r;
        if !c.is_empty() && c != REDACTED_MARKER {
            required_patterns.push(c);
        }
    }
    required_patterns.sort();
    required_patterns.dedup();

    let cassette = TombstoneCassetteV1 {
        schema: "TombstoneCassetteV1".to_owned(),
        invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
        zero_secret_leak_invariant: INV_ZERO_SECRET_LEAK.to_owned(),
        id: input.id.to_owned(),
        source_commit: clean_commit.clone(),
        file_scope: clean_scope.clone(),
        attempted_action: clean_act,
        observed_failure: clean_fail,
        kill_reason: clean_reason.clone(),
        verified_alternative: clean_alt.clone(),
        forbidden_patterns: forbidden_patterns.clone(),
        required_patterns: required_patterns.clone(),
        secret_redactions_applied: total_redactions,
        replay_mode: "offline-zero-cost-jcs-v1".to_owned(),
    };
    let cassette_val = serde_json::to_value(&cassette).map_err(|e| e.to_string())?;
    let cassette_jcs = to_rfc8785_jcs_string(&cassette_val)?;
    let cassette_sha = sha256_hex(cassette_jcs.as_bytes());

    let cassette_rel_path = format!(".chinwag/cassettes/{}.json", input.id);
    let spec = BehavioralRegressionSpecV1 {
        schema: "BehavioralRegressionSpecV1".to_owned(),
        invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
        id: input.id.to_owned(),
        directive: "DO_NOT_REPEAT".to_owned(),
        source_commit: clean_commit,
        file_scope: clean_scope,
        reason: clean_reason,
        alternative: clean_alt,
        forbidden_patterns,
        required_patterns,
        cassette_rel_path: cassette_rel_path.clone(),
        cassette_jcs_sha256: cassette_sha.clone(),
    };
    let spec_val = serde_json::to_value(&spec).map_err(|e| e.to_string())?;
    let spec_jcs = to_rfc8785_jcs_string(&spec_val)?;
    let spec_sha = sha256_hex(spec_jcs.as_bytes());

    let cassette_path = cassettes_dir.join(format!("{}.json", input.id));
    let regression_path = regressions_dir.join(format!("{}.json", input.id));
    write_regular_file_atomic(&cassette_path, format!("{cassette_jcs}\n").as_bytes())?;
    write_regular_file_atomic(&regression_path, format!("{spec_jcs}\n").as_bytes())?;

    let (pk_hex, signing_key) = generate_ephemeral_ed25519()?;
    let mut receipt = PromoteRegressionReceipt {
        ok: true,
        invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
        zero_secret_leak_invariant: INV_ZERO_SECRET_LEAK.to_owned(),
        id: input.id.to_owned(),
        regression_path: format!(".chinwag/regressions/{}.json", input.id),
        cassette_path: cassette_rel_path,
        spec_jcs_sha256: spec_sha,
        cassette_jcs_sha256: cassette_sha,
        secret_redactions_applied: total_redactions,
        payload_sha256_hex: String::new(),
        runner_ed25519_pk_hex: pk_hex,
        runner_ed25519_sig_hex: String::new(),
    };
    let canonical = receipt.canonical_signing_bytes()?;
    receipt.payload_sha256_hex = sha256_hex(&canonical);
    let sig: Signature = signing_key.sign(&canonical);
    receipt.runner_ed25519_sig_hex = hex_encode_bytes(&sig.to_bytes());
    receipt.verify_signature()?;
    Ok(receipt)
}

/// Offline `$0` verifier replaying `.chinwag/regressions/*.json` + `.chinwag/cassettes/*.json`.
pub fn verify_regressions(
    repo_root: &Path,
    filter_id: Option<&str>,
) -> Result<RegressionVerifyReportV1, String> {
    let root_st = statat(CWD, repo_root, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| format!("stat {}: {e}", repo_root.display()))?;
    if FileType::from_raw_mode(root_st.st_mode) != FileType::Directory {
        return Err(format!(
            "refusing symlink or non-directory repo root `{}`",
            repo_root.display()
        ));
    }

    let chinwag_dir = repo_root.join(".chinwag");
    if let Ok(cst) = statat(CWD, &chinwag_dir, AtFlags::SYMLINK_NOFOLLOW) {
        if FileType::from_raw_mode(cst.st_mode) != FileType::Directory {
            return Err(format!(
                "refusing symlink or non-directory `{}`",
                chinwag_dir.display()
            ));
        }
    } else {
        return RegressionVerifyReportV1::build_signed(true, 0, 0, 0, Vec::new());
    }

    let regressions_dir = chinwag_dir.join("regressions");
    if let Ok(rst) = statat(CWD, &regressions_dir, AtFlags::SYMLINK_NOFOLLOW) {
        if FileType::from_raw_mode(rst.st_mode) != FileType::Directory {
            return Err(format!(
                "refusing symlink or non-directory `{}`",
                regressions_dir.display()
            ));
        }
    } else {
        return RegressionVerifyReportV1::build_signed(true, 0, 0, 0, Vec::new());
    }

    let mut spec_files: Vec<PathBuf> = fs::read_dir(&regressions_dir)
        .map_err(|e| format!("read_dir {}: {e}", regressions_dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    spec_files.sort();

    let all_repo_files = collect_repo_source_files(repo_root);
    let mut specs_verified = 0_usize;
    let mut cassettes_verified = 0_usize;
    let mut scoped_files_checked = 0_usize;
    let mut failures = Vec::new();

    for spec_path in spec_files {
        let stem_str = spec_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("<invalid>")
            .to_owned();
        if let Err(fs_err) = ensure_regular_file_no_follow(&spec_path) {
            failures.push(RegressionFailureV1 {
                id: stem_str,
                invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                target: spec_path.display().to_string(),
                detail: fs_err,
            });
            continue;
        }

        let raw_spec = fs::read_to_string(&spec_path)
            .map_err(|e| format!("read {}: {e}", spec_path.display()))?;
        let spec: BehavioralRegressionSpecV1 = match serde_json::from_str(&raw_spec) {
            Ok(s) => s,
            Err(e) => {
                failures.push(RegressionFailureV1 {
                    id: stem_str,
                    invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                    target: spec_path.display().to_string(),
                    detail: format!("malformed BehavioralRegressionSpecV1 JSON: {e}"),
                });
                continue;
            }
        };
        if let Some(fid) = filter_id
            && spec.id != fid
        {
            continue;
        }
        specs_verified += 1;

        if let Err(id_err) = validate_regression_id(&spec.id) {
            failures.push(RegressionFailureV1 {
                id: spec.id.clone(),
                invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                target: spec_path.display().to_string(),
                detail: id_err,
            });
            continue;
        }
        if spec_path.file_stem() != Some(OsStr::new(&spec.id)) {
            failures.push(RegressionFailureV1 {
                id: spec.id.clone(),
                invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                target: spec_path.display().to_string(),
                detail: format!(
                    "spec filename stem `{stem_str}` does not match spec.id `{}`",
                    spec.id
                ),
            });
        }

        // 1. Secret leak scan on spec JSON (`INV-CI-ZERO-SECRET-LEAK-01`).
        let (_, spec_leaks) = scrub_secrets(&raw_spec);
        if spec_leaks > 0 {
            failures.push(RegressionFailureV1 {
                id: spec.id.clone(),
                invariant: INV_ZERO_SECRET_LEAK.to_owned(),
                target: format!(".chinwag/regressions/{}.json", spec.id),
                detail: format!(
                    "detected {spec_leaks} unredacted secret token(s) in regression spec"
                ),
            });
        }

        // 2. Verify RFC-8785 JCS canonicalization of spec on disk.
        let spec_val: Value = serde_json::from_str(&raw_spec).unwrap_or(Value::Null);
        if let Ok(expected_jcs) = to_rfc8785_jcs_string(&spec_val)
            && raw_spec.trim() != expected_jcs
        {
            failures.push(RegressionFailureV1 {
                id: spec.id.clone(),
                invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                target: format!(".chinwag/regressions/{}.json", spec.id),
                detail: "regression spec is not in canonical RFC-8785 JCS form".to_owned(),
            });
        }

        // 3. Enforce strict cassette path containment and `SYMLINK_NOFOLLOW` regular-file verification.
        let expected_cassette_rel = format!(".chinwag/cassettes/{}.json", spec.id);
        if spec.cassette_rel_path != expected_cassette_rel {
            failures.push(RegressionFailureV1 {
                id: spec.id.clone(),
                invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                target: spec.cassette_rel_path.clone(),
                detail: format!(
                    "cassette_rel_path `{}` violates containment; expected `{expected_cassette_rel}`",
                    spec.cassette_rel_path
                ),
            });
        } else {
            let cassette_path = chinwag_dir
                .join("cassettes")
                .join(format!("{}.json", spec.id));
            match ensure_regular_file_no_follow(&cassette_path)
                .and_then(|()| fs::read_to_string(&cassette_path).map_err(|e| e.to_string()))
            {
                Ok(raw_cassette) => {
                    cassettes_verified += 1;
                    let (_, cas_leaks) = scrub_secrets(&raw_cassette);
                    if cas_leaks > 0 {
                        failures.push(RegressionFailureV1 {
                            id: spec.id.clone(),
                            invariant: INV_ZERO_SECRET_LEAK.to_owned(),
                            target: spec.cassette_rel_path.clone(),
                            detail: format!(
                                "detected {cas_leaks} unredacted secret token(s) in cassette"
                            ),
                        });
                    }
                    match serde_json::from_str::<Value>(&raw_cassette)
                        .map_err(|e| e.to_string())
                        .and_then(|v| to_rfc8785_jcs_string(&v))
                    {
                        Ok(cas_jcs) => {
                            let actual_sha = sha256_hex(cas_jcs.as_bytes());
                            if actual_sha != spec.cassette_jcs_sha256 {
                                failures.push(RegressionFailureV1 {
                                    id: spec.id.clone(),
                                    invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                                    target: spec.cassette_rel_path.clone(),
                                    detail: format!(
                                        "cassette RFC-8785 JCS sha256 mismatch: expected {}, got {actual_sha}",
                                        spec.cassette_jcs_sha256
                                    ),
                                });
                            }
                        }
                        Err(e) => {
                            failures.push(RegressionFailureV1 {
                                id: spec.id.clone(),
                                invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                                target: spec.cassette_rel_path.clone(),
                                detail: format!("invalid cassette JSON: {e}"),
                            });
                        }
                    }
                }
                Err(e) => {
                    failures.push(RegressionFailureV1 {
                        id: spec.id.clone(),
                        invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                        target: spec.cassette_rel_path.clone(),
                        detail: format!("missing or unsafe bound TombstoneCassetteV1: {e}"),
                    });
                }
            }
        }

        // 4. Evaluate `forbidden_patterns` & `required_patterns` across matching files in `file_scope`.
        if !spec.forbidden_patterns.is_empty() || !spec.required_patterns.is_empty() {
            let matching_files: Vec<&(String, PathBuf)> = all_repo_files
                .iter()
                .filter(|(rel, _)| matches_scope_globs(rel, &spec.file_scope))
                .collect();
            let mut found_required: Vec<bool> = vec![false; spec.required_patterns.len()];
            for (rel, full_path) in &matching_files {
                let Ok(contents) = fs::read_to_string(full_path) else {
                    continue;
                };
                scoped_files_checked += 1;
                for forbidden in &spec.forbidden_patterns {
                    if contents.contains(forbidden) {
                        failures.push(RegressionFailureV1 {
                            id: spec.id.clone(),
                            invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                            target: rel.clone(),
                            detail: format!(
                                "forbidden tombstoned pattern `{forbidden}` reintroduced ({})",
                                spec.reason
                            ),
                        });
                    }
                }
                for (r_idx, required) in spec.required_patterns.iter().enumerate() {
                    if contents.contains(required) {
                        found_required[r_idx] = true;
                    }
                }
            }
            for (r_idx, required) in spec.required_patterns.iter().enumerate() {
                if !found_required[r_idx] {
                    failures.push(RegressionFailureV1 {
                        id: spec.id.clone(),
                        invariant: INV_BEHAVIORAL_RATCHET.to_owned(),
                        target: spec.file_scope.clone(),
                        detail: format!(
                            "required invariant pattern `{required}` missing across scope `{}`",
                            spec.file_scope
                        ),
                    });
                }
            }
        }
    }

    let passed = failures.is_empty();
    RegressionVerifyReportV1::build_signed(
        passed,
        specs_verified,
        cassettes_verified,
        scoped_files_checked,
        failures,
    )
}

fn collect_repo_source_files(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    walk_repo_files(root, root, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn walk_repo_files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if matches!(
            name,
            ".git" | ".chinwag" | "target" | "node_modules" | ".nuxt" | "dist"
        ) {
            continue;
        }
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            walk_repo_files(root, &path, out);
        } else if ft.is_file()
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push((rel.to_string_lossy().replace('\\', "/"), path));
        }
    }
}

fn matches_scope_globs(rel_path: &str, scope: &str) -> bool {
    let path = rel_path.trim().trim_start_matches("./").trim_matches('/');
    for raw_glob in scope.split(',') {
        let g = raw_glob.trim().trim_start_matches("./").trim_matches('/');
        if g.is_empty() {
            continue;
        }
        if g == "*" || g == "**" || g == path {
            return true;
        }
        if let Some(prefix) = g.strip_suffix("/**")
            && (path == prefix || path.starts_with(&format!("{prefix}/")))
        {
            return true;
        }
        if let Some(prefix) = g.strip_suffix("/*")
            && let Some(rest) = path.strip_prefix(&format!("{prefix}/"))
            && !rest.contains('/')
        {
            return true;
        }
        if wildcard_glob(g.as_bytes(), path.as_bytes()) {
            return true;
        }
    }
    false
}

fn wildcard_glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut pi, mut ti) = (0_usize, 0_usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0_usize;
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// CLI entrypoint for `chinwag regression <add|verify|list> ...`.
pub fn run_regression_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let sub = args.first().map(String::as_str).unwrap_or("verify");
    if matches!(sub, "--help" | "-h" | "help") {
        let _ = writeln!(
            stdout,
            "Usage: chinwag regression add --id <id> --file-scope <glob> --reason <why-killed> [--attempted-action <act>] [--failure <fail>] [--alternative <alt>] [--forbidden-pattern <pat>] [--required-pattern <pat>] [--commit <sha>] [--repo <path>] [--json]\n\
             \x20      chinwag regression verify [--repo <path>] [--id <id>] [--json]\n\
             \x20      chinwag regression list [--repo <path>] [--json]"
        );
        return 0;
    }

    match sub {
        "add" => run_regression_add(&args[1..], stdout, stderr),
        "verify" | "check" => run_regression_verify(&args[1..], stdout, stderr),
        "list" | "ls" => run_regression_list(&args[1..], stdout, stderr),
        other => {
            let _ = writeln!(
                stderr,
                "chinwag regression: unknown subcommand `{other}` (expected `add`, `verify`, or `list`)"
            );
            2
        }
    }
}

fn resolve_target_repo(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub(crate) fn infer_head_commit(repo_root: &Path) -> String {
    let git_bin = std::env::var("CHINWAG_GIT_BIN")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "git".to_owned());
    if let Ok(out) = std::process::Command::new(git_bin)
        .args(["-C", &repo_root.to_string_lossy(), "rev-parse", "HEAD"])
        .output()
        && out.status.success()
    {
        let sha = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !sha.is_empty() {
            return sha;
        }
    }
    "0000000000000000000000000000000000000000".to_owned()
}

fn run_regression_add(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let mut id: Option<String> = None;
    let mut file_scope = "*".to_owned();
    let mut reason: Option<String> = None;
    let mut attempted_action: Option<String> = None;
    let mut failure: Option<String> = None;
    let mut alternative: Option<String> = None;
    let mut commit: Option<String> = None;
    let mut repo_arg: Option<String> = None;
    let mut forbidden_patterns = Vec::new();
    let mut required_patterns = Vec::new();
    let mut is_json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" if i + 1 < args.len() => {
                id = Some(args[i + 1].clone());
                i += 2;
            }
            "--file-scope" | "--scope" if i + 1 < args.len() => {
                file_scope = args[i + 1].clone();
                i += 2;
            }
            "--reason" | "--why-killed" if i + 1 < args.len() => {
                reason = Some(args[i + 1].clone());
                i += 2;
            }
            "--attempted-action" | "--action" if i + 1 < args.len() => {
                attempted_action = Some(args[i + 1].clone());
                i += 2;
            }
            "--failure" if i + 1 < args.len() => {
                failure = Some(args[i + 1].clone());
                i += 2;
            }
            "--alternative" | "--alt" if i + 1 < args.len() => {
                alternative = Some(args[i + 1].clone());
                i += 2;
            }
            "--forbidden-pattern" | "--forbid" if i + 1 < args.len() => {
                forbidden_patterns.push(args[i + 1].clone());
                i += 2;
            }
            "--required-pattern" | "--require" if i + 1 < args.len() => {
                required_patterns.push(args[i + 1].clone());
                i += 2;
            }
            "--commit" | "--source-commit" if i + 1 < args.len() => {
                commit = Some(args[i + 1].clone());
                i += 2;
            }
            "--repo" if i + 1 < args.len() => {
                repo_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--json" => {
                is_json = true;
                i += 1;
            }
            other => {
                let _ = writeln!(stderr, "chinwag regression add: invalid argument `{other}`");
                return 2;
            }
        }
    }

    let Some(id) = id else {
        let _ = writeln!(stderr, "chinwag regression add: missing `--id <id>`");
        return 2;
    };
    let Some(reason) = reason else {
        let _ = writeln!(
            stderr,
            "chinwag regression add: missing `--reason <why-killed>`"
        );
        return 2;
    };

    let repo_root = resolve_target_repo(repo_arg.as_deref());
    let source_commit = commit.unwrap_or_else(|| infer_head_commit(&repo_root));
    let act =
        attempted_action.unwrap_or_else(|| format!("Modifying {file_scope} with rejected pattern"));
    let fail = failure.unwrap_or_else(|| reason.clone());
    let alt = alternative
        .unwrap_or_else(|| "Follow active verified_invariants in .chinwag/state.crdb".to_owned());

    match promote_tombstone_regression(
        &repo_root,
        &PromoteRegressionInput {
            id: &id,
            source_commit: &source_commit,
            file_scope: &file_scope,
            attempted_action: &act,
            failure: &fail,
            reason: &reason,
            alternative: &alt,
            forbidden_patterns,
            required_patterns,
        },
    ) {
        Ok(receipt) => {
            if is_json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&receipt).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string(&receipt).unwrap_or_default()
                );
            }
            0
        }
        Err(e) => {
            let _ = writeln!(stderr, "chinwag regression add: {e}");
            1
        }
    }
}

fn run_regression_verify(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let mut repo_arg: Option<String> = None;
    let mut filter_id: Option<String> = None;
    let mut is_json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" if i + 1 < args.len() => {
                repo_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--id" if i + 1 < args.len() => {
                filter_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--json" => {
                is_json = true;
                i += 1;
            }
            other => {
                let _ = writeln!(
                    stderr,
                    "chinwag regression verify: invalid argument `{other}`"
                );
                return 2;
            }
        }
    }
    let repo_root = resolve_target_repo(repo_arg.as_deref());
    match verify_regressions(&repo_root, filter_id.as_deref()) {
        Ok(report) => {
            if is_json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string(&report).unwrap_or_default()
                );
            }
            if report.passed {
                0
            } else {
                for f in &report.failures {
                    let _ = writeln!(
                        stderr,
                        "chinwag regression verify: [{}] {} — {}",
                        f.id, f.target, f.detail
                    );
                }
                1
            }
        }
        Err(e) => {
            let _ = writeln!(stderr, "chinwag regression verify: {e}");
            1
        }
    }
}

fn run_regression_list(args: &[String], stdout: &mut dyn Write, _stderr: &mut dyn Write) -> u8 {
    let mut repo_arg: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--repo" && i + 1 < args.len() {
            repo_arg = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    let repo_root = resolve_target_repo(repo_arg.as_deref());
    let regressions_dir = repo_root.join(".chinwag").join("regressions");
    let mut items = Vec::new();
    if let Ok(entries) = fs::read_dir(&regressions_dir) {
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            if p.extension().and_then(|s| s.to_str()) == Some("json")
                && ensure_regular_file_no_follow(&p).is_ok()
                && let Ok(raw) = fs::read_to_string(&p)
                && let Ok(val) = serde_json::from_str::<Value>(&raw)
            {
                items.push(val);
            }
        }
    }
    let payload = json!({
        "ok": true,
        "invariant": INV_BEHAVIORAL_RATCHET,
        "count": items.len(),
        "regressions": items,
    });
    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_scrubber_redacts_tokens_keys_and_pem_blocks_deterministically() {
        let sk_tok = format!("{}{}", concat!("sk", "-proj-"), "1234567890abcdefghij");
        let gh_tok = format!(
            "{}{}",
            concat!("gh", "p_"),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
        );
        let phantom_tok = format!("{}{}", concat!("chwg", "_phantom_"), "secret887766");
        let pem_open = concat!("-----", "BEGIN ", "OPENSSH ", "PRIVATE KEY-----");
        let pem_close = concat!("-----", "END ", "OPENSSH ", "PRIVATE KEY-----");
        let dirty = format!(
            "Failed calling API with Authorization: Bearer   {sk_tok} \
             and Rotated api_key because api_key=supersecret9999 failed \
             and x-api-key: hdr_secret_value_4455 and Authorization: token  {gh_tok} \
             and phantom={phantom_tok} \
             and {pem_open}\nabcdef12345\n{pem_close}"
        );
        let (clean, count) = scrub_secrets(&dirty);
        assert!(count >= 6, "count={count}, clean={clean}");
        assert!(!clean.contains(concat!("sk", "-proj-")));
        assert!(!clean.contains(concat!("gh", "p_")));
        assert!(!clean.contains(concat!("chwg", "_phantom_")));
        assert!(!clean.contains("supersecret9999"));
        assert!(!clean.contains("hdr_secret_value_4455"));
        assert!(!clean.contains(concat!("OPENSSH ", "PRIVATE KEY")));
        assert!(clean.contains(REDACTED_MARKER));
    }

    #[test]
    fn rfc8785_jcs_orders_keys_lexicographically_and_promotes_verifiable_ratchet() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/app.rs"), "pub fn safe_call() {}\n").unwrap();
        let attempted = format!(
            "Used legacy_fake_pass() with token {}{}",
            concat!("sk", "-live-"),
            "9999888877776666"
        );

        let receipt = promote_tombstone_regression(
            dir.path(),
            &PromoteRegressionInput {
                id: "tombstone-no-legacy-stub-v1",
                source_commit: "abc1234567890def",
                file_scope: "src/**",
                attempted_action: &attempted,
                failure: "Produced fake green status",
                reason: "Never use legacy_fake_pass stub",
                alternative: "Use safe_call()",
                forbidden_patterns: vec!["legacy_fake_pass".to_owned()],
                required_patterns: vec!["safe_call".to_owned()],
            },
        )
        .unwrap();

        receipt.verify_signature().unwrap();
        assert_eq!(receipt.secret_redactions_applied, 1);

        let cas_path = dir.path().join(&receipt.cassette_path);
        let reg_path = dir.path().join(&receipt.regression_path);
        assert_eq!(
            fs::metadata(&cas_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&reg_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let cas_raw = fs::read_to_string(&cas_path).unwrap();
        assert!(!cas_raw.contains(concat!("sk", "-live-")));
        assert!(cas_raw.contains(REDACTED_MARKER));

        // Clean codebase passes offline `$0` replay with verified Ed25519 signature.
        let ok_report = verify_regressions(dir.path(), None).unwrap();
        ok_report.verify_signature().unwrap();
        assert!(ok_report.passed, "{ok_report:?}");
        assert_eq!(ok_report.specs_verified, 1);
        assert_eq!(ok_report.cassettes_verified, 1);

        // Reintroducing the forbidden pattern fails closed!
        fs::write(
            dir.path().join("src/app.rs"),
            "pub fn safe_call() { legacy_fake_pass(); }\n",
        )
        .unwrap();
        let bad_report = verify_regressions(dir.path(), None).unwrap();
        bad_report.verify_signature().unwrap();
        assert!(!bad_report.passed);
        assert_eq!(bad_report.failures.len(), 1);
        assert!(bad_report.failures[0].detail.contains("legacy_fake_pass"));
    }
}
