// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed UI geometry, interactive button/popover/`<select>` inset, and HTTP link gate
//! (`CHWG-0251` · `INV-UI-DESKTOP-CLICK-AND-LINK-QA-01` & `INV-UI-GEOMETRY-GATE-01`).
//!
//! Supports `--surface local-app|site|docs|all` and consumes either:
//! - Structured `UiAuditReportV1` JSON emitted by `chinwag ui-gate --url <url> --out <audit.json>`, or
//! - Legacy top-level array audit JSON `[ ... ]`.
//!
//! Fails closed (`passed: false`, `ok: false`, non-zero exit) whenever:
//! - `--surface local-app` or `--audit-json` yields `0` `1440×900` desktop records OR `0` `390×844` mobile records,
//! - Any audit record exists with non-`200` HTTP status, horizontal or vertical text/pill overflow
//!   (`scrollWidth > clientWidth` or `scrollHeight > clientHeight` on constrained containers),
//!   dead/failing `<button>` / `[role="button"]` / popover triggers, `<select>` inset geometry defects,
//!   or non-`200` (`404`/`5xx`/unreachable) internal or outbound `<a href>` links,
//! - Any static pricing or docs formatting invariant is violated on `site`/`docs`/`all` surfaces.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, openat, statat};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

pub const INV_UI_DESKTOP_CLICK_AND_LINK_QA: &str = "INV-UI-DESKTOP-CLICK-AND-LINK-QA-01";
pub const INV_UI_GEOMETRY_GATE: &str = "INV-UI-GEOMETRY-GATE-01";

/// Target surface evaluated by `chinwag-ci ui-gate` and `chinwag ui-gate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UiGateSurface {
    #[serde(rename = "local-app")]
    LocalApp,
    #[serde(rename = "site")]
    Site,
    #[serde(rename = "docs")]
    Docs,
    #[serde(rename = "all")]
    All,
}

impl UiGateSurface {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "local-app" | "local_app" | "localapp" | "app" => Ok(Self::LocalApp),
            "site" | "website" => Ok(Self::Site),
            "docs" | "doc" | "documentation" => Ok(Self::Docs),
            "all" | "both" => Ok(Self::All),
            other => Err(format!(
                "invalid --surface `{other}`: expected `local-app`, `site`, `docs`, or `all`"
            )),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalApp => "local-app",
            Self::Site => "site",
            Self::Docs => "docs",
            Self::All => "all",
        }
    }
}

/// Forbidden per-seat / per-agent pricing substrings (`INV-CREDIT-ONLY-PRICING-01`).
pub const FORBIDDEN_PER_SEAT_STRINGS: &[&str] = &[
    "$24/seat",
    "$16/seat",
    "$60/seat",
    "$36/seat",
    "per human seat",
    "per agent seat",
    "/seat/mo",
];

const RETIRED_HTML_MOCKUPS: &[&str] = &["index-v2.html", "mock-v2.html", "index-v1-legacy.html"];

/// Single deterministic invariant, geometry, interactive control, or link violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiGateViolationV1 {
    pub invariant: String,
    pub target: String,
    pub detail: String,
}

/// Summary of static repository invariant scanning (`scan_repo_invariants`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoScanReportV1 {
    pub html_files_scanned: usize,
    pub markdown_files_scanned: usize,
    pub violations: Vec<UiGateViolationV1>,
}

/// Summary of Desktop (`1440×900`) + Mobile (`390×844`) geometry, button/select, and link verification.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditJsonReportV1 {
    pub audit_records_verified: usize,
    pub desktop_1440x900_records: usize,
    pub mobile_390x844_records: usize,
    pub interactive_controls_verified: usize,
    pub links_verified: usize,
    pub violations: Vec<UiGateViolationV1>,
}

/// Ephemeral in-RAM Ed25519 runner keypair for signing `UiGateReceiptV1`.
pub struct EphemeralUiGateSigner {
    signing_key: SigningKey,
}

impl EphemeralUiGateSigner {
    pub fn generate() -> Result<Self, String> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *seed).map_err(|e| format!("OS CSPRNG failure: {e}"))?;
        if seed.iter().all(|&b| b == 0) {
            return Err("OS CSPRNG returned all-zero seed".to_owned());
        }
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(Self { signing_key })
    }

    #[must_use]
    pub fn pk_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

/// Cryptographically signed UI Gate receipt (`UiGateReceiptV1`), aligned with `chinwag ui-gate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiGateReceiptV1 {
    pub ok: bool,
    pub schema: String,
    pub command: String,
    pub document_id: String,
    pub org_id_hash: String,
    pub ticket_id: String,
    pub surface: String,
    pub commit_sha: String,
    pub repo_path: String,
    pub host_arch: String,
    pub passed: bool,
    pub html_files_scanned: usize,
    pub markdown_files_scanned: usize,
    pub audit_records_verified: usize,
    pub desktop_1440x900_records: usize,
    pub mobile_390x844_records: usize,
    pub interactive_controls_verified: usize,
    pub links_verified: usize,
    pub invariants_verified: Vec<String>,
    pub violations: Vec<UiGateViolationV1>,
    pub artifacts_git_ref: String,
    pub payload_sha256_hex: String,
    #[serde(alias = "pk_ci_k1_hex")]
    pub runner_ed25519_pk_hex: String,
    #[serde(alias = "k1_signature_hex")]
    pub runner_ed25519_sig_hex: String,
}

impl UiGateReceiptV1 {
    fn canonical_signing_bytes(&self) -> Result<Vec<u8>, String> {
        let violations_val = serde_json::to_value(&self.violations)
            .map_err(|e| format!("serialize violations: {e}"))?;
        let unsigned = json!({
            "artifacts_git_ref": self.artifacts_git_ref,
            "audit_records_verified": self.audit_records_verified,
            "command": self.command,
            "commit_sha": self.commit_sha,
            "desktop_1440x900_records": self.desktop_1440x900_records,
            "document_id": self.document_id,
            "host_arch": self.host_arch,
            "html_files_scanned": self.html_files_scanned,
            "interactive_controls_verified": self.interactive_controls_verified,
            "invariants_verified": self.invariants_verified,
            "links_verified": self.links_verified,
            "markdown_files_scanned": self.markdown_files_scanned,
            "mobile_390x844_records": self.mobile_390x844_records,
            "ok": self.ok,
            "org_id_hash": self.org_id_hash,
            "passed": self.passed,
            "repo_path": self.repo_path,
            "schema": self.schema,
            "surface": self.surface,
            "ticket_id": self.ticket_id,
            "violations": violations_val,
        });
        to_rfc8785_jcs_string(&unsigned).map(String::into_bytes)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_signed(
        signer: &EphemeralUiGateSigner,
        org_id_hash: &str,
        ticket_id: &str,
        surface: UiGateSurface,
        commit_sha: &str,
        repo_path: &str,
        host_arch: &str,
        scan_report: &RepoScanReportV1,
        audit_report: &AuditJsonReportV1,
    ) -> Result<Self, String> {
        let mut violations = Vec::new();
        violations.extend(scan_report.violations.clone());
        violations.extend(audit_report.violations.clone());
        let passed = violations.is_empty()
            && (!matches!(surface, UiGateSurface::LocalApp | UiGateSurface::All)
                || (audit_report.desktop_1440x900_records > 0
                    && audit_report.mobile_390x844_records > 0));
        let surface_str = surface.as_str();
        let runner_ed25519_pk_hex = signer.pk_hex();

        let mut receipt = Self {
            ok: passed,
            schema: "UiGateReceiptV1".to_owned(),
            command: "chinwag-ci ui-gate".to_owned(),
            document_id: "CHWG-CI-RUNNER-01".to_owned(),
            org_id_hash: org_id_hash.to_owned(),
            ticket_id: ticket_id.to_owned(),
            surface: surface_str.to_owned(),
            commit_sha: commit_sha.to_owned(),
            repo_path: repo_path.to_owned(),
            host_arch: host_arch.to_owned(),
            passed,
            html_files_scanned: scan_report.html_files_scanned,
            markdown_files_scanned: scan_report.markdown_files_scanned,
            audit_records_verified: audit_report.audit_records_verified,
            desktop_1440x900_records: audit_report.desktop_1440x900_records,
            mobile_390x844_records: audit_report.mobile_390x844_records,
            interactive_controls_verified: audit_report.interactive_controls_verified,
            links_verified: audit_report.links_verified,
            invariants_verified: vec![
                INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                INV_UI_GEOMETRY_GATE.to_owned(),
                "INV-CREDIT-ONLY-PRICING-01".to_owned(),
                "INV-NO-RAW-MDC-HEADING-BRACES-01".to_owned(),
                "INV-NO-CLI-IN-H1-01".to_owned(),
            ],
            violations,
            artifacts_git_ref: format!("refs/chinwag/ui-gate/{ticket_id}/{commit_sha}"),
            payload_sha256_hex: String::new(),
            runner_ed25519_pk_hex,
            runner_ed25519_sig_hex: String::new(),
        };
        let canonical = receipt.canonical_signing_bytes()?;
        receipt.payload_sha256_hex = hex::encode(Sha256::digest(&canonical));
        let sig = signer.sign(&canonical);
        receipt.runner_ed25519_sig_hex = hex::encode(sig.to_bytes());
        receipt.verify_signature()?;
        Ok(receipt)
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        let canonical = self.canonical_signing_bytes()?;
        let expected_sha256 = hex::encode(Sha256::digest(&canonical));
        if self.payload_sha256_hex != expected_sha256 {
            return Err("UiGateReceiptV1 payload_sha256_hex mismatch".to_owned());
        }
        let pk_bytes: [u8; 32] = hex::decode(&self.runner_ed25519_pk_hex)
            .map_err(|e| format!("invalid runner_ed25519_pk_hex: {e}"))?
            .try_into()
            .map_err(|_| "runner_ed25519_pk_hex must be 32 bytes".to_owned())?;
        let vk = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("invalid runner pubkey: {e}"))?;
        let sig_bytes: [u8; 64] = hex::decode(&self.runner_ed25519_sig_hex)
            .map_err(|e| format!("invalid runner_ed25519_sig_hex: {e}"))?
            .try_into()
            .map_err(|_| "runner_ed25519_sig_hex must be 64 bytes".to_owned())?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(&canonical, &sig)
            .map_err(|e| format!("UiGateReceiptV1 signature failed verify_strict: {e}"))
    }

    pub fn verify_k1(&self) -> Result<(), String> {
        self.verify_signature()
    }
}

fn to_rfc8785_jcs_string(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_jcs_val(value, &mut out)?;
    Ok(out)
}

fn write_jcs_val(value: &Value, out: &mut String) -> Result<(), String> {
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
        Value::String(s) => write_jcs_str(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs_val(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_jcs_obj(map, out)?,
    }
    Ok(())
}

fn write_jcs_obj(map: &Map<String, Value>, out: &mut String) -> Result<(), String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    out.push('{');
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_jcs_str(k, out);
        out.push(':');
        if let Some(v) = map.get(*k) {
            write_jcs_val(v, out)?;
        }
    }
    out.push('}');
    Ok(())
}

fn write_jcs_str(s: &str, out: &mut String) {
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
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn ensure_regular_file_no_follow(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let pst = statat(CWD, parent, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("stat parent `{}`: {e}", parent.display()))?;
        if FileType::from_raw_mode(pst.st_mode) != FileType::Directory {
            return Err(format!(
                "refusing symlink or non-directory parent `{}`",
                parent.display()
            ));
        }
    }
    let st = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| format!("unable to stat UI audit JSON `{}`: {e}", path.display()))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(format!(
            "refusing symlinked or non-regular UI audit JSON `{}`",
            path.display()
        ));
    }
    if st.st_nlink > 1 {
        return Err(format!(
            "refusing hardlinked UI audit JSON `{}` (nlink={})",
            path.display(),
            st.st_nlink
        ));
    }
    Ok(())
}

fn write_regular_file_atomic_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    for comp in parent.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(format!(
                "refusing `..` traversal in output directory `{}`",
                parent.display()
            ));
        }
    }
    let mut missing = Vec::new();
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
        missing.push(name.to_os_string());
        let Some(next) = cursor.parent() else {
            break;
        };
        cursor = if next.as_os_str().is_empty() {
            Path::new(".")
        } else {
            next
        };
    }
    let mut build = if cursor.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        cursor.to_path_buf()
    };
    for seg in missing.into_iter().rev() {
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
    getrandom::fill(&mut nonce).map_err(|e| format!("OS CSPRNG failure: {e}"))?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("rcpt"),
        std::process::id(),
        hex::encode(nonce)
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

fn verify_ui_audit_report_v1_signature(obj: &Map<String, Value>) -> Result<(), String> {
    let schema = obj
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `schema` in UiAuditReportV1 object".to_owned())?;
    if schema != "UiAuditReportV1" {
        return Err(format!(
            "unexpected schema `{schema}`, expected `UiAuditReportV1`"
        ));
    }
    let url = obj
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `url` in UiAuditReportV1".to_owned())?;
    let ticket_id = obj
        .get("ticket_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `ticket_id` in UiAuditReportV1".to_owned())?;
    let generated_at_unix = obj
        .get("generated_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing `generated_at_unix` in UiAuditReportV1".to_owned())?;
    let links_verified = obj
        .get("links_verified")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing `links_verified` in UiAuditReportV1".to_owned())?;
    let broken_links = obj
        .get("broken_links")
        .ok_or_else(|| "missing `broken_links` in UiAuditReportV1".to_owned())?;
    let records = obj
        .get("records")
        .ok_or_else(|| "missing `records` in UiAuditReportV1".to_owned())?;
    let payload_sha256_hex = obj
        .get("payload_sha256_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `payload_sha256_hex` in UiAuditReportV1".to_owned())?;
    let pk_hex = obj
        .get("runner_ed25519_pk_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `runner_ed25519_pk_hex` in UiAuditReportV1".to_owned())?;
    let sig_hex = obj
        .get("runner_ed25519_sig_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `runner_ed25519_sig_hex` in UiAuditReportV1".to_owned())?;

    let unsigned = json!({
        "broken_links": broken_links,
        "generated_at_unix": generated_at_unix,
        "links_verified": links_verified,
        "records": records,
        "schema": "UiAuditReportV1",
        "ticket_id": ticket_id,
        "url": url,
    });
    let canonical = to_rfc8785_jcs_string(&unsigned)?.into_bytes();
    let expected_sha = hex::encode(Sha256::digest(&canonical));
    if payload_sha256_hex != expected_sha {
        return Err("UiAuditReportV1 payload_sha256_hex mismatch".to_owned());
    }
    let pk_bytes: [u8; 32] = hex::decode(pk_hex)
        .map_err(|e| format!("invalid runner_ed25519_pk_hex: {e}"))?
        .try_into()
        .map_err(|_| "runner_ed25519_pk_hex must be 32 bytes".to_owned())?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .map_err(|e| format!("invalid runner_ed25519_sig_hex: {e}"))?
        .try_into()
        .map_err(|_| "runner_ed25519_sig_hex must be 64 bytes".to_owned())?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("invalid Ed25519 verifying key: {e}"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(&canonical, &sig)
        .map_err(|e| format!("UiAuditReportV1 Ed25519 signature invalid: {e}"))
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".chinwag"
            | "node_modules"
            | "target"
            | ".nuxt"
            | ".output"
            | "dist"
            | ".wrangler"
    )
}

fn collect_files_with_ext(root: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut sorted: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    sorted.sort();
    for path in sorted {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str())
                && should_skip_dir(name)
            {
                continue;
            }
            collect_files_with_ext(&path, ext, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some(ext) {
            out.push(path);
        }
    }
}

fn has_raw_mdc_heading_brace(line: &str) -> bool {
    let trimmed = line.trim_start();
    let hashes = trimmed.chars().take_while(|&c| c == '#').count();
    if !(1..=4).contains(&hashes) {
        return false;
    }
    let after_hashes = &trimmed[hashes..];
    if !after_hashes.starts_with(' ') {
        return false;
    }
    if let Some(start_idx) = after_hashes.find("{#") {
        let rest = &after_hashes[start_idx + 2..];
        if let Some(end_idx) = rest.find('}') {
            return end_idx > 0;
        }
    }
    false
}

fn extract_frontmatter(raw: &str) -> Option<&str> {
    let trimmed = raw
        .strip_prefix("---\n")
        .or_else(|| raw.strip_prefix("---\r\n"))?;
    let end_idx = trimmed.find("\n---")?;
    Some(&trimmed[..end_idx])
}

#[must_use]
pub fn scan_repo_invariants(repo_path: &Path, surface: UiGateSurface) -> RepoScanReportV1 {
    if surface == UiGateSurface::LocalApp {
        return RepoScanReportV1::default();
    }
    let mut report = RepoScanReportV1::default();

    let mut html_files = Vec::new();
    collect_files_with_ext(repo_path, "html", &mut html_files);
    for html_path in html_files {
        if let Some(fname) = html_path.file_name().and_then(|s| s.to_str())
            && RETIRED_HTML_MOCKUPS.contains(&fname)
        {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&html_path) else {
            continue;
        };
        report.html_files_scanned += 1;
        let lower = raw.to_ascii_lowercase();
        let rel = html_path
            .strip_prefix(repo_path)
            .unwrap_or(&html_path)
            .display()
            .to_string();
        for forbidden in FORBIDDEN_PER_SEAT_STRINGS {
            if lower.contains(forbidden) {
                report.violations.push(UiGateViolationV1 {
                    invariant: "INV-CREDIT-ONLY-PRICING-01".to_owned(),
                    target: rel.clone(),
                    detail: format!("forbidden per-seat pricing string `{forbidden}` in HTML"),
                });
            }
        }
    }

    let content_dir = repo_path.join("content");
    if content_dir.is_dir() {
        let mut md_files = Vec::new();
        collect_files_with_ext(&content_dir, "md", &mut md_files);
        for md_path in md_files {
            let Ok(raw) = fs::read_to_string(&md_path) else {
                continue;
            };
            report.markdown_files_scanned += 1;
            let lower = raw.to_ascii_lowercase();
            let rel = md_path
                .strip_prefix(repo_path)
                .unwrap_or(&md_path)
                .display()
                .to_string();

            for forbidden in FORBIDDEN_PER_SEAT_STRINGS {
                if lower.contains(forbidden) {
                    report.violations.push(UiGateViolationV1 {
                        invariant: "INV-CREDIT-ONLY-PRICING-01".to_owned(),
                        target: rel.clone(),
                        detail: format!(
                            "forbidden per-seat pricing string `{forbidden}` in Markdown"
                        ),
                    });
                }
            }

            let mut in_fence = false;
            for (line_idx, line) in raw.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("```") {
                    in_fence = !in_fence;
                    continue;
                }
                if !in_fence && has_raw_mdc_heading_brace(line) {
                    report.violations.push(UiGateViolationV1 {
                        invariant: "INV-NO-RAW-MDC-HEADING-BRACES-01".to_owned(),
                        target: format!("{rel}:{}", line_idx + 1),
                        detail: format!(
                            "raw `{{#...}}` MDC heading attribute on heading line: `{}`",
                            line.trim()
                        ),
                    });
                }
            }

            if let Some(frontmatter) = extract_frontmatter(&raw) {
                let mut has_command_key = false;
                for fm_line in frontmatter.lines() {
                    let trimmed = fm_line.trim();
                    if let Some(rest) = trimmed.strip_prefix("title:") {
                        let title_lower = rest.trim().to_ascii_lowercase();
                        if title_lower.contains("(chinwag ")
                            || title_lower.contains("(brew install ")
                        {
                            report.violations.push(UiGateViolationV1 {
                                invariant: "INV-NO-CLI-IN-H1-01".to_owned(),
                                target: rel.clone(),
                                detail: format!(
                                    "frontmatter `title:` embeds parenthesized CLI command: `{}`",
                                    rest.trim()
                                ),
                            });
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("command:") {
                        let val = rest.trim().trim_matches('"').trim_matches('\'').trim();
                        if !val.is_empty() {
                            has_command_key = true;
                        }
                    }
                }
                if !has_command_key {
                    report.violations.push(UiGateViolationV1 {
                        invariant: "INV-NO-CLI-IN-H1-01".to_owned(),
                        target: rel.clone(),
                        detail: "missing non-empty `command:` frontmatter field".to_owned(),
                    });
                }
            } else {
                report.violations.push(UiGateViolationV1 {
                    invariant: "INV-NO-CLI-IN-H1-01".to_owned(),
                    target: rel.clone(),
                    detail: "missing YAML frontmatter block (`---`) with `title:` and `command:`"
                        .to_owned(),
                });
            }
        }
    }

    report
}

fn is_desktop_1440x900(rec: &Value) -> bool {
    let vw = rec
        .get("check")
        .and_then(|c| c.get("vw"))
        .and_then(Value::as_u64);
    let vh = rec
        .get("check")
        .and_then(|c| c.get("vh"))
        .and_then(Value::as_u64);
    matches!((vw, vh), (Some(1440), Some(900)))
}

fn is_mobile_390x844(rec: &Value) -> bool {
    let vw = rec
        .get("check")
        .and_then(|c| c.get("vw"))
        .and_then(Value::as_u64);
    let vh = rec
        .get("check")
        .and_then(|c| c.get("vh"))
        .and_then(Value::as_u64);
    matches!((vw, vh), (Some(390), Some(844)))
}

/// Parses and validates a `UiAuditReportV1` or top-level array audit JSON file.
pub fn verify_audit_json(
    audit_path: &Path,
    surface: UiGateSurface,
    require_dual_viewport: bool,
) -> Result<AuditJsonReportV1, String> {
    ensure_regular_file_no_follow(audit_path)?;
    let raw = fs::read_to_string(audit_path).map_err(|e| {
        format!(
            "unable to read UI audit JSON `{}`: {e}",
            audit_path.display()
        )
    })?;
    verify_audit_json_str(
        &raw,
        &audit_path.display().to_string(),
        surface,
        require_dual_viewport,
    )
}

/// Validates `UiAuditReportV1` object or legacy array records from an in-memory JSON string.
pub fn verify_audit_json_str(
    raw_json: &str,
    source_label: &str,
    surface: UiGateSurface,
    require_dual_viewport: bool,
) -> Result<AuditJsonReportV1, String> {
    let parsed: Value = serde_json::from_str(raw_json)
        .map_err(|e| format!("invalid JSON in `{source_label}`: {e}"))?;

    let records: &[Value] = if let Some(arr) = parsed.as_array() {
        arr.as_slice()
    } else if let Some(obj) = parsed.as_object() {
        obj.get("records")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                format!(
                    "expected `records` array inside `{source_label}` object (schema={:?})",
                    obj.get("schema")
                )
            })?
    } else {
        return Err(format!(
            "expected `UiAuditReportV1` object or JSON array in `{source_label}`"
        ));
    };

    let mut report = AuditJsonReportV1::default();
    let filename_is_docs = source_label.contains("docs");

    if parsed.is_array() && matches!(surface, UiGateSurface::LocalApp | UiGateSurface::All) {
        report.violations.push(UiGateViolationV1 {
            invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
            target: source_label.to_owned(),
            detail: "fail-closed: unsigned top-level JSON array rejected on local-app/all; signed `UiAuditReportV1` object required".to_owned(),
        });
    }

    // Unconditional `UiAuditReportV1` schema + Ed25519 signature & link check summary on JSON objects.
    if let Some(obj) = parsed.as_object() {
        if let Err(sig_err) = verify_ui_audit_report_v1_signature(obj) {
            report.violations.push(UiGateViolationV1 {
                invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                target: source_label.to_owned(),
                detail: format!("UiAuditReportV1 signature verification failed: {sig_err}"),
            });
        }
        if let Some(lc) = obj.get("links_verified").and_then(Value::as_u64) {
            report.links_verified += lc as usize;
        }
        if let Some(broken) = obj.get("broken_links").and_then(Value::as_array) {
            for link in broken {
                report.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                    target: format!("{source_label}:links"),
                    detail: format!("broken `<a href>` link: {link}"),
                });
            }
        }
    }

    for (idx, rec) in records.iter().enumerate() {
        report.audit_records_verified += 1;
        let path = rec
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let viewport = rec
            .get("viewport")
            .and_then(Value::as_str)
            .unwrap_or("desktop");
        if is_desktop_1440x900(rec) {
            report.desktop_1440x900_records += 1;
        } else if is_mobile_390x844(rec) {
            report.mobile_390x844_records += 1;
        }
        let target = format!("{source_label}[{idx}]:{viewport}:{path}");

        // 1. HTTP status == 200
        let status = rec.get("status").and_then(Value::as_u64).unwrap_or(0);
        if status != 200 {
            report.violations.push(UiGateViolationV1 {
                invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                target: target.clone(),
                detail: format!("HTTP status is {status}, expected 200"),
            });
        }

        let Some(check) = rec.get("check").and_then(Value::as_object) else {
            report.violations.push(UiGateViolationV1 {
                invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                target: target.clone(),
                detail: "missing `check` geometry object on audit record".to_owned(),
            });
            continue;
        };

        // 2. Horizontal & vertical page / pill / text overflow (`scrollWidth <= clientWidth`, `scrollHeight <= clientHeight`)
        if let Some(vw) = check.get("vw").and_then(Value::as_u64)
            && let Some(sw) = check.get("scrollWidth").and_then(Value::as_u64)
            && sw > vw
        {
            report.violations.push(UiGateViolationV1 {
                invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                target: target.clone(),
                detail: format!(
                    "horizontal viewport overflow: scrollWidth ({sw}) > clientWidth ({vw})"
                ),
            });
        }
        if let Some(ovf) = check.get("pageOverflow") {
            match ovf {
                Value::Bool(true) => {
                    report.violations.push(UiGateViolationV1 {
                        invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                        target: target.clone(),
                        detail: "check.pageOverflow flagged horizontal overflow".to_owned(),
                    });
                }
                Value::Array(arr) if !arr.is_empty() => {
                    report.violations.push(UiGateViolationV1 {
                        invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                        target: target.clone(),
                        detail: format!(
                            "check.pageOverflow has {} overflowing elements",
                            arr.len()
                        ),
                    });
                }
                _ => {}
            }
        }
        if let Some(ovf_count) = check.get("pageOverflowCount").and_then(Value::as_u64)
            && ovf_count > 0
        {
            report.violations.push(UiGateViolationV1 {
                invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                target: target.clone(),
                detail: format!("check.pageOverflowCount is {ovf_count}, expected 0"),
            });
        }
        for ovf_key in ["pillOverflow", "verticalOverflow", "elementOverflow"] {
            if let Some(arr) = check.get(ovf_key).and_then(Value::as_array)
                && !arr.is_empty()
            {
                report.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                    target: target.clone(),
                    detail: format!(
                        "`check.{ovf_key}` has {} overflowing text/pill element(s)",
                        arr.len()
                    ),
                });
            }
        }

        // 3. Interactive controls (`<button>`, `[role="button"]`, popovers/modals, `<select>` inset geometry)
        if let Some(cnt) = check.get("buttonsExercised").and_then(Value::as_u64) {
            report.interactive_controls_verified += cnt as usize;
        }
        if let Some(cnt) = check.get("selectsChecked").and_then(Value::as_u64) {
            report.interactive_controls_verified += cnt as usize;
        }
        for interactive_err_key in [
            "deadButtons",
            "interactiveDefects",
            "popoverDefects",
            "selectGeometryDefects",
        ] {
            if let Some(arr) = check.get(interactive_err_key).and_then(Value::as_array)
                && !arr.is_empty()
            {
                report.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                    target: target.clone(),
                    detail: format!(
                        "`check.{interactive_err_key}` reported {} interactive/geometry defect(s): {}",
                        arr.len(),
                        arr[0]
                    ),
                });
            }
        }

        // 4. Per-record `<a href>` HTTP 200 link verification
        if let Some(lc) = check.get("linksChecked").and_then(Value::as_u64) {
            report.links_verified += lc as usize;
        }
        if let Some(broken_links) = check
            .get("brokenLinks")
            .and_then(Value::as_array)
            .or_else(|| rec.get("brokenLinks").and_then(Value::as_array))
            && !broken_links.is_empty()
        {
            report.violations.push(UiGateViolationV1 {
                invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                target: target.clone(),
                detail: format!(
                    "detected {} non-200 `<a href>` link(s): {}",
                    broken_links.len(),
                    broken_links[0]
                ),
            });
        }

        // 5. Raw Markdown/brace artifacts, console errors, pageerrors, badRequests
        if let Some(artifacts) = check.get("artifacts").and_then(Value::as_array)
            && !artifacts.is_empty()
        {
            report.violations.push(UiGateViolationV1 {
                invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                target: target.clone(),
                detail: format!(
                    "check.artifacts has {} raw Markdown/template/brace artifact groups",
                    artifacts.len()
                ),
            });
        }
        for err_key in ["console", "pageerrors", "badRequests"] {
            let arr = rec
                .get(err_key)
                .and_then(Value::as_array)
                .or_else(|| check.get(err_key).and_then(Value::as_array));
            if let Some(items) = arr
                && !items.is_empty()
            {
                report.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                    target: target.clone(),
                    detail: format!("`{err_key}` has {} runtime/network errors", items.len()),
                });
            }
        }

        let is_docs_record =
            rec.get("docs").is_some() || filename_is_docs || surface == UiGateSurface::Docs;
        if is_docs_record {
            if let Some(clipped) = check.get("clippedHidden").and_then(Value::as_array)
                && !clipped.is_empty()
            {
                report.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                    target: target.clone(),
                    detail: format!(
                        "docs record has {} check.clippedHidden elements",
                        clipped.len()
                    ),
                });
            }
            if let Some(spills) = check.get("inlineCodeSpill").and_then(Value::as_array) {
                let mut parent_spill_count = 0usize;
                for item in spills {
                    let parent_right = item.get("parentRight").and_then(Value::as_f64);
                    let item_right = item.get("right").and_then(Value::as_f64).or_else(|| {
                        let rect = item.get("rect")?.as_array()?;
                        if rect.len() >= 3 {
                            Some(rect[0].as_f64()? + rect[2].as_f64()?)
                        } else {
                            None
                        }
                    });
                    match (item_right, parent_right) {
                        (Some(r), Some(pr)) if r > pr + 2.0 => parent_spill_count += 1,
                        (None, _) | (_, None) => parent_spill_count += 1,
                        _ => {}
                    }
                }
                if parent_spill_count > 0 {
                    report.violations.push(UiGateViolationV1 {
                        invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                        target: target.clone(),
                        detail: format!(
                            "docs record has {parent_spill_count} check.inlineCodeSpill items spilling past parentRight + 2"
                        ),
                    });
                }
            }
        } else if (path == "/privacy" || path == "/privacy.html")
            && let Some(tbl_broken) = check.get("tableBroken").and_then(Value::as_array)
            && !tbl_broken.is_empty()
        {
            report.violations.push(UiGateViolationV1 {
                invariant: INV_UI_GEOMETRY_GATE.to_owned(),
                target: target.clone(),
                detail: format!(
                    "site /privacy has {} broken tables in check.tableBroken",
                    tbl_broken.len()
                ),
            });
        }
    }

    if require_dual_viewport || matches!(surface, UiGateSurface::LocalApp | UiGateSurface::All) {
        if report.desktop_1440x900_records == 0 {
            report.violations.push(UiGateViolationV1 {
                invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                target: source_label.to_owned(),
                detail: "fail-closed: 0 `1440x900` desktop viewport records verified".to_owned(),
            });
        }
        if report.mobile_390x844_records == 0 {
            report.violations.push(UiGateViolationV1 {
                invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                target: source_label.to_owned(),
                detail: "fail-closed: 0 `390x844` mobile viewport records verified".to_owned(),
            });
        }
    } else if report.audit_records_verified == 0 {
        report.violations.push(UiGateViolationV1 {
            invariant: INV_UI_GEOMETRY_GATE.to_owned(),
            target: source_label.to_owned(),
            detail: "fail-closed: UI audit JSON contains 0 records".to_owned(),
        });
    }

    Ok(report)
}

#[must_use]
pub fn resolve_audit_json_paths(
    repo_path: &Path,
    explicit_audit_json: Option<&str>,
) -> Vec<PathBuf> {
    if let Some(raw) = explicit_audit_json {
        return raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    let local_audit = repo_path.join(".chinwag/ui-audit-results.json");
    if ensure_regular_file_no_follow(&local_audit).is_ok() {
        return vec![local_audit];
    }
    Vec::new()
}

#[must_use]
pub fn resolve_repo_scan_targets(
    explicit_repo: Option<&str>,
    surface: UiGateSurface,
) -> Vec<PathBuf> {
    if let Some(repo) = explicit_repo {
        return vec![PathBuf::from(repo)];
    }
    let mut targets = Vec::new();
    if matches!(surface, UiGateSurface::Site | UiGateSurface::All)
        && let Ok(site_dir) = std::env::var("CHINWAG_SITE_DIR")
        && !site_dir.trim().is_empty()
    {
        targets.push(PathBuf::from(site_dir));
    }
    if matches!(surface, UiGateSurface::Docs | UiGateSurface::All)
        && let Ok(docs_dir) = std::env::var("CHINWAG_DOCS_DIR")
        && !docs_dir.trim().is_empty()
    {
        targets.push(PathBuf::from(docs_dir));
    }
    if targets.is_empty() {
        targets.push(PathBuf::from("."));
    }
    targets
}

/// Executes the full `ui-gate` verification pipeline and signs `UiGateReceiptV1`.
pub fn execute_ui_gate(
    surface: UiGateSurface,
    explicit_repo: Option<&str>,
    explicit_audit_json: Option<&str>,
    ticket_id: &str,
    commit_sha: &str,
    org_id_hash: &str,
) -> Result<UiGateReceiptV1, String> {
    let repo_targets = resolve_repo_scan_targets(explicit_repo, surface);
    let mut combined_scan = RepoScanReportV1::default();
    let mut repo_labels = Vec::new();
    for target in &repo_targets {
        repo_labels.push(target.display().to_string());
        let part = scan_repo_invariants(target, surface);
        combined_scan.html_files_scanned += part.html_files_scanned;
        combined_scan.markdown_files_scanned += part.markdown_files_scanned;
        combined_scan.violations.extend(part.violations);
    }

    let primary_repo = repo_targets
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("."));
    let audit_paths = resolve_audit_json_paths(&primary_repo, explicit_audit_json);
    let require_dual_viewport = matches!(surface, UiGateSurface::LocalApp | UiGateSurface::All)
        || explicit_audit_json.is_some();

    let mut combined_audit = AuditJsonReportV1::default();
    if audit_paths.is_empty() && require_dual_viewport {
        combined_audit.violations.push(UiGateViolationV1 {
            invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
            target: primary_repo.display().to_string(),
            detail: "fail-closed: missing UI audit JSON (0 `1440x900` desktop and 0 `390x844` mobile records)"
                .to_owned(),
        });
    } else {
        for audit_path in &audit_paths {
            let part = verify_audit_json(audit_path, surface, false)?;
            combined_audit.audit_records_verified += part.audit_records_verified;
            combined_audit.desktop_1440x900_records += part.desktop_1440x900_records;
            combined_audit.mobile_390x844_records += part.mobile_390x844_records;
            combined_audit.interactive_controls_verified += part.interactive_controls_verified;
            combined_audit.links_verified += part.links_verified;
            combined_audit.violations.extend(part.violations);
        }
        if require_dual_viewport {
            if combined_audit.desktop_1440x900_records == 0 {
                combined_audit.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                    target: primary_repo.display().to_string(),
                    detail: "fail-closed: 0 `1440x900` desktop viewport records verified"
                        .to_owned(),
                });
            }
            if combined_audit.mobile_390x844_records == 0 {
                combined_audit.violations.push(UiGateViolationV1 {
                    invariant: INV_UI_DESKTOP_CLICK_AND_LINK_QA.to_owned(),
                    target: primary_repo.display().to_string(),
                    detail: "fail-closed: 0 `390x844` mobile viewport records verified".to_owned(),
                });
            }
        }
    }

    let signer = EphemeralUiGateSigner::generate()?;
    let receipt = UiGateReceiptV1::build_signed(
        &signer,
        org_id_hash,
        ticket_id,
        surface,
        commit_sha,
        &repo_labels.join(","),
        std::env::consts::ARCH,
        &combined_scan,
        &combined_audit,
    )?;
    receipt.verify_signature()?;
    Ok(receipt)
}

/// CLI entrypoint for `chinwag-ci ui-gate ...`.
pub fn run_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut surface = UiGateSurface::LocalApp;
    let mut repo_arg: Option<String> = None;
    let mut audit_json_arg: Option<String> = None;
    let mut ticket_id = "CHWG-0251".to_owned();
    let mut commit_sha = "HEAD".to_owned();
    let mut org_hash = "local-org".to_owned();
    let mut out_path: Option<PathBuf> = None;
    let mut _is_json = false;

    let mut i = 0;
    while i < args.len() {
        let raw = args[i].as_str();
        if matches!(raw, "--help" | "-h") {
            let _ = writeln!(
                stdout,
                "Usage: chinwag-ci ui-gate --surface <local-app|site|docs|all> [--audit-json <path>] [--repo <path>] [--ticket <id>] [--commit <sha>] [--org-hash <hash>] [--out <receipt.json>] [--json]"
            );
            return 0;
        }
        if raw == "--json" {
            _is_json = true;
            i += 1;
            continue;
        }
        let (flag, val) = if let Some((f, v)) = raw.split_once('=') {
            i += 1;
            (f, v.to_owned())
        } else if i + 1 < args.len() {
            let v = args[i + 1].clone();
            i += 2;
            (raw, v)
        } else {
            let _ = writeln!(stderr, "chinwag-ci ui-gate: missing value for `{raw}`");
            return 2;
        };
        match flag {
            "--surface" => match UiGateSurface::parse(&val) {
                Ok(s) => surface = s,
                Err(e) => {
                    let _ = writeln!(stderr, "chinwag-ci ui-gate: {e}");
                    return 2;
                }
            },
            "--repo" => repo_arg = Some(val),
            "--audit-json" => audit_json_arg = Some(val),
            "--ticket" => ticket_id = val,
            "--commit" => commit_sha = val,
            "--org" | "--org-hash" => {
                let trimmed = val.trim();
                org_hash = if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    trimmed.to_ascii_lowercase()
                } else {
                    hex::encode(Sha256::digest(trimmed.as_bytes()))
                };
            }
            "--out" => out_path = Some(PathBuf::from(val)),
            other => {
                let _ = writeln!(stderr, "chinwag-ci ui-gate: invalid argument `{other}`");
                return 2;
            }
        }
    }

    match execute_ui_gate(
        surface,
        repo_arg.as_deref(),
        audit_json_arg.as_deref(),
        &ticket_id,
        &commit_sha,
        &org_hash,
    ) {
        Ok(receipt) => {
            let encoded = serde_json::to_string_pretty(&receipt).unwrap_or_default();
            if let Some(ref out_file) = out_path
                && let Err(e) =
                    write_regular_file_atomic_0600(out_file, format!("{encoded}\n").as_bytes())
            {
                let _ = writeln!(
                    stderr,
                    "chinwag-ci ui-gate: failed writing receipt {}: {e}",
                    out_file.display()
                );
                return 1;
            }
            let _ = writeln!(stdout, "{encoded}");
            if receipt.passed {
                0
            } else {
                for v in &receipt.violations {
                    let _ = writeln!(
                        stderr,
                        "chinwag-ci ui-gate FAILED [{}] {}: {}",
                        v.invariant, v.target, v.detail
                    );
                }
                1
            }
        }
        Err(e) => {
            let _ = writeln!(stderr, "chinwag-ci ui-gate: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_signed_audit_report_json(
        links_verified: usize,
        broken_links: Value,
        records: Value,
    ) -> String {
        let signer = EphemeralUiGateSigner::generate().unwrap();
        let unsigned = json!({
            "broken_links": broken_links,
            "generated_at_unix": 1_794_630_000_u64,
            "links_verified": links_verified,
            "records": records,
            "schema": "UiAuditReportV1",
            "ticket_id": "CHWG-0251",
            "url": "http://127.0.0.1:5487/",
        });
        let canonical = to_rfc8785_jcs_string(&unsigned).unwrap();
        let sha = hex::encode(Sha256::digest(canonical.as_bytes()));
        let sig = signer.sign(canonical.as_bytes());
        let signed = json!({
            "schema": "UiAuditReportV1",
            "url": "http://127.0.0.1:5487/",
            "ticket_id": "CHWG-0251",
            "generated_at_unix": 1_794_630_000_u64,
            "links_verified": links_verified,
            "broken_links": broken_links,
            "records": records,
            "payload_sha256_hex": sha,
            "runner_ed25519_pk_hex": signer.pk_hex(),
            "runner_ed25519_sig_hex": hex::encode(sig.to_bytes()),
        });
        serde_json::to_string_pretty(&signed).unwrap()
    }

    #[test]
    fn local_app_and_all_surfaces_fail_closed_when_desktop_or_mobile_records_are_zero() {
        let dir = tempfile::tempdir().unwrap();
        for surface in [UiGateSurface::LocalApp, UiGateSurface::All] {
            let r0 = execute_ui_gate(
                surface,
                Some(dir.path().to_str().unwrap()),
                None,
                "CHWG-0251",
                "abc1234",
                "org_test",
            )
            .unwrap();
            assert!(!r0.passed);
            assert!(!r0.ok);
            assert_eq!(r0.desktop_1440x900_records, 0);
            assert_eq!(r0.mobile_390x844_records, 0);
        }

        // Case 2: Desktop-only audit JSON (`mobile_390x844_records == 0`) -> passed == false!
        let desktop_only = dir.path().join("desktop-only.json");
        fs::write(
            &desktop_only,
            build_signed_audit_report_json(
                0,
                json!([]),
                json!([{"path":"/","viewport":"desktop-light","status":200,"check":{"vw":1440,"vh":900,"scrollWidth":1440,"pageOverflow":false}}]),
            ),
        )
        .unwrap();
        let r1 = execute_ui_gate(
            UiGateSurface::LocalApp,
            Some(dir.path().to_str().unwrap()),
            Some(desktop_only.to_str().unwrap()),
            "CHWG-0251",
            "abc1234",
            "org_test",
        )
        .unwrap();
        assert!(!r1.passed);
        assert_eq!(r1.desktop_1440x900_records, 1);
        assert_eq!(r1.mobile_390x844_records, 0);
        assert!(
            r1.violations
                .iter()
                .any(|v| v.detail.contains("0 `390x844` mobile"))
        );

        // Case 3: Mobile-only audit JSON (`desktop_1440x900_records == 0`) -> passed == false!
        let mobile_only = dir.path().join("mobile-only.json");
        fs::write(
            &mobile_only,
            build_signed_audit_report_json(
                0,
                json!([]),
                json!([{"path":"/","viewport":"mobile","status":200,"check":{"vw":390,"vh":844,"scrollWidth":390,"pageOverflow":false}}]),
            ),
        )
        .unwrap();
        let r2 = execute_ui_gate(
            UiGateSurface::LocalApp,
            Some(dir.path().to_str().unwrap()),
            Some(mobile_only.to_str().unwrap()),
            "CHWG-0251",
            "abc1234",
            "org_test",
        )
        .unwrap();
        assert!(!r2.passed);
        assert_eq!(r2.desktop_1440x900_records, 0);
        assert_eq!(r2.mobile_390x844_records, 1);
        assert!(
            r2.violations
                .iter()
                .any(|v| v.detail.contains("0 `1440x900` desktop"))
        );

        // Case 4: Unsigned `UiAuditReportV1` fails closed on signature verification!
        let unsigned_path = dir.path().join("unsigned.json");
        fs::write(
            &unsigned_path,
            r#"{"schema":"UiAuditReportV1","records":[{"path":"/","viewport":"desktop-light","status":200,"check":{"vw":1440,"vh":900}},{"path":"/","viewport":"mobile","status":200,"check":{"vw":390,"vh":844}}]}"#,
        )
        .unwrap();
        let r3 = execute_ui_gate(
            UiGateSurface::LocalApp,
            Some(dir.path().to_str().unwrap()),
            Some(unsigned_path.to_str().unwrap()),
            "CHWG-0251",
            "abc1234",
            "org_test",
        )
        .unwrap();
        assert!(!r3.passed);
        assert!(
            r3.violations
                .iter()
                .any(|v| v.detail.contains("signature verification failed"))
        );

        // Case 5: Stripped `"schema"` object (`{"records":[...]}`) and unsigned top-level array `[...]` BOTH fail closed!
        let stripped_schema_path = dir.path().join("stripped-schema.json");
        fs::write(
            &stripped_schema_path,
            r#"{"records":[{"path":"/","viewport":"desktop-light","status":200,"check":{"vw":1440,"vh":900}},{"path":"/","viewport":"mobile","status":200,"check":{"vw":390,"vh":844}}]}"#,
        )
        .unwrap();
        let r4 = execute_ui_gate(
            UiGateSurface::LocalApp,
            Some(dir.path().to_str().unwrap()),
            Some(stripped_schema_path.to_str().unwrap()),
            "CHWG-0251",
            "abc1234",
            "org_test",
        )
        .unwrap();
        assert!(!r4.passed);
        assert!(
            r4.violations
                .iter()
                .any(|v| v.detail.contains("missing `schema`"))
        );

        let unsigned_arr_path = dir.path().join("unsigned-arr.json");
        fs::write(
            &unsigned_arr_path,
            r#"[{"path":"/","viewport":"desktop-light","status":200,"check":{"vw":1440,"vh":900}},{"path":"/","viewport":"mobile","status":200,"check":{"vw":390,"vh":844}}]"#,
        )
        .unwrap();
        for surface in [UiGateSurface::LocalApp, UiGateSurface::All] {
            let r5 = execute_ui_gate(
                surface,
                Some(dir.path().to_str().unwrap()),
                Some(unsigned_arr_path.to_str().unwrap()),
                "CHWG-0251",
                "abc1234",
                "org_test",
            )
            .unwrap();
            assert!(!r5.passed);
            assert!(
                r5.violations
                    .iter()
                    .any(|v| v.detail.contains("unsigned top-level JSON array rejected"))
            );
        }

        // Case 6: `--org acme-corp` hashes org identifier via SHA-256 without leaking raw slug!
        let (mut out_buf, mut err_buf) = (Vec::new(), Vec::new());
        let cli_args: Vec<String> = [
            "--surface",
            "site",
            "--repo",
            dir.path().to_str().unwrap(),
            "--org",
            "acme-corp",
            "--json",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let exit_code = run_cli(&cli_args, &mut out_buf, &mut err_buf);
        assert_eq!(exit_code, 0, "stderr={}", String::from_utf8_lossy(&err_buf));
        let cli_rcpt: UiGateReceiptV1 = serde_json::from_slice(&out_buf).unwrap();
        assert_eq!(cli_rcpt.org_id_hash.len(), 64);
        assert!(!cli_rcpt.org_id_hash.contains("acme-corp"));
    }

    #[test]
    fn local_app_surface_passes_clean_dual_viewport_and_catches_overflow_select_and_404_links() {
        let dir = tempfile::tempdir().unwrap();
        let clean = dir.path().join("clean.json");
        fs::write(
            &clean,
            build_signed_audit_report_json(
                4,
                json!([]),
                json!([
                  {
                    "path": "/",
                    "viewport": "desktop-light",
                    "status": 200,
                    "check": {
                      "vw": 1440,
                      "vh": 900,
                      "scrollWidth": 1440,
                      "pageOverflow": false,
                      "pillOverflow": [],
                      "buttonsExercised": 3,
                      "selectsChecked": 1,
                      "deadButtons": [],
                      "selectGeometryDefects": [],
                      "brokenLinks": []
                    }
                  },
                  {
                    "path": "/",
                    "viewport": "mobile",
                    "status": 200,
                    "check": {
                      "vw": 390,
                      "vh": 844,
                      "scrollWidth": 390,
                      "pageOverflow": false,
                      "pillOverflow": [],
                      "buttonsExercised": 3,
                      "selectsChecked": 1,
                      "deadButtons": [],
                      "selectGeometryDefects": [],
                      "brokenLinks": []
                    }
                  }
                ]),
            ),
        )
        .unwrap();

        let receipt = execute_ui_gate(
            UiGateSurface::LocalApp,
            Some(dir.path().to_str().unwrap()),
            Some(clean.to_str().unwrap()),
            "CHWG-0251",
            "deadbeef",
            "org_test",
        )
        .unwrap();
        assert!(receipt.passed, "{receipt:?}");
        assert!(receipt.ok);
        assert_eq!(receipt.desktop_1440x900_records, 1);
        assert_eq!(receipt.mobile_390x844_records, 1);
        assert_eq!(receipt.interactive_controls_verified, 8);
        assert_eq!(receipt.links_verified, 4);
        receipt.verify_signature().unwrap();
        receipt.verify_k1().unwrap();

        // Defect report with pill overflow, `<select>` inset defect, dead button, and 404 link:
        let bad = dir.path().join("bad.json");
        fs::write(
            &bad,
            build_signed_audit_report_json(
                1,
                json!([]),
                json!([
                  {
                    "path": "/",
                    "viewport": "desktop-light",
                    "status": 200,
                    "check": {
                      "vw": 1440,
                      "vh": 900,
                      "scrollWidth": 1520,
                      "pageOverflow": true,
                      "pillOverflow": [{"selector": ".status-pill", "scrollWidth": 180, "clientWidth": 90}],
                      "deadButtons": [{"selector": "#broken-btn", "reason": "zero-area"}],
                      "selectGeometryDefects": [{"selector": "select#model", "reason": "clipped-right-inset"}],
                      "brokenLinks": [{"href": "/missing", "status": 404}]
                    }
                  },
                  {
                    "path": "/",
                    "viewport": "mobile",
                    "status": 200,
                    "check": {
                      "vw": 390,
                      "vh": 844,
                      "scrollWidth": 390,
                      "pageOverflow": false
                    }
                  }
                ]),
            ),
        )
        .unwrap();
        let bad_receipt = execute_ui_gate(
            UiGateSurface::LocalApp,
            Some(dir.path().to_str().unwrap()),
            Some(bad.to_str().unwrap()),
            "CHWG-0251",
            "deadbeef",
            "org_test",
        )
        .unwrap();
        assert!(!bad_receipt.passed);
        assert!(bad_receipt.violations.len() >= 4);
    }
}
