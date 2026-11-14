// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Deterministic Website & Documentation UI Gate (`chinwag-ci ui-gate`).
//!
//! Enforces:
//! - `INV-CREDIT-ONLY-PRICING-01`: Zero legacy per-seat / per-agent pricing strings
//! - `INV-NO-RAW-MDC-HEADING-BRACES-01`: Zero raw `{#...}` heading attributes in `content/**/*.md`
//! - `INV-NO-CLI-IN-H1-01`: Zero parenthesized CLI commands in `title:` frontmatter + mandatory `command:`
//! - `INV-DOCS-ZERO-LEAK-01`: Zero leaked internal terms or RFC-6598 Tailscale CGNAT (`100.64.0.0/10`) IPs
//! - `INV-UI-GEOMETRY-GATE-01`: Playwright Desktop (`1440x900`) & Mobile (`390x844`) geometry audit verification
//!   with `Ed25519` + `SHA-256` `UiGateReceiptV1` attestation (`0` hardcoded organization IP literals).

use super::EphemeralRunnerSigner;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Canonical Desktop viewport width (`1440x900`).
pub const DESKTOP_VIEWPORT_WIDTH: u32 = 1440;
/// Canonical Desktop viewport height (`1440x900`).
pub const DESKTOP_VIEWPORT_HEIGHT: u32 = 900;
/// Canonical Mobile viewport width (`390x844`).
pub const MOBILE_VIEWPORT_WIDTH: u32 = 390;
/// Canonical Mobile viewport height (`390x844`).
pub const MOBILE_VIEWPORT_HEIGHT: u32 = 844;

/// Target surface evaluated by `chinwag-ci ui-gate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UiGateSurface {
    Site,
    Docs,
    All,
}

impl UiGateSurface {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "site" | "website" => Ok(Self::Site),
            "docs" | "doc" | "documentation" => Ok(Self::Docs),
            "all" | "both" => Ok(Self::All),
            other => Err(format!(
                "invalid --surface `{other}`: expected `site`, `docs`, or `all`"
            )),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
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

/// Single deterministic invariant or geometry violation captured by `chinwag-ci ui-gate`.
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

/// Summary of Playwright `1440x900` Desktop + `390x844` Mobile audit verification (`verify_audit_json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditJsonReportV1 {
    pub audit_records_verified: usize,
    pub desktop_1440x900_records: usize,
    pub mobile_390x844_records: usize,
    pub violations: Vec<UiGateViolationV1>,
}

/// Cryptographically signed UI Gate receipt (`UiGateReceiptV1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiGateReceiptV1 {
    pub ok: bool,
    pub schema: String,
    pub command: String,
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
    pub invariants_verified: Vec<String>,
    pub violations: Vec<UiGateViolationV1>,
    pub artifacts_git_ref: String,
    pub payload_sha256_hex: String,
    pub pk_ci_k1_hex: String,
    pub k1_signature_hex: String,
}

impl UiGateReceiptV1 {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn canonical_transcript_bytes(
        org_id_hash: &str,
        ticket_id: &str,
        surface: &str,
        commit_sha: &str,
        repo_path: &str,
        host_arch: &str,
        passed: bool,
        html_files_scanned: usize,
        markdown_files_scanned: usize,
        audit_records_verified: usize,
        desktop_1440x900_records: usize,
        mobile_390x844_records: usize,
        pk_ci_k1_hex: &str,
    ) -> Vec<u8> {
        let mut out = b"chinwag-ui-gate-receipt-v2\0".to_vec();
        let fields = [
            org_id_hash.to_string(),
            ticket_id.to_string(),
            surface.to_string(),
            commit_sha.to_string(),
            repo_path.to_string(),
            host_arch.to_string(),
            passed.to_string(),
            html_files_scanned.to_string(),
            markdown_files_scanned.to_string(),
            audit_records_verified.to_string(),
            desktop_1440x900_records.to_string(),
            mobile_390x844_records.to_string(),
            pk_ci_k1_hex.to_string(),
        ];
        for f in &fields {
            let bytes = f.as_bytes();
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_signed(
        runner_signer: &EphemeralRunnerSigner,
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
        let passed = violations.is_empty();
        let surface_str = surface.as_str();
        let pk_ci_k1_hex = runner_signer.public_key_hex();

        let transcript = Self::canonical_transcript_bytes(
            org_id_hash,
            ticket_id,
            surface_str,
            commit_sha,
            repo_path,
            host_arch,
            passed,
            scan_report.html_files_scanned,
            scan_report.markdown_files_scanned,
            audit_report.audit_records_verified,
            audit_report.desktop_1440x900_records,
            audit_report.mobile_390x844_records,
            &pk_ci_k1_hex,
        );
        let payload_sha256_hex = hex::encode(Sha256::digest(&transcript));
        let k1_sig = runner_signer.sign(&transcript);

        let receipt = Self {
            ok: passed,
            schema: "UiGateReceiptV1".to_string(),
            command: "chinwag-ci ui-gate".to_string(),
            org_id_hash: org_id_hash.to_string(),
            ticket_id: ticket_id.to_string(),
            surface: surface_str.to_string(),
            commit_sha: commit_sha.to_string(),
            repo_path: repo_path.to_string(),
            host_arch: host_arch.to_string(),
            passed,
            html_files_scanned: scan_report.html_files_scanned,
            markdown_files_scanned: scan_report.markdown_files_scanned,
            audit_records_verified: audit_report.audit_records_verified,
            desktop_1440x900_records: audit_report.desktop_1440x900_records,
            mobile_390x844_records: audit_report.mobile_390x844_records,
            invariants_verified: vec![
                "INV-CREDIT-ONLY-PRICING-01".to_string(),
                "INV-NO-RAW-MDC-HEADING-BRACES-01".to_string(),
                "INV-NO-CLI-IN-H1-01".to_string(),
                "INV-DOCS-ZERO-LEAK-01".to_string(),
                "INV-UI-GEOMETRY-GATE-01".to_string(),
            ],
            violations,
            artifacts_git_ref: format!("refs/chinwag/ui-gate/{ticket_id}/{commit_sha}"),
            payload_sha256_hex,
            pk_ci_k1_hex,
            k1_signature_hex: hex::encode(k1_sig.to_bytes()),
        };
        receipt.verify_k1()?;
        Ok(receipt)
    }

    pub fn verify_k1(&self) -> Result<(), String> {
        let expected_transcript = Self::canonical_transcript_bytes(
            &self.org_id_hash,
            &self.ticket_id,
            &self.surface,
            &self.commit_sha,
            &self.repo_path,
            &self.host_arch,
            self.passed,
            self.html_files_scanned,
            self.markdown_files_scanned,
            self.audit_records_verified,
            self.desktop_1440x900_records,
            self.mobile_390x844_records,
            &self.pk_ci_k1_hex,
        );
        let expected_sha = hex::encode(Sha256::digest(&expected_transcript));
        if self.payload_sha256_hex != expected_sha {
            return Err("UiGateReceiptV1 payload_sha256_hex mismatch".to_string());
        }
        let pk_bytes: [u8; 32] = hex::decode(&self.pk_ci_k1_hex)
            .map_err(|e| format!("invalid pk_ci_k1_hex: {e}"))?
            .try_into()
            .map_err(|_| "pk_ci_k1_hex must be 32 bytes".to_string())?;
        let vk =
            VerifyingKey::from_bytes(&pk_bytes).map_err(|e| format!("invalid K1 pubkey: {e}"))?;
        let sig_bytes: [u8; 64] = hex::decode(&self.k1_signature_hex)
            .map_err(|e| format!("invalid k1_signature_hex: {e}"))?
            .try_into()
            .map_err(|_| "k1_signature_hex must be 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(&expected_transcript, &sig)
            .map_err(|e| format!("UiGateReceiptV1 K1 signature failed verify_strict: {e}"))
    }
}

/// Detects any RFC-6598 Tailscale / CGNAT IPv4 address (`100.64.0.0/10`, i.e., `100.64..=127.*.*`)
/// without hardcoding any organization-specific IP address literals.
#[must_use]
pub fn find_rfc6598_cgnat_ipv4(text: &str) -> Option<String> {
    for raw_token in text
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter(|s| !s.is_empty())
    {
        let trimmed = raw_token.trim_matches('.');
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() == 4 {
            let octets: Result<Vec<u8>, _> = parts.iter().map(|p| p.parse::<u8>()).collect();
            if let Ok(oct) = octets
                && oct[0] == 100
                && (64..=127).contains(&oct[1])
            {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "node_modules" | "target" | ".nuxt" | ".output" | "dist" | ".wrangler"
    )
}

fn collect_files_with_ext(root: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut sorted: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    sorted.sort();
    for path in sorted {
        if path.is_dir() {
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

/// Scans `.html` and `content/**/*.md` files in `repo_path` for static UI Gate invariants.
#[must_use]
pub fn scan_repo_invariants_with_terms(
    repo_path: &Path,
    _surface: UiGateSurface,
    extra_forbidden_terms: &[String],
) -> RepoScanReportV1 {
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
                    invariant: "INV-CREDIT-ONLY-PRICING-01".to_string(),
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
                        invariant: "INV-CREDIT-ONLY-PRICING-01".to_string(),
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
                        invariant: "INV-NO-RAW-MDC-HEADING-BRACES-01".to_string(),
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
                                invariant: "INV-NO-CLI-IN-H1-01".to_string(),
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
                        invariant: "INV-NO-CLI-IN-H1-01".to_string(),
                        target: rel.clone(),
                        detail: "missing non-empty `command:` frontmatter field".to_string(),
                    });
                }
            } else {
                report.violations.push(UiGateViolationV1 {
                    invariant: "INV-NO-CLI-IN-H1-01".to_string(),
                    target: rel.clone(),
                    detail: "missing YAML frontmatter block (`---`) with `title:` and `command:`"
                        .to_string(),
                });
            }

            for custom in extra_forbidden_terms {
                let c_lower = custom.trim().to_ascii_lowercase();
                if !c_lower.is_empty() && lower.contains(&c_lower) {
                    report.violations.push(UiGateViolationV1 {
                        invariant: "INV-DOCS-ZERO-LEAK-01".to_string(),
                        target: rel.clone(),
                        detail: format!(
                            "leaked configured forbidden term `{}` in documentation Markdown",
                            custom.trim()
                        ),
                    });
                }
            }
            if let Some(cgnat_ip) = find_rfc6598_cgnat_ipv4(&raw) {
                report.violations.push(UiGateViolationV1 {
                    invariant: "INV-DOCS-ZERO-LEAK-01".to_string(),
                    target: rel,
                    detail: format!(
                        "leaked RFC-6598 CGNAT IPv4 `{cgnat_ip}` in documentation Markdown"
                    ),
                });
            }
        }
    }

    report
}

/// Validates Playwright Desktop (`1440x900`) & Mobile (`390x844`) geometry audit JSON records.
pub fn verify_audit_json_str(
    raw_json: &str,
    source_label: &str,
    _surface: UiGateSurface,
) -> Result<AuditJsonReportV1, String> {
    let parsed: Value = serde_json::from_str(raw_json)
        .map_err(|e| format!("invalid JSON in `{source_label}`: {e}"))?;
    let records = parsed
        .as_array()
        .ok_or_else(|| format!("expected top-level JSON array in `{source_label}`"))?;
    if records.is_empty() {
        return Err(format!(
            "Playwright audit JSON `{source_label}` contains 0 records"
        ));
    }

    let mut report = AuditJsonReportV1::default();
    for (idx, rec) in records.iter().enumerate() {
        report.audit_records_verified += 1;
        let path = rec
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        let viewport = rec
            .get("viewport")
            .and_then(|v| v.as_str())
            .unwrap_or("desktop");
        if viewport == "desktop" {
            report.desktop_1440x900_records += 1;
        } else if viewport == "mobile" {
            report.mobile_390x844_records += 1;
        }
        let target = format!("{source_label}[{idx}]:{viewport}:{path}");

        let status = rec.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
        if status != 200 {
            report.violations.push(UiGateViolationV1 {
                invariant: "INV-UI-GEOMETRY-GATE-01".to_string(),
                target: target.clone(),
                detail: format!("HTTP status is {status}, expected 200"),
            });
        }

        let Some(check) = rec.get("check").and_then(|v| v.as_object()) else {
            report.violations.push(UiGateViolationV1 {
                invariant: "INV-UI-GEOMETRY-GATE-01".to_string(),
                target,
                detail: "missing `check` geometry object on audit record".to_string(),
            });
            continue;
        };

        if let Some(ovf) = check.get("pageOverflow") {
            match ovf {
                Value::Bool(true) => report.violations.push(UiGateViolationV1 {
                    invariant: "INV-UI-GEOMETRY-GATE-01".to_string(),
                    target: target.clone(),
                    detail: "check.pageOverflow is true".to_string(),
                }),
                Value::Array(arr) if !arr.is_empty() => report.violations.push(UiGateViolationV1 {
                    invariant: "INV-UI-GEOMETRY-GATE-01".to_string(),
                    target: target.clone(),
                    detail: format!("check.pageOverflow has {} overflowing elements", arr.len()),
                }),
                _ => {}
            }
        }
        for zero_field in [
            "pageOverflowCount",
            "clippedCount",
            "inlineCodeSpillCount",
            "runtimeErrorCount",
            "consoleErrorCount",
        ] {
            if let Some(n) = check.get(zero_field).and_then(|v| v.as_u64())
                && n > 0
            {
                report.violations.push(UiGateViolationV1 {
                    invariant: "INV-UI-GEOMETRY-GATE-01".to_string(),
                    target: target.clone(),
                    detail: format!("check.{zero_field} is {n}, expected 0"),
                });
            }
        }
    }

    Ok(report)
}

/// Executes `chinwag-ci ui-gate` across static repository files and optional Playwright audit JSONs.
#[allow(clippy::too_many_arguments)]
pub fn execute_ui_gate(
    signer: &EphemeralRunnerSigner,
    surface: UiGateSurface,
    repo_dir: Option<&Path>,
    audit_json_paths: &[PathBuf],
    extra_forbidden_terms: &[String],
    ticket_id: &str,
    commit_sha: &str,
    org_id_hash: &str,
) -> Result<UiGateReceiptV1, String> {
    let resolved_repo = repo_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let mut configured_terms: Vec<String> = extra_forbidden_terms.to_vec();
    if let Ok(env_terms) = std::env::var("CHINWAG_UI_FORBIDDEN_TERMS") {
        for item in env_terms.split(',') {
            let t = item.trim();
            if !t.is_empty() && !configured_terms.iter().any(|x| x == t) {
                configured_terms.push(t.to_string());
            }
        }
    }

    let scan_report = scan_repo_invariants_with_terms(&resolved_repo, surface, &configured_terms);
    let mut combined_audit = AuditJsonReportV1::default();
    for audit_path in audit_json_paths {
        let raw = fs::read_to_string(audit_path).map_err(|e| {
            format!(
                "unable to read Playwright audit JSON `{}`: {e}",
                audit_path.display()
            )
        })?;
        let part = verify_audit_json_str(&raw, &audit_path.display().to_string(), surface)?;
        combined_audit.audit_records_verified += part.audit_records_verified;
        combined_audit.desktop_1440x900_records += part.desktop_1440x900_records;
        combined_audit.mobile_390x844_records += part.mobile_390x844_records;
        combined_audit.violations.extend(part.violations);
    }

    UiGateReceiptV1::build_signed(
        signer,
        org_id_hash,
        ticket_id,
        surface,
        commit_sha,
        &resolved_repo.display().to_string(),
        std::env::consts::ARCH,
        &scan_report,
        &combined_audit,
    )
}
