// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Pre-encryption environment/token secret scrubber and ANSI/prompt-injection
//! quarantine sanitizer (`INV-CI-ZERO-SECRET-LEAK-01`, `INV-CI-FORK-QUARANTINE-01`).

use serde::{Deserialize, Serialize};

const SENSITIVE_KEY_MARKERS: [&str; 14] = [
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASS",
    "CREDENTIAL",
    "AUTH",
    "DSN",
    "DATABASE_URL",
    "REDIS_URL",
    "PRIVATE",
    "BEARER",
    "COOKIE",
    "WEBHOOK",
];

/// Summary of secrets redacted prior to diagnostic formatting or sealing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubReport {
    pub scrubbed_text: String,
    pub redacted_env_keys: Vec<String>,
    pub redacted_patterns: Vec<String>,
    pub total_redactions: usize,
}

#[must_use]
pub fn is_sensitive_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "PATH"
            | "HOME"
            | "USER"
            | "SHELL"
            | "TERM"
            | "PWD"
            | "RUST_BACKTRACE"
            | "CARGO_TARGET_DIR"
            | "RUSTUP_TOOLCHAIN"
    ) {
        return false;
    }
    SENSITIVE_KEY_MARKERS.iter().any(|m| upper.contains(m))
}

/// Strips terminal CSI/OSC escape sequences and raw ASCII control characters (except `\n` and `\t`).
#[must_use]
pub fn strip_ansi_escape_codes(input: &str) -> (String, usize) {
    let mut cleaned = String::with_capacity(input.len());
    let mut control_stripped = 0usize;
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == 0x1b {
            control_stripped += 1;
            i += 1;
            if i < bytes.len() && bytes[i] == b'[' {
                i += 1;
                while i < bytes.len() && (0x20..=0x3f).contains(&bytes[i]) {
                    i += 1;
                }
                if i < bytes.len() && (0x40..=0x7e).contains(&bytes[i]) {
                    i += 1;
                }
            } else if i < bytes.len() && bytes[i] == b']' {
                i += 1;
                while i < bytes.len() && bytes[i] != 0x07 && bytes[i] != 0x1b {
                    i += 1;
                }
                if i < bytes.len() {
                    if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            continue;
        }
        if bytes[i] < 0x20 && bytes[i] != b'\n' && bytes[i] != b'\t' {
            control_stripped += 1;
            i += 1;
            continue;
        }
        while i < bytes.len() && !input.is_char_boundary(i) {
            i += 1;
        }
        if i < bytes.len()
            && let Some(ch) = input[i..].chars().next()
        {
            cleaned.push(ch);
            i += ch.len_utf8();
        }
    }
    (cleaned, control_stripped)
}

/// Scrubs sensitive environment variable values (sorted longest-first) and common
/// token/credential patterns (`ghp_*`, `sk_live_*`, `sk-proj-*`, `xoxb-*`, `AKIA*`,
/// `Bearer <token>`, JWTs, PEM blocks, and URL userinfo credentials).
///
/// Strips ANSI CSI/OSC escape codes *before* matching so `CARGO_TERM_COLOR=always`
/// color escapes adjacent to or inside tokens can never bypass redaction (`[AF-02-R3]`).
#[must_use]
pub fn scrub_ci_secrets(raw_log: &str, env_snapshot: &[(String, String)]) -> ScrubReport {
    let (mut out, _) = strip_ansi_escape_codes(raw_log);
    let mut redacted_env_keys = Vec::new();
    let mut redacted_patterns = Vec::new();
    let mut total_redactions = 0usize;

    let mut candidates: Vec<(&str, &str)> = env_snapshot
        .iter()
        .filter(|(k, v)| is_sensitive_env_key(k) && v.trim().len() >= 6)
        .map(|(k, v)| (k.as_str(), v.trim()))
        .collect();
    candidates.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));

    for (key, secret_val) in candidates {
        if out.contains(secret_val) {
            let replacement = format!("[REDACTED:ENV:{key}]");
            let count = out.matches(secret_val).count();
            out = out.replace(secret_val, &replacement);
            total_redactions += count;
            push_unique(&mut redacted_env_keys, key);
        }
    }

    while let Some(begin_idx) = out.find("-----BEGIN ") {
        let rest = &out[begin_idx..];
        if let Some(end_marker_rel) = rest.find("PRIVATE KEY-----") {
            let after_first = &rest[end_marker_rel + "PRIVATE KEY-----".len()..];
            if let Some(close_rel) = after_first.find("PRIVATE KEY-----") {
                let total_end = begin_idx
                    + end_marker_rel
                    + "PRIVATE KEY-----".len()
                    + close_rel
                    + "PRIVATE KEY-----".len();
                out.replace_range(begin_idx..total_end, "[REDACTED:PATTERN:PEM_PRIVATE_KEY]");
                total_redactions += 1;
                push_unique(&mut redacted_patterns, "PEM_PRIVATE_KEY");
                continue;
            }
        }
        break;
    }

    for scheme in [
        "postgres://",
        "postgresql://",
        "mysql://",
        "redis://",
        "rediss://",
        "mongodb://",
        "amqp://",
        "https://",
        "http://",
    ] {
        let mut search_from = 0;
        while let Some(rel) = out[search_from..].find(scheme) {
            let start = search_from + rel + scheme.len();
            let rest = &out[start..];
            let authority_end = rest
                .find(['/', ' ', '\n', '\r', '\t', '"', '\''])
                .unwrap_or(rest.len());
            let authority = &rest[..authority_end];
            if let Some(at_pos) = authority.find('@') {
                let userinfo = &authority[..at_pos];
                if userinfo.contains(':') && !userinfo.contains("[REDACTED") {
                    out.replace_range(start..start + at_pos, "[REDACTED:PATTERN:URL_CREDENTIALS]");
                    total_redactions += 1;
                    push_unique(&mut redacted_patterns, "URL_CREDENTIALS");
                    search_from = start + "[REDACTED:PATTERN:URL_CREDENTIALS]".len();
                    continue;
                }
            }
            search_from = start;
        }
    }

    let prefix_rules: [(&str, &str, usize); 20] = [
        ("ghp_", "GITHUB_TOKEN", 8),
        ("ghs_", "GITHUB_TOKEN", 8),
        ("gho_", "GITHUB_TOKEN", 8),
        ("ghu_", "GITHUB_TOKEN", 8),
        ("ghr_", "GITHUB_TOKEN", 8),
        ("github_pat_", "GITHUB_TOKEN", 14),
        ("xoxb-", "SLACK_TOKEN", 8),
        ("xoxp-", "SLACK_TOKEN", 8),
        ("xoxa-", "SLACK_TOKEN", 8),
        ("xoxr-", "SLACK_TOKEN", 8),
        ("sk_live_", "STRIPE_LIVE_KEY", 12),
        ("sk_test_", "STRIPE_TEST_KEY", 12),
        ("sk-proj-", "OPENAI_API_KEY", 12),
        ("sk-svcacct-", "OPENAI_API_KEY", 15),
        ("sk-ant-", "ANTHROPIC_API_KEY", 12),
        ("sk-", "API_SECRET_KEY", 16),
        ("xai-", "XAI_API_KEY", 12),
        ("lin_api_", "LINEAR_API_KEY", 12),
        ("phc_", "POSTHOG_KEY", 8),
        ("cw_ci_org_", "CHINWAG_CI_ORG_TOKEN", 14),
    ];
    for (prefix, kind, min_len) in prefix_rules {
        let mut scan_from = 0usize;
        while let Some(rel) = out[scan_from..].find(prefix) {
            let pos = scan_from + rel;
            let token_len = out[pos..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .map(char::len_utf8)
                .sum::<usize>();
            if token_len >= min_len {
                let replacement = format!("[REDACTED:PATTERN:{kind}]");
                out.replace_range(pos..pos + token_len, &replacement);
                total_redactions += 1;
                push_unique(&mut redacted_patterns, kind);
                scan_from = pos + replacement.len();
            } else {
                scan_from = pos + prefix.len();
            }
        }
    }

    // Case-insensitive generic `Bearer <token>` redaction for non-JWT OAuth/Cloudflare/GCP tokens
    let mut bearer_scan = 0usize;
    while bearer_scan < out.len() {
        let lower_tail = out[bearer_scan..].to_ascii_lowercase();
        let Some(rel) = lower_tail.find("bearer ") else {
            break;
        };
        let kw_pos = bearer_scan + rel;
        let tok_start = kw_pos + "bearer ".len();
        let ws_skip = out[tok_start..]
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .map(char::len_utf8)
            .sum::<usize>();
        let val_start = tok_start + ws_skip;
        let val_len = out[val_start..]
            .chars()
            .take_while(|c| {
                c.is_ascii_alphanumeric() || matches!(*c, '_' | '-' | '.' | '~' | '+' | '/' | '=')
            })
            .map(char::len_utf8)
            .sum::<usize>();
        if val_len >= 8 && !out[val_start..].starts_with("[REDACTED") {
            let replacement = "[REDACTED:PATTERN:BEARER_TOKEN]";
            out.replace_range(val_start..val_start + val_len, replacement);
            total_redactions += 1;
            push_unique(&mut redacted_patterns, "BEARER_TOKEN");
            bearer_scan = val_start + replacement.len();
        } else if val_len > 0 {
            bearer_scan = val_start + val_len;
        } else if let Some(ch) = out[val_start..].chars().next() {
            bearer_scan = val_start + ch.len_utf8();
        } else {
            break;
        }
    }

    let mut idx = 0;
    while let Some(rel) = out[idx..].find("AKIA") {
        let pos = idx + rel;
        let candidate = &out[pos..];
        if candidate.as_bytes().get(..20).is_some_and(|b| {
            b.iter()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        }) {
            out.replace_range(pos..pos + 20, "[REDACTED:PATTERN:AWS_ACCESS_KEY]");
            total_redactions += 1;
            push_unique(&mut redacted_patterns, "AWS_ACCESS_KEY");
            idx = pos + "[REDACTED:PATTERN:AWS_ACCESS_KEY]".len();
        } else {
            idx = pos + 4;
        }
    }

    let mut jwt_search = 0;
    while let Some(rel) = out[jwt_search..].find("eyJ") {
        let pos = jwt_search + rel;
        let rest = &out[pos..];
        let token_len = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
            .map(char::len_utf8)
            .sum::<usize>();
        let candidate = &rest[..token_len];
        let parts: Vec<&str> = candidate.split('.').collect();
        if parts.len() == 3 && parts[1].starts_with("eyJ") && parts[2].len() >= 6 {
            out.replace_range(pos..pos + token_len, "[REDACTED:PATTERN:JWT_TOKEN]");
            total_redactions += 1;
            push_unique(&mut redacted_patterns, "JWT_TOKEN");
            jwt_search = pos + "[REDACTED:PATTERN:JWT_TOKEN]".len();
        } else {
            jwt_search = pos + 3;
        }
    }

    ScrubReport {
        scrubbed_text: out,
        redacted_env_keys,
        redacted_patterns,
        total_redactions,
    }
}

/// Extended scrubber also redacting inline literal assignments to secret identifiers in diffs.
#[must_use]
pub fn scrub_secrets(raw_text: &str, env_snapshot: &[(String, String)]) -> ScrubReport {
    let mut report = scrub_ci_secrets(raw_text, env_snapshot);
    let mut scrubbed_lines = Vec::new();
    let mut modified = false;

    for line in report.scrubbed_text.lines() {
        if let Some(redacted_line) = redact_inline_secret_assignment_line(line) {
            scrubbed_lines.push(redacted_line);
            report.total_redactions += 1;
            push_unique(&mut report.redacted_patterns, "INLINE_SECRET_ASSIGNMENT");
            modified = true;
        } else {
            scrubbed_lines.push(line.to_string());
        }
    }

    if modified {
        let had_trailing_newline = report.scrubbed_text.ends_with('\n');
        report.scrubbed_text = scrubbed_lines.join("\n");
        if had_trailing_newline {
            report.scrubbed_text.push('\n');
        }
    }
    report
}

fn redact_inline_secret_assignment_line(line: &str) -> Option<String> {
    let eq_pos = line.find('=')?;
    let lhs_upper = line[..eq_pos].to_ascii_uppercase();
    let has_secret_ident = [
        "SECRET",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "PASSWORD",
        "PASSWD",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "SIGNING_KEY",
    ]
    .iter()
    .any(|marker| lhs_upper.contains(marker));
    if !has_secret_ident {
        return None;
    }

    let rhs = &line[eq_pos + 1..];
    let rhs_trimmed = rhs.trim_start();
    if rhs_trimmed.starts_with("std::env::")
        || rhs_trimmed.starts_with("env::")
        || rhs_trimmed.starts_with("env!(")
        || rhs_trimmed.starts_with("option_env!(")
        || rhs_trimmed.starts_with("process.env")
        || rhs_trimmed.starts_with("os.environ")
        || rhs_trimmed.starts_with("os.getenv")
        || rhs_trimmed.contains("SecretStore")
        || rhs_trimmed.contains("secret_store")
    {
        return None;
    }

    for quote in ['"', '\''] {
        if let Some(q_start_rel) = rhs.find(quote) {
            let val_start = eq_pos + 1 + q_start_rel + 1;
            if let Some(q_end_rel) = line[val_start..].find(quote) {
                let val_end = val_start + q_end_rel;
                let literal_val = &line[val_start..val_end];
                if literal_val.len() >= 6
                    && !literal_val.contains("[REDACTED")
                    && !literal_val.chars().all(|c| c == '*')
                {
                    let mut updated = String::with_capacity(line.len() + 16);
                    updated.push_str(&line[..val_start]);
                    updated.push_str("[REDACTED:PATTERN:INLINE_SECRET_ASSIGNMENT]");
                    updated.push_str(&line[val_end..]);
                    return Some(updated);
                }
            }
        }
    }
    None
}

/// Strips terminal CSI/OSC escape sequences, ASCII control characters (except `\n` and `\t`),
/// and prompt-injection framing markers inside untrusted compiler/test streams.
#[must_use]
pub fn strip_ansi_and_prompt_injections(input: &str) -> (String, usize, usize) {
    let (mut cleaned, control_stripped) = strip_ansi_escape_codes(input);

    let mut injection_neutralized = 0usize;
    for marker in [
        "<SYSTEM_MESSAGE>",
        "</SYSTEM_MESSAGE>",
        "<USER_REQUEST>",
        "</USER_REQUEST>",
        "<TOOL_OUTPUT>",
        "</TOOL_OUTPUT>",
        "<ADDITIONAL_METADATA>",
        "</ADDITIONAL_METADATA>",
        "<|im_start|>",
        "<|im_end|>",
        "IGNORE ALL PREVIOUS INSTRUCTIONS",
        "SYSTEM OVERRIDE:",
    ] {
        let (replaced, count) =
            replace_ascii_case_insensitive(&cleaned, marker, "[QUARANTINED_INJECTION_MARKER]");
        if count > 0 {
            injection_neutralized += count;
            cleaned = replaced;
        }
    }

    (cleaned, control_stripped, injection_neutralized)
}

fn replace_ascii_case_insensitive(
    haystack: &str,
    needle: &str,
    replacement: &str,
) -> (String, usize) {
    if needle.is_empty() || haystack.len() < needle.len() {
        return (haystack.to_string(), 0);
    }
    let needle_bytes = needle.as_bytes();
    let hay_bytes = haystack.as_bytes();
    let mut out = String::with_capacity(haystack.len());
    let mut count = 0usize;
    let mut last_copied = 0usize;
    let mut i = 0usize;

    while i + needle_bytes.len() <= hay_bytes.len() {
        if haystack.is_char_boundary(i)
            && haystack.is_char_boundary(i + needle_bytes.len())
            && hay_bytes[i..i + needle_bytes.len()].eq_ignore_ascii_case(needle_bytes)
        {
            out.push_str(&haystack[last_copied..i]);
            out.push_str(replacement);
            count += 1;
            i += needle_bytes.len();
            last_copied = i;
        } else {
            i += 1;
        }
    }
    if count == 0 {
        return (haystack.to_string(), 0);
    }
    out.push_str(&haystack[last_copied..]);
    (out, count)
}

fn push_unique(vec: &mut Vec<String>, item: &str) {
    if !vec.iter().any(|x| x == item) {
        vec.push(item.to_string());
    }
}
