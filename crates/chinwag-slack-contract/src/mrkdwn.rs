// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Anti-injection Slack `mrkdwn` sanitizer and secret/entropy egress guards.

use crate::ContractError;

const SECRET_PREFIXES: &[&str] = &[
    "chwg_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xapp-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "lin_api_",
    "sk-",
    "AIza",
    "AKIA",
    "eyJ",
];

/// Returns `true` if `ch` is an ASCII/C1 control character or Unicode bidi override.
#[must_use]
pub fn is_forbidden_control_or_bidi(ch: char) -> bool {
    let u = ch as u32;
    u <= 0x1F
        || (0x7F..=0x9F).contains(&u)
        || (0x202A..=0x202E).contains(&u)
        || (0x2066..=0x2069).contains(&u)
        || matches!(u, 0x200E | 0x200F | 0x061C)
}

/// Escape an untrusted symbolic string for safe Slack Block Kit `mrkdwn` display.
/// Strips control & bidi override codepoints, neutralizes `<!channel>`, `<!here>`,
/// `<@U123>`, and link spoofing `<https://evil|label>`, and caps output at `max_chars`.
#[must_use]
pub fn escape_slack_mrkdwn(input: &str, max_chars: usize) -> String {
    let mut cleaned = String::with_capacity(input.len());
    for ch in input.chars() {
        if is_forbidden_control_or_bidi(ch) {
            continue;
        }
        match ch {
            '&' => cleaned.push_str("&amp;"),
            '<' => cleaned.push_str("&lt;"),
            '>' => cleaned.push_str("&gt;"),
            '`' | '*' | '~' | '_' => {
                cleaned.push('\\');
                cleaned.push(ch);
            }
            c => cleaned.push(c),
        }
    }
    cleaned.chars().take(max_chars).collect()
}

/// Compute Shannon entropy (bits per character) over ASCII bytes of `token`.
fn shannon_entropy_bits(token: &str) -> f64 {
    if token.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut total = 0usize;
    for &b in token.as_bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let n = total as f64;
    let mut ent = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / n;
            ent -= p * p.log2();
        }
    }
    ent
}

/// Rejects strings containing secret prefixes, `${` env-var interpolation,
/// raw Slack special mentions (`<!channel>`, `<!here>`, `<!everyone>`, `<@`),
/// bidi overrides, banned copy (`tribunal`), or high-entropy secret tokens.
pub fn validate_safe_display_token(input: &str, max_len: usize) -> Result<(), ContractError> {
    if input.is_empty() || input.len() > max_len {
        return Err(ContractError::InvalidField("display_token_length"));
    }
    if input.chars().any(is_forbidden_control_or_bidi) {
        return Err(ContractError::InjectionOrBidiDetected);
    }
    if input.contains("${") {
        return Err(ContractError::EnvInterpolationForbidden);
    }
    let lower = input.to_ascii_lowercase();
    if lower.contains("<!channel")
        || lower.contains("<!here")
        || lower.contains("<!everyone")
        || lower.contains("<@")
        || (input.contains('<') && input.contains('|') && input.contains('>'))
    {
        return Err(ContractError::InjectionOrBidiDetected);
    }
    if lower.contains("tribunal") || lower.contains(concat!("rogue", " machine")) {
        return Err(ContractError::BannedCopyTerm);
    }
    for token in input.split(|c: char| c.is_ascii_whitespace() || c == ',' || c == ';') {
        if token.is_empty() {
            continue;
        }
        for prefix in SECRET_PREFIXES {
            if token.starts_with(prefix) {
                return Err(ContractError::SecretMaterialDetected);
            }
        }
        if token.len() >= 24
            && !token.starts_with("blake3:")
            && !token.starts_with("ed25519:")
            && shannon_entropy_bits(token) > 4.35
        {
            return Err(ContractError::SecretMaterialDetected);
        }
    }
    Ok(())
}
