// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RFC 8785 JSON Canonicalization Scheme (JCS) serializer over `serde_json::Value`.
//! Keys are sorted by UTF-16 code units (matching ECMAScript `<` / RFC 8785 §3.2.3).

use crate::ContractError;
use serde::Serialize;
use serde_json::Value;

/// Serialize any `Serialize` value into deterministic RFC 8785 JCS UTF-8 bytes.
pub fn to_jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    let json_val = serde_json::to_value(value).map_err(|_| ContractError::Canonicalization)?;
    let mut out = String::with_capacity(256);
    write_jcs_value(&json_val, &mut out)?;
    Ok(out.into_bytes())
}

/// Serialize any `Serialize` value into a deterministic RFC 8785 JCS UTF-8 string.
pub fn to_jcs_string<T: Serialize>(value: &T) -> Result<String, ContractError> {
    let bytes = to_jcs_bytes(value)?;
    String::from_utf8(bytes).map_err(|_| ContractError::Canonicalization)
}

fn cmp_utf16_code_units(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
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
            c if (c as u32) <= 0x1F => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

const MAX_IEEE754_SAFE_INT: i64 = 9_007_199_254_740_991;
const MIN_IEEE754_SAFE_INT: i64 = -9_007_199_254_740_991;

fn write_jcs_value(val: &Value, out: &mut String) -> Result<(), ContractError> {
    match val {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if !(MIN_IEEE754_SAFE_INT..=MAX_IEEE754_SAFE_INT).contains(&i) {
                    return Err(ContractError::Canonicalization);
                }
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                if u > MAX_IEEE754_SAFE_INT as u64 {
                    return Err(ContractError::Canonicalization);
                }
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                if f == 0.0 {
                    // RFC 8785 §3.2.2.3 normalizes -0.0 and +0.0 to "0"
                    out.push('0');
                } else {
                    // Wire contract forbids floating-point numbers (`u64` uses decimal-string CanonicalU64)
                    return Err(ContractError::Canonicalization);
                }
            } else {
                return Err(ContractError::Canonicalization);
            }
        }
        Value::String(s) => write_jcs_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_jcs_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&str, &Value)> =
                map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            entries.sort_by(|(ka, _), (kb, _)| cmp_utf16_code_units(ka, kb));
            out.push('{');
            for (idx, (k, v)) in entries.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_jcs_string(k, out);
                out.push(':');
                write_jcs_value(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}
