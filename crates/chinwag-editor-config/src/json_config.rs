//! Add one object member without reserializing unrelated input bytes or numbers.
#![forbid(unsafe_code)]
use crate::{Launch, MAX_BYTES, Refusal};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use serde_json::{Value, json, value::RawValue};
use std::{collections::BTreeMap, fmt};

struct RawObject<'a>(BTreeMap<String, &'a RawValue>);
impl<'de> Deserialize<'de> for RawObject<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = RawObject<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object without duplicate keys")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut result = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if result.contains_key(&key) {
                        return Err(serde::de::Error::custom("Duplicate object key"));
                    }
                    result.insert(key, map.next_value::<&'de RawValue>()?);
                }
                Ok(RawObject(result))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}
fn object(source: &str) -> Result<RawObject<'_>, Refusal> {
    serde_json::from_str(source).map_err(|_| Refusal::InvalidDocument)
}
fn unique(raw: &RawValue, depth: usize, nodes: &mut usize) -> Result<(), Refusal> {
    *nodes += 1;
    if depth > 64 || *nodes > 10_000 {
        return Err(Refusal::Limit);
    }
    match raw.get().as_bytes().first() {
        Some(b'{') => {
            for value in object(raw.get())?.0.values() {
                unique(value, depth + 1, nodes)?;
            }
        }
        Some(b'[') => {
            let values: Vec<&RawValue> =
                serde_json::from_str(raw.get()).map_err(|_| Refusal::InvalidDocument)?;
            for value in values {
                unique(value, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn proposal(source: &str, launch: &Launch<'_>) -> Result<Option<String>, Refusal> {
    let raw: &RawValue = serde_json::from_str(source).map_err(|_| Refusal::InvalidDocument)?;
    unique(raw, 0, &mut 0)?;
    let root = object(source)?;
    let desired = json!({"type":"stdio", "command":launch.command, "args":launch.args});
    let (container, empty, field) = match root.0.get("mcpServers") {
        Some(raw) => {
            let servers = object(raw.get()).map_err(|_| Refusal::UnsupportedLayout)?;
            if let Some(existing) = servers.0.get("chinwag") {
                let existing: Value =
                    serde_json::from_str(existing.get()).map_err(|_| Refusal::Conflict)?;
                return if existing == desired {
                    Ok(None)
                } else {
                    Err(Refusal::Conflict)
                };
            }
            (*raw, servers.0.is_empty(), format!("\"chinwag\":{desired}"))
        }
        None => (
            raw,
            root.0.is_empty(),
            format!("\"mcpServers\":{{\"chinwag\":{desired}}}"),
        ),
    };
    // Borrowed RawValue points into the supplied source, with no decoding/copy.
    // Check the complete slice before using its offset for a single insertion.
    let start = (container.get().as_ptr() as usize)
        .checked_sub(source.as_ptr() as usize)
        .ok_or(Refusal::InvalidDocument)?;
    let end = start
        .checked_add(container.get().len())
        .ok_or(Refusal::Limit)?;
    if source.get(start..end) != Some(container.get()) || !container.get().ends_with('}') {
        return Err(Refusal::InvalidDocument);
    }
    let insertion = format!("{}\n{field}\n", if empty { "" } else { "," });
    if source.len().saturating_add(insertion.len()) > MAX_BYTES {
        return Err(Refusal::Limit);
    }
    let at = end - 1;
    let mut proposed = String::with_capacity(source.len() + insertion.len());
    proposed.push_str(&source[..at]);
    proposed.push_str(&insertion);
    proposed.push_str(&source[at..]);
    let verified: &RawValue =
        serde_json::from_str(&proposed).map_err(|_| Refusal::InvalidDocument)?;
    unique(verified, 0, &mut 0)?;
    Ok(Some(proposed))
}
