use crate::{CLI_VERSION, ClaudeError, SavedInput};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, json};
use std::fmt;
pub(crate) const MAX_FRAME: usize = 256 * 1024;
pub(crate) const MAX_OUTBOUND: usize = 64 * 1024;
pub(crate) enum Event {
    ControlSuccess {
        request_id: String,
        version: Option<String>,
    },
    ControlError {
        request_id: String,
    },
    Init {
        session: String,
        version: String,
        cwd: String,
        manual_empty: bool,
    },
    Replay {
        session: String,
        id: String,
        text: String,
    },
    Reply {
        session: String,
        ids: Vec<String>,
        text: Option<String>,
    },
    Result {
        session: String,
        ids: Vec<String>,
        error: bool,
    },
    OwnerRequest,
    Other,
}
pub(crate) fn value(bytes: &[u8]) -> crate::Result<Value> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(ClaudeError::Unavailable);
    }
    let Unique(v) = serde_json::from_slice(bytes).map_err(|_| ClaudeError::Unavailable)?;
    v.as_object().ok_or(ClaudeError::Unavailable)?;
    Ok(v)
}
fn bounded(v: Option<&Value>, max: usize) -> crate::Result<String> {
    v.and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
        .map(String::from)
        .ok_or(ClaudeError::Unavailable)
}
fn ids(v: &Value) -> crate::Result<Vec<String>> {
    let mut list = Vec::new();
    let present = v.get("user_message_uuids").is_some();
    if let Some(a) = v.get("user_message_uuids") {
        let a = a.as_array().ok_or(ClaudeError::Unavailable)?;
        if a.len() > 64 {
            return Err(ClaudeError::Unavailable);
        }
        for id in a {
            let s = bounded(Some(id), 128)?;
            if !crate::api::valid_uuid(&s) || list.contains(&s) {
                return Err(ClaudeError::Unavailable);
            }
            list.push(s);
        }
    }
    if let Some(id) = v.get("user_message_uuid") {
        let s = bounded(Some(id), 128)?;
        if !crate::api::valid_uuid(&s) || (present && !list.contains(&s)) {
            return Err(ClaudeError::Unavailable);
        }
        if !present {
            list.push(s);
        }
    }
    Ok(list)
}
fn main_message(v: &Value) -> bool {
    v.get("parent_tool_use_id").is_none_or(Value::is_null)
        && v.get("agent_id").is_none_or(Value::is_null)
}
fn message(v: &Value) -> crate::Result<&Vec<Value>> {
    if v.get("role").and_then(Value::as_str) != Some("assistant")
        || v.get("type").and_then(Value::as_str) != Some("message")
    {
        return Err(ClaudeError::Unavailable);
    }
    bounded(v.get("id"), 256)?;
    let a = v
        .get("content")
        .and_then(Value::as_array)
        .ok_or(ClaudeError::Unavailable)?;
    if a.len() > 1024
        || a.iter()
            .any(|b| !b.is_object() || b.get("type").and_then(Value::as_str).is_none())
    {
        return Err(ClaudeError::Unavailable);
    }
    Ok(a)
}
fn native_uuid(v: &Value) -> crate::Result<()> {
    let id = bounded(v.get("uuid"), 128)?;
    if !crate::api::valid_uuid(&id) {
        return Err(ClaudeError::Unavailable);
    }
    Ok(())
}
pub(crate) fn parse(bytes: &[u8]) -> crate::Result<Event> {
    let v = value(bytes)?;
    let kind = bounded(v.get("type"), 64)?;
    match kind.as_str() {
        "control_response" => {
            let r = v
                .get("response")
                .and_then(Value::as_object)
                .ok_or(ClaudeError::Unavailable)?;
            let id = bounded(r.get("request_id"), 128)?;
            match r.get("subtype").and_then(Value::as_str) {
                Some("success") => Ok(Event::ControlSuccess {
                    request_id: id,
                    version: r
                        .get("response")
                        .and_then(|v| v.get("claude_code_version"))
                        .map(|v| bounded(Some(v), 32))
                        .transpose()?,
                }),
                Some("error") => Ok(Event::ControlError { request_id: id }),
                _ => Err(ClaudeError::Unavailable),
            }
        }
        "conversation_reset" => Ok(Event::OwnerRequest),
        "control_request" => {
            bounded(v.get("request_id"), 128)?;
            v.get("request")
                .and_then(Value::as_object)
                .ok_or(ClaudeError::Unavailable)?;
            Ok(Event::OwnerRequest)
        }
        "system" if v.get("subtype").and_then(Value::as_str) == Some("init") => {
            let tools = v
                .get("tools")
                .and_then(Value::as_array)
                .ok_or(ClaudeError::Unavailable)?;
            Ok(Event::Init {
                session: bounded(v.get("session_id"), 128)?,
                version: bounded(v.get("claude_code_version"), 32)?,
                cwd: bounded(v.get("cwd"), 4096)?,
                manual_empty: tools.is_empty()
                    && v.get("permissionMode").and_then(Value::as_str) == Some("default"),
            })
        }
        "user" if v.get("isReplay").and_then(Value::as_bool) == Some(true) && main_message(&v) => {
            let m = v.get("message").ok_or(ClaudeError::Unavailable)?;
            if m.get("role").and_then(Value::as_str) != Some("user") {
                return Err(ClaudeError::Unavailable);
            }
            let c = m.get("content").ok_or(ClaudeError::Unavailable)?;
            let text: String = if let Some(s) = c.as_str() {
                s.into()
            } else {
                let a = c.as_array().ok_or(ClaudeError::Unavailable)?;
                if a.len() != 1 || a[0].get("type").and_then(Value::as_str) != Some("text") {
                    return Ok(Event::Other);
                }
                a[0].get("text")
                    .and_then(Value::as_str)
                    .ok_or(ClaudeError::Unavailable)?
                    .into()
            };
            if !crate::api::valid_text(&text) {
                return Ok(Event::Other);
            }
            let id = bounded(v.get("uuid"), 128)?;
            if !crate::api::valid_uuid(&id) {
                return Err(ClaudeError::Unavailable);
            }
            Ok(Event::Replay {
                session: bounded(v.get("session_id"), 128)?,
                id,
                text,
            })
        }
        "assistant" if main_message(&v) => {
            native_uuid(&v)?;
            let blocks = message(v.get("message").ok_or(ClaudeError::Unavailable)?)?;
            if !v.get("error").is_none_or(Value::is_null) {
                return Ok(Event::Other);
            }
            let text = if v.get("error").is_none_or(Value::is_null) {
                let mut text = String::new();
                for block in blocks {
                    if block.get("type").and_then(Value::as_str) == Some("text") {
                        let s = block
                            .get("text")
                            .and_then(Value::as_str)
                            .ok_or(ClaudeError::Unavailable)?;
                        if text.len() >= crate::MAX_TEXT_BYTES {
                            continue;
                        }
                        if !text.is_empty() {
                            text.push('\n');
                        }
                        for c in s
                            .chars()
                            .filter(|c| !c.is_control() || matches!(*c, '\n' | '\r' | '\t'))
                        {
                            if text.len() + c.len_utf8() > crate::MAX_TEXT_BYTES {
                                break;
                            }
                            text.push(c);
                        }
                    }
                }
                Some(text)
            } else {
                None
            };
            Ok(Event::Reply {
                session: bounded(v.get("session_id"), 128)?,
                ids: ids(&v)?,
                text,
            })
        }
        "stream_event" if main_message(&v) => {
            native_uuid(&v)?;
            let event = v
                .get("event")
                .and_then(Value::as_object)
                .ok_or(ClaudeError::Unavailable)?;
            let kind = bounded(event.get("type"), 64)?;
            match kind.as_str() {
                "ping" => return Ok(Event::Other),
                "message_start" => {
                    message(event.get("message").ok_or(ClaudeError::Unavailable)?)?;
                }
                "content_block_start" => {
                    if event.get("index").and_then(Value::as_u64).is_none() {
                        return Err(ClaudeError::Unavailable);
                    }
                    event
                        .get("content_block")
                        .and_then(Value::as_object)
                        .ok_or(ClaudeError::Unavailable)?;
                }
                "content_block_delta" => {
                    if event.get("index").and_then(Value::as_u64).is_none() {
                        return Err(ClaudeError::Unavailable);
                    }
                    let delta = event
                        .get("delta")
                        .and_then(Value::as_object)
                        .ok_or(ClaudeError::Unavailable)?;
                    bounded(delta.get("type"), 64)?;
                }
                "message_delta" => {
                    event
                        .get("delta")
                        .and_then(Value::as_object)
                        .ok_or(ClaudeError::Unavailable)?;
                }
                "content_block_stop" | "message_stop" => {}
                _ => return Ok(Event::Other),
            }
            Ok(Event::Reply {
                session: bounded(v.get("session_id"), 128)?,
                ids: ids(&v)?,
                text: None,
            })
        }
        "result" if main_message(&v) => {
            native_uuid(&v)?;
            let subtype = bounded(v.get("subtype"), 64)?;
            if subtype == "success" {
                v.get("result")
                    .and_then(Value::as_str)
                    .ok_or(ClaudeError::Unavailable)?;
            } else if matches!(
                subtype.as_str(),
                "error_during_execution"
                    | "error_max_turns"
                    | "error_max_budget_usd"
                    | "error_max_structured_output_retries"
            ) {
                let a = v
                    .get("errors")
                    .and_then(Value::as_array)
                    .ok_or(ClaudeError::Unavailable)?;
                if a.len() > 128 || a.iter().any(|e| !e.is_string()) {
                    return Err(ClaudeError::Unavailable);
                }
            } else {
                return Err(ClaudeError::Unavailable);
            }
            Ok(Event::Result {
                session: bounded(v.get("session_id"), 128)?,
                ids: ids(&v)?,
                error: v
                    .get("is_error")
                    .and_then(Value::as_bool)
                    .ok_or(ClaudeError::Unavailable)?,
            })
        }
        _ => Ok(Event::Other),
    }
}
pub(crate) fn encode(v: Value) -> crate::Result<Vec<u8>> {
    let mut b = serde_json::to_vec(&v).map_err(|_| ClaudeError::InvalidInput)?;
    b.push(b'\n');
    if b.len() > MAX_OUTBOUND {
        return Err(ClaudeError::InvalidInput);
    }
    Ok(b)
}
pub(crate) fn initialize(id: &str) -> crate::Result<Vec<u8>> {
    encode(json!({"type":"control_request","request_id":id,"request":{"subtype":"initialize"}}))
}
pub(crate) fn input(saved: &SavedInput) -> crate::Result<Vec<u8>> {
    saved.validate()?;
    encode(
        json!({"type":"user","uuid":saved.id,"session_id":saved.session_id,"message":{"role":"user","content":[{"type":"text","text":saved.text}]},"parent_tool_use_id":null,"priority":saved.timing.wire(),"origin":{"kind":"human"},"client_composed":true}),
    )
}
pub(crate) fn compatible(v: Option<&str>) -> bool {
    v == Some(CLI_VERSION)
}
// serde_json::Value normally silently replaces duplicate keys. Correlation
// fields must instead be unambiguous at every nested object boundary.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded JSON without duplicate fields")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                self.visit_unit()
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = seq.next_element::<Unique>()? {
                    values.push(value);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut object = Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if object.contains_key(&key) {
                        return Err(de::Error::custom("duplicate field"));
                    }
                    let Unique(value) = access.next_value::<Unique>()?;
                    object.insert(key, value);
                }
                Ok(Unique(Value::Object(object)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

#[cfg(test)]
mod tests;
