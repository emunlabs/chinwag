use crate::{ActionKind, GeminiError, Result, SavedOperation, StopReason, api::valid_uuid};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, json};
use std::fmt;
pub(crate) const MAX_FRAME: usize = 256 * 1024;
pub(crate) const MAX_OUTBOUND: usize = 64 * 1024;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RpcId {
    String(String),
    Number(i64),
}
impl RpcId {
    pub(crate) fn value(&self) -> Value {
        match self {
            Self::String(s) => json!(s),
            Self::Number(n) => json!(n),
        }
    }
    pub(crate) fn string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
}
pub(crate) enum Update {
    Text(String),
    Mode(String),
    Other,
}
pub(crate) enum Event {
    Response {
        id: RpcId,
        result: Option<Value>,
        error: bool,
    },
    Update {
        session: String,
        update: Update,
    },
    Permission {
        id: RpcId,
        session: String,
    },
    OwnerRequest,
    Other,
}
pub(crate) fn value(bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(GeminiError::Unavailable);
    }
    let Unique(v) = serde_json::from_slice(bytes).map_err(|_| GeminiError::Unavailable)?;
    v.as_object().ok_or(GeminiError::Unavailable)?;
    Ok(v)
}
fn bounded(v: Option<&Value>, max: usize) -> Result<String> {
    v.and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
        .map(String::from)
        .ok_or(GeminiError::Unavailable)
}
fn session(v: Option<&Value>) -> Result<String> {
    let s = bounded(v, 128)?;
    if !valid_uuid(&s) {
        return Err(GeminiError::Unavailable);
    }
    Ok(s)
}
fn rpc_id(v: &Value) -> Result<RpcId> {
    if v.is_string() {
        let s = bounded(Some(v), 128)?;
        Ok(RpcId::String(s))
    } else {
        v.as_i64()
            .map(RpcId::Number)
            .ok_or(GeminiError::Unavailable)
    }
}
pub(crate) fn parse(bytes: &[u8]) -> Result<Event> {
    let v = value(bytes)?;
    if v.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(GeminiError::Unavailable);
    }
    if let Some(method) = v.get("method") {
        let method = bounded(Some(method), 128)?;
        if v.get("result").is_some() || v.get("error").is_some() {
            return Err(GeminiError::Unavailable);
        }
        let params = v.get("params").ok_or(GeminiError::Unavailable)?;
        if let Some(id) = v.get("id") {
            let id = rpc_id(id)?;
            if method == "session/request_permission" {
                let sid = session(params.get("sessionId"))?;
                params
                    .get("toolCall")
                    .and_then(Value::as_object)
                    .ok_or(GeminiError::Unavailable)?;
                let options = params
                    .get("options")
                    .and_then(Value::as_array)
                    .ok_or(GeminiError::Unavailable)?;
                if options.len() > 16 {
                    return Err(GeminiError::Unavailable);
                }
                for o in options {
                    bounded(o.get("optionId"), 128)?;
                }
                return Ok(Event::Permission { id, session: sid });
            }
            return Ok(Event::OwnerRequest);
        }
        if method == "session/update" {
            let sid = session(params.get("sessionId"))?;
            let update = params.get("update").ok_or(GeminiError::Unavailable)?;
            let kind = bounded(update.get("sessionUpdate"), 64)?;
            let update = match kind.as_str() {
                "agent_message_chunk" => {
                    let content = update.get("content").ok_or(GeminiError::Unavailable)?;
                    if content.get("type").and_then(Value::as_str) == Some("text") {
                        let text = content
                            .get("text")
                            .and_then(Value::as_str)
                            .ok_or(GeminiError::Unavailable)?;
                        let mut out = String::new();
                        for c in text
                            .chars()
                            .filter(|c| !c.is_control() || matches!(*c, '\n' | '\r' | '\t'))
                        {
                            if out.len() + c.len_utf8() > crate::MAX_TEXT_BYTES {
                                break;
                            }
                            out.push(c);
                        }
                        Update::Text(out)
                    } else {
                        Update::Other
                    }
                }
                "current_mode_update" => Update::Mode(bounded(update.get("currentModeId"), 64)?),
                _ => Update::Other,
            };
            return Ok(Event::Update {
                session: sid,
                update,
            });
        }
        return Ok(Event::Other);
    }
    let id = rpc_id(v.get("id").ok_or(GeminiError::Unavailable)?)?;
    match (v.get("result"), v.get("error")) {
        (Some(result), None) => Ok(Event::Response {
            id,
            result: Some(result.clone()),
            error: false,
        }),
        (None, Some(error)) if error.is_object() => Ok(Event::Response {
            id,
            result: None,
            error: true,
        }),
        _ => Err(GeminiError::Unavailable),
    }
}
pub(crate) fn initialization(v: &Value) -> Result<()> {
    if v.get("protocolVersion").and_then(Value::as_u64) != Some(1)
        || v.get("agentInfo")
            .and_then(|a| a.get("name"))
            .and_then(Value::as_str)
            != Some("gemini-cli")
        || v.get("agentInfo")
            .and_then(|a| a.get("version"))
            .and_then(Value::as_str)
            != Some(crate::CLI_VERSION)
    {
        return Err(GeminiError::Unavailable);
    }
    Ok(())
}
pub(crate) fn new_session(v: &Value) -> Result<String> {
    if v.get("modes")
        .and_then(|m| m.get("currentModeId"))
        .and_then(Value::as_str)
        != Some("default")
    {
        return Err(GeminiError::OwnerInterventionRequired);
    }
    session(v.get("sessionId"))
}
pub(crate) fn terminal(v: &Value) -> Result<StopReason> {
    match v.get("stopReason").and_then(Value::as_str) {
        Some("end_turn") => Ok(StopReason::EndTurn),
        Some("max_tokens") => Ok(StopReason::MaxTokens),
        Some("max_turn_requests") => Ok(StopReason::MaxTurnRequests),
        Some("refusal") => Ok(StopReason::Refusal),
        Some("cancelled") => Ok(StopReason::Cancelled),
        _ => Err(GeminiError::Unavailable),
    }
}
pub(crate) fn encode(v: Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&v).map_err(|_| GeminiError::InvalidInput)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_OUTBOUND {
        return Err(GeminiError::InvalidInput);
    }
    Ok(bytes)
}
pub(crate) fn initialize(id: &str) -> Result<Vec<u8>> {
    encode(
        json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{},"clientInfo":{"name":"chinwag-gemini-control","version":"1"}}}),
    )
}
pub(crate) fn create_session(id: &str, cwd: &std::path::Path) -> Result<Vec<u8>> {
    if !crate::api::valid_path(cwd) {
        return Err(GeminiError::InvalidInput);
    }
    encode(
        json!({"jsonrpc":"2.0","id":id,"method":"session/new","params":{"cwd":cwd,"mcpServers":[]}}),
    )
}
pub(crate) fn prompt(saved: &SavedOperation, sid: &str) -> Result<Vec<u8>> {
    saved.validate()?;
    if !matches!(saved.kind, ActionKind::Start | ActionKind::Prompt)
        || !valid_uuid(sid)
        || saved.session_id.as_ref().is_some_and(|s| s != sid)
    {
        return Err(GeminiError::InvalidInput);
    }
    encode(
        json!({"jsonrpc":"2.0","id":saved.prompt_rpc_id,"method":"session/prompt","params":{"sessionId":sid,"prompt":[{"type":"text","text":saved.text}]}}),
    )
}
pub(crate) fn cancel(sid: &str) -> Result<Vec<u8>> {
    if !valid_uuid(sid) {
        return Err(GeminiError::InvalidInput);
    }
    encode(json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":sid}}))
}
pub(crate) fn permission_cancel(id: &RpcId) -> Result<Vec<u8>> {
    encode(json!({"jsonrpc":"2.0","id":id.value(),"result":{"outcome":{"outcome":"cancelled"}}}))
}

// serde_json::Value normally silently replaces duplicate keys. Correlation
// fields must instead be unambiguous at every nested object boundary.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded JSON without duplicate fields")
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                self.visit_unit()
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = seq.next_element::<Unique>()? {
                    values.push(value);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
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
