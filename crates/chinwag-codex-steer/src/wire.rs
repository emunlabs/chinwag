//! Fixed rust-v0.162.1 app-server lane. Codex omits the JSON-RPC version field.

use crate::{SavedSteer, SteerError};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::fmt;

pub(crate) const MAX_FRAME_BYTES: usize = 256 * 1024;
pub(crate) const MAX_OUTBOUND_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WireId {
    String(String),
    Integer(i64),
}
#[derive(Debug)]
pub(crate) enum Incoming {
    Success {
        id: WireId,
        turn_id: String,
    },
    Error {
        id: WireId,
    },
    Started {
        thread_id: String,
        turn_id: String,
    },
    Completed {
        thread_id: String,
        turn_id: String,
    },
    Recorded {
        thread_id: String,
        turn_id: String,
        client_id: String,
        text: String,
    },
    ServerRequest,
    Other,
}

pub(crate) fn steer_frame(rpc_id: &str, record: &SavedSteer) -> crate::Result<Vec<u8>> {
    record.validate()?;
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "id":rpc_id,"method":"turn/steer","params":{
            "threadId":record.thread_id,"expectedTurnId":record.expected_turn_id,
            "clientUserMessageId":record.id,
            "input":[{"type":"text","text":record.text,"text_elements":[]}]
        }
    }))
    .map_err(|_| SteerError::InvalidInput)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_OUTBOUND_BYTES {
        return Err(SteerError::InvalidInput);
    }
    Ok(bytes)
}

pub(crate) fn parse(bytes: &[u8]) -> crate::Result<Incoming> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(SteerError::Unavailable);
    }
    let Unique(value): Unique =
        serde_json::from_slice(bytes).map_err(|_| SteerError::Unavailable)?;
    let object = value.as_object().ok_or(SteerError::Unavailable)?;
    let id = object.get("id");
    let method = object.get("method");
    let result = object.get("result");
    let error = object.get("error");
    if method.is_some() {
        if result.is_some() || error.is_some() {
            return Err(SteerError::Unavailable);
        }
        let method = method
            .and_then(Value::as_str)
            .ok_or(SteerError::Unavailable)?;
        if let Some(id) = id {
            let _ = wire_id(id)?;
            return Ok(Incoming::ServerRequest);
        }
        let Some(params) = object.get("params").and_then(Value::as_object) else {
            return Ok(Incoming::Other);
        };
        match method {
            "turn/started" | "turn/completed" => {
                let thread_id = target(params.get("threadId"))?;
                let turn = params
                    .get("turn")
                    .and_then(Value::as_object)
                    .ok_or(SteerError::Unavailable)?;
                let turn_id = target(turn.get("id"))?;
                let status = turn
                    .get("status")
                    .and_then(Value::as_str)
                    .ok_or(SteerError::Unavailable)?;
                if !matches!(
                    status,
                    "inProgress" | "completed" | "failed" | "interrupted"
                ) {
                    return Err(SteerError::Unavailable);
                }
                if let Some(view) = turn.get("itemsView")
                    && !matches!(view.as_str(), Some("full" | "summary" | "notLoaded"))
                {
                    return Err(SteerError::Unavailable);
                }
                if !turn.get("items").is_some_and(Value::is_array) {
                    return Err(SteerError::Unavailable);
                }
                if method == "turn/started" && status == "inProgress" {
                    Ok(Incoming::Started { thread_id, turn_id })
                } else if method == "turn/completed" {
                    Ok(Incoming::Completed { thread_id, turn_id })
                } else {
                    Ok(Incoming::Other)
                }
            }
            "item/completed" => {
                let Some(item) = params.get("item").and_then(Value::as_object) else {
                    return Err(SteerError::Unavailable);
                };
                if item.get("type").and_then(Value::as_str) != Some("userMessage") {
                    return Ok(Incoming::Other);
                }
                let Some(client_id) = item.get("clientId").and_then(Value::as_str) else {
                    return Ok(Incoming::Other);
                };
                if !crate::record::valid_operation_id(client_id) {
                    return Ok(Incoming::Other);
                }
                let content = item
                    .get("content")
                    .and_then(Value::as_array)
                    .ok_or(SteerError::Unavailable)?;
                if content.len() != 1 {
                    return Ok(Incoming::Other);
                }
                let text = &content[0];
                if text.get("type").and_then(Value::as_str) != Some("text")
                    || text
                        .get("text_elements")
                        .and_then(Value::as_array)
                        .is_none_or(|elements| !elements.is_empty())
                {
                    return Ok(Incoming::Other);
                }
                let Some(text) = text.get("text").and_then(Value::as_str) else {
                    return Err(SteerError::Unavailable);
                };
                if !crate::record::valid_text(text) {
                    return Ok(Incoming::Other);
                }
                Ok(Incoming::Recorded {
                    thread_id: target(params.get("threadId"))?,
                    turn_id: target(params.get("turnId"))?,
                    client_id: client_id.into(),
                    text: text.into(),
                })
            }
            _ => Ok(Incoming::Other),
        }
    } else {
        let id = wire_id(id.ok_or(SteerError::Unavailable)?)?;
        if result.is_some() == error.is_some() || object.contains_key("params") {
            return Err(SteerError::Unavailable);
        }
        if let Some(result) = result {
            let result = result.as_object().ok_or(SteerError::Unavailable)?;
            if result.len() != 1 {
                return Err(SteerError::Unavailable);
            }
            Ok(Incoming::Success {
                id,
                turn_id: target(result.get("turnId"))?,
            })
        } else {
            let error = error
                .and_then(Value::as_object)
                .ok_or(SteerError::Unavailable)?;
            if !error
                .get("code")
                .is_some_and(|value| value.as_i64().is_some())
                || !error.get("message").is_some_and(Value::is_string)
            {
                return Err(SteerError::Unavailable);
            }
            Ok(Incoming::Error { id })
        }
    }
}
fn target(value: Option<&Value>) -> crate::Result<String> {
    let value = value
        .and_then(Value::as_str)
        .filter(|value| crate::record::valid_target_id(value))
        .ok_or(SteerError::Unavailable)?;
    Ok(value.into())
}
fn wire_id(value: &Value) -> crate::Result<WireId> {
    if let Some(value) = value.as_str().filter(|value| {
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
    }) {
        Ok(WireId::String(value.into()))
    } else if let Some(value) = value.as_i64() {
        Ok(WireId::Integer(value))
    } else {
        Err(SteerError::Unavailable)
    }
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
