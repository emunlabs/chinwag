//! Typed private fixture seeding; absent from the normal library feature set.
use super::{Decision, domain, one_row};
use crate::{Result, Value, native::Connection};
pub struct SeedMessage {
    id: String,
    thread: String,
    author: String,
    role: String,
    body: String,
    time: i64,
}
impl SeedMessage {
    pub fn try_new(
        id: String,
        thread: String,
        author: String,
        role: String,
        body: String,
        time: i64,
    ) -> std::result::Result<Self, &'static str> {
        if id.is_empty()
            || thread.is_empty()
            || time < 0
            || [&id, &thread, &author, &role, &body]
                .iter()
                .any(|s| s.len() > crate::MAX_VALUE_BYTES)
        {
            return Err("private_seed_message_fields");
        }
        Ok(Self {
            id,
            thread,
            author,
            role,
            body,
            time,
        })
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        domain::digest(
            "private_seed_message",
            &[&self.id, &self.thread, &self.author, &self.role, &self.body],
            &[self.time],
        )
    }
}
pub(super) fn seed(native: &Connection, request: SeedMessage) -> Result<Decision> {
    let existing = one_row(native.query(
        c"SELECT id,thread_id,author_key_id,role,body,created_at_ms FROM messages WHERE id=?1",
        &[Value::Text(request.id.clone())],
    )?)?;
    let desired = vec![
        Value::Text(request.id.clone()),
        Value::Text(request.thread),
        Value::Text(request.author),
        Value::Text(request.role),
        Value::Text(request.body),
        Value::Integer(request.time),
    ];
    let dirty = match existing {
        Some(row) if row == desired => false,
        Some(_) => {
            return Ok(domain::refused(
                "private_message_conflict",
                "Private message ID conflict",
            ));
        }
        None => true,
    };
    let decision = domain::bound(Decision {
        dirty,
        response: serde_json::json!({"private_seed_message":request.id,"replayed":!dirty}),
        outcome: "private_message_seed",
        is_error: false,
    })?;
    if decision.is_error {
        return Ok(decision);
    }
    if dirty {
        native.query(c"INSERT INTO messages(id,thread_id,author_key_id,role,body,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6)", &desired)?;
    }
    Ok(decision)
}
