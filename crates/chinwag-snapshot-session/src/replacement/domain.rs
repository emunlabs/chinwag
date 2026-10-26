use super::{Decision, one_row};
use crate::{Error, Result, Value, native::Connection};
use serde_json::json;
use sha2::{Digest, Sha256};

const MAX_RESPONSE_BYTES: usize = 65_536;

/// Request data only; this is not an owner, authorization or completion token.
pub struct PinRequest {
    id: String,
    thread_id: String,
    file_path: String,
    symbol_hash: String,
    source_commit: String,
    body: String,
    created_at_ms: i64,
    create_thread: Option<ThreadStart>,
}
impl PinRequest {
    pub fn try_new(
        id: String,
        thread_id: String,
        file_path: String,
        symbol_hash: String,
        source_commit: String,
        body: String,
        created_at_ms: i64,
    ) -> std::result::Result<Self, &'static str> {
        for text in [&id, &thread_id, &file_path, &symbol_hash, &source_commit] {
            if text.is_empty() || text.len() > crate::MAX_VALUE_BYTES {
                return Err("pin_text_limit");
            }
        }
        if body.len() > crate::MAX_VALUE_BYTES || created_at_ms < 0 {
            return Err("pin_body_or_time");
        }
        Ok(Self {
            id,
            thread_id,
            file_path,
            symbol_hash,
            source_commit,
            body,
            created_at_ms,
            create_thread: None,
        })
    }
    pub fn with_new_thread(mut self, thread: ThreadStart) -> Self {
        self.create_thread = Some(thread);
        self
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        if let Some(thread) = &self.create_thread {
            return digest(
                "pin_context_new_thread",
                &[
                    &self.id,
                    &self.thread_id,
                    &self.file_path,
                    &self.symbol_hash,
                    &self.source_commit,
                    &self.body,
                    &thread.repo_id,
                    &thread.branch_ref,
                    &thread.title,
                ],
                &[self.created_at_ms],
            );
        }
        digest(
            "pin_context",
            &[
                &self.id,
                &self.thread_id,
                &self.file_path,
                &self.symbol_hash,
                &self.source_commit,
                &self.body,
            ],
            &[self.created_at_ms],
        )
    }
}
/// Explicit caller metadata for a new thread and its first decision pin.
/// These labels are request data, not a Git ref proof or authorization token.
pub struct ThreadStart {
    repo_id: String,
    branch_ref: String,
    title: String,
}
impl ThreadStart {
    pub fn try_new(
        repo_id: String,
        branch_ref: String,
        title: String,
    ) -> std::result::Result<Self, &'static str> {
        if [&repo_id, &branch_ref, &title]
            .iter()
            .any(|text| text.is_empty() || text.len() > crate::MAX_VALUE_BYTES)
        {
            return Err("new_thread_text_limit");
        }
        Ok(Self {
            repo_id,
            branch_ref,
            title,
        })
    }
}

pub(super) fn digest(kind: &str, texts: &[&str], numbers: &[i64]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for text in std::iter::once(kind).chain(texts.iter().copied()) {
        hash.update((text.len() as u64).to_be_bytes());
        hash.update(text.as_bytes());
    }
    for number in numbers {
        hash.update(number.to_be_bytes());
    }
    hash.finalize().into()
}
pub(super) fn bound(decision: Decision) -> Result<Decision> {
    if serde_json::to_vec(&decision.response)
        .map_err(|_| Error::Contract("Response encoding"))?
        .len()
        > MAX_RESPONSE_BYTES
    {
        Ok(refused(
            "response_limit",
            "Private context result exceeds output limit",
        ))
    } else {
        Ok(decision)
    }
}
pub(super) fn refused(outcome: &'static str, message: &'static str) -> Decision {
    Decision {
        dirty: false,
        response: json!({"error":message}),
        outcome,
        is_error: true,
    }
}
pub(super) fn cancelled() -> Decision {
    refused(
        "cancelled_before_staging",
        "Request cancelled before persistence",
    )
}
pub(super) fn pin(native: &Connection, request: PinRequest) -> Result<Decision> {
    if request.create_thread.is_some() {
        return first_pin(native, request);
    }
    let mut preview = bound(Decision {
        dirty: false,
        response: json!({"pin":{
        "id": &request.id, "thread_id": &request.thread_id, "file_path": &request.file_path,
        "symbol_hash": &request.symbol_hash, "source_commit": &request.source_commit,
        "body": &request.body, "created_at_ms": request.created_at_ms}, "replayed":false}),
        outcome: "pin_stored",
        is_error: false,
    })?;
    if preview.is_error {
        return Ok(preview);
    }
    let thread = one_row(native.query(
        c"SELECT id FROM threads WHERE id=?1",
        &[Value::Text(request.thread_id.clone())],
    )?)?;
    match thread.as_deref() {
        None => return Ok(refused("unknown_thread", "Unknown thread")),
        Some([Value::Text(id)]) if id == &request.thread_id => {}
        _ => return Err(Error::Contract("Unexpected thread row shape")),
    }
    let desired = vec![
        Value::Text(request.id.clone()),
        Value::Text(request.thread_id),
        Value::Text(request.file_path),
        Value::Text(request.symbol_hash),
        Value::Text(request.source_commit),
        Value::Text(request.body),
        Value::Integer(request.created_at_ms),
    ];
    let existing = one_row(native.query(c"SELECT id,thread_id,file_path,symbol_hash,source_commit,body,created_at_ms FROM context_pins WHERE id=?1", &[Value::Text(request.id)])?)?;
    match existing {
        Some(row) if row == desired => {
            preview.response["replayed"] = serde_json::Value::Bool(true);
            preview.outcome = "pin_matches_current_state";
        }
        Some(_) => {
            return Ok(refused(
                "pin_id_conflict",
                "Pin ID already exists with different content",
            ));
        }
        None => {
            native.query(c"INSERT INTO context_pins(id,thread_id,file_path,symbol_hash,source_commit,body,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)", &desired)?;
            preview.dirty = true;
        }
    }
    Ok(preview)
}

fn first_pin(native: &Connection, request: PinRequest) -> Result<Decision> {
    let thread = request
        .create_thread
        .as_ref()
        .ok_or(Error::Contract("New thread metadata missing"))?;
    let mut preview = bound(Decision {
        dirty: false,
        response: json!({"pin":{
            "id": &request.id, "thread_id": &request.thread_id,
            "file_path": &request.file_path, "symbol_hash": &request.symbol_hash,
            "source_commit": &request.source_commit, "body": &request.body,
            "created_at_ms":request.created_at_ms},
            "thread":{"id":&request.thread_id,"repo_id":&thread.repo_id,
                "branch_ref":&thread.branch_ref,"title":&thread.title,
                "created_at_ms":request.created_at_ms,"updated_at_ms":request.created_at_ms},
            "replayed":false}),
        outcome: "thread_and_first_pin_stored",
        is_error: false,
    })?;
    if preview.is_error {
        return Ok(preview);
    }
    let desired_thread = vec![
        Value::Text(request.thread_id.clone()),
        Value::Text(thread.repo_id.clone()),
        Value::Text(thread.branch_ref.clone()),
        Value::Text(thread.title.clone()),
        Value::Integer(request.created_at_ms),
        Value::Integer(request.created_at_ms),
    ];
    let desired_pin = vec![
        Value::Text(request.id.clone()),
        Value::Text(request.thread_id.clone()),
        Value::Text(request.file_path),
        Value::Text(request.symbol_hash),
        Value::Text(request.source_commit),
        Value::Text(request.body),
        Value::Integer(request.created_at_ms),
    ];
    let existing_thread = one_row(native.query(
        c"SELECT id,repo_id,branch_ref,title,created_at_ms,updated_at_ms FROM threads WHERE id=?1",
        &[Value::Text(request.thread_id)],
    )?)?;
    let existing_pin = one_row(native.query(
        c"SELECT id,thread_id,file_path,symbol_hash,source_commit,body,created_at_ms FROM context_pins WHERE id=?1",
        &[Value::Text(request.id)],
    )?)?;
    match (existing_thread, existing_pin) {
        (None, None) => {
            native.query(c"INSERT INTO threads(id,repo_id,branch_ref,title,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6)", &desired_thread)?;
            native.query(c"INSERT INTO context_pins(id,thread_id,file_path,symbol_hash,source_commit,body,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)", &desired_pin)?;
            preview.dirty = true;
        }
        (Some(thread), Some(pin)) if thread == desired_thread && pin == desired_pin => {
            preview.response["replayed"] = serde_json::Value::Bool(true);
            preview.outcome = "thread_and_first_pin_matches_current_state";
        }
        _ => {
            return Ok(refused(
                "thread_or_first_pin_conflict",
                "New thread or first pin already exists with different state",
            ));
        }
    }
    Ok(preview)
}

#[cfg(feature = "private-probe")]
pub struct SeedThread {
    id: String,
    repo_id: String,
    branch_ref: String,
    title: String,
    created_at_ms: i64,
    updated_at_ms: i64,
}
#[cfg(feature = "private-probe")]
impl SeedThread {
    pub fn try_new(
        id: String,
        repo_id: String,
        branch_ref: String,
        title: String,
        created_at_ms: i64,
        updated_at_ms: i64,
    ) -> std::result::Result<Self, &'static str> {
        if id.is_empty()
            || [&id, &repo_id, &branch_ref, &title]
                .iter()
                .any(|s| s.len() > crate::MAX_VALUE_BYTES)
            || created_at_ms < 0
            || updated_at_ms < 0
        {
            return Err("private_seed_thread_fields");
        }
        Ok(Self {
            id,
            repo_id,
            branch_ref,
            title,
            created_at_ms,
            updated_at_ms,
        })
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        digest(
            "private_seed_thread",
            &[&self.id, &self.repo_id, &self.branch_ref, &self.title],
            &[self.created_at_ms, self.updated_at_ms],
        )
    }
}
#[cfg(feature = "private-probe")]
pub(super) fn seed(native: &Connection, request: SeedThread) -> Result<Decision> {
    let mut response = bound(Decision {
        dirty: false,
        response: json!({"private_seed_thread": &request.id, "replayed":false}),
        outcome: "private_seed_thread_stored",
        is_error: false,
    })?;
    if response.is_error {
        return Ok(response);
    }
    let desired = vec![
        Value::Text(request.id.clone()),
        Value::Text(request.repo_id),
        Value::Text(request.branch_ref),
        Value::Text(request.title),
        Value::Integer(request.created_at_ms),
        Value::Integer(request.updated_at_ms),
    ];
    let existing = one_row(native.query(
        c"SELECT id,repo_id,branch_ref,title,created_at_ms,updated_at_ms FROM threads WHERE id=?1",
        &[Value::Text(request.id)],
    )?)?;
    match existing {
        Some(row) if row == desired => {
            response.response["replayed"] = serde_json::Value::Bool(true);
            response.outcome = "private_seed_thread_matches";
        }
        Some(_) => {
            return Ok(refused(
                "private_thread_id_conflict",
                "Private seed thread ID conflict",
            ));
        }
        None => {
            native.query(c"INSERT INTO threads(id,repo_id,branch_ref,title,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6)", &desired)?;
            response.dirty = true;
        }
    }
    Ok(response)
}
