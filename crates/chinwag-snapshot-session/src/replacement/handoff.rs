//! A frozen local context offer. This does not contact or authenticate a target.
use super::{Decision, domain, one_row};
use crate::{Error, Result, Rows, Value, native::Connection};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};

const ROLE: &str = "local_context_offer_v1";
const FORMAT: &str = "chinwag-local-context-offer/v1";
const MAX_SNAPSHOT: usize = 24_576;
const MAX_STORED: usize = 32_768;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RequestRecord {
    id: String,
    thread_id: String,
    target_label: String,
    note: String,
    created_at_ms: i64,
}
/// Validated request data only. No public fields or Deserialize bypass.
pub struct HandoffRequest {
    record: RequestRecord,
}
impl HandoffRequest {
    pub fn try_new(
        id: String,
        thread_id: String,
        target_label: String,
        note: String,
        created_at_ms: i64,
    ) -> std::result::Result<Self, &'static str> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || created_at_ms < 0
        {
            return Err("Invalid local offer ID or timestamp");
        }
        if [&thread_id, &target_label]
            .iter()
            .any(|s| s.is_empty() || s.len() > crate::MAX_VALUE_BYTES)
            || note.len() > crate::MAX_VALUE_BYTES
        {
            return Err("Invalid local offer text or note byte limit");
        }
        Ok(Self {
            record: RequestRecord {
                id,
                thread_id,
                target_label,
                note,
                created_at_ms,
            },
        })
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        let r = &self.record;
        domain::digest(
            "local_context_offer_v1",
            &[&r.id, &r.thread_id, &r.target_label, &r.note],
            &[r.created_at_ms],
        )
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ThreadRecord {
    id: String,
    repo_id: String,
    branch_ref: String,
    title: String,
    created_at_ms: i64,
    updated_at_ms: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MessageRecord {
    id: String,
    thread_id: String,
    author_key_id: String,
    role: String,
    body: String,
    created_at_ms: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PinRecord {
    id: String,
    thread_id: String,
    file_path: String,
    symbol_hash: String,
    source_commit: String,
    body: String,
    created_at_ms: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    thread: ThreadRecord,
    messages: Vec<MessageRecord>,
    pins: Vec<PinRecord>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    format: String,
    request: RequestRecord,
    snapshot: Snapshot,
}
impl Snapshot {
    fn valid(&self, thread: &str) -> bool {
        self.thread.id == thread
            && self
                .messages
                .iter()
                .all(|m| m.thread_id == thread && m.role != ROLE)
            && self.pins.iter().all(|p| p.thread_id == thread)
            && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= MAX_SNAPSHOT)
    }
}
fn refuse(message: &'static str) -> Decision {
    domain::refused("local_offer_refused", message)
}
fn objects(rows: Rows, names: &[&str]) -> std::result::Result<Vec<Json>, &'static str> {
    rows.into_iter()
        .map(|row| {
            if row.len() != names.len() {
                return Err("Stored context row width");
            }
            let mut object = serde_json::Map::new();
            for (name, value) in names.iter().zip(row) {
                object.insert(
                    (*name).into(),
                    match value {
                        Value::Text(text) => Json::String(text),
                        Value::Integer(i) => json!(i),
                        _ => return Err("Stored context cell type"),
                    },
                );
            }
            Ok(Json::Object(object))
        })
        .collect()
}
fn snapshot(
    native: &Connection,
    thread: &str,
) -> Result<std::result::Result<Snapshot, &'static str>> {
    let values = [Value::Text(thread.into())];
    let threads = native.query(c"SELECT id,repo_id,branch_ref,title,created_at_ms,updated_at_ms FROM threads WHERE id=?1 ORDER BY id", &values)?;
    if threads.len() != 1 {
        return Ok(Err("Unknown or invalid local offer thread"));
    }
    let messages = native.query(c"SELECT id,thread_id,author_key_id,role,body,created_at_ms FROM messages WHERE thread_id=?1 AND role<>?2 ORDER BY id", &[Value::Text(thread.into()), Value::Text(ROLE.into())])?;
    let pins = native.query(c"SELECT id,thread_id,file_path,symbol_hash,source_commit,body,created_at_ms FROM context_pins WHERE thread_id=?1 ORDER BY id", &values)?;
    let converted = (|| {
        let mut threads = objects(
            threads,
            &[
                "id",
                "repo_id",
                "branch_ref",
                "title",
                "created_at_ms",
                "updated_at_ms",
            ],
        )?;
        let messages = objects(
            messages,
            &[
                "id",
                "thread_id",
                "author_key_id",
                "role",
                "body",
                "created_at_ms",
            ],
        )?;
        let pins = objects(
            pins,
            &[
                "id",
                "thread_id",
                "file_path",
                "symbol_hash",
                "source_commit",
                "body",
                "created_at_ms",
            ],
        )?;
        let thread = threads.pop().ok_or("Local offer thread missing")?;
        serde_json::from_value::<Snapshot>(json!({"thread":thread,"messages":messages,"pins":pins}))
            .map_err(|_| "Local offer snapshot shape")
    })();
    Ok(converted)
}
pub(super) fn record(native: &Connection, request: HandoffRequest) -> Result<Decision> {
    let args = request.record;
    let row_id = format!("chinwag:local-handoff:v1:{}", args.id);
    // Identity lookup is before ANY current context query, also after restart.
    let existing = one_row(native.query(
        c"SELECT id,thread_id,author_key_id,role,body,created_at_ms FROM messages WHERE id=?1",
        &[Value::Text(row_id.clone())],
    )?)?;
    let (offer, replayed) = if let Some(row) = existing {
        let [
            Value::Text(id),
            Value::Text(thread),
            Value::Text(author),
            Value::Text(role),
            Value::Text(body),
            Value::Integer(time),
        ] = row.as_slice()
        else {
            return Ok(refuse("Stored offer row shape refused"));
        };
        if id != &row_id
            || thread != &args.thread_id
            || !author.is_empty()
            || role != ROLE
            || *time != args.created_at_ms
            || body.len() > MAX_STORED
        {
            return Ok(refuse("Local offer ID conflicts with existing message"));
        }
        let offer: Offer = match serde_json::from_str(body) {
            Ok(offer) => offer,
            Err(_) => return Ok(refuse("Stored local offer envelope refused")),
        };
        if offer.format != FORMAT
            || offer.request != args
            || !offer.snapshot.valid(&args.thread_id)
            || serde_json::to_string(&offer)
                .map_err(|_| Error::Contract("Offer encoding failed"))?
                != *body
        {
            return Ok(refuse("Local offer ID already has different content"));
        }
        (offer, true)
    } else {
        let snapshot = match snapshot(native, &args.thread_id)? {
            Ok(s) => s,
            Err(message) => return Ok(refuse(message)),
        };
        if !snapshot.valid(&args.thread_id) {
            return Ok(refuse("Local offer snapshot refused or exceeds byte limit"));
        }
        (
            Offer {
                format: FORMAT.into(),
                request: args.clone(),
                snapshot,
            },
            false,
        )
    };
    let body =
        serde_json::to_string(&offer).map_err(|_| Error::Contract("Offer encoding failed"))?;
    if body.len() > MAX_STORED {
        return Ok(refuse("Local offer envelope exceeds stored byte limit"));
    }
    let decision = domain::bound(Decision {
        dirty: !replayed,
        response: json!({"state":"recorded_local_offer","delivery":"not_attempted","author_authentication":"none","target_label_kind":"caller_supplied_unverified","authority":"context_only_no_grants","snapshot_source":"local_database_unverified","offer":offer,"replayed":replayed}),
        outcome: if replayed {
            "local_offer_matches_frozen_snapshot"
        } else {
            "local_offer_stored"
        },
        is_error: false,
    })?;
    if !decision.is_error && !replayed {
        native.query(c"INSERT INTO messages(id,thread_id,author_key_id,role,body,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6)", &[Value::Text(row_id),Value::Text(args.thread_id),Value::Text(String::new()),Value::Text(ROLE.into()),Value::Text(body),Value::Integer(args.created_at_ms)])?;
    }
    Ok(decision)
}
