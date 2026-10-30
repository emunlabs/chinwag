//! Fixed fresh-thread bootstrap. The caller retains its IO on every error.
use crate::{Result, SteerError, record::valid_target_id, wire, work_journal::CommittedWork};
use serde_json::{Value, json};
use std::{collections::VecDeque, time::Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

pub(crate) struct FreshThreadProof {
    thread: String,
    id: String,
    text: String,
    deadline: Instant,
    prefix: Vec<u8>,
}
impl FreshThreadProof {
    pub(crate) fn thread_id(&self) -> &str {
        &self.thread
    }
    pub(crate) fn into_parts(self) -> (String, String, String, Instant, Vec<u8>) {
        (self.thread, self.id, self.text, self.deadline, self.prefix)
    }
}

pub(crate) async fn bootstrap<R, W>(
    work: &CommittedWork,
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<FreshThreadProof>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !work.dedicated_explicit_login_consent() {
        return Err(SteerError::PermissionDenied);
    }
    if Instant::now() >= work.deadline() {
        return Err(SteerError::PermissionDenied);
    }
    let mut prefix = VecDeque::new();
    write(writer, json!({"id":"chinwag-owned-initialize","method":"initialize","params":{"clientInfo":{"name":"chinwag-owned-work","title":"Chinwag owned work","version":env!("CARGO_PKG_VERSION")},"capabilities":{"explicitGatewayOauth":true,"experimentalApi":false,"requestAttestation":false}}}), work.deadline()).await?;
    let result = response(
        reader,
        "chinwag-owned-initialize",
        &mut prefix,
        work.deadline(),
    )
    .await?;
    let object = result.as_object().ok_or(SteerError::Unavailable)?;
    for (field, cap) in [
        ("userAgent", 1024),
        ("codexHome", 4096),
        ("platformFamily", 64),
        ("platformOs", 64),
    ] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty() && s.len() <= cap && !s.chars().any(char::is_control))
        {
            return Err(SteerError::Unavailable);
        }
    }
    write(writer, json!({"method":"initialized"}), work.deadline()).await?;
    write(
        writer,
        json!({"id":"chinwag-owned-thread","method":"thread/start","params":{"cwd":work.cwd()}}),
        work.deadline(),
    )
    .await?;
    let result = response(reader, "chinwag-owned-thread", &mut prefix, work.deadline()).await?;
    let thread = result
        .get("thread")
        .and_then(Value::as_object)
        .ok_or(SteerError::Unavailable)?;
    if thread.get("cwd").and_then(Value::as_str) != work.cwd().to_str() {
        return Err(SteerError::Unavailable);
    }
    let id = thread
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| valid_target_id(s))
        .ok_or(SteerError::Unavailable)?;
    if !thread
        .get("turns")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Err(SteerError::Unavailable);
    }
    if Instant::now() >= work.deadline() {
        return Err(SteerError::PermissionDenied);
    }
    Ok(FreshThreadProof {
        thread: id.into(),
        id: work.id().into(),
        text: work.text().into(),
        deadline: work.deadline(),
        prefix: prefix.into_iter().flatten().collect(),
    })
}
async fn write<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: Value,
    deadline: Instant,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| SteerError::InvalidInput)?;
    bytes.push(b'\n');
    if bytes.len() > wire::MAX_OUTBOUND_BYTES {
        return Err(SteerError::InvalidInput);
    }
    let duration = deadline
        .saturating_duration_since(Instant::now())
        .min(std::time::Duration::from_secs(2));
    if duration.is_zero() {
        return Err(SteerError::PermissionDenied);
    }
    tokio::time::timeout(duration, async {
        writer.write_all(&bytes).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| SteerError::Uncertain)?
    .map_err(|_| SteerError::Uncertain)
}
async fn response<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    expected: &str,
    prefix: &mut VecDeque<Vec<u8>>,
    deadline: Instant,
) -> Result<Value> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SteerError::Uncertain);
        }
        let mut bytes = Vec::new();
        let n = tokio::time::timeout(
            remaining,
            (&mut *reader)
                .take((wire::MAX_FRAME_BYTES + 1) as u64)
                .read_until(b'\n', &mut bytes),
        )
        .await
        .map_err(|_| SteerError::Uncertain)?
        .map_err(|_| SteerError::Unavailable)?;
        if n == 0 || bytes.len() > wire::MAX_FRAME_BYTES || !bytes.ends_with(b"\n") {
            return Err(SteerError::Unavailable);
        }
        let value = wire::unique_value(&bytes)?;
        let object = value.as_object().ok_or(SteerError::Unavailable)?;
        if object.get("method").is_some() {
            if object.contains_key("id") {
                return Err(SteerError::OwnerInterventionRequired);
            }
            if object.contains_key("result")
                || object.contains_key("error")
                || !object.get("method").is_some_and(Value::is_string)
            {
                return Err(SteerError::Unavailable);
            }
            if prefix.len() >= 64
                || prefix.iter().map(Vec::len).sum::<usize>() + bytes.len() > wire::MAX_FRAME_BYTES
            {
                return Err(SteerError::Capacity);
            }
            prefix.push_back(bytes);
            continue;
        }
        if object.get("id").and_then(Value::as_str) != Some(expected)
            || object.contains_key("params")
            || object.contains_key("result") == object.contains_key("error")
        {
            return Err(SteerError::Unavailable);
        }
        if object.contains_key("error") {
            return Err(SteerError::Uncertain);
        }
        return object.get("result").cloned().ok_or(SteerError::Unavailable);
    }
}

#[cfg(test)]
mod tests;
