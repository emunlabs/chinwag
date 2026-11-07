#![forbid(unsafe_code)]

//! Streaming analysis of an existing bus JSONL journal. These results are
//! observations or unpersisted preparation, never a lock, write or fsync grant.

use crate::bus_federation::{BusMessage, same_immutable_original};
use std::io::{self, BufRead, Read, Write};

/// Existing journals may contain larger legacy rows. This bounds one complete
/// raw row including its newline; it does not impose a total-history count cap.
pub const MAX_LEGACY_JSONL_RECORD_BYTES: usize = 1024 * 1024;
/// New native preparation must fit this full serialized JSONL line, including
/// its newline. This does not enlarge the separate native bus frame limit.
pub const MAX_NEW_NATIVE_JSONL_RECORD_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    Io(io::ErrorKind),
    OversizedLegacyRecord,
    PartialTail,
    MalformedRecord,
    InvalidStoredSequence,
    ConflictingOriginal,
    SequenceOverflow,
    OversizedNativeRecord,
    Serialization,
}
impl std::fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "bus journal analysis refused: {self:?}")
    }
}
impl std::error::Error for JournalError {}

#[derive(Debug)]
pub enum JournalPreparation {
    HistoricalReplay(HistoricalReplay),
    PreparedAppend(Box<PreparedAppend>),
}
/// Full-history replay observation. It is not a fresh persistence receipt or a
/// processing/start ACK. The original sink still owns its retained file checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoricalReplay {
    local_sequence: u64,
}
impl HistoricalReplay {
    pub fn local_sequence(&self) -> u64 {
        self.local_sequence
    }
}
/// Unpersisted bytes only. The original owner must retain/flock/revalidate its
/// file, append once, fsync and read back before claiming an actual stored row.
#[derive(Debug)]
pub struct PreparedAppend {
    message: BusMessage,
    line: Vec<u8>,
    observed_max_sequence: u64,
}
impl PreparedAppend {
    pub fn message(&self) -> &BusMessage {
        &self.message
    }
    pub fn line(&self) -> &[u8] {
        &self.line
    }
    pub fn local_sequence(&self) -> u64 {
        self.message.seq
    }
    pub fn observed_max_sequence(&self) -> u64 {
        self.observed_max_sequence
    }
}

/// Scan the entire stream. A later conflict, malformed row or uncertain tail
/// overrides an earlier matching ID. Memory use is bounded by one legacy row,
/// its parsed message and one bounded new native preparation, not history size.
/// The retained owner must provide the complete journal positioned at its
/// beginning; a generic BufRead cannot prove file origin or snapshot stability.
pub fn analyze_journal<R: BufRead + ?Sized>(
    reader: &mut R,
    incoming: &BusMessage,
) -> Result<JournalPreparation, JournalError> {
    let mut line = Vec::new();
    let mut maximum_sequence = 0_u64;
    let mut original_sequence = None;
    loop {
        line.clear();
        // Take applies the bound before read_until can extend its buffer.
        let read = Read::take(&mut *reader, (MAX_LEGACY_JSONL_RECORD_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|error| JournalError::Io(error.kind()))?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_LEGACY_JSONL_RECORD_BYTES {
            return Err(JournalError::OversizedLegacyRecord);
        }
        if !line.ends_with(b"\n") {
            return Err(JournalError::PartialTail);
        }
        if line
            .iter()
            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            continue;
        }
        let stored: BusMessage =
            serde_json::from_slice(&line).map_err(|_| JournalError::MalformedRecord)?;
        if stored.seq == 0 {
            return Err(JournalError::InvalidStoredSequence);
        }
        maximum_sequence = maximum_sequence.max(stored.seq);
        if stored.id == incoming.id {
            if !same_immutable_original(&stored, incoming) {
                return Err(JournalError::ConflictingOriginal);
            }
            // Preserve the first original sequence; later exact observations
            // never replace it with a newer sequence/display representation.
            original_sequence.get_or_insert(stored.seq);
        }
    }
    if let Some(local_sequence) = original_sequence {
        return Ok(JournalPreparation::HistoricalReplay(HistoricalReplay {
            local_sequence,
        }));
    }
    let next_sequence = maximum_sequence
        .checked_add(1)
        .ok_or(JournalError::SequenceOverflow)?;
    // Check the caller's complete serialized input before cloning any of its
    // potentially large strings. Sequence expansion is checked again below.
    let mut counter = BoundedWriter::counting(MAX_NEW_NATIVE_JSONL_RECORD_BYTES - 1);
    serialize(incoming, &mut counter)?;
    let mut message = incoming.clone();
    message.seq = next_sequence;
    let mut output = BoundedWriter::buffered(MAX_NEW_NATIVE_JSONL_RECORD_BYTES - 1);
    serialize(&message, &mut output)?;
    let mut line = output.bytes;
    line.push(b'\n');
    Ok(JournalPreparation::PreparedAppend(Box::new(
        PreparedAppend {
            message,
            line,
            observed_max_sequence: maximum_sequence,
        },
    )))
}

struct BoundedWriter {
    bytes: Vec<u8>,
    buffered: bool,
    remaining: usize,
    exceeded: bool,
}
impl BoundedWriter {
    fn counting(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            buffered: false,
            remaining: limit,
            exceeded: false,
        }
    }
    fn buffered(limit: usize) -> Self {
        Self {
            buffered: true,
            ..Self::counting(limit)
        }
    }
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("bounded native journal preparation"));
        }
        self.remaining -= bytes.len();
        if self.buffered {
            self.bytes.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn serialize(message: &BusMessage, writer: &mut BoundedWriter) -> Result<(), JournalError> {
    serde_json::to_writer(&mut *writer, message).map_err(|_| {
        if writer.exceeded {
            JournalError::OversizedNativeRecord
        } else {
            JournalError::Serialization
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn message(id: &str, sequence: u64) -> BusMessage {
        BusMessage {
            id: id.into(),
            seq: sequence,
            ts_unix: 100,
            ts_iso: "display only".into(),
            room: "#eng".into(),
            sender: "DEV#original".into(),
            sender_cast: "■".into(),
            sender_endpoint_id: "endpoint witness".into(),
            to: Some("QA#existing".into()),
            task_id: Some("TASK-1".into()),
            body: "original body".into(),
            digest_sha256: "digest witness".into(),
            pubkey_ed25519: Some("opaque public key witness".into()),
            signature_ed25519: Some("opaque signature witness".into()),
            sig_verified: false,
        }
    }
    fn history(messages: &[BusMessage]) -> Vec<u8> {
        let mut output = Vec::new();
        for message in messages {
            serde_json::to_writer(&mut output, message).unwrap();
            output.push(b'\n');
        }
        output
    }
    fn analyze(bytes: Vec<u8>, incoming: &BusMessage) -> Result<JournalPreparation, JournalError> {
        analyze_journal(&mut Cursor::new(bytes), incoming)
    }
    fn replay(result: JournalPreparation) -> HistoricalReplay {
        match result {
            JournalPreparation::HistoricalReplay(replay) => replay,
            _ => panic!("expected historical replay"),
        }
    }
    fn append(result: JournalPreparation) -> PreparedAppend {
        match result {
            JournalPreparation::PreparedAppend(append) => *append,
            _ => panic!("expected unpersisted append preparation"),
        }
    }
    #[test]
    fn empty_journal_prepares_one_line_and_changes_only_local_sequence() {
        let mut incoming = message("new-original", 99);
        incoming.body = "body with newline\nand Unicode ✓".into();
        let prepared = append(analyze(vec![], &incoming).unwrap());
        assert_eq!(prepared.local_sequence(), 1);
        assert_eq!(prepared.observed_max_sequence(), 0);
        assert!(same_immutable_original(&incoming, prepared.message()));
        assert_eq!(incoming.seq, 99);
        assert_eq!(
            prepared
                .line()
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
            1
        );
        let decoded: BusMessage = serde_json::from_slice(prepared.line()).unwrap();
        assert!(same_immutable_original(&incoming, &decoded));
        assert_eq!(decoded.seq, 1);
        assert_eq!(decoded.ts_iso, incoming.ts_iso);
        assert_eq!(decoded.sender_cast, incoming.sender_cast);
        assert_eq!(decoded.sig_verified, incoming.sig_verified);
    }
    #[test]
    fn complete_history_uses_maximum_sequence_not_last_line() {
        let rows = [message("a", 8), message("b", 3), message("c", 5)];
        let prepared = append(analyze(history(&rows), &message("new", 0)).unwrap());
        assert_eq!(prepared.local_sequence(), 9);
        assert_eq!(prepared.observed_max_sequence(), 8);
    }
    #[test]
    fn one_and_multiple_record_replay_preserves_first_original_sequence() {
        let original = message("target", 4);
        assert_eq!(
            replay(analyze(history(std::slice::from_ref(&original)), &original).unwrap())
                .local_sequence(),
            4
        );
        let mut later = original.clone();
        later.seq = 9;
        later.ts_iso = "later display".into();
        let rows = [
            message("other", 10),
            original.clone(),
            later,
            message("last", 2),
        ];
        assert_eq!(
            replay(analyze(history(&rows), &original).unwrap()).local_sequence(),
            4
        );
    }
    #[test]
    fn later_conflicting_original_refuses_even_after_an_exact_match() {
        let original = message("target", 4);
        for field in 0..10 {
            let mut conflict = original.clone();
            conflict.seq = 8;
            match field {
                0 => conflict.body.push('!'),
                1 => conflict.to = Some("other".into()),
                2 => conflict.room = "#qa".into(),
                3 => conflict.task_id = Some("TASK-2".into()),
                4 => conflict.ts_unix += 1,
                5 => conflict.sender = "DEV#other".into(),
                6 => conflict.pubkey_ed25519 = Some("other-key".into()),
                7 => conflict.signature_ed25519 = Some("other-signature".into()),
                8 => conflict.digest_sha256 = "other-digest".into(),
                9 => conflict.sender_endpoint_id = "other-endpoint".into(),
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    analyze(
                        history(&[original.clone(), message("unrelated", 5), conflict]),
                        &original
                    ),
                    Err(JournalError::ConflictingOriginal)
                ),
                "field {field}"
            );
        }
    }
    #[test]
    fn only_presentation_and_local_sequence_differences_replay() {
        let original = message("target", 4);
        let mut received = original.clone();
        received.seq = 99;
        received.ts_iso = "received display".into();
        received.sender_cast = "●".into();
        received.sig_verified = true;
        assert_eq!(
            replay(analyze(history(&[original]), &received).unwrap()).local_sequence(),
            4
        );
    }
    #[test]
    fn malformed_later_record_overrides_earlier_replay() {
        let original = message("target", 4);
        let mut rows = history(std::slice::from_ref(&original));
        rows.extend(b"{malformed}\n");
        assert!(matches!(
            analyze(rows, &original),
            Err(JournalError::MalformedRecord)
        ));
    }
    #[test]
    fn partial_tail_is_never_skipped_or_repaired() {
        let original = message("target", 4);
        for tail in [
            serde_json::to_vec(&message("partial", 5)).unwrap(),
            b"{\"id\":".to_vec(),
            b"  ".to_vec(),
        ] {
            let mut rows = history(std::slice::from_ref(&original));
            rows.extend(tail);
            assert!(matches!(
                analyze(rows, &original),
                Err(JournalError::PartialTail)
            ));
        }
    }
    #[test]
    fn invalid_utf8_and_non_json_control_rows_are_malformed() {
        for row in [
            vec![b'{', 0xff, b'}', b'\n'],
            vec![0x0b, b'\n'],
            vec![0x0c, b'\n'],
        ] {
            assert!(matches!(
                analyze(row, &message("new", 0)),
                Err(JournalError::MalformedRecord)
            ));
        }
    }
    #[test]
    fn complete_blank_lines_and_legacy_json_whitespace_are_allowed() {
        let original = message("target", 4);
        let mut rows = b"\n \t\r\n \t".to_vec();
        rows.extend(serde_json::to_vec(&original).unwrap());
        rows.extend(b" \t\r\n\n");
        assert_eq!(
            replay(analyze(rows, &original).unwrap()).local_sequence(),
            4
        );
    }
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }
    impl BufRead for FailingReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
        fn consume(&mut self, _: usize) {}
    }
    #[test]
    fn io_failure_after_exact_match_refuses_without_preparation() {
        let original = message("target", 4);
        let mut input = Cursor::new(history(std::slice::from_ref(&original))).chain(FailingReader);
        assert!(matches!(
            analyze_journal(&mut input, &original),
            Err(JournalError::Io(io::ErrorKind::PermissionDenied))
        ));
    }
    #[test]
    fn oversized_line_is_stopped_at_limit_plus_one_before_parsing() {
        let mut input = Cursor::new(vec![b' '; MAX_LEGACY_JSONL_RECORD_BYTES + 100]);
        assert!(matches!(
            analyze_journal(&mut input, &message("new", 0)),
            Err(JournalError::OversizedLegacyRecord)
        ));
        assert_eq!(input.position(), (MAX_LEGACY_JSONL_RECORD_BYTES + 1) as u64);
    }
    #[test]
    fn larger_legacy_rows_are_read_but_new_native_rows_stay_bounded() {
        let mut legacy = message("legacy-large", 1);
        legacy.body = "x".repeat(300_000);
        let prepared = append(analyze(history(&[legacy.clone()]), &message("new", 0)).unwrap());
        assert_eq!(prepared.local_sequence(), 2);
        assert!(matches!(
            analyze(vec![], &legacy),
            Err(JournalError::OversizedNativeRecord)
        ));
        assert_eq!(
            replay(analyze(history(std::slice::from_ref(&legacy)), &legacy).unwrap())
                .local_sequence(),
            1
        );
    }
    #[test]
    fn exact_legacy_and_new_native_line_boundaries_do_not_truncate() {
        for limit in [
            MAX_NEW_NATIVE_JSONL_RECORD_BYTES,
            MAX_LEGACY_JSONL_RECORD_BYTES,
        ] {
            let mut boundary = message("boundary", 1);
            boundary.body.clear();
            let overhead = history(std::slice::from_ref(&boundary)).len();
            boundary.body = "x".repeat(limit - overhead);
            let original = history(std::slice::from_ref(&boundary));
            assert_eq!(original.len(), limit);
            assert_eq!(
                replay(analyze(original, &boundary).unwrap()).local_sequence(),
                1
            );
            if limit == MAX_NEW_NATIVE_JSONL_RECORD_BYTES {
                assert_eq!(
                    append(analyze(vec![], &boundary).unwrap()).line().len(),
                    limit
                );
                boundary.body.push('x');
                assert!(matches!(
                    analyze(vec![], &boundary),
                    Err(JournalError::OversizedNativeRecord)
                ));
            } else {
                boundary.body.push('x');
                assert!(matches!(
                    analyze(history(&[boundary]), &message("new", 0)),
                    Err(JournalError::OversizedLegacyRecord)
                ));
            }
        }
    }
    #[test]
    fn zero_sequence_refuses_and_overflow_never_wraps() {
        assert!(matches!(
            analyze(history(&[message("bad", 0)]), &message("new", 0)),
            Err(JournalError::InvalidStoredSequence)
        ));
        let maximum = message("maximum", u64::MAX);
        assert!(matches!(
            analyze(history(std::slice::from_ref(&maximum)), &message("new", 0)),
            Err(JournalError::SequenceOverflow)
        ));
        assert_eq!(
            replay(analyze(history(std::slice::from_ref(&maximum)), &maximum).unwrap())
                .local_sequence(),
            u64::MAX
        );
    }
    struct RepeatedLines {
        line: Vec<u8>,
        offset: usize,
        remaining: usize,
    }
    impl Read for RepeatedLines {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let input = self.fill_buf()?;
            let count = input.len().min(output.len());
            output[..count].copy_from_slice(&input[..count]);
            self.consume(count);
            Ok(count)
        }
    }
    impl BufRead for RepeatedLines {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.remaining == 0 {
                Ok(&[])
            } else {
                Ok(&self.line[self.offset..])
            }
        }
        fn consume(&mut self, count: usize) {
            self.offset += count;
            if self.offset == self.line.len() && self.remaining > 0 {
                self.offset = 0;
                self.remaining -= 1;
            }
        }
    }
    #[test]
    fn complete_stream_has_no_arbitrary_total_record_count_cap() {
        let original = message("target", 1);
        let mut input = RepeatedLines {
            line: history(std::slice::from_ref(&original)),
            offset: 0,
            remaining: 10_001,
        };
        assert_eq!(
            replay(analyze_journal(&mut input, &original).unwrap()).local_sequence(),
            1
        );
        assert_eq!(input.remaining, 0);
    }
}
