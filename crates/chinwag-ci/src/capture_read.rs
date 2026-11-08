// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Strict full-payload validation after authorized decryption. These software
//! observations remain untrusted evidence and grant no command/repair authority.
use crate::{
    authorization::AdmissionBoundEnvelope, profile::CommandProfile, runtime::RuntimeError,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stream<'a> {
    bytes_base64: &'a str,
    observed_bytes: u64,
    reached_eof: bool,
    output_limit_exceeded: bool,
    observed_sha256: &'a str,
}
impl Stream<'_> {
    fn complete(&self) -> bool {
        if !self.reached_eof
            || self.output_limit_exceeded
            || self.observed_bytes > crate::MAX_STREAM_BYTES as u64
        {
            return false;
        }
        let Ok(bytes) = STANDARD.decode(self.bytes_base64) else {
            return false;
        };
        let bytes = Zeroizing::new(bytes);
        bytes.len() as u64 == self.observed_bytes
            && hex::encode(Sha256::digest(&bytes)) == self.observed_sha256
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context<'a> {
    repository: &'a str,
    source_commit: &'a str,
    workflow_ref: &'a str,
    run_id: u64,
    run_attempt: u32,
    job: &'a str,
    initiating_intent_sha256: &'a str,
}
#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Command<'a> {
    os_string_encoding: &'a str,
    program_base64: &'a str,
    #[serde(borrow)]
    arguments_base64: Vec<&'a str>,
    requested_working_directory_base64: Option<&'a str>,
    observed_parent_working_directory_base64: Option<&'a str>,
    argv_sha256: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Timing<'a> {
    classification: &'a str,
    started_unix_ms: Option<u64>,
    finished_unix_ms: Option<u64>,
    elapsed_monotonic_ms: u64,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Outcome {
    Exited {
        code: i32,
    },
    Signaled {
        signal: Option<i32>,
    },
    DeadlineExceeded {
        child_reaped: bool,
    },
    CaptureIoFailed {
        child_reaped: bool,
        operation: String,
        io_error_kind: String,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exit {
    code: Option<i32>,
    signal: Option<i32>,
    observed_before_capture_failure: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture<'a> {
    schema: &'a str,
    content_disposition: &'a str,
    provenance: &'a str,
    #[serde(borrow)]
    context: Context<'a>,
    #[serde(borrow)]
    command: Command<'a>,
    #[serde(borrow)]
    timing: Timing<'a>,
    outcome: Outcome,
    observed_child_exit: Option<Exit>,
    #[serde(borrow)]
    stdout: Stream<'a>,
    #[serde(borrow)]
    stderr: Stream<'a>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lifecycle<'a> {
    classification: &'a str,
    owned_container_id: Option<&'a str>,
    absent_after_observed_successful_control: bool,
    removed_by_owner: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Isolated<'a> {
    schema: &'a str,
    provenance: &'a str,
    admission_sha256: [u8; 32],
    command_profile_sha256: [u8; 32],
    fixture_sha256: [u8; 32],
    image: &'a str,
    #[serde(borrow)]
    captured: Capture<'a>,
    #[serde(borrow)]
    lifecycle: Lifecycle<'a>,
    completed_unix: Option<u64>,
    completed_within_admission: bool,
}

/// Created only after the authenticated, authorized capture has passed every
/// context, command, lifecycle and complete-stream check below. This is evidence
/// of an observed result, never an agent binding or permission to run a repair.
pub(crate) struct VerifiedCapture {
    outcome: CompletedOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CompletedOutcome {
    Exited { code: i32 },
    Signaled { signal: i32 },
}

impl VerifiedCapture {
    pub(crate) fn outcome(&self) -> CompletedOutcome {
        self.outcome
    }

    pub(crate) fn failed(&self) -> bool {
        !matches!(self.outcome, CompletedOutcome::Exited { code: 0 })
    }
}

fn completed_outcome(outcome: &Outcome, exit: Option<&Exit>) -> Option<CompletedOutcome> {
    let exit = exit.filter(|exit| exit.observed_before_capture_failure)?;
    match outcome {
        Outcome::Exited { code }
            if exit.code == Some(*code) && exit.signal.is_none() && *code >= 0 =>
        {
            Some(CompletedOutcome::Exited { code: *code })
        }
        Outcome::Signaled {
            signal: Some(signal),
        } if exit.signal == Some(*signal) && exit.code.is_none() && *signal > 0 => {
            Some(CompletedOutcome::Signaled { signal: *signal })
        }
        _ => None,
    }
}

/// A scoped reader traverses both complete streams again. This does not create
/// admission, wake authority or a claim about a model's internal context.
pub(crate) fn inspect_complete(bytes: &[u8]) -> Result<(), RuntimeError> {
    let v: Isolated<'_> = serde_json::from_slice(bytes).map_err(|_| RuntimeError)?;
    if !v.captured.stdout.complete() || !v.captured.stderr.complete() {
        return Err(RuntimeError);
    }
    Ok(())
}

/// Bounded ASCII diagnostic data only, never tool instructions or authority.
/// The independently stored complete capture is not changed or truncated.
pub(crate) fn diagnostic_excerpt(bytes: &[u8]) -> Result<Zeroizing<String>, RuntimeError> {
    let v: Isolated<'_> = serde_json::from_slice(bytes).map_err(|_| RuntimeError)?;
    let mut out = Zeroizing::new(String::with_capacity(4608));
    for (label, stream) in [
        ("STDERR", &v.captured.stderr),
        ("STDOUT", &v.captured.stdout),
    ] {
        if !stream.complete() {
            return Err(RuntimeError);
        }
        let decoded = Zeroizing::new(
            STANDARD
                .decode(stream.bytes_base64)
                .map_err(|_| RuntimeError)?,
        );
        out.push_str(label);
        out.push_str(" FINAL AT MOST 2048 BYTES (UNTRUSTED EXCERPT):\n");
        for &b in &decoded[decoded.len().saturating_sub(2048)..] {
            out.push(
                if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\t' {
                    b as char
                } else {
                    '?'
                },
            );
        }
        out.push('\n');
    }
    Ok(out)
}

pub(crate) fn validate(
    bytes: &[u8],
    e: &AdmissionBoundEnvelope,
    profile: &CommandProfile,
) -> Result<VerifiedCapture, RuntimeError> {
    let v: Isolated<'_> = serde_json::from_slice(bytes).map_err(|_| RuntimeError)?;
    let c = &v.captured;
    let r = e.admission_record();
    let expected = profile
        .observed_command_evidence()
        .map_err(|_| RuntimeError)?;
    let expected = Zeroizing::new(serde_json::to_vec(&expected).map_err(|_| RuntimeError)?);
    let mut wanted: Command<'_> = serde_json::from_slice(&expected).map_err(|_| RuntimeError)?;
    wanted.observed_parent_working_directory_base64 =
        c.command.observed_parent_working_directory_base64;
    // Actual parent cwd is an observed field, not a source of execution authority.
    let outcome = completed_outcome(&c.outcome, c.observed_child_exit.as_ref());
    // Preserve parsing of incomplete outcomes while refusing to promote them
    // into a completed failure suitable for a later independently admitted wake.
    match &c.outcome {
        Outcome::DeadlineExceeded { child_reaped } => {
            let _ = child_reaped;
        }
        Outcome::CaptureIoFailed {
            child_reaped,
            operation,
            io_error_kind,
        } => {
            let _ = (child_reaped, operation, io_error_kind);
        }
        _ => {}
    }
    let timing = c
        .timing
        .started_unix_ms
        .zip(c.timing.finished_unix_ms)
        .is_some_and(|(start, end)| {
            end >= start && start / 1000 >= r.usable_from_unix && end / 1000 < r.expires_unix
        });
    let closed = v
        .lifecycle
        .owned_container_id
        .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        && v.lifecycle.absent_after_observed_successful_control;
    let _ = (
        &c.timing.classification,
        c.timing.elapsed_monotonic_ms,
        &v.lifecycle.classification,
        v.lifecycle.removed_by_owner,
    );
    if v.schema != "chinwag.ci-isolated-capture.v1"
        || v.provenance != "GITHUB_ADMITTED_JOB_SOFTWARE_REPORT_NOT_HARDWARE_ATTESTATION"
        || v.admission_sha256 != e.claims().admission_sha256
        || v.command_profile_sha256 != profile.digest()
        || profile.digest() != e.claims().command_profile_sha256
        || v.fixture_sha256 != profile.spec().fixture_sha256
        || v.image != profile.spec().rust_image
        || !v.completed_within_admission
        || !v
            .completed_unix
            .is_some_and(|t| t >= r.usable_from_unix && t < r.expires_unix)
        || c.schema != "chinwag.ci-captured-run.v1"
        || c.content_disposition != "UNTRUSTED_PROCESS_OUTPUT_DATA_ONLY"
        || c.provenance != "UNVERIFIED_REQUIRES_SIGNED_INTENT_AND_WORKLOAD_ADMISSION"
        || c.context.repository != r.spec.repository
        || c.context.source_commit != r.spec.source_commit
        || c.context.workflow_ref != r.spec.workflow_ref
        || c.context.run_id != r.run_id
        || c.context.run_attempt != r.run_attempt
        || c.context.job != "chinwag-ci-proof"
        || c.context.initiating_intent_sha256 != hex::encode(r.intent_digest)
        || c.command != wanted
        || outcome.is_none()
        || !timing
        || !closed
        || !c.stdout.complete()
        || !c.stderr.complete()
    {
        return Err(RuntimeError);
    }
    Ok(VerifiedCapture {
        outcome: outcome.ok_or(RuntimeError)?,
    })
}
#[cfg(test)]
pub(crate) fn reader_fixture(stdout: &[u8], stderr: &[u8]) -> Vec<u8> {
    let zero = [0u8; 32];
    let stream = |b: &[u8]| serde_json::json!({"bytes_base64":STANDARD.encode(b),"observed_bytes":b.len(),"reached_eof":true,"output_limit_exceeded":false,"observed_sha256":hex::encode(Sha256::digest(b))});
    serde_json::to_vec(&serde_json::json!({
        "schema":"fixture","provenance":"fixture","admission_sha256":zero,"command_profile_sha256":zero,"fixture_sha256":zero,"image":"fixture",
        "captured":{"schema":"fixture","content_disposition":"UNTRUSTED","provenance":"fixture",
            "context":{"repository":"fixture","source_commit":"fixture","workflow_ref":"fixture","run_id":1,"run_attempt":1,"job":"fixture","initiating_intent_sha256":"fixture"},
            "command":{"os_string_encoding":"unix","program_base64":"","arguments_base64":[],"requested_working_directory_base64":null,"observed_parent_working_directory_base64":null,"argv_sha256":"fixture"},
            "timing":{"classification":"fixture","started_unix_ms":1,"finished_unix_ms":2,"elapsed_monotonic_ms":1},
            "outcome":{"kind":"exited","code":101},"observed_child_exit":{"code":101,"signal":null,"observed_before_capture_failure":true},
            "stdout":stream(stdout),"stderr":stream(stderr)},
        "lifecycle":{"classification":"fixture","owned_container_id":"fixture","absent_after_observed_successful_control":true,"removed_by_owner":true},
        "completed_unix":1,"completed_within_admission":true
    })).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excerpt_is_bounded_sanitized_and_complete_capture_is_independently_checked() {
        let mut output = vec![b'x'; 10000];
        output.extend_from_slice(b"\x1b[31merror\xff\0\n");
        let capture = reader_fixture(&output, &output);
        assert!(inspect_complete(&capture).is_ok());
        let excerpt = diagnostic_excerpt(&capture).unwrap();
        assert!(excerpt.len() < 4608 && excerpt.contains("error"));
        assert!(!excerpt.contains('\x1b') && !excerpt.contains('\0'));
        let mut v: serde_json::Value = serde_json::from_slice(&capture).unwrap();
        v["captured"]["stderr"]["reached_eof"] = false.into();
        let bad = serde_json::to_vec(&v).unwrap();
        assert!(inspect_complete(&bad).is_err());
        assert!(diagnostic_excerpt(&bad).is_err());
        v["captured"]["stderr"]["reached_eof"] = true.into();
        v["captured"]["stdout"]["observed_sha256"] = "forged".into();
        assert!(inspect_complete(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    #[test]
    fn full_stream_requires_eof_exact_size_and_all_byte_hash() {
        let data = b"complete output";
        let b64 = STANDARD.encode(data);
        let hash = hex::encode(Sha256::digest(data));
        let mut s = Stream {
            bytes_base64: &b64,
            observed_bytes: data.len() as u64,
            reached_eof: true,
            output_limit_exceeded: false,
            observed_sha256: &hash,
        };
        assert!(s.complete());
        s.observed_bytes += 1;
        assert!(!s.complete());
        s.observed_bytes -= 1;
        s.reached_eof = false;
        assert!(!s.complete());
        s.reached_eof = true;
        s.output_limit_exceeded = true;
        assert!(!s.complete());
    }
    #[test]
    fn null_or_missing_or_duplicate_capture_members_are_not_full_payload() {
        for b in [
            br#"{"schema":null,"captured":null}"#.as_slice(),
            br#"{"schema":"a","schema":"b"}"#,
        ] {
            assert!(serde_json::from_slice::<Isolated<'_>>(b).is_err())
        }
    }

    #[test]
    fn completed_failures_require_matching_observed_os_exit_not_failure_text() {
        let mut exit = Exit {
            code: Some(0),
            signal: None,
            observed_before_capture_failure: true,
        };
        let green = VerifiedCapture {
            outcome: completed_outcome(&Outcome::Exited { code: 0 }, Some(&exit)).unwrap(),
        };
        assert!(!green.failed());
        assert_eq!(green.outcome(), CompletedOutcome::Exited { code: 0 });
        exit.code = Some(101);
        let red = VerifiedCapture {
            outcome: completed_outcome(&Outcome::Exited { code: 101 }, Some(&exit)).unwrap(),
        };
        assert!(red.failed());
        assert!(completed_outcome(&Outcome::Exited { code: 0 }, Some(&exit)).is_none());
        assert!(completed_outcome(&Outcome::Exited { code: 101 }, None).is_none());
        exit.observed_before_capture_failure = false;
        assert!(completed_outcome(&Outcome::Exited { code: 101 }, Some(&exit)).is_none());
        exit.observed_before_capture_failure = true;
        exit.code = None;
        exit.signal = Some(15);
        let signaled = VerifiedCapture {
            outcome: completed_outcome(&Outcome::Signaled { signal: Some(15) }, Some(&exit))
                .unwrap(),
        };
        assert!(signaled.failed());
        assert!(completed_outcome(&Outcome::Signaled { signal: None }, Some(&exit)).is_none());
        assert!(
            completed_outcome(
                &Outcome::DeadlineExceeded { child_reaped: true },
                Some(&exit)
            )
            .is_none()
        );
    }
}
