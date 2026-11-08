// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Strict full-payload validation after authorized decryption. These software
//! observations remain untrusted evidence and grant no command/repair authority.
use crate::{
    authorization::AdmissionBoundEnvelope, profile::CommandProfile, runtime::RuntimeError,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
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
pub(crate) fn validate(
    bytes: &[u8],
    e: &AdmissionBoundEnvelope,
    profile: &CommandProfile,
) -> Result<(), RuntimeError> {
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
    let valid_outcome = match (&c.outcome, &c.observed_child_exit) {
        (Outcome::Exited { code }, Some(exit)) => {
            exit.code == Some(*code)
                && exit.signal.is_none()
                && exit.observed_before_capture_failure
        }
        (Outcome::Signaled { signal }, Some(exit)) => {
            *signal == exit.signal && exit.code.is_none() && exit.observed_before_capture_failure
        }
        (Outcome::DeadlineExceeded { child_reaped }, _) => {
            let _ = child_reaped;
            false
        }
        (
            Outcome::CaptureIoFailed {
                child_reaped,
                operation,
                io_error_kind,
            },
            _,
        ) => {
            let _ = (child_reaped, operation, io_error_kind);
            false
        }
        _ => false,
    };
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
        || !valid_outcome
        || !timing
        || !closed
        || !c.stdout.complete()
        || !c.stderr.complete()
    {
        return Err(RuntimeError);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
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
}
