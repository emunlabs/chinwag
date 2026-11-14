// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! `chinwag-ci` zero-source blind Slack beat emitter (`CHWG-0253.04`).

pub mod emitter;
pub mod outbox;
pub mod projection;

pub use emitter::{
    CiBlindSlackEmitter, CiRelayEndpointConfig, PEER_ATTESTATION_DOMAIN, PeerBeatAttestation,
    WrappedCiRunReport, sign_peer_beat_attestation, verify_peer_attestations,
};
pub use outbox::{CiOutboxEntry, CiSlackOutbox};
pub use projection::{CiBeatContext, CiTransitionSpec, project_ci_blind_beat};

#[cfg(test)]
mod tests {
    use super::*;
    use chinwag_slack_contract::{
        AuthorizationRef, CiProviderV1, CiRemediationStepV1, Digest32, Ed25519KeyPairSigner,
        EventId, OpaqueOperationId, OpaqueOrgId, OpaqueRef, PolicyHoldStepV1, QueueStatusV1,
        SceneProgressV1, VerificationPolicyV1, decode_and_verify_signed_beat_bytes,
        sign_blind_slack_beat,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tempfile::TempDir;
    use tokio::process::Command;

    fn sample_ci_emitter(
        outbox_dir: &std::path::Path,
        endpoint: Option<CiRelayEndpointConfig>,
    ) -> CiBlindSlackEmitter {
        let seed = *blake3::hash(b"TEST_ONLY:CI_RUNNER_K1").as_bytes();
        let signer = Ed25519KeyPairSigner::from_seed_bytes(&seed);
        let ctx = CiBeatContext {
            org_id: OpaqueOrgId::parse("org_01JCISLACK").unwrap(),
            operation_id: OpaqueOperationId::parse("op_ci_418").unwrap(),
            provider: CiProviderV1::GithubActions,
            runner_lease_ref: OpaqueRef::parse("lease_gha_418").unwrap(),
            run_ref: OpaqueRef::parse("run_418").unwrap(),
            shard_ref: Some(OpaqueRef::parse("shard_01").unwrap()),
            authorization_ref: AuthorizationRef::parse("auth_ci_01").unwrap(),
            k1_key_id: signer.public_fingerprint(),
        };
        let outbox = CiSlackOutbox::open(outbox_dir).unwrap();
        CiBlindSlackEmitter::new(ctx, signer, outbox, endpoint)
    }

    #[tokio::test]
    async fn preserves_wrapped_exit_code_101_while_offline_and_never_leaks_stdout_or_diffs() {
        let tmp = TempDir::new().unwrap();
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);

        let outbox_dir = tmp.path().join("ci_outbox");
        let emitter = sample_ci_emitter(
            &outbox_dir,
            Some(CiRelayEndpointConfig {
                endpoint_url: format!("http://127.0.0.1:{port}/v1/slack/beats"),
                allow_loopback_http: true,
                timeout_ms: 250,
            }),
        );

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("echo '@@ -1,2 +1,2 @@ PROPRIETARY_SOURCE_LINE'; echo 'panicked at jwt.rs:142' >&2; exit 101");

        let report = emitter.run_wrapped_command(cmd, 148, 6).await.unwrap();
        assert_eq!(report.wrapped_exit_code, 101);
        assert_eq!(report.emitted_event_ids.len(), 2);
        assert_eq!(report.pending_unacked_beats, 2);

        // Inspect persisted SQLite DB + WAL bytes on disk: ZERO proprietary source/stderr strings!
        for entry in std::fs::read_dir(&outbox_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let raw_bytes = std::fs::read(&path).unwrap();
                let lossy = String::from_utf8_lossy(&raw_bytes);
                assert!(!lossy.contains("PROPRIETARY_SOURCE_LINE"));
                assert!(!lossy.contains("panicked at jwt.rs:142"));
            }
        }

        let entries = emitter.outbox().pending_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].signed_beat.beat.progress,
            SceneProgressV1::CiRemediation {
                step: CiRemediationStepV1::Building
            }
        );
        assert_eq!(
            entries[1].signed_beat.beat.progress,
            SceneProgressV1::CiRemediation {
                step: CiRemediationStepV1::Failed
            }
        );
    }

    #[tokio::test]
    async fn scrubs_wp04_policy_hold_zero_bytes_kept_and_verifies_cryptographic_peer_attestations()
    {
        let tmp = TempDir::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let wire_payloads: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let wire_clone = Arc::clone(&wire_payloads);

        let server = thread::spawn(move || {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut raw = Vec::new();
                let mut chunk = [0u8; 4096];
                let mut expected_total = None;
                loop {
                    let n = stream.read(&mut chunk).unwrap();
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&chunk[..n]);
                    if expected_total.is_none()
                        && let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n")
                    {
                        let hdr_str = String::from_utf8_lossy(&raw[..hdr_end]);
                        let content_len = hdr_str
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.trim()
                                    .eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        expected_total = Some(hdr_end + 4 + content_len);
                    }
                    if let Some(tot) = expected_total
                        && raw.len() >= tot
                    {
                        let hdr_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                        wire_clone
                            .lock()
                            .unwrap()
                            .push(raw[hdr_end + 4..tot].to_vec());
                        break;
                    }
                }
                stream
                    .write_all(
                        b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    )
                    .unwrap();
            }
        });

        let emitter = sample_ci_emitter(
            &tmp.path().join("ci_live_outbox"),
            Some(CiRelayEndpointConfig {
                endpoint_url: format!("http://127.0.0.1:{port}/v1/slack/beats"),
                allow_loopback_http: true,
                timeout_ms: 1_000,
            }),
        );

        let mut sensitive_buf = b"SENSITIVE_PLAINTEXT_ARTIFACT_TO_SCRUB".to_vec();
        let (held_id, scrub_id) = emitter
            .emit_wp04_hold_and_scrub(&mut sensitive_buf, 78, 1)
            .unwrap();
        assert!(sensitive_buf.is_empty());
        assert!(!held_id.is_empty() && !scrub_id.is_empty());

        let cand_digest = Digest32::from_bytes(*blake3::hash(b"cand_4d8e91b").as_bytes());

        // Self-attestation with the runner's own K1 key MUST fail closed!
        let self_signer = Ed25519KeyPairSigner::from_seed_bytes(
            blake3::hash(b"TEST_ONLY:CI_RUNNER_K1").as_bytes(),
        );
        let self_att = sign_peer_beat_attestation(&self_signer, &cand_digest);
        assert!(
            emitter
                .emit_candidate_verified_and_green(
                    cand_digest.clone(),
                    &[self_att],
                    148,
                    6,
                    19_400,
                    18,
                    50
                )
                .is_err()
        );

        // Genuine independent QA peer Ed25519 signature produces verified attestation_count == 2!
        let qa_peer = Ed25519KeyPairSigner::from_seed_bytes(
            blake3::hash(b"TEST_ONLY:QA_VERIFIER_PEER").as_bytes(),
        );
        let peer_att = sign_peer_beat_attestation(&qa_peer, &cand_digest);

        let (ver_id, green_id) = emitter
            .emit_candidate_verified_and_green(cand_digest, &[peer_att], 148, 6, 19_400, 18, 50)
            .unwrap();
        assert!(!ver_id.is_empty() && !green_id.is_empty());

        server.join().unwrap();
        assert_eq!(emitter.outbox().pending_entries().unwrap().len(), 0);

        let received = wire_payloads.lock().unwrap();
        assert_eq!(received.len(), 4);
        let policy = VerificationPolicyV1::default();

        let (b0, _) = decode_and_verify_signed_beat_bytes(&received[0], &policy).unwrap();
        assert_eq!(
            b0.beat.progress,
            SceneProgressV1::PolicyHold {
                step: PolicyHoldStepV1::Held
            }
        );
        assert_eq!(b0.beat.evidence.plaintext_source_bytes, 0);
        assert_eq!(b0.beat.evidence.ed25519_attestation_count, 1);
        assert_eq!(
            b0.beat.evidence.policy_gate_id.as_ref().unwrap().as_str(),
            "WP-04"
        );

        let (b3, _) = decode_and_verify_signed_beat_bytes(&received[3], &policy).unwrap();
        assert_eq!(
            b3.beat.progress,
            SceneProgressV1::CiRemediation {
                step: CiRemediationStepV1::Passed
            }
        );
        assert_eq!(b3.beat.evidence.ed25519_attestation_count, 2);
        if let chinwag_slack_contract::SlackMetadataV1::StrictZk { summary } = &b3.beat.metadata {
            assert_eq!(summary.queue_status, QueueStatusV1::TerminalGreen);
            assert_eq!(summary.credits_charged.get(), 50);
        } else {
            panic!("expected strict_zk default on CI emitter");
        }
    }

    #[tokio::test]
    async fn concurrently_drains_large_stdout_and_stderr_without_deadlock_and_concurrent_sqlite_outbox()
     {
        let tmp = TempDir::new().unwrap();
        let emitter = sample_ci_emitter(&tmp.path().join("heavy_pipes"), None);

        // Emit 256 KiB to stderr AND 256 KiB to stdout simultaneously — sequential pipe read would deadlock OS pipe buffers!
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(
            "dd if=/dev/zero bs=4096 count=64 2>/dev/null >&2 & \
             dd if=/dev/zero bs=4096 count=64 2>/dev/null; \
             wait; exit 101",
        );

        let report = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            emitter.run_wrapped_command(cmd, 64, 4),
        )
        .await
        .expect("concurrent pipe drain must never deadlock")
        .unwrap();
        assert_eq!(report.wrapped_exit_code, 101);
        let entries = emitter.outbox().all_entries().unwrap();
        // Without peer attestations, single-signer beats strictly report ed25519_attestation_count == 1!
        assert_eq!(
            entries[1]
                .signed_beat
                .beat
                .evidence
                .ed25519_attestation_count,
            1
        );

        // Concurrent multi-thread SQLite WAL outbox durability: 8 threads x 5 beats = 40 beats, 0 lost!
        let shared_dir = tmp.path().join("shared_wal_outbox");
        let _ = CiSlackOutbox::open(&shared_dir).unwrap();
        let mut handles = Vec::new();
        for t in 0..8u32 {
            let dir_clone = shared_dir.clone();
            handles.push(thread::spawn(move || {
                let outbox = CiSlackOutbox::open(&dir_clone).unwrap();
                let seed = *blake3::hash(format!("TEST_SHARD_{t}").as_bytes()).as_bytes();
                let signer = Ed25519KeyPairSigner::from_seed_bytes(&seed);
                let ctx = CiBeatContext {
                    org_id: OpaqueOrgId::parse("org_01JWALCONC").unwrap(),
                    operation_id: OpaqueOperationId::parse(format!("op_shard_{t}")).unwrap(),
                    provider: CiProviderV1::GithubActions,
                    runner_lease_ref: OpaqueRef::parse("lease_conc_01").unwrap(),
                    run_ref: OpaqueRef::parse("run_conc_01").unwrap(),
                    shard_ref: Some(OpaqueRef::parse(format!("shard_{t}")).unwrap()),
                    authorization_ref: AuthorizationRef::parse("auth_conc_01").unwrap(),
                    k1_key_id: signer.public_fingerprint(),
                };
                for idx in 0..5u64 {
                    let ev = EventId::parse(format!("ev_t{t}_b{idx}")).unwrap();
                    let beat = project_ci_blind_beat(
                        &ctx,
                        CiTransitionSpec {
                            event_id: ev,
                            sequence: idx + 1,
                            occurred_at_ms: 1_794_400_000_000 + idx,
                            progress: SceneProgressV1::CiRemediation {
                                step: CiRemediationStepV1::Building,
                            },
                            queue_status: QueueStatusV1::Active,
                            cwcard_digest: Digest32::from_bytes(
                                *blake3::hash(format!("dig_{t}_{idx}").as_bytes()).as_bytes(),
                            ),
                            policy_gate_id: None,
                            attestation_count: 1,
                            specs_passed: 0,
                            specs_total: 10,
                            gates_passed: 0,
                            gates_total: 4,
                            loc_added: 0,
                            loc_removed: 0,
                            command_exit_code: None,
                            duration_ms: 100,
                            est_minutes_saved: 0,
                            credits_charged: 0,
                        },
                    )
                    .unwrap();
                    let (dig, signed) = sign_blind_slack_beat(&signer, beat).unwrap();
                    outbox.enqueue(signed, &dig).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let final_outbox = CiSlackOutbox::open(&shared_dir).unwrap();
        assert_eq!(final_outbox.all_entries().unwrap().len(), 40);
    }
}
