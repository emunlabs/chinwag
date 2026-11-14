// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Real-boundary CI blind emitter (`CHWG-0253.04`).
//! Concurrently drains subprocess `stdout` and `stderr` via bounded `8 KiB` `Zeroizing` chunks
//! into streaming `BLAKE3` digests (zero pipe deadlock, zero unbounded memory, zero plaintext
//! retained), preserves the wrapped subprocess exit code (`0`, `101`, etc.) unconditionally even
//! if Relay/Slack is offline, scrubs sensitive buffers (`0 bytes kept`) on `WP-04` policy holds,
//! and derives `ed25519_attestation_count` strictly from cryptographically verified peer signers.

use crate::slack::outbox::CiSlackOutbox;
use crate::slack::projection::{
    CiBeatContext, CiTransitionSpec, ci_build_progress, ci_failed_progress, ci_passed_progress,
    ci_verifying_candidate_progress, ci_wp04_held_progress, ci_wp04_scrub_packaging_progress,
    project_ci_blind_beat,
};
use chinwag_slack_contract::{
    ApprovedHttpsUrl, Digest32, Ed25519KeyPairSigner, EventId, KeyFingerprint, OpaqueRef,
    QueueStatusV1, SceneProgressV1, Signature64, sign_blind_slack_beat, to_jcs_bytes,
    verify_ed25519_strict,
};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

pub const PEER_ATTESTATION_DOMAIN: &[u8] = b"chinwag.ci.peer_attestation.v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerBeatAttestation {
    pub signer_pubkey: KeyFingerprint,
    pub signature: Signature64,
}

#[must_use]
pub fn sign_peer_beat_attestation(
    peer_signer: &Ed25519KeyPairSigner,
    cwcard_digest: &Digest32,
) -> PeerBeatAttestation {
    let mut signing_input = Vec::with_capacity(PEER_ATTESTATION_DOMAIN.len() + 32);
    signing_input.extend_from_slice(PEER_ATTESTATION_DOMAIN);
    signing_input.extend_from_slice(cwcard_digest.as_bytes());
    PeerBeatAttestation {
        signer_pubkey: peer_signer.public_fingerprint(),
        signature: peer_signer.sign_raw_domain_payload(&signing_input),
    }
}

pub fn verify_peer_attestations(
    primary_k1: &KeyFingerprint,
    cwcard_digest: &Digest32,
    peer_attestations: &[PeerBeatAttestation],
) -> Result<u8, String> {
    let mut seen_keys = BTreeSet::new();
    let mut signing_input = Vec::with_capacity(PEER_ATTESTATION_DOMAIN.len() + 32);
    signing_input.extend_from_slice(PEER_ATTESTATION_DOMAIN);
    signing_input.extend_from_slice(cwcard_digest.as_bytes());

    for peer in peer_attestations {
        if peer.signer_pubkey == *primary_k1 {
            return Err("peer attestation cannot reuse primary K1 runner key".to_owned());
        }
        let key_str = peer.signer_pubkey.to_prefixed_string();
        if !seen_keys.insert(key_str) {
            return Err("duplicate peer attestation signer key rejected".to_owned());
        }
        verify_ed25519_strict(&peer.signer_pubkey, &signing_input, &peer.signature)
            .map_err(|e| format!("invalid peer attestation signature: {e}"))?;
    }

    let peer_count = u8::try_from(peer_attestations.len())
        .map_err(|_| "peer attestation count exceeds u8 ceiling".to_owned())?;
    1u8.checked_add(peer_count)
        .ok_or_else(|| "attestation count overflow".to_owned())
}

#[derive(Clone, Debug)]
pub struct CiRelayEndpointConfig {
    pub endpoint_url: String,
    pub allow_loopback_http: bool,
    pub timeout_ms: u64,
}

pub struct CiBlindSlackEmitter {
    ctx: CiBeatContext,
    k1_signer: Ed25519KeyPairSigner,
    outbox: CiSlackOutbox,
    endpoint: Option<CiRelayEndpointConfig>,
    sequence: AtomicU64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedCiRunReport {
    pub wrapped_exit_code: i32,
    pub captured_output_digest: Digest32,
    pub emitted_event_ids: Vec<String>,
    pub pending_unacked_beats: usize,
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

async fn drain_pipe_blind<R: AsyncRead + Unpin>(
    pipe: Option<R>,
    stream_domain: &'static [u8],
) -> std::io::Result<Digest32> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(stream_domain);
    if let Some(mut reader) = pipe {
        let mut chunk = Zeroizing::new([0u8; 8192]);
        loop {
            let n = reader.read(&mut *chunk).await?;
            if n == 0 {
                break;
            }
            hasher.update(&chunk[..n]);
            chunk[..n].zeroize();
        }
    }
    let digest_bytes = *hasher.finalize().as_bytes();
    // Overwrite BLAKE3's internal 1 KiB chunk state with zeros so zero residual subprocess plaintext remains
    hasher.reset();
    hasher.update(&[0u8; 1024]);
    hasher.reset();
    Ok(Digest32::from_bytes(digest_bytes))
}

impl CiBlindSlackEmitter {
    pub fn new(
        ctx: CiBeatContext,
        k1_signer: Ed25519KeyPairSigner,
        outbox: CiSlackOutbox,
        endpoint: Option<CiRelayEndpointConfig>,
    ) -> Self {
        Self {
            ctx,
            k1_signer,
            outbox,
            endpoint,
            sequence: AtomicU64::new(0),
        }
    }

    fn next_seq_and_event_id(&self, tag: &str) -> Result<(u64, EventId), String> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let ev = EventId::parse(format!(
            "ev_{}_{}_{seq:02}",
            self.ctx.operation_id.as_str(),
            tag
        ))
        .map_err(|e| e.to_string())?;
        Ok((seq, ev))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn emit_transition(
        &self,
        tag: &str,
        progress: SceneProgressV1,
        queue_status: QueueStatusV1,
        cwcard_digest: Digest32,
        policy_gate_id: Option<OpaqueRef>,
        command_exit_code: Option<i32>,
        duration_ms: u64,
        specs_passed: u32,
        specs_total: u32,
        gates_passed: u8,
        gates_total: u8,
        est_minutes_saved: u32,
        credits_charged: u64,
    ) -> Result<String, String> {
        self.emit_transition_with_peers(
            tag,
            progress,
            queue_status,
            cwcard_digest,
            &[],
            policy_gate_id,
            command_exit_code,
            duration_ms,
            specs_passed,
            specs_total,
            gates_passed,
            gates_total,
            est_minutes_saved,
            credits_charged,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn emit_transition_with_peers(
        &self,
        tag: &str,
        progress: SceneProgressV1,
        queue_status: QueueStatusV1,
        cwcard_digest: Digest32,
        peer_attestations: &[PeerBeatAttestation],
        policy_gate_id: Option<OpaqueRef>,
        command_exit_code: Option<i32>,
        duration_ms: u64,
        specs_passed: u32,
        specs_total: u32,
        gates_passed: u8,
        gates_total: u8,
        est_minutes_saved: u32,
        credits_charged: u64,
    ) -> Result<String, String> {
        let attestation_count =
            verify_peer_attestations(&self.ctx.k1_key_id, &cwcard_digest, peer_attestations)?;
        let (seq, event_id) = self.next_seq_and_event_id(tag)?;
        let ev_str = event_id.as_str().to_owned();
        let beat = project_ci_blind_beat(
            &self.ctx,
            CiTransitionSpec {
                event_id,
                sequence: seq,
                occurred_at_ms: now_epoch_ms(),
                progress,
                queue_status,
                cwcard_digest,
                policy_gate_id,
                attestation_count,
                specs_passed,
                specs_total,
                gates_passed,
                gates_total,
                loc_added: 0,
                loc_removed: 0,
                command_exit_code,
                duration_ms,
                est_minutes_saved,
                credits_charged,
            },
        )?;

        let (digest, signed) =
            sign_blind_slack_beat(&self.k1_signer, beat).map_err(|e| e.to_string())?;
        self.outbox.enqueue(signed, &digest)?;
        // Best-effort flush; network failures NEVER bubble up as CI errors.
        let _ = self.flush_pending();
        Ok(ev_str)
    }

    /// Emits `WP-04` fail-closed policy hold + scrub beats and cryptographically zeroes `sensitive_buffer`
    /// in place (`0 bytes kept`).
    pub fn emit_wp04_hold_and_scrub(
        &self,
        sensitive_buffer: &mut Vec<u8>,
        exit_code: i32,
        duration_ms: u64,
    ) -> Result<(String, String), String> {
        let redacted_tag_digest =
            Digest32::from_bytes(*blake3::hash(b"wp04:scrubbed:0_bytes_kept").as_bytes());
        sensitive_buffer.zeroize();
        sensitive_buffer.clear();
        sensitive_buffer.shrink_to_fit();

        let wp04_gate = OpaqueRef::parse("WP-04").map_err(|e| e.to_string())?;
        let held_ev = self.emit_transition(
            "wp04_held",
            ci_wp04_held_progress(),
            QueueStatusV1::PolicyHoldFailClosed,
            redacted_tag_digest.clone(),
            Some(wp04_gate.clone()),
            Some(exit_code),
            duration_ms,
            0,
            1,
            5,
            6,
            0,
            0,
        )?;
        let scrub_ev = self.emit_transition(
            "wp04_scrub",
            ci_wp04_scrub_packaging_progress(),
            QueueStatusV1::PolicyHoldFailClosed,
            redacted_tag_digest,
            Some(wp04_gate),
            Some(exit_code),
            duration_ms,
            0,
            1,
            5,
            6,
            0,
            0,
        )?;
        Ok((held_ev, scrub_ev))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn emit_candidate_verified_and_green(
        &self,
        cwcard_digest: Digest32,
        peer_attestations: &[PeerBeatAttestation],
        specs_total: u32,
        gates_total: u8,
        duration_ms: u64,
        est_minutes_saved: u32,
        credits_charged: u64,
    ) -> Result<(String, String), String> {
        // Validate peer signatures upfront before emitting either transition
        let _ = verify_peer_attestations(&self.ctx.k1_key_id, &cwcard_digest, peer_attestations)?;

        let verify_ev = self.emit_transition_with_peers(
            "verify_cand",
            ci_verifying_candidate_progress(),
            QueueStatusV1::Active,
            cwcard_digest.clone(),
            &[],
            None,
            None,
            duration_ms,
            specs_total,
            specs_total,
            gates_total,
            gates_total,
            0,
            0,
        )?;
        let green_ev = self.emit_transition_with_peers(
            "green",
            ci_passed_progress(),
            QueueStatusV1::TerminalGreen,
            cwcard_digest,
            peer_attestations,
            None,
            Some(0),
            duration_ms,
            specs_total,
            specs_total,
            gates_total,
            gates_total,
            est_minutes_saved,
            credits_charged,
        )?;
        Ok((verify_ev, green_ev))
    }

    /// Executes `command`, drains `stdout` and `stderr` **concurrently** via `8 KiB` `Zeroizing` chunks
    /// into streaming `BLAKE3` digests (preventing pipe buffer deadlock and unbounded RAM growth),
    /// emits `Building` + (`Passed` or `Failed(exit_code)`), and ALWAYS preserves the wrapped command's
    /// exact exit code even if Relay/Slack is completely unreachable.
    pub async fn run_wrapped_command(
        &self,
        mut command: Command,
        specs_total: u32,
        gates_total: u8,
    ) -> Result<WrappedCiRunReport, std::io::Error> {
        let started = Instant::now();
        let initial_digest = Digest32::from_bytes(
            *blake3::hash(format!("build_start:{}", self.ctx.operation_id.as_str()).as_bytes())
                .as_bytes(),
        );
        let mut emitted = Vec::new();
        if let Ok(ev) = self.emit_transition(
            "building",
            ci_build_progress(),
            QueueStatusV1::Active,
            initial_digest,
            None,
            None,
            0,
            0,
            specs_total.max(1),
            0,
            gates_total.max(1),
            0,
            0,
        ) {
            emitted.push(ev);
        }

        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let mut child = command.spawn()?;

        let out_pipe = child.stdout.take();
        let err_pipe = child.stderr.take();
        let (out_res, err_res, wait_res) = tokio::join!(
            drain_pipe_blind(out_pipe, b"chinwag.ci.stdout.v1\0"),
            drain_pipe_blind(err_pipe, b"chinwag.ci.stderr.v1\0"),
            child.wait(),
        );
        let out_digest = out_res?;
        let err_digest = err_res?;
        let status = wait_res?;
        let wrapped_exit_code = status.code().unwrap_or(1);
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        let mut witness_hasher = blake3::Hasher::new();
        witness_hasher.update(b"chinwag.ci.sealed_cwcard_witness.v1\0");
        witness_hasher.update(out_digest.as_bytes());
        witness_hasher.update(err_digest.as_bytes());
        let captured_output_digest = Digest32::from_bytes(*witness_hasher.finalize().as_bytes());

        let boundary_res = if wrapped_exit_code == 0 {
            self.emit_transition(
                "passed",
                ci_passed_progress(),
                QueueStatusV1::TerminalGreen,
                captured_output_digest.clone(),
                None,
                Some(0),
                elapsed_ms,
                specs_total.max(1),
                specs_total.max(1),
                gates_total.max(1),
                gates_total.max(1),
                0,
                0,
            )
        } else {
            self.emit_transition(
                "failed",
                ci_failed_progress(),
                QueueStatusV1::Active,
                captured_output_digest.clone(),
                None,
                Some(wrapped_exit_code),
                elapsed_ms,
                0,
                specs_total.max(1),
                0,
                gates_total.max(1),
                0,
                0,
            )
        };
        if let Ok(ev) = boundary_res {
            emitted.push(ev);
        }

        let pending_unacked_beats = self.outbox.pending_entries().map_or(0, |v| v.len());
        Ok(WrappedCiRunReport {
            wrapped_exit_code,
            captured_output_digest,
            emitted_event_ids: emitted,
            pending_unacked_beats,
        })
    }

    pub fn flush_pending(&self) -> Result<usize, String> {
        let Some(cfg) = &self.endpoint else {
            return Ok(0);
        };
        let pending = self.outbox.pending_entries()?;
        let mut acked = 0usize;
        for entry in pending {
            let jcs = to_jcs_bytes(&entry.signed_beat).map_err(|e| e.to_string())?;
            match post_beat_bytes(cfg, &entry.event_id, &jcs) {
                Ok(200..=299) => {
                    self.outbox.mark_acked(&entry.event_id)?;
                    acked += 1;
                }
                Ok(status) => {
                    self.outbox
                        .mark_failed_attempt(&entry.event_id, &format!("HTTP {status}"))?;
                }
                Err(err) => {
                    self.outbox.mark_failed_attempt(&entry.event_id, &err)?;
                }
            }
        }
        Ok(acked)
    }

    #[must_use]
    pub fn outbox(&self) -> &CiSlackOutbox {
        &self.outbox
    }
}

fn post_beat_bytes(
    cfg: &CiRelayEndpointConfig,
    idempotency_key: &str,
    body: &[u8],
) -> Result<u16, String> {
    let parsed = Url::parse(&cfg.endpoint_url).map_err(|e| e.to_string())?;
    match parsed.scheme() {
        "https" => {
            let _ = ApprovedHttpsUrl::parse(&cfg.endpoint_url).map_err(|e| e.to_string())?;
            post_https_curl(&cfg.endpoint_url, idempotency_key, body, cfg.timeout_ms)
        }
        "http" if cfg.allow_loopback_http => {
            let host = parsed.host_str().unwrap_or("");
            if host != "127.0.0.1" && host != "localhost" && host != "::1" {
                return Err("plain HTTP only allowed on loopback".to_owned());
            }
            let port = parsed.port_or_known_default().unwrap_or(80);
            let addr: SocketAddr = format!("127.0.0.1:{port}")
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?;
            let timeout = Duration::from_millis(cfg.timeout_ms.max(150));
            let mut stream =
                TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            let req = format!(
                "POST {} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nIdempotency-Key: {idempotency_key}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                parsed.path(),
                body.len()
            );
            let mut full_req = Vec::with_capacity(req.len() + body.len());
            full_req.extend_from_slice(req.as_bytes());
            full_req.extend_from_slice(body);
            stream
                .write_all(&full_req)
                .and_then(|()| stream.flush())
                .map_err(|e| e.to_string())?;
            let mut resp = Vec::with_capacity(256);
            stream
                .take(16_384)
                .read_to_end(&mut resp)
                .map_err(|e| e.to_string())?;
            let text = String::from_utf8_lossy(&resp);
            let first = text
                .lines()
                .next()
                .ok_or_else(|| "empty response".to_owned())?;
            first
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse::<u16>().ok())
                .ok_or_else(|| format!("invalid HTTP status: {first}"))
        }
        _ => Err("HTTPS endpoint required".to_owned()),
    }
}

fn post_https_curl(
    endpoint_url: &str,
    idempotency_key: &str,
    body: &[u8],
    timeout_ms: u64,
) -> Result<u16, String> {
    let max_secs = (timeout_ms.div_ceil(1_000)).max(1).to_string();
    let mut child = std::process::Command::new("/usr/bin/curl")
        .args([
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            &max_secs,
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            &format!("Idempotency-Key: {idempotency_key}"),
            "--data-binary",
            "@-",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            endpoint_url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(body).map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u16>()
        .map_err(|e| e.to_string())
}
