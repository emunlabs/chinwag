// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! `chinwag slack` CLI surface, browser-assisted `K1` workspace binding, durable SQLite outbox,
//! and post-first-verified-function CLI expansion nudge (`CHWG-0253.03`).

pub mod authorization;
pub mod commands;
pub mod emitter;
pub mod outbox;
pub mod projection;

use std::io::Write;

/// Deterministic CLI exit codes per `CHWG-0253.03` contract (`0..=6`).
pub const EXIT_OK: u8 = 0;
pub const EXIT_INVALID_ARGS_OR_ARGV_SECRET: u8 = 2;
pub const EXIT_NOT_CONNECTED: u8 = 3;
pub const EXIT_AUTH_PENDING: u8 = 4;
pub const EXIT_AUTH_DENIED_OR_REVOKED: u8 = 5;
pub const EXIT_TEMP_UNAVAILABLE_QUEUED: u8 = 6;

pub fn run_slack_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    commands::dispatch_slack_command(args, stdout, stderr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slack::authorization::{
        ConnectBindingGrantV1, K1_CONNECT_EXCHANGE_DOMAIN, RequestedMetadataMode,
        SignedConnectExchangeRequestV1, SlackBindingState, load_binding_state, pkce_s256_challenge,
        sign_connect_binding_grant,
    };
    use crate::slack::outbox::SqliteSlackOutbox;
    use crate::slack::projection::maybe_format_post_verify_slack_nudge;
    use chinwag_slack_contract::{
        AuthorizationRef, CanonicalU64, Ed25519KeyPairSigner, OpaqueOrgId, OpaqueRef,
        QueueStatusV1, SCHEMA_VERSION_V1, VerificationPolicyV1,
        decode_and_verify_signed_beat_bytes, domain_separated_jcs_signing_input, to_jcs_bytes,
        verify_ed25519_strict,
    };
    use std::io::Read;
    use std::net::TcpListener;
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tempfile::TempDir;

    fn run_args(state_dir: &std::path::Path, args: &[&str]) -> (u8, String, String) {
        let mut full: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        full.push(format!("--state-dir={}", state_dir.display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_slack_cli(&full, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn enforces_zero_argv_secrets_rog580_and_rejects_symlinks() {
        let tmp = TempDir::new().unwrap();
        // 1. --token flag in argv -> exit 2 without echoing secret
        let fake_tok = ["xoxb", "111122223333", "fakeSecretTokenValue"].join("-");
        let (code, stdout, stderr) = run_args(tmp.path(), &["connect", "--token", &fake_tok]);
        assert_eq!(code, EXIT_INVALID_ARGS_OR_ARGV_SECRET);
        assert!(!stdout.contains(&fake_tok));
        assert!(!stderr.contains(&fake_tok));

        // 2. Positional secret prefix -> exit 2
        let fake_chwg = ["chwg", "liveSecret998877665544"].join("_");
        let (code2, _, stderr2) = run_args(tmp.path(), &["status", &fake_chwg]);
        assert_eq!(code2, EXIT_INVALID_ARGS_OR_ARGV_SECRET);
        assert!(!stderr2.contains(&fake_chwg));

        // 3. Insecure 0755 directory is rejected fail-closed
        let insecure_dir = tmp.path().join("slack_insecure_0755");
        std::fs::create_dir_all(&insecure_dir).unwrap();
        std::fs::set_permissions(
            &insecure_dir,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .unwrap();
        let (code_insec, _, _) = run_args(&insecure_dir, &["status"]);
        assert_eq!(code_insec, EXIT_INVALID_ARGS_OR_ARGV_SECRET);

        // 4. Symlinked state file inside a 0700 directory is rejected fail-closed
        let evil_target = tmp.path().join("outside.json");
        std::fs::write(&evil_target, b"{}").unwrap();
        let state_sub = tmp.path().join("slack_state");
        std::fs::create_dir_all(&state_sub).unwrap();
        std::fs::set_permissions(
            &state_sub,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        symlink(&evil_target, state_sub.join("slack_binding.json")).unwrap();
        let (code3, _, _) = run_args(&state_sub, &["status"]);
        assert_eq!(code3, EXIT_INVALID_ARGS_OR_ARGV_SECRET);
    }

    fn read_single_http_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
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
                let headers = String::from_utf8_lossy(&raw[..hdr_end]).into_owned();
                return (headers, raw[hdr_end + 4..tot].to_vec());
            }
        }
        panic!("incomplete HTTP request on loopback socket");
    }

    #[test]
    fn walks_exit_codes_0_3_4_5_6_pkce_k2_exchange_and_durable_sqlite_outbox_recovery() {
        let tmp = TempDir::new().unwrap();
        let state_dir = tmp.path().join("slack");

        // Initially not connected -> exit 3
        let (c_not_conn, _, _) = run_args(&state_dir, &["status", "--json"]);
        assert_eq!(c_not_conn, EXIT_NOT_CONNECTED);

        // Missing --org fails closed -> exit 2 (zero hardcoded org_default!)
        let (c_missing_org, _, _) = run_args(&state_dir, &["connect", "--json"]);
        assert_eq!(c_missing_org, EXIT_INVALID_ARGS_OR_ARGV_SECRET);

        // Spin up loopback Coordinator for PKCE + K1 -> K2 connect exchange
        let coord_k2 = Ed25519KeyPairSigner::from_seed_bytes(
            blake3::hash(b"TEST_ONLY:COORDINATOR_K2_CONNECT").as_bytes(),
        );
        let coord_k2_pub = coord_k2.public_fingerprint().to_prefixed_string();
        let rogue_k2 = Ed25519KeyPairSigner::from_seed_bytes(
            blake3::hash(b"TEST_ONLY:ROGUE_K2_CONNECT").as_bytes(),
        );
        let rogue_k2_pub = rogue_k2.public_fingerprint().to_prefixed_string();

        let connect_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let connect_port = connect_listener.local_addr().unwrap().port();
        let connect_origin = format!("http://127.0.0.1:{connect_port}");

        // Initiate browser-assisted OAuth handoff -> exit 4 (Pending) + writes 0600 PKCE verifier
        let (c_pending, out_pending, _) = run_args(
            &state_dir,
            &[
                "connect",
                "--org",
                "org_01JTESTSLACK",
                "--connect-origin",
                &connect_origin,
                "--allow-loopback-http",
                "--metadata-mode",
                "strict_zk",
                "--json",
            ],
        );
        assert_eq!(c_pending, EXIT_AUTH_PENDING);
        assert!(state_dir.join("slack_pkce_verifier.bin").exists());
        let pending_val: serde_json::Value = serde_json::from_str(&out_pending).unwrap();
        let challenge_id = pending_val["challenge_id"].as_str().unwrap().to_owned();
        let verification_url = pending_val["verification_url"].as_str().unwrap().to_owned();
        assert!(verification_url.starts_with(&format!("{connect_origin}/connect/slack/start?")));
        let expected_pkce_challenge = url::Url::parse(&verification_url)
            .unwrap()
            .query_pairs()
            .find_map(|(k, v)| (k == "pkce").then(|| v.into_owned()))
            .unwrap();

        // Status while pending -> exit 4
        let (c_stat_pend, _, _) = run_args(&state_dir, &["status", "--json"]);
        assert_eq!(c_stat_pend, EXIT_AUTH_PENDING);

        // Spawn Coordinator exchange handler that cryptographically checks K1 + PKCE S256 and signs with K2
        let expected_pkce_for_srv = expected_pkce_challenge.clone();
        let coord_srv = thread::spawn(move || {
            let (mut stream, _) = connect_listener.accept().unwrap();
            let (_headers, body) = read_single_http_request(&mut stream);
            let req: SignedConnectExchangeRequestV1 = serde_json::from_slice(&body).unwrap();
            let (_, k1_input) =
                domain_separated_jcs_signing_input(K1_CONNECT_EXCHANGE_DOMAIN, &req.payload)
                    .unwrap();
            verify_ed25519_strict(&req.payload.k1_key_id, &k1_input, &req.k1_signature).unwrap();
            assert_eq!(
                pkce_s256_challenge(&req.payload.pkce_code_verifier),
                expected_pkce_for_srv
            );

            let grant = ConnectBindingGrantV1 {
                schema_version: SCHEMA_VERSION_V1,
                challenge_id: req.payload.challenge_id,
                org_id: req.payload.org_id,
                team_id: OpaqueRef::parse("T01TENANTA1").unwrap(),
                installation_ref: OpaqueRef::parse("inst_vconnect_a1").unwrap(),
                authorization_ref: AuthorizationRef::parse("auth_bind_a1").unwrap(),
                k1_key_id: req.payload.k1_key_id,
                pkce_code_challenge: expected_pkce_for_srv,
                metadata_mode: RequestedMetadataMode::StrictZk,
                passkey_attestation: None,
                authorization_epoch: CanonicalU64::new(1),
                issued_at_ms: CanonicalU64::new(1_794_400_005_000),
            };
            let signed_grant = sign_connect_binding_grant(&coord_k2, grant).unwrap();
            let grant_bytes = to_jcs_bytes(&signed_grant).unwrap();
            let resp_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                grant_bytes.len()
            );
            let mut full = resp_head.into_bytes();
            full.extend_from_slice(&grant_bytes);
            stream.write_all(&full).unwrap();
        });

        // Complete browser challenge via real PKCE + K2 verification -> exit 0 (Connected) & scrubs PKCE file!
        let (c_conn, _, _) = run_args(
            &state_dir,
            &[
                "connect",
                "--complete-challenge",
                &challenge_id,
                "--callback-ref",
                "cb_01JTESTCALLBACK",
                "--coordinator-k2-pubkey",
                &coord_k2_pub,
                "--allow-loopback-http",
                "--json",
            ],
        );
        assert_eq!(c_conn, EXIT_OK);
        coord_srv.join().unwrap();
        assert!(
            !state_dir.join("slack_pkce_verifier.bin").exists(),
            "single-use PKCE code_verifier must be scrubbed and deleted on redemption"
        );

        // Also verify untrusted Coordinator K2 key is rejected fail-closed on a separate state_dir
        let rogue_dir = tmp.path().join("slack_rogue");
        let rogue_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let rogue_port = rogue_listener.local_addr().unwrap().port();
        let rogue_origin = format!("http://127.0.0.1:{rogue_port}");
        let (_, out_rogue_pend, _) = run_args(
            &rogue_dir,
            &[
                "connect",
                "--org",
                "org_01JROGUE",
                "--connect-origin",
                &rogue_origin,
                "--allow-loopback-http",
                "--json",
            ],
        );
        let rogue_ch =
            serde_json::from_str::<serde_json::Value>(&out_rogue_pend).unwrap()["challenge_id"]
                .as_str()
                .unwrap()
                .to_owned();
        let coord_k2_for_rogue = Ed25519KeyPairSigner::from_seed_bytes(
            blake3::hash(b"TEST_ONLY:COORDINATOR_K2_CONNECT").as_bytes(),
        );
        let rogue_srv = thread::spawn(move || {
            let (mut stream, _) = rogue_listener.accept().unwrap();
            let (_, body) = read_single_http_request(&mut stream);
            let req: SignedConnectExchangeRequestV1 = serde_json::from_slice(&body).unwrap();
            let pkce_ch = pkce_s256_challenge(&req.payload.pkce_code_verifier);
            let grant = ConnectBindingGrantV1 {
                schema_version: SCHEMA_VERSION_V1,
                challenge_id: req.payload.challenge_id,
                org_id: req.payload.org_id,
                team_id: OpaqueRef::parse("T01TENANTA1").unwrap(),
                installation_ref: OpaqueRef::parse("inst_vconnect_a1").unwrap(),
                authorization_ref: AuthorizationRef::parse("auth_bind_a1").unwrap(),
                k1_key_id: req.payload.k1_key_id,
                pkce_code_challenge: pkce_ch,
                metadata_mode: RequestedMetadataMode::StrictZk,
                passkey_attestation: None,
                authorization_epoch: CanonicalU64::new(1),
                issued_at_ms: CanonicalU64::new(1_794_400_005_000),
            };
            let signed_grant = sign_connect_binding_grant(&coord_k2_for_rogue, grant).unwrap();
            let grant_bytes = to_jcs_bytes(&signed_grant).unwrap();
            let mut full = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                grant_bytes.len()
            )
            .into_bytes();
            full.extend_from_slice(&grant_bytes);
            stream.write_all(&full).unwrap();
        });
        let (c_rogue_reject, _, _) = run_args(
            &rogue_dir,
            &[
                "connect",
                "--complete-challenge",
                &rogue_ch,
                "--callback-ref",
                "cb_01JROGUE",
                "--coordinator-k2-pubkey",
                &rogue_k2_pub,
                "--allow-loopback-http",
                "--json",
            ],
        );
        assert_eq!(c_rogue_reject, EXIT_AUTH_DENIED_OR_REVOKED);
        rogue_srv.join().unwrap();

        // Channel-map set / list / clear -> exit 0
        let (c_map_set, _, _) = run_args(
            &state_dir,
            &["channel-map", "set", "ci-builds", "C01CIBUILDS", "--json"],
        );
        assert_eq!(c_map_set, EXIT_OK);
        let (c_map_list, out_list, _) = run_args(&state_dir, &["channel-map", "list", "--json"]);
        assert_eq!(c_map_list, EXIT_OK);
        assert!(out_list.contains("C01CIBUILDS"));
        let (c_map_clr, _, _) =
            run_args(&state_dir, &["channel-map", "clear", "ci-builds", "--json"]);
        assert_eq!(c_map_clr, EXIT_OK);

        // Offline / unreachable port -> exit 6 AND beat + channel_override queued durably in SQLite outbox!
        let closed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let (c_offline, out_offline, _) = run_args(
            &state_dir,
            &[
                "test",
                "--channel",
                "C01OFFLINE1",
                "--endpoint",
                &format!("http://127.0.0.1:{closed_port}/v1/slack/beats"),
                "--allow-loopback-http",
                "--json",
            ],
        );
        assert_eq!(c_offline, EXIT_TEMP_UNAVAILABLE_QUEUED);
        let offline_val: serde_json::Value = serde_json::from_str(&out_offline).unwrap();
        assert_eq!(offline_val["pending_outbox_count"].as_u64(), Some(1));

        // Bring live loopback relay server online; next `test` flushes queued beat (preserving C01OFFLINE1!) + ACKs new beat -> exit 0!
        type CapturedHttpReqs = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
        let live_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let live_port = live_listener.local_addr().unwrap().port();
        let received_reqs: CapturedHttpReqs = Arc::new(Mutex::new(Vec::new()));
        let received_clone = Arc::clone(&received_reqs);

        let server_handle = thread::spawn(move || {
            for idx in 0..3 {
                let (mut stream, _) = live_listener.accept().unwrap();
                let (headers, body) = read_single_http_request(&mut stream);
                received_clone.lock().unwrap().push((headers, body));

                let resp = if idx < 2 {
                    let ack = r#"{"k2_receipt_ref":"lrcpt_k2_live_01"}"#;
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ack}",
                        ack.len()
                    )
                } else {
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_owned()
                };
                stream.write_all(resp.as_bytes()).unwrap();
            }
        });

        let live_url = format!("http://127.0.0.1:{live_port}/v1/slack/beats");
        let (c_live_ok, out_live, _) = run_args(
            &state_dir,
            &[
                "test",
                "--channel",
                "C01CIBUILDS",
                "--endpoint",
                &live_url,
                "--allow-loopback-http",
                "--json",
            ],
        );
        assert_eq!(c_live_ok, EXIT_OK);
        let live_val: serde_json::Value = serde_json::from_str(&out_live).unwrap();
        assert_eq!(live_val["flushed_prior_outbox"].as_u64(), Some(1));
        assert_eq!(live_val["pending_outbox_count"].as_u64(), Some(0));

        // 3rd call hits 403 Forbidden -> transitions local state to Revoked and exits 5!
        let (c_revoked, _, _) = run_args(
            &state_dir,
            &[
                "test",
                "--endpoint",
                &live_url,
                "--allow-loopback-http",
                "--json",
            ],
        );
        assert_eq!(c_revoked, EXIT_AUTH_DENIED_OR_REVOKED);
        server_handle.join().unwrap();

        // Verify replayed outbox row preserved X-Chinwag-Channel-Hint: C01OFFLINE1, second had C01CIBUILDS, and all 3 verify under K1!
        let reqs = received_reqs.lock().unwrap();
        assert_eq!(reqs.len(), 3);
        assert!(
            reqs[0].0.contains("X-Chinwag-Channel-Hint: C01OFFLINE1"),
            "flushed offline outbox beat must preserve original channel_override"
        );
        assert!(reqs[1].0.contains("X-Chinwag-Channel-Hint: C01CIBUILDS"));
        let policy = VerificationPolicyV1::default();
        for (_, b) in reqs.iter() {
            let (signed, _) = decode_and_verify_signed_beat_bytes(b, &policy).unwrap();
            assert_eq!(signed.beat.evidence.plaintext_source_bytes, 0);
        }
        let _ = OpaqueOrgId::parse("org_01JTESTSLACK").unwrap();
    }

    #[test]
    fn emits_post_verify_nudge_exactly_once_only_when_not_connected_and_green() {
        let tmp = TempDir::new().unwrap();
        let state_dir = tmp.path().join("nudge_state");
        let outbox = SqliteSlackOutbox::open(&state_dir).unwrap();
        let binding = load_binding_state(&state_dir).unwrap();
        assert_eq!(binding, SlackBindingState::NotConnected);

        // Non-terminal run -> no nudge before value is delivered
        assert_eq!(
            maybe_format_post_verify_slack_nudge(
                &binding,
                &outbox,
                QueueStatusV1::Active,
                "op_418",
                18,
                50,
                1_794_400_000_000,
            )
            .unwrap(),
            None
        );

        // First TerminalGreen run -> emits exact one-time nudge
        let first = maybe_format_post_verify_slack_nudge(
            &binding,
            &outbox,
            QueueStatusV1::TerminalGreen,
            "op_418",
            18,
            50,
            1_794_400_001_000,
        )
        .unwrap()
        .expect("expected first verified green nudge");
        assert!(first.contains("18 dev mins saved on this run. 50 credits."));
        assert!(first.contains("chinwag slack connect"));

        // Second TerminalGreen run -> never nags twice!
        assert_eq!(
            maybe_format_post_verify_slack_nudge(
                &binding,
                &outbox,
                QueueStatusV1::TerminalGreen,
                "op_419",
                22,
                50,
                1_794_400_002_000,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn migrates_legacy_outbox_schema_scrubs_pkce_inode_in_place_and_rejects_null_passkey_field() {
        use crate::slack::authorization::{scrub_and_remove_pkce_verifier, write_atomic_0600};
        use crate::slack::projection::{DaemonProbeParams, build_daemon_probe_beat};
        use chinwag_slack_contract::{EventId, OpaqueOperationId, sign_blind_slack_beat};
        use std::os::unix::fs::OpenOptionsExt;

        let tmp = TempDir::new().unwrap();

        // 1. Legacy slack_outbox DB without `channel_override` column migrates cleanly via ALTER TABLE
        let legacy_dir = tmp.path().join("legacy_outbox");
        std::fs::create_dir_all(&legacy_dir).unwrap();
        std::fs::set_permissions(
            &legacy_dir,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let legacy_db = legacy_dir.join("slack_outbox.sqlite3");
        {
            let _f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&legacy_db)
                .unwrap();
        }
        let status = std::process::Command::new("/usr/bin/sqlite3")
            .arg(&legacy_db)
            .arg(
                "CREATE TABLE slack_outbox (
                    event_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL,
                    beat_digest TEXT NOT NULL,
                    payload_jcs TEXT NOT NULL,
                    delivery_state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at_ms INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    k2_receipt_ref TEXT,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );",
            )
            .status()
            .unwrap();
        assert!(status.success());

        let migrated = SqliteSlackOutbox::open(&legacy_dir).unwrap();
        let signer = Ed25519KeyPairSigner::from_seed_bytes(
            blake3::hash(b"TEST_ONLY:LEGACY_MIGRATION").as_bytes(),
        );
        let beat = build_daemon_probe_beat(DaemonProbeParams {
            event_id: EventId::parse("ev_legacy_mig_01").unwrap(),
            org_id: OpaqueOrgId::parse("org_01JLEGACY").unwrap(),
            operation_id: OpaqueOperationId::parse("op_legacy_01").unwrap(),
            device_ref: OpaqueRef::parse("dev_01").unwrap(),
            session_ref: OpaqueRef::parse("sess_01").unwrap(),
            authorization_ref: AuthorizationRef::parse("auth_01").unwrap(),
            k1_key_id: signer.public_fingerprint(),
            metadata_mode: RequestedMetadataMode::StrictZk,
            passkey_attestation: None,
            now_ms: 1_794_400_000_000,
        })
        .unwrap();
        let (dig, signed) = sign_blind_slack_beat(&signer, beat).unwrap();
        migrated
            .enqueue_idempotent(&signed, &dig, Some("C01LEGACY01"), 1_794_400_000_000)
            .unwrap();
        let row = migrated
            .get_row(&EventId::parse("ev_legacy_mig_01").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(row.channel_override.as_deref(), Some("C01LEGACY01"));

        // 2. Hard-link observer proves `scrub_and_remove_pkce_verifier` zeroes the EXISTING inode in place!
        let pkce_dir = tmp.path().join("pkce_scrub");
        let secret_verifier = b"SECRET_PKCE_CODE_VERIFIER_43_BYTES_MINIMUM_AAAA1111";
        let pkce_path =
            write_atomic_0600(&pkce_dir, "slack_pkce_verifier.bin", secret_verifier).unwrap();
        let inode_observer = pkce_dir.join("inode_observer.hardlink");
        std::fs::hard_link(&pkce_path, &inode_observer).unwrap();

        scrub_and_remove_pkce_verifier(&pkce_dir).unwrap();
        assert!(!pkce_path.exists());
        let observed_bytes = std::fs::read(&inode_observer).unwrap();
        assert!(observed_bytes.len() >= 128);
        assert!(
            observed_bytes.iter().all(|b| *b == 0),
            "existing PKCE verifier inode must be overwritten with zeros in place"
        );

        // 3. Explicit `"passkey_attestation": null` on ConnectBindingGrantV1 is rejected fail-closed!
        let null_grant_json = r#"{
            "schema_version": 1,
            "challenge_id": "ch_01",
            "org_id": "org_01JNULL",
            "team_id": "T01TENANTA1",
            "installation_ref": "inst_01",
            "authorization_ref": "auth_01",
            "k1_key_id": "ed25519:00e70e4562051fee27c748b42ff4a491e7535cb33069b4751aeeda579c0235de",
            "pkce_code_challenge": "challenge_abc",
            "metadata_mode": "strict_zk",
            "passkey_attestation": null,
            "authorization_epoch": "1",
            "issued_at_ms": "1794400005000"
        }"#;
        assert!(serde_json::from_str::<ConnectBindingGrantV1>(null_grant_json).is_err());
    }
}
