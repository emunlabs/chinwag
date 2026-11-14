// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! `chinwag slack connect|status|test|channel-map` subcommand implementations
//! with deterministic exit codes `0..6` and zero `argv` secrets (`ROG-580`).

use crate::slack::authorization::{
    ConnectExchangeOutcome, RequestedMetadataMode, SlackBindingState, begin_browser_oauth_handoff,
    exchange_pkce_challenge_with_coordinator, guard_zero_argv_secrets, load_binding_state,
    load_or_create_k1_signer, save_binding_state, scrub_and_remove_pkce_verifier,
};
use crate::slack::emitter::{
    DeliveryOutcome, RelayDispatchTarget, flush_due_outbox, sign_enqueue_and_dispatch,
};
use crate::slack::outbox::{SqliteSlackOutbox, validate_slack_channel_id};
use crate::slack::projection::{DaemonProbeParams, build_daemon_probe_beat};
use crate::slack::{
    EXIT_AUTH_DENIED_OR_REVOKED, EXIT_AUTH_PENDING, EXIT_INVALID_ARGS_OR_ARGV_SECRET,
    EXIT_NOT_CONNECTED, EXIT_OK, EXIT_TEMP_UNAVAILABLE_QUEUED,
};
use chinwag_slack_contract::{
    CanonicalU64, EventId, KeyFingerprint, OpaqueOperationId, OpaqueOrgId, OpaqueRef,
};
use rand::RngCore;
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_SLACK_WEB_ORIGIN: &str = "https://slack.chinwag.sh";
pub const DEFAULT_SLACK_RELAY_INGRESS: &str = "https://relay.chinwag.sh/v1/slack/beats";

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn default_state_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("CHINWAG_SLACK_STATE_DIR")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit);
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.trim().is_empty()
    {
        return PathBuf::from(home).join(".chinwag").join("slack");
    }
    PathBuf::from(".chinwag/slack")
}

fn default_relay_endpoint() -> String {
    std::env::var("CHINWAG_SLACK_RELAY_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SLACK_RELAY_INGRESS.to_owned())
}

fn default_connect_origin() -> String {
    std::env::var("CHINWAG_SLACK_CONNECT_ORIGIN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SLACK_WEB_ORIGIN.to_owned())
}

fn allow_loopback_http_from_env_or_flag(args: &[String]) -> bool {
    args.iter().any(|a| a == "--allow-loopback-http")
        || std::env::var("CHINWAG_SLACK_ALLOW_LOOPBACK_HTTP")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn emit_error(
    json_mode: bool,
    code: u8,
    error: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    if json_mode {
        let _ = writeln!(
            stdout,
            "{}",
            json!({
                "ok": false,
                "exit_code": code,
                "error": error,
            })
        );
    } else {
        let _ = writeln!(stderr, "chinwag slack: {error}");
    }
    code
}

pub fn dispatch_slack_command(
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let json_mode = args.iter().any(|a| a == "--json");
    if let Err(err) = guard_zero_argv_secrets(args) {
        return emit_error(
            json_mode,
            EXIT_INVALID_ARGS_OR_ARGV_SECRET,
            &err.to_string(),
            stdout,
            stderr,
        );
    }

    let Some(sub) = args.first().map(String::as_str) else {
        return print_usage(json_mode, stdout, stderr, EXIT_INVALID_ARGS_OR_ARGV_SECRET);
    };
    if matches!(sub, "-h" | "--help" | "help") {
        return print_usage(json_mode, stdout, stderr, EXIT_OK);
    }

    let rest = &args[1..];
    let state_dir = match extract_flag_value(rest, "--state-dir") {
        Ok(Some(p)) => PathBuf::from(p),
        Ok(None) => default_state_dir(),
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e,
                stdout,
                stderr,
            );
        }
    };

    match sub {
        "connect" => cmd_connect(&state_dir, rest, json_mode, stdout, stderr),
        "status" => cmd_status(&state_dir, rest, json_mode, stdout, stderr),
        "test" => cmd_test(&state_dir, rest, json_mode, stdout, stderr),
        "channel-map" => cmd_channel_map(&state_dir, rest, json_mode, stdout, stderr),
        other => emit_error(
            json_mode,
            EXIT_INVALID_ARGS_OR_ARGV_SECRET,
            &format!("unknown subcommand '{other}'; expected connect|status|test|channel-map"),
            stdout,
            stderr,
        ),
    }
}

fn print_usage(json_mode: bool, stdout: &mut dyn Write, _stderr: &mut dyn Write, code: u8) -> u8 {
    if json_mode {
        let _ = writeln!(
            stdout,
            "{}",
            json!({
                "ok": code == EXIT_OK,
                "commands": [
                    "chinwag slack connect [--org <org_id>] [--metadata-mode strict_zk|rich_symbols] [--json]",
                    "chinwag slack status [--json]",
                    "chinwag slack test [--channel <C...>] [--endpoint <url>] [--json]",
                    "chinwag slack channel-map list|set|clear [--json]"
                ],
                "exit_codes": {
                    "0": "success",
                    "2": "invalid arguments or forbidden secret in argv (ROG-580)",
                    "3": "Slack not connected",
                    "4": "browser authorization pending",
                    "5": "authorization denied or revoked",
                    "6": "temporary service unavailable (beat queued durably in SQLite outbox)"
                }
            })
        );
    } else {
        let _ = writeln!(
            stdout,
            "Usage:\n  \
             chinwag slack connect [--org <org_id>] [--metadata-mode strict_zk|rich_symbols] [--json]\n  \
             chinwag slack status [--json]\n  \
             chinwag slack test [--channel <C...>] [--endpoint <url>] [--json]\n  \
             chinwag slack channel-map <list|set|clear> [args] [--json]"
        );
    }
    code
}

fn extract_flag_value(args: &[String], flag: &str) -> Result<Option<String>, String> {
    let mut found = None;
    let mut idx = 0;
    while idx < args.len() {
        if args[idx] == flag {
            let val = args
                .get(idx + 1)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            if val.starts_with("--") {
                return Err(format!("{flag} requires a value"));
            }
            found = Some(val.clone());
            idx += 2;
        } else if let Some(rhs) = args[idx].strip_prefix(&format!("{flag}=")) {
            if rhs.is_empty() {
                return Err(format!("{flag} cannot be empty"));
            }
            found = Some(rhs.to_owned());
            idx += 1;
        } else {
            idx += 1;
        }
    }
    Ok(found)
}

fn cmd_connect(
    state_dir: &Path,
    args: &[String],
    json_mode: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let now_ms = now_epoch_ms();
    let mode = match extract_flag_value(args, "--metadata-mode") {
        Ok(Some(m)) => match RequestedMetadataMode::parse_flag(&m) {
            Some(parsed) => parsed,
            None => {
                return emit_error(
                    json_mode,
                    EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                    "expected --metadata-mode strict_zk|rich_symbols",
                    stdout,
                    stderr,
                );
            }
        },
        Ok(None) => RequestedMetadataMode::StrictZk,
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e,
                stdout,
                stderr,
            );
        }
    };

    let allow_loopback_http = allow_loopback_http_from_env_or_flag(args);

    if args.iter().any(|a| a == "--revoke") {
        let existing_org = match load_binding_state(state_dir) {
            Ok(
                SlackBindingState::Pending { org_id, .. }
                | SlackBindingState::Connected { org_id, .. }
                | SlackBindingState::Revoked { org_id, .. },
            ) => Some(org_id),
            _ => None,
        };
        let org_id = if let Some(existing) = existing_org {
            existing
        } else {
            let Some(org_raw) = extract_flag_value(args, "--org")
                .ok()
                .flatten()
                .or_else(|| std::env::var("CHINWAG_SLACK_ORG_ID").ok())
            else {
                return emit_error(
                    json_mode,
                    EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                    "--revoke requires an existing workspace binding or --org <org_id>",
                    stdout,
                    stderr,
                );
            };
            let Ok(parsed) = OpaqueOrgId::parse(org_raw) else {
                return emit_error(
                    json_mode,
                    EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                    "invalid --org identifier",
                    stdout,
                    stderr,
                );
            };
            parsed
        };
        if let Err(e) = scrub_and_remove_pkce_verifier(state_dir) {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e.to_string(),
                stdout,
                stderr,
            );
        }
        let revoked = SlackBindingState::Revoked {
            org_id,
            reason: "revoked_by_operator".to_owned(),
            revoked_at_ms: CanonicalU64::new(now_ms),
        };
        if let Err(e) = save_binding_state(state_dir, &revoked) {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e.to_string(),
                stdout,
                stderr,
            );
        }
        return emit_error(
            json_mode,
            EXIT_AUTH_DENIED_OR_REVOKED,
            "Slack installation binding marked revoked",
            stdout,
            stderr,
        );
    }

    // Complete an existing pending challenge via real PKCE + K1 -> Coordinator K2 grant exchange
    if let Ok(Some(challenge_str)) = extract_flag_value(args, "--complete-challenge") {
        let Some(callback_raw) = extract_flag_value(args, "--callback-ref").ok().flatten() else {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                "--complete-challenge requires --callback-ref <cb_...>",
                stdout,
                stderr,
            );
        };
        let Ok(callback_ref) = OpaqueRef::parse(callback_raw) else {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                "invalid --callback-ref identifier",
                stdout,
                stderr,
            );
        };
        let Some(k2_raw) = extract_flag_value(args, "--coordinator-k2-pubkey")
            .ok()
            .flatten()
            .or_else(|| std::env::var("CHINWAG_SLACK_COORDINATOR_K2_PUBKEY").ok())
        else {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                "--complete-challenge requires --coordinator-k2-pubkey <ed25519:...> or CHINWAG_SLACK_COORDINATOR_K2_PUBKEY",
                stdout,
                stderr,
            );
        };
        let Ok(expected_k2) = KeyFingerprint::parse_prefixed(k2_raw.trim()) else {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                "invalid Coordinator K2 Ed25519 public key format",
                stdout,
                stderr,
            );
        };
        let trusted_admin_passkey = match extract_flag_value(args, "--admin-passkey-pubkey")
            .ok()
            .flatten()
            .or_else(|| std::env::var("CHINWAG_SLACK_ADMIN_PASSKEY_PUBKEY").ok())
            .filter(|s| !s.trim().is_empty())
        {
            Some(raw_pk) => match KeyFingerprint::parse_prefixed(raw_pk.trim()) {
                Ok(parsed) => Some(parsed),
                Err(_) => {
                    return emit_error(
                        json_mode,
                        EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                        "invalid OrgAdminPasskey Ed25519 public key format",
                        stdout,
                        stderr,
                    );
                }
            },
            None => None,
        };

        return match exchange_pkce_challenge_with_coordinator(
            state_dir,
            &challenge_str,
            callback_ref,
            &expected_k2,
            trusted_admin_passkey.as_ref(),
            allow_loopback_http,
            3_000,
            now_ms,
        ) {
            Ok(ConnectExchangeOutcome::Connected(boxed)) => {
                if let SlackBindingState::Connected {
                    org_id,
                    team_id,
                    installation_ref,
                    authorization_ref,
                    k1_key_id,
                    coordinator_k2_pubkey,
                    metadata_mode,
                    ..
                } = *boxed
                {
                    if json_mode {
                        let _ = writeln!(
                            stdout,
                            "{}",
                            json!({
                                "ok": true,
                                "exit_code": EXIT_OK,
                                "state": "connected",
                                "org_id": org_id.as_str(),
                                "team_id": team_id.as_str(),
                                "installation_ref": installation_ref.as_str(),
                                "authorization_ref": authorization_ref.as_str(),
                                "k1_key_id": k1_key_id.to_prefixed_string(),
                                "coordinator_k2_pubkey": coordinator_k2_pubkey.to_prefixed_string(),
                                "metadata_mode": metadata_mode.as_str(),
                            })
                        );
                    } else {
                        let _ = writeln!(
                            stdout,
                            "Connected Slack workspace {} ({}) with K1 {}",
                            team_id.as_str(),
                            metadata_mode.as_str(),
                            k1_key_id.to_prefixed_string()
                        );
                    }
                }
                EXIT_OK
            }
            Ok(ConnectExchangeOutcome::AuthDeniedOrRevoked(reason)) => emit_error(
                json_mode,
                EXIT_AUTH_DENIED_OR_REVOKED,
                &reason,
                stdout,
                stderr,
            ),
            Ok(ConnectExchangeOutcome::TempUnavailable(reason)) => emit_error(
                json_mode,
                EXIT_TEMP_UNAVAILABLE_QUEUED,
                &reason,
                stdout,
                stderr,
            ),
            Err(e) => emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e.to_string(),
                stdout,
                stderr,
            ),
        };
    }

    let Some(org_raw) = extract_flag_value(args, "--org")
        .ok()
        .flatten()
        .or_else(|| std::env::var("CHINWAG_SLACK_ORG_ID").ok())
    else {
        return emit_error(
            json_mode,
            EXIT_INVALID_ARGS_OR_ARGV_SECRET,
            "missing required --org <org_id> (or CHINWAG_SLACK_ORG_ID)",
            stdout,
            stderr,
        );
    };
    let Ok(org_id) = OpaqueOrgId::parse(org_raw) else {
        return emit_error(
            json_mode,
            EXIT_INVALID_ARGS_OR_ARGV_SECRET,
            "invalid --org identifier",
            stdout,
            stderr,
        );
    };
    let connect_origin = extract_flag_value(args, "--connect-origin")
        .ok()
        .flatten()
        .unwrap_or_else(default_connect_origin);

    match begin_browser_oauth_handoff(
        state_dir,
        &connect_origin,
        allow_loopback_http,
        org_id,
        mode,
        now_ms,
    ) {
        Ok(SlackBindingState::Pending {
            challenge_id,
            verification_url,
            k1_key_id,
            requested_mode,
            expires_at_ms,
            ..
        }) => {
            if json_mode {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "ok": true,
                        "exit_code": EXIT_AUTH_PENDING,
                        "state": "pending",
                        "challenge_id": challenge_id.as_str(),
                        "verification_url": verification_url,
                        "k1_key_id": k1_key_id.to_prefixed_string(),
                        "requested_mode": requested_mode.as_str(),
                        "expires_at_ms": expires_at_ms.to_string(),
                    })
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "Complete Slack OAuth v2 + K1 seat binding in your browser:\n  {verification_url}"
                );
            }
            EXIT_AUTH_PENDING
        }
        Ok(_) => EXIT_AUTH_PENDING,
        Err(e) => emit_error(
            json_mode,
            EXIT_INVALID_ARGS_OR_ARGV_SECRET,
            &e.to_string(),
            stdout,
            stderr,
        ),
    }
}

fn cmd_status(
    state_dir: &Path,
    _args: &[String],
    json_mode: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let state = match load_binding_state(state_dir) {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e.to_string(),
                stdout,
                stderr,
            );
        }
    };
    let outbox = match SqliteSlackOutbox::open(state_dir) {
        Ok(o) => o,
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e.to_string(),
                stdout,
                stderr,
            );
        }
    };
    let pending_outbox = outbox.pending_count().unwrap_or(0);
    let mappings = outbox.list_channel_mappings().unwrap_or_default();

    match state {
        SlackBindingState::NotConnected => {
            if json_mode {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "ok": false,
                        "exit_code": EXIT_NOT_CONNECTED,
                        "state": "not_connected",
                        "pending_outbox_count": pending_outbox,
                    })
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "Slack is not connected. Run `chinwag slack connect` to link your workspace."
                );
            }
            EXIT_NOT_CONNECTED
        }
        SlackBindingState::Pending {
            challenge_id,
            verification_url,
            k1_key_id,
            requested_mode,
            ..
        } => {
            if json_mode {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "ok": false,
                        "exit_code": EXIT_AUTH_PENDING,
                        "state": "pending",
                        "challenge_id": challenge_id.as_str(),
                        "verification_url": verification_url,
                        "k1_key_id": k1_key_id.to_prefixed_string(),
                        "requested_mode": requested_mode.as_str(),
                        "pending_outbox_count": pending_outbox,
                    })
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "Slack authorization pending ({}): {verification_url}",
                    challenge_id.as_str(),
                );
            }
            EXIT_AUTH_PENDING
        }
        SlackBindingState::Revoked {
            org_id,
            reason,
            revoked_at_ms,
        } => {
            if json_mode {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "ok": false,
                        "exit_code": EXIT_AUTH_DENIED_OR_REVOKED,
                        "state": "revoked",
                        "org_id": org_id.as_str(),
                        "reason": reason,
                        "revoked_at_ms": revoked_at_ms.to_string(),
                        "pending_outbox_count": pending_outbox,
                    })
                );
            } else {
                let _ = writeln!(stderr, "Slack authorization revoked: {reason}");
            }
            EXIT_AUTH_DENIED_OR_REVOKED
        }
        SlackBindingState::Connected {
            org_id,
            team_id,
            installation_ref,
            authorization_ref,
            k1_key_id,
            metadata_mode,
            authorization_epoch,
            ..
        } => {
            if json_mode {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "ok": true,
                        "exit_code": EXIT_OK,
                        "state": "connected",
                        "org_id": org_id.as_str(),
                        "team_id": team_id.as_str(),
                        "installation_ref": installation_ref.as_str(),
                        "authorization_ref": authorization_ref.as_str(),
                        "k1_key_id": k1_key_id.to_prefixed_string(),
                        "metadata_mode": metadata_mode.as_str(),
                        "authorization_epoch": authorization_epoch.to_string(),
                        "pending_outbox_count": pending_outbox,
                        "channel_mappings": mappings,
                    })
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "Slack connected: org={} team={} mode={} k1={} pending_outbox={}",
                    org_id.as_str(),
                    team_id.as_str(),
                    metadata_mode.as_str(),
                    k1_key_id.to_prefixed_string(),
                    pending_outbox
                );
            }
            EXIT_OK
        }
    }
}

fn cmd_test(
    state_dir: &Path,
    args: &[String],
    json_mode: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let now_ms = now_epoch_ms();
    let state = match load_binding_state(state_dir) {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e.to_string(),
                stdout,
                stderr,
            );
        }
    };
    let (org_id, authorization_ref, metadata_mode, passkey_att) = match state {
        SlackBindingState::NotConnected => {
            return emit_error(
                json_mode,
                EXIT_NOT_CONNECTED,
                "Slack is not connected; run `chinwag slack connect` first",
                stdout,
                stderr,
            );
        }
        SlackBindingState::Pending { .. } => {
            return emit_error(
                json_mode,
                EXIT_AUTH_PENDING,
                "Slack browser authorization is still pending",
                stdout,
                stderr,
            );
        }
        SlackBindingState::Revoked { reason, .. } => {
            return emit_error(
                json_mode,
                EXIT_AUTH_DENIED_OR_REVOKED,
                &format!("Slack authorization revoked: {reason}"),
                stdout,
                stderr,
            );
        }
        SlackBindingState::Connected {
            org_id,
            authorization_ref,
            metadata_mode,
            passkey_attestation,
            ..
        } => (
            org_id,
            authorization_ref,
            metadata_mode,
            passkey_attestation,
        ),
    };

    let channel_hint = match extract_flag_value(args, "--channel") {
        Ok(Some(ch)) => {
            if let Err(e) = validate_slack_channel_id(&ch) {
                return emit_error(
                    json_mode,
                    EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                    &e.to_string(),
                    stdout,
                    stderr,
                );
            }
            Some(ch)
        }
        Ok(None) => None,
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e,
                stdout,
                stderr,
            );
        }
    };

    let endpoint = match extract_flag_value(args, "--endpoint") {
        Ok(Some(u)) => u,
        Ok(None) => default_relay_endpoint(),
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e,
                stdout,
                stderr,
            );
        }
    };

    let signer = match load_or_create_k1_signer(state_dir) {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e.to_string(),
                stdout,
                stderr,
            );
        }
    };
    let outbox = match SqliteSlackOutbox::open(state_dir) {
        Ok(o) => o,
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e.to_string(),
                stdout,
                stderr,
            );
        }
    };

    let target = RelayDispatchTarget {
        endpoint_url: endpoint,
        allow_loopback_http: allow_loopback_http_from_env_or_flag(args),
        timeout_ms: 3_000,
    };

    // Explicit operator connectivity probe flushes any queued outbox rows immediately
    let flushed_prior = flush_due_outbox(&outbox, &target, i64::MAX as u64, 16).unwrap_or(0);

    let mut rand_id = [0u8; 8];
    rand::rng().fill_bytes(&mut rand_id);
    let hex_id = hex::encode(rand_id);
    let Ok(event_id) = EventId::parse(format!("ev_probe_{hex_id}")) else {
        return EXIT_INVALID_ARGS_OR_ARGV_SECRET;
    };
    let Ok(op_id) = OpaqueOperationId::parse(format!("op_probe_{hex_id}")) else {
        return EXIT_INVALID_ARGS_OR_ARGV_SECRET;
    };
    let Ok(device_ref) = OpaqueRef::parse("dev_local_cli") else {
        return EXIT_INVALID_ARGS_OR_ARGV_SECRET;
    };
    let Ok(session_ref) = OpaqueRef::parse(format!("sess_{hex_id}")) else {
        return EXIT_INVALID_ARGS_OR_ARGV_SECRET;
    };

    let beat = match build_daemon_probe_beat(DaemonProbeParams {
        event_id,
        org_id: org_id.clone(),
        operation_id: op_id,
        device_ref,
        session_ref,
        authorization_ref,
        k1_key_id: signer.public_fingerprint(),
        metadata_mode,
        passkey_attestation: passkey_att.as_deref(),
        now_ms,
    }) {
        Ok(b) => b,
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e,
                stdout,
                stderr,
            );
        }
    };

    match sign_enqueue_and_dispatch(
        &signer,
        beat,
        &outbox,
        &target,
        channel_hint.as_deref(),
        now_ms,
    ) {
        Ok(DeliveryOutcome::Acked {
            event_id,
            k2_receipt_ref,
        }) => {
            if json_mode {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "ok": true,
                        "exit_code": EXIT_OK,
                        "event_id": event_id,
                        "k2_receipt_ref": k2_receipt_ref,
                        "flushed_prior_outbox": flushed_prior,
                        "pending_outbox_count": outbox.pending_count().unwrap_or(0),
                    })
                );
            } else {
                let _ = writeln!(stdout, "Slack blind probe beat acknowledged ({event_id}).");
            }
            EXIT_OK
        }
        Ok(DeliveryOutcome::AuthDeniedOrRevoked { status, message }) => {
            let _ = save_binding_state(
                state_dir,
                &SlackBindingState::Revoked {
                    org_id,
                    reason: message.clone(),
                    revoked_at_ms: CanonicalU64::new(now_ms),
                },
            );
            emit_error(
                json_mode,
                EXIT_AUTH_DENIED_OR_REVOKED,
                &format!("{message} (HTTP {status})"),
                stdout,
                stderr,
            )
        }
        Ok(DeliveryOutcome::QueuedTransient {
            reason,
            retry_after_ms,
        }) => {
            let pending = outbox.pending_count().unwrap_or(1);
            if json_mode {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "ok": false,
                        "exit_code": EXIT_TEMP_UNAVAILABLE_QUEUED,
                        "queued_in_outbox": true,
                        "pending_outbox_count": pending,
                        "retry_after_ms": retry_after_ms,
                        "reason": reason,
                    })
                );
            } else {
                let _ = writeln!(
                    stderr,
                    "Slack relay temporarily unavailable ({reason}); beat durably queued in SQLite outbox ({pending} pending)."
                );
            }
            EXIT_TEMP_UNAVAILABLE_QUEUED
        }
        Err(e) => emit_error(
            json_mode,
            EXIT_INVALID_ARGS_OR_ARGV_SECRET,
            &e,
            stdout,
            stderr,
        ),
    }
}

fn cmd_channel_map(
    state_dir: &Path,
    args: &[String],
    json_mode: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let now_ms = now_epoch_ms();
    let outbox = match SqliteSlackOutbox::open(state_dir) {
        Ok(o) => o,
        Err(e) => {
            return emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e.to_string(),
                stdout,
                stderr,
            );
        }
    };

    let positional: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with("--"))
        .collect();

    match positional.first().copied() {
        Some("list") | None => match outbox.list_channel_mappings() {
            Ok(rows) => {
                if json_mode {
                    let _ = writeln!(
                        stdout,
                        "{}",
                        json!({
                            "ok": true,
                            "exit_code": EXIT_OK,
                            "mappings": rows,
                        })
                    );
                } else if rows.is_empty() {
                    let _ = writeln!(stdout, "No Slack channel mappings configured.");
                } else {
                    for r in rows {
                        let _ = writeln!(
                            stdout,
                            "{} -> {} ({})",
                            r.archetype, r.channel_id, r.metadata_mode
                        );
                    }
                }
                EXIT_OK
            }
            Err(e) => emit_error(
                json_mode,
                EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                &e.to_string(),
                stdout,
                stderr,
            ),
        },
        Some("set") => {
            let archetype = extract_flag_value(args, "--archetype")
                .ok()
                .flatten()
                .or_else(|| positional.get(1).map(|s| (*s).to_owned()));
            let channel_id = extract_flag_value(args, "--channel")
                .ok()
                .flatten()
                .or_else(|| positional.get(2).map(|s| (*s).to_owned()));
            let mode_str = extract_flag_value(args, "--metadata-mode")
                .ok()
                .flatten()
                .unwrap_or_else(|| "strict_zk".to_owned());
            let (Some(arch), Some(ch), Some(mode)) = (
                archetype,
                channel_id,
                RequestedMetadataMode::parse_flag(&mode_str),
            ) else {
                return emit_error(
                    json_mode,
                    EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                    "usage: chinwag slack channel-map set <ci-builds|security|pair|delivery> <C...> [--metadata-mode strict_zk|rich_symbols]",
                    stdout,
                    stderr,
                );
            };
            if let Err(e) = outbox.set_channel_mapping(&arch, &ch, mode, now_ms) {
                return emit_error(
                    json_mode,
                    EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                    &e.to_string(),
                    stdout,
                    stderr,
                );
            }
            if json_mode {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "ok": true,
                        "exit_code": EXIT_OK,
                        "archetype": arch,
                        "channel_id": ch,
                        "metadata_mode": mode.as_str(),
                    })
                );
            } else {
                let _ = writeln!(stdout, "Mapped {arch} -> {ch} ({})", mode.as_str());
            }
            EXIT_OK
        }
        Some("clear") => {
            let archetype = extract_flag_value(args, "--archetype")
                .ok()
                .flatten()
                .or_else(|| positional.get(1).map(|s| (*s).to_owned()));
            let Some(arch) = archetype else {
                return emit_error(
                    json_mode,
                    EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                    "usage: chinwag slack channel-map clear <ci-builds|security|pair|delivery>",
                    stdout,
                    stderr,
                );
            };
            if let Err(e) = outbox.clear_channel_mapping(&arch) {
                return emit_error(
                    json_mode,
                    EXIT_INVALID_ARGS_OR_ARGV_SECRET,
                    &e.to_string(),
                    stdout,
                    stderr,
                );
            }
            if json_mode {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "ok": true,
                        "exit_code": EXIT_OK,
                        "cleared": arch,
                    })
                );
            } else {
                let _ = writeln!(stdout, "Cleared mapping for {arch}");
            }
            EXIT_OK
        }
        Some(other) => emit_error(
            json_mode,
            EXIT_INVALID_ARGS_OR_ARGV_SECRET,
            &format!("unknown channel-map action '{other}'; expected list|set|clear"),
            stdout,
            stderr,
        ),
    }
}
