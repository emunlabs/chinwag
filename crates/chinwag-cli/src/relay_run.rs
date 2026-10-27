// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct GrokBotSeat {
    pub seat: &'static str,
    pub grokbot_uuid: &'static str,
    pub grokbot_name: &'static str,
    pub is_group: bool,
    pub slack_channel: &'static str,
    pub webhook_env: &'static str,
    pub agentmail_inbox: &'static str,
    pub direct_reports: &'static [&'static str],
}

pub const MGMT_CHANNEL_UUID: &str = "c5a97346-e424-44bf-90d2-9caaa7594c11";
pub const GROUP_INFRA_ENG_UUID: &str = "1e14427a-5234-4411-a3de-d0127f9bbf57";
pub const GROUP_ENG_BRIAN_UUID: &str = "d8873fe8-ea86-4b19-92ae-402f290c422f";

pub const GROKBOT_MGMT_ROSTER: &[GrokBotSeat] = &[
    GrokBotSeat {
        seat: "INFRA",
        grokbot_uuid: "407d2c36-b5c3-491a-9e08-527ad7f18a06",
        grokbot_name: "infra · Infrastructure",
        is_group: false,
        slack_channel: "#infra (C0AERHZ1XB4)",
        webhook_env: "infra.env",
        agentmail_inbox: "infra-bot@mail.grokbot.com",
        direct_reports: &["QA", "FLINT", "ALISTAIR", "DOCS", "HOUSEKEEPING", "EPHEMERAL-QA"],
    },
    GrokBotSeat {
        seat: "BIZFIN",
        grokbot_uuid: "e484d158-8f4d-41f3-a7c9-b2bf8167cbcb",
        grokbot_name: "bizfin · BUSINESS, FINANCE, LEGAL",
        is_group: false,
        slack_channel: "#bizfin (C0C93BV4Q8Z)",
        webhook_env: "bizfin.env",
        agentmail_inbox: "bizfin@agentmail.to",
        direct_reports: &["MO", "VENTURE", "EAGLE-EYE", "DEX", "EPHEMERAL-ANALYST"],
    },
    GrokBotSeat {
        seat: "ENG",
        grokbot_uuid: "a692d662-495c-4def-896b-6a787087de01",
        grokbot_name: "eng · ENGINEERING MANAGER",
        is_group: false,
        slack_channel: "#eng (C0C8S2WDRHB)",
        webhook_env: "eng.env",
        agentmail_inbox: "spector-eng@agentmail.to",
        direct_reports: &["ARCHITECT", "RUST", "INDEX", "EPHEMERAL-DEV"],
    },
    GrokBotSeat {
        seat: "PRODUCT",
        grokbot_uuid: "382e7010-ea4d-48f7-a1bb-96dca02a0921",
        grokbot_name: "product · CREATIVE AND PRODUCT TEAM MANAGER/RELAY",
        is_group: false,
        slack_channel: "#product (C0C9VRFBFKJ)",
        webhook_env: "product.env",
        agentmail_inbox: "spector-product@agentmail.to",
        direct_reports: &["GEMINI-PM", "TYPE", "SCRIBE", "MOTION", "FREQUENCY", "DELIVERY", "EPHEMERAL-RENDER"],
    },
    GrokBotSeat {
        seat: "S-AND-M",
        grokbot_uuid: "16593278-278d-4a2b-9e94-3a189bcaf599",
        grokbot_name: "s-and-m · SALES AND MARKETING",
        is_group: false,
        slack_channel: "#s-and-m (C0C954LTM7W)",
        webhook_env: "s-and-m.env",
        agentmail_inbox: "spector-sm@agentmail.to",
        direct_reports: &[
            "DECLARATION",
            "GROWTH",
            "SALES",
            "SUPPORT",
            "SOCIAL",
            "EPHEMERAL-SDR",
            "EPHEMERAL-SUPPORT",
        ],
    },
    GrokBotSeat {
        seat: "PA",
        grokbot_uuid: "419c9d1d-f01c-4d3c-9972-93e56f95c5d9",
        grokbot_name: "personal-assistant",
        is_group: false,
        slack_channel: "#mgmt (MGMT c5a97346-e424-44bf-90d2-9caaa7594c11)",
        webhook_env: "product.env",
        agentmail_inbox: "brian@emunlabs.com",
        direct_reports: &["FOUNDER-CHECKLIST", "VIP-CISO-CALENDAR", "APPLE-JOURNAL"],
    },
];

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn read_webhook_url(env_file: &str) -> Option<String> {
    let home = env::var("HOME").ok()?;
    let path = PathBuf::from(home)
        .join(".paperclip-pilot/secrets/relay-webhooks")
        .join(env_file);
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("RELAY_SLACK_WEBHOOK_URL=") {
            let clean = rest.trim_matches('"').trim_matches('\'').trim().to_string();
            if clean.starts_with("https://") {
                return Some(clean);
            }
        }
    }
    None
}

fn post_slack_webhook(webhook_url: &str, text: &str) -> (bool, u16) {
    let payload = json!({ "text": text }).to_string();
    let output = Command::new("/usr/bin/curl")
        .args([
            "-sS",
            "-m",
            "10",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--data",
            &payload,
            webhook_url,
        ])
        .output();
    match output {
        Ok(out) => {
            let code_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let code = code_str.parse::<u16>().unwrap_or(0);
            (code >= 200 && code < 300, code)
        }
        Err(_) => (false, 0),
    }
}

fn send_agentmail(to_inbox: &str, subject: &str, text: &str) -> (bool, u16) {
    let home = match env::var("HOME") {
        Ok(h) => h,
        Err(_) => return (false, 0),
    };
    let env_path = PathBuf::from(home).join(".paperclip-pilot/bridges/agentmail.env");
    let content = match fs::read_to_string(env_path) {
        Ok(c) => c,
        Err(_) => return (false, 0),
    };
    let mut api_key = String::new();
    let mut from_inbox = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let clean_v = v.trim().trim_matches('"').trim_matches('\'').to_string();
            match k.trim() {
                "AGENTMAIL_API_KEY" => {
                    api_key = clean_v
                        .strip_prefix("AGENTMAIL_API_KEY=")
                        .unwrap_or(&clean_v)
                        .to_string();
                }
                "AGENTMAIL_INBOX_ID" => {
                    from_inbox = clean_v;
                }
                _ => {}
            }
        }
    }
    if api_key.is_empty() || from_inbox.is_empty() {
        return (false, 0);
    }
    let encoded_inbox = from_inbox.replace('@', "%40");
    let url = format!("https://api.agentmail.to/v0/inboxes/{}/messages/send", encoded_inbox);
    let payload = json!({
        "to": [to_inbox],
        "subject": subject,
        "text": text
    })
    .to_string();

    use std::process::Stdio;
    let mut child = match Command::new("/usr/bin/curl")
        .args([
            "-sS",
            "-m",
            "15",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-X",
            "POST",
            "-K",
            "-",
            "-H",
            "Content-Type: application/json",
            "--data",
            &payload,
            &url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return (false, 0),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "header = \"Authorization: Bearer {}\"", api_key);
    }
    match child.wait_with_output() {
        Ok(out) => {
            let code_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let code = code_str.parse::<u16>().unwrap_or(0);
            (code >= 200 && code < 300, code)
        }
        Err(_) => (false, 0),
    }
}

pub fn run_relay_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "status" => {
            let seats: Vec<_> = GROKBOT_MGMT_ROSTER
                .iter()
                .map(|s| {
                    json!({
                        "seat": s.seat,
                        "grokbot_uuid": s.grokbot_uuid,
                        "grokbot_name": s.grokbot_name,
                        "slack_channel": s.slack_channel,
                        "webhook_env": s.webhook_env,
                        "agentmail_inbox": s.agentmail_inbox,
                        "direct_reports": s.direct_reports,
                        "relay_engine": "chinwag-rust-native-v0.1.1"
                    })
                })
                .collect();
            let report = json!({
                "ok": true,
                "engine": "chinwag-rust-relay",
                "binary": "/Users/brianspector/.local/bin/chinwag",
                "legacy_python_bridge_retired": true,
                "mgmt_group_channel": {
                    "name": "MGMT",
                    "uuid": MGMT_CHANNEL_UUID,
                    "member_count": 6,
                    "member_uuids": GROKBOT_MGMT_ROSTER.iter().map(|s| s.grokbot_uuid).collect::<Vec<_>>()
                },
                "group_channels": [
                    { "name": "MGMT", "uuid": MGMT_CHANNEL_UUID },
                    { "name": "Brian Spector, infra, eng", "uuid": GROUP_INFRA_ENG_UUID },
                    { "name": "eng, Brian Spector", "uuid": GROUP_ENG_BRIAN_UUID }
                ],
                "retired_bots": [
                    { "name": "social (GrokBot)", "uuid": "5d325d18-24eb-4c37-a1c7-57a8abb50ecf", "status": "retired_moved_under_s_and_m" }
                ],
                "seats": seats
            });
            let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            0
        }
        "brief-mgmt" => {
            let run_ts = now_ms();
            let mut receipts = Vec::new();
            let planner_db = "/Users/brianspector/WORKSPACE/delivery-planner/data/planner.sqlite";
            let crdb_path = "/Users/brianspector/WORKSPACE/chinwag/.chinwag/state.crdb";

            for seat in GROKBOT_MGMT_ROSTER {
                let run_id = format!("chinwag-rust-mgmt-{}-{}", seat.seat.to_lowercase(), run_ts);
                let listener_prefix = if seat.seat == "INFRA" {
                    "HOUSEKEEPING"
                } else if seat.seat == "PA" {
                    "PRODUCT"
                } else {
                    seat.seat
                };
                let subj = format!(
                    "[Paperclip] {} | CHWG-MGMT-BRIEF: Management Charter, Direct Reports & Native Rust Relay Cutover",
                    listener_prefix
                );
                let msg = format!(
                    "{}\n\
                    Run: {}   Wake reason: issue_assigned (chinwag-rust-relay)\n\
                    Receipt marker (include in any receipt comment): [relay-receipt run={}]\n\n\
                    ACTION REQUIRED FROM BRIAN SPECTOR & GEMINI-PM — POST YOUR RECEIPT IN GROK BOT `MGMT` GROUP CHANNEL ({}):\n\
                    1. UNPAUSE YOUR SLACK CHANNEL LISTENER FOR CHINWAG RUST RELAY: Do NOT call the retired Paperclip HTTP API (:3110), DO keep your Slack channel listener ({}) and AgentMail listener ({}) ACTIVE for `[Paperclip] {} |` messages dispatched by our native Rust `/Users/brianspector/.local/bin/chinwag relay` binary.\n\
                    2. POST CONFIRMATION IN `MGMT` ({}): Immediately post a short confirmation message in the Grok Bot `MGMT` group room (`{}`) confirming your seat (`{}` / `{}`), your direct reports {:?}, and that you are running on Chinwag Mission Control (`https://brians-mac-studio-468.tail23ad5.ts.net:5487/`).\n\
                    3. INFRA BOT (`407d2c36-b5c3-491a-9e08-527ad7f18a06`): Because `eng`, `bizfin`, `product`, and `s-and-m` paused their routines earlier today, please immediately post this Management Charter briefing directly into the Grok Bot `MGMT` group conversation (`c5a97346-e424-44bf-90d2-9caaa7594c11`) AND send a direct agent message to `eng` (`a692d662-495c-4def-896b-6a787087de01`), `bizfin` (`e484d158-8f4d-41f3-a7c9-b2bf8167cbcb`), `product` (`382e7010-ea4d-48f7-a1bb-96dca02a0921`), `s-and-m` (`16593278-278d-4a2b-9e94-3a189bcaf599`), and `Personal Bot` (`419c9d1d-f01c-4d3c-9972-93e56f95c5d9`) telling them to post their readiness check-in in `MGMT` (`c5a97346-e424-44bf-90d2-9caaa7594c11`)!\n\
                    4. PURE CHINWAG STACK: Hindsight (:8888) and Wiki.js (:4320) are retired. Use `/Users/brianspector/.local/bin/chinwag memory recall | retain | tombstone` (`.chinwag/state.crdb` + `.chinwag/memory.crdb.leann`) and Docus Wiki (`:8795` / `:5487` `Docs · Wiki`).\n\
                    5. MANAGEMENT SLA: Always delegate to your specialist direct reports {:?}, triage blockers within 15m, post daily `#mgmt` standups (`What's working / What's not`), and enforce the 14-Slide Initiative Sign-Off Deck Gate (`INV-INIT-01`, including `INIT-07` Cloudflare Livestream Shorts + `chinwag.tv` `AXEL` vs `RANDO`) + `chinwag ui-gate` (`SOP-QA-02`).",
                    subj,
                    run_id,
                    run_id,
                    MGMT_CHANNEL_UUID,
                    seat.slack_channel,
                    seat.agentmail_inbox,
                    listener_prefix,
                    MGMT_CHANNEL_UUID,
                    MGMT_CHANNEL_UUID,
                    seat.seat,
                    seat.grokbot_uuid,
                    seat.direct_reports,
                    seat.direct_reports
                );

                let (slack_delivered, slack_http_code) = if let Some(url) = read_webhook_url(seat.webhook_env) {
                    post_slack_webhook(&url, &msg)
                } else {
                    (false, 0)
                };

                let (email_delivered, email_http_code) = if seat.agentmail_inbox.contains("@agentmail.to") || seat.agentmail_inbox.contains("@mail.grokbot.com") {
                    send_agentmail(seat.agentmail_inbox, &subj, &msg)
                } else {
                    (false, 0)
                };

                let escaped_msg = msg.replace('\'', "''");
                let sql = format!(
                    "INSERT INTO agent_messages (id, agent_name, sender, role, item_key, body, created_at) VALUES ('msg-rust-relay-{}-{}', '{}', 'CHINWAG-RUST-RELAY', 'assistant', 'MGMT · {}', '{}', datetime('now'));",
                    seat.seat.to_lowercase(),
                    run_ts,
                    seat.seat,
                    MGMT_CHANNEL_UUID,
                    escaped_msg
                );
                let _ = Command::new("sqlite3").arg(planner_db).arg(&sql).output();

                receipts.push(json!({
                    "seat": seat.seat,
                    "listener_prefix": listener_prefix,
                    "grokbot_uuid": seat.grokbot_uuid,
                    "grokbot_name": seat.grokbot_name,
                    "run_id": run_id,
                    "slack_delivered": slack_delivered,
                    "slack_http_status": slack_http_code,
                    "agentmail_inbox": seat.agentmail_inbox,
                    "agentmail_delivered": email_delivered,
                    "agentmail_http_status": email_http_code,
                    "direct_reports": seat.direct_reports
                }));
            }

            let pin_sql = format!(
                "INSERT OR REPLACE INTO context_pins (id, author_cast, author_handle, file_scope, summary, source_commit, created_at) VALUES ('chinwag-rust-relay-mgmt-brief-v1', 'infra', 'CHINWAG-RUST-RELAY', 'rust-comms/src/relay_run.rs', 'All 6 GrokBot MGMT seats in channel {} briefed via native Rust chinwag relay brief-mgmt (INFRA 407d2c36, BIZFIN e484d158, ENG a692d662, PRODUCT 382e7010, S-AND-M 16593278, PA 419c9d1d). SUPPORT + EPHEMERAL-SUPPORT spun up under S-AND-M.', 'b1745094d9cb9014361fca30c7de3535c140dd20', datetime('now'));",
                MGMT_CHANNEL_UUID
            );
            let _ = Command::new("sqlite3").arg(crdb_path).arg(&pin_sql).output();

            let out = json!({
                "ok": true,
                "action": "brief-mgmt",
                "mgmt_channel_uuid": MGMT_CHANNEL_UUID,
                "receipts": receipts
            });
            let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            0
        }
        _ => {
            let _ = writeln!(
                stderr,
                "Usage: chinwag relay <status | brief-mgmt>"
            );
            2
        }
    }
}
