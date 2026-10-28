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

#[allow(dead_code)]
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

#[derive(Debug, Clone)]
pub struct IdentityConfig {
    pub actor_id: String,
    pub handle: String,
    pub display_name: String,
    pub machine_name: String,
    pub mission_control_url: String,
    pub fallback_hub_url: String,
    pub api_key: String,
}

fn detect_local_hostname() -> String {
    if let Ok(h) = env::var("CHINWAG_HOSTNAME").or_else(|_| env::var("HOSTNAME")) {
        let trimmed = h.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    if let Ok(out) = Command::new("/bin/hostname").output() {
        let h = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    "brians-mac-studio-468".to_string()
}

pub fn resolve_identity_config() -> IdentityConfig {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let local_host = detect_local_hostname();
    let is_studio_host = local_host.to_ascii_lowercase().starts_with("brians-mac-studio");

    let identity_path = env::var("CHINWAG_IDENTITY_FILE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&home).join(".chinwag/identity.toml"));

    let mut actor_id = String::new();
    let mut handle = String::new();
    let mut display_name = String::new();
    let mut machine_name = String::new();
    let mut mission_control_url = String::new();
    let mut studio_origin = String::new();
    let mut fallback_hub_url = String::new();

    if let Ok(content) = fs::read_to_string(&identity_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim();
                let val = v.trim().trim_matches('"').trim_matches('\'').trim().to_string();
                match key {
                    "actor_id" => actor_id = val,
                    "handle" => handle = val,
                    "display_name" => display_name = val,
                    "machine_name" => machine_name = val,
                    "mission_control_url" => mission_control_url = val,
                    "studio_origin" => studio_origin = val,
                    "fallback_hub_url" => fallback_hub_url = val,
                    _ => {}
                }
            }
        }
    }

    let config_json_path = PathBuf::from(&home).join(".config/delivery-planner/config.json");
    let mut cfg_api_key = String::new();
    let mut cfg_studio_origin = String::new();
    let mut cfg_actor_id = String::new();
    let mut cfg_actor = String::new();
    let mut cfg_machine_name = String::new();
    if let Ok(raw_cfg) = fs::read_to_string(&config_json_path) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw_cfg) {
            if let Some(v) = parsed.get("apiKey").and_then(|v| v.as_str()) {
                cfg_api_key = v.trim().to_string();
            }
            if let Some(v) = parsed
                .get("missionControlUrl")
                .or_else(|| parsed.get("studioOrigin"))
                .and_then(|v| v.as_str())
            {
                cfg_studio_origin = v.trim().to_string();
            }
            if let Some(v) = parsed.get("actorId").and_then(|v| v.as_str()) {
                cfg_actor_id = v.trim().to_string();
            }
            if let Some(v) = parsed.get("actor").and_then(|v| v.as_str()) {
                cfg_actor = v.trim().to_string();
            }
            if let Some(v) = parsed.get("machineName").and_then(|v| v.as_str()) {
                cfg_machine_name = v.trim().to_string();
            }
        }
    }

    if let Ok(env_actor_id) = env::var("CHINWAG_ACTOR_ID") {
        if !env_actor_id.trim().is_empty() {
            actor_id = env_actor_id.trim().to_string();
        }
    }
    if let Ok(env_actor) = env::var("CHINWAG_ACTOR") {
        if !env_actor.trim().is_empty() {
            handle = env_actor.trim().to_string();
        }
    }
    if actor_id.is_empty() && !cfg_actor_id.is_empty() {
        actor_id = cfg_actor_id;
    }
    if handle.is_empty() && !cfg_actor.is_empty() {
        handle = cfg_actor;
    }
    if machine_name.is_empty() && !cfg_machine_name.is_empty() {
        machine_name = cfg_machine_name;
    }
    if machine_name.is_empty() {
        machine_name = local_host.clone();
    }

    let effective_is_studio = is_studio_host
        && !machine_name.to_ascii_lowercase().contains("nic")
        && actor_id != "actor-nic";

    if actor_id.is_empty() {
        actor_id = if effective_is_studio {
            "actor-brian".to_string()
        } else {
            "actor-nic".to_string()
        };
    }
    if handle.is_empty() {
        handle = if actor_id == "actor-nic" {
            "● Nic".to_string()
        } else {
            "● Brian".to_string()
        };
    }
    if display_name.is_empty() {
        display_name = if actor_id == "actor-nic" {
            "Nicola (Nic) Spector".to_string()
        } else {
            "Brian Spector".to_string()
        };
    }

    if let Ok(env_url) = env::var("CHINWAG_MISSION_CONTROL_URL") {
        if !env_url.trim().is_empty() {
            mission_control_url = env_url.trim().to_string();
        }
    }
    if mission_control_url.is_empty() && !studio_origin.is_empty() {
        mission_control_url = studio_origin;
    }
    if mission_control_url.is_empty() && !cfg_studio_origin.is_empty() {
        mission_control_url = cfg_studio_origin;
    }
    if mission_control_url.is_empty() {
        mission_control_url = if effective_is_studio {
            "http://127.0.0.1:5487".to_string()
        } else {
            "http://100.66.156.76:5487".to_string()
        };
    }
    mission_control_url = mission_control_url.trim_end_matches('/').to_string();

    if fallback_hub_url.is_empty() {
        fallback_hub_url = "http://192.168.1.166:5487".to_string();
    } else {
        fallback_hub_url = fallback_hub_url.trim_end_matches('/').to_string();
    }

    let mut api_key = env::var("CHINWAG_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if api_key.is_empty() {
        let nic_key_path = PathBuf::from(&home).join(".chinwag/nic-api.key");
        if let Ok(k) = fs::read_to_string(nic_key_path) {
            api_key = k.trim().to_string();
        }
    }
    if api_key.is_empty() && !cfg_api_key.is_empty() {
        api_key = cfg_api_key;
    }
    if api_key.is_empty() {
        let studio_key_path =
            PathBuf::from(&home).join("WORKSPACE/delivery-planner/data/delivery-api.key");
        if let Ok(k) = fs::read_to_string(studio_key_path) {
            api_key = k.trim().to_string();
        }
    }

    IdentityConfig {
        actor_id,
        handle,
        display_name,
        machine_name,
        mission_control_url,
        fallback_hub_url,
        api_key,
    }
}

fn curl_post_json_endpoint(
    endpoint_url: &str,
    payload_str: &str,
    identity: &IdentityConfig,
    use_tailnet_resolve: bool,
) -> (bool, u16) {
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args([
        "-sS",
        "--connect-timeout",
        "2",
        "-m",
        "6",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
    ]);
    if use_tailnet_resolve && endpoint_url.contains("brians-mac-studio-468.tail23ad5.ts.net:5487") {
        cmd.args([
            "--resolve",
            "brians-mac-studio-468.tail23ad5.ts.net:5487:100.66.156.76",
        ]);
    }
    if !identity.api_key.is_empty() {
        cmd.args(["-H", &format!("Authorization: Bearer {}", identity.api_key)]);
    }
    if !identity.actor_id.is_empty() {
        cmd.args(["-H", &format!("X-Chinwag-Actor: {}", identity.actor_id)]);
        cmd.args(["-H", &format!("X-Chinwag-Actor-Id: {}", identity.actor_id)]);
    }
    if !identity.machine_name.is_empty() {
        cmd.args(["-H", &format!("X-Chinwag-Machine: {}", identity.machine_name)]);
    }
    cmd.args(["--data", payload_str, endpoint_url]);
    match cmd.output() {
        Ok(out) => {
            let code_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let code = code_str.parse::<u16>().unwrap_or(0);
            (code >= 200 && code < 300, code)
        }
        Err(_) => (false, 0),
    }
}

fn post_mission_control_with_fallback(
    base_url: &str,
    path: &str,
    payload_str: &str,
    identity: &IdentityConfig,
) -> (bool, u16, String) {
    let trimmed_base = base_url.trim_end_matches('/');
    let primary_endpoint = format!("{trimmed_base}{path}");

    let (ok, code) = curl_post_json_endpoint(&primary_endpoint, payload_str, identity, false);
    if ok {
        return (true, code, primary_endpoint);
    }

    let mut fallbacks: Vec<(String, bool)> = Vec::new();
    let fb_base = identity.fallback_hub_url.trim_end_matches('/');
    if !fb_base.is_empty() {
        let fb_ep = format!("{fb_base}{path}");
        if fb_ep != primary_endpoint {
            fallbacks.push((fb_ep, false));
        }
    }
    for lan_base in [
        "http://192.168.1.166:5487",
        "http://192.168.1.161:5487",
        "https://brians-mac-studio-468.tail23ad5.ts.net:5487",
        "http://127.0.0.1:5487",
    ] {
        let ep = format!("{lan_base}{path}");
        let use_resolve = lan_base.starts_with("https://");
        if ep != primary_endpoint || use_resolve {
            fallbacks.push((ep, use_resolve));
        }
    }

    let mut last_code = code;
    for (fb_url, use_resolve) in fallbacks {
        let (fb_ok, fb_code) = curl_post_json_endpoint(&fb_url, payload_str, identity, use_resolve);
        if fb_ok {
            return (true, fb_code, fb_url);
        }
        if fb_code != 0 {
            last_code = fb_code;
        }
    }
    (false, last_code, primary_endpoint)
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

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    for i in 0..=(buf.len() - 4) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

fn beam_curl_exchange(
    hub_base: &str,
    method: &str,
    path_and_query: &str,
    req_content_type: Option<&str>,
    req_accept: Option<&str>,
    req_actor_override: Option<&str>,
    req_body: &[u8],
    identity: &IdentityConfig,
    use_tailnet_resolve: bool,
) -> Option<(String, Vec<(String, String)>, Vec<u8>)> {
    use std::process::Stdio;
    let url = format!("{}{}", hub_base.trim_end_matches('/'), path_and_query);
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args([
        "--http1.1",
        "-sS",
        "-i",
        "--connect-timeout",
        "1.5",
        "-m",
        "10",
        "-H",
        "Expect:",
        "-H",
        "X-Chinwag-Beam: iroh-twine-spoke",
    ]);
    if method.eq_ignore_ascii_case("HEAD") {
        cmd.arg("-I");
    } else {
        cmd.args(["-X", method]);
    }
    if use_tailnet_resolve && url.contains("brians-mac-studio-468.tail23ad5.ts.net:5487") {
        cmd.args([
            "--resolve",
            "brians-mac-studio-468.tail23ad5.ts.net:5487:100.66.156.76",
        ]);
    }
    if !identity.api_key.is_empty() {
        cmd.args(["-H", &format!("Authorization: Bearer {}", identity.api_key)]);
    }
    let ascii_actor = req_actor_override
        .filter(|s| !s.is_empty() && s.is_ascii())
        .unwrap_or_else(|| {
            if !identity.actor_id.is_empty() {
                identity.actor_id.as_str()
            } else {
                "actor-nic"
            }
        });
    cmd.args(["-H", &format!("X-Chinwag-Actor: {ascii_actor}")]);
    if !identity.actor_id.is_empty() {
        cmd.args(["-H", &format!("X-Chinwag-Actor-Id: {}", identity.actor_id)]);
    }
    if !identity.machine_name.is_empty() {
        cmd.args(["-H", &format!("X-Chinwag-Machine: {}", identity.machine_name)]);
    }
    if let Some(ct) = req_content_type {
        if !ct.is_empty() {
            cmd.args(["-H", &format!("Content-Type: {ct}")]);
        }
    }
    if let Some(acc) = req_accept {
        if !acc.is_empty() {
            cmd.args(["-H", &format!("Accept: {acc}")]);
        }
    }
    if !req_body.is_empty() && !method.eq_ignore_ascii_case("HEAD") {
        cmd.args(["--data-binary", "@-"]);
    }
    cmd.arg(&url);
    cmd.stdin(if req_body.is_empty() || method.eq_ignore_ascii_case("HEAD") {
        Stdio::null()
    } else {
        Stdio::piped()
    });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());

    let mut child = cmd.spawn().ok()?;
    if !req_body.is_empty() && !method.eq_ignore_ascii_case("HEAD") {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(req_body);
        }
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }
    let sep = find_double_crlf(&out.stdout)?;
    let header_block = String::from_utf8_lossy(&out.stdout[..sep]).to_string();
    let body = if method.eq_ignore_ascii_case("HEAD") {
        Vec::new()
    } else {
        out.stdout[sep + 4..].to_vec()
    };
    let mut lines = header_block.lines();
    let status_line = lines.next()?.trim().to_string();
    if status_line.contains(" 400 ") && body.windows(12).any(|w| w == b"HTTPS server") {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let lower = key.to_ascii_lowercase();
            if lower == "transfer-encoding"
                || lower == "content-length"
                || lower == "connection"
                || lower == "keep-alive"
            {
                continue;
            }
            headers.push((key.to_string(), v.trim().to_string()));
        }
    }
    Some((status_line, headers, body))
}

fn forward_beam_http_request(
    hub_url: &str,
    fallback_hub_url: &str,
    method: &str,
    path_and_query: &str,
    req_content_type: Option<&str>,
    req_accept: Option<&str>,
    req_actor_override: Option<&str>,
    req_body: &[u8],
    identity: &IdentityConfig,
) -> (String, Vec<(String, String)>, Vec<u8>, String) {
    let mut candidates: Vec<(String, bool)> = Vec::new();
    let push_candidate = |list: &mut Vec<(String, bool)>, url: &str, use_resolve: bool| {
        let clean = url.trim_end_matches('/').to_string();
        if clean.is_empty()
            || clean.contains("127.0.0.1:5487")
            || clean.contains("localhost:5487")
            || clean.contains("[::1]:5487")
        {
            return;
        }
        if !list.iter().any(|(u, r)| u == &clean && *r == use_resolve) {
            list.push((clean, use_resolve));
        }
    };

    if !hub_url.contains("tail23ad5.ts.net") {
        push_candidate(&mut candidates, hub_url, false);
    }
    if !fallback_hub_url.is_empty() {
        push_candidate(&mut candidates, fallback_hub_url, false);
    }
    push_candidate(&mut candidates, "http://192.168.1.166:5487", false);
    push_candidate(&mut candidates, "http://192.168.1.161:5487", false);
    if hub_url.contains("tail23ad5.ts.net") {
        push_candidate(&mut candidates, hub_url, true);
        push_candidate(&mut candidates, hub_url, false);
    }
    push_candidate(
        &mut candidates,
        "https://brians-mac-studio-468.tail23ad5.ts.net:5487",
        true,
    );

    for (cand, use_resolve) in candidates {
        if let Some((status_line, headers, body)) = beam_curl_exchange(
            &cand,
            method,
            path_and_query,
            req_content_type,
            req_accept,
            req_actor_override,
            req_body,
            identity,
            use_resolve,
        ) {
            return (status_line, headers, body, cand);
        }
    }
    let err_body = json!({
        "ok": false,
        "error": "chinwag_beam_upstream_unreachable",
        "hub_url": hub_url,
        "fallback_hub_url": fallback_hub_url,
        "actor": identity.handle,
        "machine_name": identity.machine_name
    })
    .to_string()
    .into_bytes();
    (
        "HTTP/1.1 502 Bad Gateway".to_string(),
        vec![("Content-Type".to_string(), "application/json".to_string())],
        err_body,
        hub_url.to_string(),
    )
}

fn handle_beam_stream(
    mut stream: std::net::TcpStream,
    hub_url: &str,
    fallback_hub_url: &str,
    identity: &IdentityConfig,
) {
    use std::io::Read;
    use std::time::Duration;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));

    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => {
                if buf.is_empty() && n > 0 && chunk[0] == 0x16 {
                    // Reject TLS ClientHello immediately so browsers fall back to HTTP in <1ms
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = find_double_crlf(&buf) {
                    break pos;
                }
                if buf.len() > 65536 {
                    return;
                }
            }
            Err(_) => return,
        }
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_str.lines();
    let req_line = match lines.next() {
        Some(l) => l.trim(),
        None => return,
    };
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let raw_target = parts.next().unwrap_or("/");
    let path_and_query = if raw_target.starts_with('/') {
        raw_target.to_string()
    } else {
        format!("/{raw_target}")
    };

    let mut content_length: usize = 0;
    let mut req_content_type: Option<String> = None;
    let mut req_accept: Option<String> = None;
    let mut req_actor_override: Option<String> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let lower = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            match lower.as_str() {
                "content-length" => content_length = val.parse::<usize>().unwrap_or(0),
                "content-type" => req_content_type = Some(val),
                "accept" => req_accept = Some(val),
                "x-chinwag-actor" => req_actor_override = Some(val),
                _ => {}
            }
        }
    }

    let body_start = header_end + 4;
    while buf.len() < body_start.saturating_add(content_length) && buf.len() < 2 * 1024 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let req_body = if buf.len() > body_start {
        let end = std::cmp::min(buf.len(), body_start.saturating_add(content_length));
        &buf[body_start..end]
    } else {
        &[][..]
    };

    let (status_line, headers, resp_body, effective_hub) = forward_beam_http_request(
        hub_url,
        fallback_hub_url,
        method,
        &path_and_query,
        req_content_type.as_deref(),
        req_accept.as_deref(),
        req_actor_override.as_deref(),
        req_body,
        identity,
    );

    let mut resp_head = format!("{status_line}\r\n");
    for (k, v) in headers {
        resp_head.push_str(&format!("{k}: {v}\r\n"));
    }
    resp_head.push_str("X-Chinwag-Beam: iroh-twine-spoke\r\n");
    resp_head.push_str(&format!("X-Chinwag-Beam-Hub: {effective_hub}\r\n"));
    let ascii_beam_actor = if !identity.actor_id.is_empty() && identity.actor_id.is_ascii() {
        identity.actor_id.as_str()
    } else {
        "actor-nic"
    };
    resp_head.push_str(&format!("X-Chinwag-Beam-Actor: {ascii_beam_actor}\r\n"));
    resp_head.push_str(&format!(
        "X-Chinwag-Beam-Machine: {}\r\n",
        identity.machine_name
    ));
    resp_head.push_str(&format!("Content-Length: {}\r\n", resp_body.len()));
    resp_head.push_str("Connection: close\r\n\r\n");

    let _ = stream.write_all(resp_head.as_bytes());
    if !method.eq_ignore_ascii_case("HEAD") {
        let _ = stream.write_all(&resp_body);
    }
    let _ = stream.flush();
}

pub fn run_beam_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if args.iter().any(|a| a == "--help" || a == "-h" || a == "help") {
        let _ = writeln!(
            stdout,
            "Usage: chinwag beam [--listen 127.0.0.1:5487] [--hub <mission-control-url>] [--status | --once]"
        );
        return 0;
    }

    let identity = resolve_identity_config();
    let mut listen_addr = "127.0.0.1:5487".to_string();
    let mut explicit_listen = false;
    let mut hub_url = if identity.mission_control_url.contains("127.0.0.1:5487") {
        "https://brians-mac-studio-468.tail23ad5.ts.net:5487".to_string()
    } else {
        identity.mission_control_url.clone()
    };
    let mut is_status = false;
    let mut is_once = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "beam" => {
                i += 1;
            }
            "--listen" | "-l" if i + 1 < args.len() => {
                listen_addr = args[i + 1].clone();
                explicit_listen = true;
                i += 2;
            }
            "--hub" | "--url" | "-u" if i + 1 < args.len() => {
                hub_url = args[i + 1].trim_end_matches('/').to_string();
                i += 2;
            }
            "--status" => {
                is_status = true;
                i += 1;
            }
            "--once" => {
                is_once = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    if is_status {
        let (status_line, _headers, body, effective_hub) = forward_beam_http_request(
            &hub_url,
            &identity.fallback_hub_url,
            "GET",
            "/api/auth/whoami",
            None,
            Some("application/json"),
            None,
            &[],
            &identity,
        );
        let hub_ok = status_line.contains(" 200 ");
        let whoami_json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|_| json!(null));
        let out = json!({
            "ok": hub_ok,
            "command": "chinwag beam",
            "mode": "status",
            "beam_transport": "iroh-twine-spoke",
            "listen": listen_addr,
            "hub_url": hub_url,
            "fallback_hub_url": identity.fallback_hub_url,
            "effective_hub_url": effective_hub,
            "hub_reachable": hub_ok,
            "hub_status_line": status_line,
            "actor_id": identity.actor_id,
            "actor": identity.handle,
            "display_name": identity.display_name,
            "machine_name": identity.machine_name,
            "headers_injected": [
                "X-Chinwag-Actor",
                "X-Chinwag-Actor-Id",
                "X-Chinwag-Machine",
                "X-Chinwag-Beam",
                "Authorization"
            ],
            "whoami": whoami_json
        });
        let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return if hub_ok { 0 } else { 1 };
    }

    if is_once {
        let listener = match std::net::TcpListener::bind(&listen_addr) {
            Ok(l) => l,
            Err(_) if !explicit_listen => match std::net::TcpListener::bind("127.0.0.1:0") {
                Ok(l) => l,
                Err(e) => {
                    let _ = writeln!(stderr, "chinwag beam: failed to bind listener: {e}");
                    return 1;
                }
            },
            Err(e) => {
                let _ = writeln!(stderr, "chinwag beam: failed to bind {listen_addr}: {e}");
                return 1;
            }
        };
        let bound_addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| listen_addr.clone());
        let hub_clone = hub_url.clone();
        let fb_clone = identity.fallback_hub_url.clone();
        let id_clone = identity.clone();
        let handle = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handle_beam_stream(stream, &hub_clone, &fb_clone, &id_clone);
            }
        });
        let probe_url = format!("http://{bound_addr}/api/auth/whoami");
        let probe_out = Command::new("/usr/bin/curl")
            .args(["-sS", "-m", "8", &probe_url])
            .output();
        let _ = handle.join();
        let (probe_ok, whoami_val) = match probe_out {
            Ok(o) if o.status.success() => {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&o.stdout).unwrap_or_else(|_| json!(null));
                let ok = parsed.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                (ok, parsed)
            }
            _ => (false, json!(null)),
        };
        let out = json!({
            "ok": probe_ok,
            "command": "chinwag beam",
            "mode": "once",
            "beam_transport": "iroh-twine-spoke",
            "bound_listen": bound_addr,
            "hub_url": hub_url,
            "fallback_hub_url": identity.fallback_hub_url,
            "actor_id": identity.actor_id,
            "actor": identity.handle,
            "display_name": identity.display_name,
            "machine_name": identity.machine_name,
            "whoami": whoami_val
        });
        let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return if probe_ok { 0 } else { 1 };
    }

    let listener = match std::net::TcpListener::bind(&listen_addr) {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AddrInUse
                && identity
                    .machine_name
                    .to_ascii_lowercase()
                    .starts_with("brians-mac-studio")
            {
                let msg = json!({
                    "ok": true,
                    "event": "chinwag_beam_hub_already_active",
                    "listen": listen_addr,
                    "machine_name": identity.machine_name,
                    "actor": identity.handle
                });
                let _ = writeln!(stdout, "{msg}");
                return 0;
            }
            let _ = writeln!(stderr, "chinwag beam: failed to bind {listen_addr}: {e}");
            return 1;
        }
    };

    let banner = json!({
        "ok": true,
        "event": "chinwag_beam_listening",
        "beam_transport": "iroh-twine-spoke",
        "listen": listen_addr,
        "hub_url": hub_url,
        "fallback_hub_url": identity.fallback_hub_url,
        "actor_id": identity.actor_id,
        "actor": identity.handle,
        "machine_name": identity.machine_name
    });
    let _ = writeln!(stdout, "{banner}");
    let _ = stdout.flush();

    if listen_addr == "127.0.0.1:5487" {
        if let Ok(v6_listener) = std::net::TcpListener::bind("[::1]:5487") {
            let hub_v6 = hub_url.clone();
            let fb_v6 = identity.fallback_hub_url.clone();
            let id_v6 = identity.clone();
            std::thread::spawn(move || {
                for incoming in v6_listener.incoming() {
                    if let Ok(stream) = incoming {
                        let hc = hub_v6.clone();
                        let fc = fb_v6.clone();
                        let ic = id_v6.clone();
                        std::thread::spawn(move || {
                            handle_beam_stream(stream, &hc, &fc, &ic);
                        });
                    }
                }
            });
        }
    }

    for incoming in listener.incoming() {
        if let Ok(stream) = incoming {
            let hub_clone = hub_url.clone();
            let fb_clone = identity.fallback_hub_url.clone();
            let id_clone = identity.clone();
            std::thread::spawn(move || {
                handle_beam_stream(stream, &hub_clone, &fb_clone, &id_clone);
            });
        }
    }
    0
}

pub fn run_relay_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if args.iter().any(|a| a == "--help" || a == "-h" || a == "help") {
        let _ = writeln!(
            stdout,
            "Usage:\n  \
             chinwag relay <status | brief-mgmt | send | reply | beam>\n  \
             chinwag relay send [--seat <SEAT|ALL>] [--ticket <CHWG-id>] [--channel <#mgmt>] [--title \"<title>\"] --message \"<text>\"\n  \
             chinwag reply [--url <mission-control-url>] --channel <#mgmt|#eng-swarm|#product-studio|#bizfin-legal|#s-and-m-growth|#infra-cleanroom|#pa-private> --from <SEAT> --message \"<text>\" [--run <run-id>] [--ticket <CHWG-id>]\n  \
             chinwag beam [--listen 127.0.0.1:5487] [--hub <mission-control-url>] [--status | --once]"
        );
        return 0;
    }

    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "beam" => run_beam_cli(&args[1..], stdout, stderr),
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
                "binary": "/opt/homebrew/bin/chinwag",
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
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
            let planner_db = &format!("{home}/WORKSPACE/delivery-planner/data/planner.sqlite");
            let crdb_path = &format!("{home}/WORKSPACE/chinwag/.chinwag/state.crdb");

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
                    1. UNPAUSE YOUR SLACK CHANNEL LISTENER FOR CHINWAG RUST RELAY: Do NOT call the retired Paperclip HTTP API (:3110), DO keep your Slack channel listener ({}) and AgentMail listener ({}) ACTIVE for `[Paperclip] {} |` messages dispatched by our native Rust `/opt/homebrew/bin/chinwag relay` binary.\n\
                    2. POST CONFIRMATION IN `MGMT` ({}): Immediately post a short confirmation message in the Grok Bot `MGMT` group room (`{}`) confirming your seat (`{}` / `{}`), your direct reports {:?}, and that you are running on Chinwag Mission Control (`https://brians-mac-studio-468.tail23ad5.ts.net:5487/`).\n\
                    3. INFRA BOT (`407d2c36-b5c3-491a-9e08-527ad7f18a06`): Because `eng`, `bizfin`, `product`, and `s-and-m` paused their routines earlier today, please immediately post this Management Charter briefing directly into the Grok Bot `MGMT` group conversation (`c5a97346-e424-44bf-90d2-9caaa7594c11`) AND send a direct agent message to `eng` (`a692d662-495c-4def-896b-6a787087de01`), `bizfin` (`e484d158-8f4d-41f3-a7c9-b2bf8167cbcb`), `product` (`382e7010-ea4d-48f7-a1bb-96dca02a0921`), `s-and-m` (`16593278-278d-4a2b-9e94-3a189bcaf599`), and `Personal Bot` (`419c9d1d-f01c-4d3c-9972-93e56f95c5d9`) telling them to post their readiness check-in in `MGMT` (`c5a97346-e424-44bf-90d2-9caaa7594c11`)!\n\
                    4. PURE CHINWAG STACK: Hindsight (:8888) and Wiki.js (:4320) are retired. Use `/opt/homebrew/bin/chinwag memory recall | retain | tombstone` (`.chinwag/state.crdb` + `.chinwag/memory.crdb.leann`) and Docus Wiki (`:8795` / `:5487` `Docs · Wiki`).\n\
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
        "reply" | "post" => {
            let identity = resolve_identity_config();
            let mut channel = "#mgmt".to_string();
            let mut from_seat = "ENG".to_string();
            let mut explicit_from = false;
            let mut message = String::new();
            let mut run_id = format!("chinwag-reply-{}", now_ms());
            let mut item_key = "CHWG-BRIDGE-1".to_string();
            let mut mission_control_url = identity.mission_control_url.clone();

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--channel" | "-c" if i + 1 < args.len() => {
                        channel = args[i + 1].clone();
                        i += 2;
                    }
                    "--from" | "--seat" | "-f" if i + 1 < args.len() => {
                        from_seat = args[i + 1].clone();
                        explicit_from = true;
                        i += 2;
                    }
                    "--url" | "-u" if i + 1 < args.len() => {
                        mission_control_url = args[i + 1].trim_end_matches('/').to_string();
                        i += 2;
                    }
                    "--message" | "--body" | "-m" if i + 1 < args.len() => {
                        message = args[i + 1].clone();
                        i += 2;
                    }
                    "--run" | "-r" if i + 1 < args.len() => {
                        run_id = args[i + 1].clone();
                        i += 2;
                    }
                    "--item" | "--ticket" | "-t" if i + 1 < args.len() => {
                        item_key = args[i + 1].clone();
                        i += 2;
                    }
                    other => {
                        if message.is_empty() {
                            message = other.to_string();
                        } else {
                            message.push(' ');
                            message.push_str(other);
                        }
                        i += 1;
                    }
                }
            }

            if message.trim().is_empty() {
                let _ = writeln!(
                    stderr,
                    "Usage: chinwag reply [--url <mission-control-url>] --channel <#mgmt|#eng-swarm|#product-studio|#bizfin-legal|#s-and-m-growth|#infra-cleanroom|#pa-private> --from <SEAT> --message \"<text>\" [--run <run-id>] [--ticket <CHWG-id>]"
                );
                return 2;
            }

            let sender_label = if !explicit_from && identity.actor_id == "actor-nic" {
                identity.handle.clone()
            } else if from_seat.starts_with("● ") {
                from_seat.clone()
            } else {
                format!(
                    "[{}]",
                    from_seat.trim_matches(|c| c == '[' || c == ']').to_uppercase()
                )
            };
            let sender_cast = if sender_label.starts_with("● ") {
                "●"
            } else {
                "■"
            };

            let mut role_str = format!(
                "Seat {} · Chinwag Reply ({})",
                from_seat.to_uppercase(),
                identity.machine_name
            );
            if role_str.len() > 76 {
                role_str.truncate(76);
            }
            let mut engine_str = format!("chinwag reply ({})", identity.machine_name);
            if engine_str.len() > 76 {
                engine_str.truncate(76);
            }

            let post_payload = json!({
                "channelId": channel,
                "sender": sender_label,
                "senderCast": sender_cast,
                "role": role_str,
                "engine": engine_str,
                "body": format!("{} `[relay-receipt run={}]`", message.trim(), run_id),
                "itemKey": item_key
            });

            let payload_str = post_payload.to_string();
            let (mut http_ok, mut http_code, mut effective_endpoint) =
                post_mission_control_with_fallback(
                    &mission_control_url,
                    "/api/comms/channel",
                    &payload_str,
                    &identity,
                );
            if !http_ok {
                let (ok2, code2, ep2) = post_mission_control_with_fallback(
                    &mission_control_url,
                    "/api/comms/channels",
                    &payload_str,
                    &identity,
                );
                if ok2 {
                    http_ok = ok2;
                    http_code = code2;
                    effective_endpoint = ep2;
                }
            }

            let out = json!({
                "ok": http_ok,
                "action": "reply",
                "channel": channel,
                "from": from_seat,
                "actor": identity.handle,
                "actor_id": identity.actor_id,
                "machine_name": identity.machine_name,
                "run_id": run_id,
                "item_key": item_key,
                "mission_control_url": mission_control_url,
                "effective_endpoint": effective_endpoint,
                "http_status": http_code,
                "delivered_to_mission_control_5487": http_ok,
                "ui_url": mission_control_url
            });
            let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            0
        }
        "send" | "dispatch" => {
            let mut target_seat = "ALL".to_string();
            let mut ticket = "CHWG-BRIDGE-1".to_string();
            let mut title = "Founder Message from Chinwag Mission Control (:5487)".to_string();
            let mut message = String::new();
            let mut reply_channel = "#mgmt".to_string();

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--seat" | "--to" | "-s" if i + 1 < args.len() => {
                        target_seat = args[i + 1].to_uppercase();
                        i += 2;
                    }
                    "--ticket" | "--item" | "-t" if i + 1 < args.len() => {
                        ticket = args[i + 1].clone();
                        i += 2;
                    }
                    "--title" if i + 1 < args.len() => {
                        title = args[i + 1].clone();
                        i += 2;
                    }
                    "--channel" | "-c" if i + 1 < args.len() => {
                        reply_channel = args[i + 1].clone();
                        i += 2;
                    }
                    "--message" | "--body" | "-m" if i + 1 < args.len() => {
                        message = args[i + 1].clone();
                        i += 2;
                    }
                    other => {
                        if message.is_empty() {
                            message = other.to_string();
                        } else {
                            message.push(' ');
                            message.push_str(other);
                        }
                        i += 1;
                    }
                }
            }

            if message.trim().is_empty() {
                let _ = writeln!(
                    stderr,
                    "Usage: chinwag relay send [--seat <SEAT|ALL>] [--ticket <CHWG-id>] [--channel <#mgmt>] [--title \"<title>\"] --message \"<text>\""
                );
                return 2;
            }

            let run_ts = now_ms();
            let mut receipts = Vec::new();
            for seat in GROKBOT_MGMT_ROSTER {
                let seat_upper = seat.seat.to_uppercase();
                let matches = target_seat == "ALL"
                    || target_seat == "#MGMT"
                    || target_seat == "MGMT"
                    || target_seat == seat_upper
                    || (target_seat == "HOUSEKEEPING" && seat_upper == "INFRA");
                if !matches {
                    continue;
                }
                let listener_prefix = if seat_upper == "INFRA" {
                    "HOUSEKEEPING"
                } else if seat_upper == "PA" {
                    "PRODUCT"
                } else {
                    seat.seat
                };
                let run_id = format!("chinwag-ui-{}-{}-{}", seat.seat.to_lowercase(), ticket.to_lowercase(), run_ts);
                let subj = format!("[Paperclip] {} | {}: {}", listener_prefix, ticket, title);
                let msg = format!(
                    "{}\n\
                    Run: {}   Wake reason: issue_assigned (chinwag-rust-relay)\n\
                    Receipt marker (include in any receipt comment): [relay-receipt run={}]\n\
                    Task: {} — https://brians-mac-studio-468.tail23ad5.ts.net:5487/\n\n\
                    MESSAGE FROM BRIAN SPECTOR (CEO) IN CHINWAG MISSION CONTROL (:5487):\n\
                    {}\n\n\
                    HOW TO REPLY DIRECTLY IN CHINWAG UI (SO BRIAN DOES NOT HAVE TO OPEN GROK BOT):\n\
                    Run this command on Mac Studio to post your reply directly into Chinwag Mission Control (:5487):\n\
                    `/opt/homebrew/bin/chinwag reply --channel \"{}\" --from \"{}\" --run \"{}\" --ticket \"{}\" --message \"<your reply>\"`",
                    subj,
                    run_id,
                    run_id,
                    ticket,
                    message,
                    reply_channel,
                    seat.seat,
                    run_id,
                    ticket
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

                receipts.push(json!({
                    "seat": seat.seat,
                    "listener_prefix": listener_prefix,
                    "run_id": run_id,
                    "ticket": ticket,
                    "slack_delivered": slack_delivered,
                    "slack_http_status": slack_http_code,
                    "agentmail_delivered": email_delivered,
                    "agentmail_http_status": email_http_code
                }));
            }

            let out = json!({
                "ok": true,
                "action": "send",
                "target": target_seat,
                "ticket": ticket,
                "reply_channel": reply_channel,
                "receipts": receipts
            });
            let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            0
        }
        _ => {
            let _ = writeln!(
                stderr,
                "Usage: chinwag relay <status | brief-mgmt | send | reply | beam> OR chinwag reply --channel <#mgmt> --from <SEAT> --message \"<text>\""
            );
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_help_flags_do_not_broadcast() {
        for flag in ["--help", "-h", "help"] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let args = vec!["send".to_string(), flag.to_string()];
            let code = run_relay_cli(&args, &mut out, &mut err);
            assert_eq!(code, 0);
            let out_str = String::from_utf8_lossy(&out);
            assert!(out_str.contains("Usage:"));
            assert!(err.is_empty());

            let mut out2 = Vec::new();
            let mut err2 = Vec::new();
            let args2 = vec!["reply".to_string(), flag.to_string()];
            let code2 = run_relay_cli(&args2, &mut out2, &mut err2);
            assert_eq!(code2, 0);
            assert!(String::from_utf8_lossy(&out2).contains("Usage:"));
            assert!(err2.is_empty());
        }
    }

    #[test]
    fn relay_send_empty_message_is_rejected() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let args = vec!["send".to_string(), "--seat".to_string(), "ENG".to_string()];
        let code = run_relay_cli(&args, &mut out, &mut err);
        assert_eq!(code, 2);
        assert!(out.is_empty());
        assert!(String::from_utf8_lossy(&err).contains("Usage: chinwag relay send"));
    }

    #[test]
    fn beam_help_exits_cleanly() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let args = vec!["--help".to_string()];
        let code = run_beam_cli(&args, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&out).contains("Usage: chinwag beam"));
        assert!(err.is_empty());
    }
}
