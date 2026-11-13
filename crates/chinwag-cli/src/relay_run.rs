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

#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RelayPolicy {
    management_channel: String,
    seats: Vec<GrokBotSeat>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrokBotSeat {
    pub seat: String,
    pub grokbot_uuid: String,
    pub grokbot_name: String,
    pub slack_channel: String,
    pub webhook_env: String,
    pub agentmail_inbox: String,
    #[serde(default)]
    pub direct_reports: Vec<String>,
}

fn relay_policy() -> Result<RelayPolicy, String> {
    let Some(manifest) = chinwag_cli::canonical_seat_pubkeys::configured_manifest() else {
        return Ok(RelayPolicy::default());
    };
    manifest
        .extensions
        .get("relay")
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|error| format!("invalid fleet relay policy: {error}"))
        })
        .unwrap_or_else(|| Ok(RelayPolicy::default()))
}

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
    "unconfigured".to_string()
}

pub fn resolve_identity_config() -> IdentityConfig {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let local_host = detect_local_hostname();

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
                let val = v
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .trim()
                    .to_string();
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
    if let Ok(raw_cfg) = fs::read_to_string(&config_json_path)
        && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw_cfg)
    {
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

    if let Ok(env_actor_id) = env::var("CHINWAG_ACTOR_ID")
        && !env_actor_id.trim().is_empty()
    {
        actor_id = env_actor_id.trim().to_string();
    }
    if let Ok(env_actor) = env::var("CHINWAG_ACTOR")
        && !env_actor.trim().is_empty()
    {
        handle = env_actor.trim().to_string();
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

    if actor_id.is_empty() {
        actor_id = handle.clone();
    }
    if handle.is_empty() {
        handle = "unconfigured".into();
    }
    if display_name.is_empty() {
        display_name = handle.clone();
    }

    if let Ok(env_url) = env::var("CHINWAG_MISSION_CONTROL_URL")
        && !env_url.trim().is_empty()
    {
        mission_control_url = env_url.trim().to_string();
    }
    if mission_control_url.is_empty() && !studio_origin.is_empty() {
        mission_control_url = studio_origin;
    }
    if mission_control_url.is_empty() && !cfg_studio_origin.is_empty() {
        mission_control_url = cfg_studio_origin;
    }
    if mission_control_url.is_empty() {
        mission_control_url =
            env::var("CHINWAG_HUB_URL").unwrap_or_else(|_| "http://127.0.0.1:5487".into());
    }
    mission_control_url = mission_control_url.trim_end_matches('/').to_string();
    fallback_hub_url = fallback_hub_url.trim_end_matches('/').to_string();

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

pub fn resolve_agent_relay_identity(seat: &str, base: &IdentityConfig) -> IdentityConfig {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let clean_seat = seat
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_start_matches("■ ")
        .trim()
        .to_ascii_uppercase();
    let seat_slug = clean_seat
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();

    let mut agent_key = env::var("CHINWAG_AGENT_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if agent_key.is_empty() {
        let studio_agent_key =
            PathBuf::from(&home).join("WORKSPACE/delivery-planner/data/agent-relay.key");
        if let Ok(k) = fs::read_to_string(studio_agent_key) {
            agent_key = k.trim().to_string();
        }
    }
    if agent_key.is_empty() {
        let local_agent_key = PathBuf::from(&home).join(".chinwag/agent-relay.key");
        if let Ok(k) = fs::read_to_string(local_agent_key) {
            agent_key = k.trim().to_string();
        }
    }
    if agent_key.is_empty() {
        agent_key = base.api_key.clone();
    }

    IdentityConfig {
        actor_id: format!("agent-{seat_slug}"),
        handle: format!("[{clean_seat}]"),
        display_name: format!("■ {clean_seat} Seat Relay"),
        machine_name: base.machine_name.clone(),
        mission_control_url: base.mission_control_url.clone(),
        fallback_hub_url: base.fallback_hub_url.clone(),
        api_key: agent_key,
    }
}

fn curl_post_json_endpoint(
    endpoint_url: &str,
    payload_str: &str,
    identity: &IdentityConfig,
    _use_tailnet_resolve: bool,
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
    if !identity.api_key.is_empty() {
        cmd.args(["-H", &format!("Authorization: Bearer {}", identity.api_key)]);
    }
    if identity.actor_id.starts_with("agent-") {
        let seat_clean = identity.handle.trim_matches(|c| c == '[' || c == ']');
        cmd.args(["-H", &format!("X-Chinwag-Agent-Seat: {seat_clean}")]);
        cmd.args(["-H", &format!("X-Chinwag-Actor-Id: {}", identity.actor_id)]);
    } else if !identity.actor_id.is_empty() {
        cmd.args(["-H", &format!("X-Chinwag-Actor: {}", identity.actor_id)]);
        cmd.args(["-H", &format!("X-Chinwag-Actor-Id: {}", identity.actor_id)]);
    }
    if !identity.machine_name.is_empty() {
        cmd.args([
            "-H",
            &format!("X-Chinwag-Machine: {}", identity.machine_name),
        ]);
    }
    cmd.args(["--data", payload_str, endpoint_url]);
    match cmd.output() {
        Ok(out) => {
            let code_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let code = code_str.parse::<u16>().unwrap_or(0);
            ((200..300).contains(&code), code)
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
            ((200..300).contains(&code), code)
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
    let url = format!(
        "https://api.agentmail.to/v0/inboxes/{}/messages/send",
        encoded_inbox
    );
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
            ((200..300).contains(&code), code)
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

/// Response headers as ordered `(name, value)` pairs.
type BeamHeaders = Vec<(String, String)>;
/// Status line, headers and body returned by one upstream exchange.
type BeamResponse = (String, BeamHeaders, Vec<u8>);

/// One inbound beam request to be replayed against the upstream hub.
struct BeamRequest<'a> {
    method: &'a str,
    path_and_query: &'a str,
    content_type: Option<&'a str>,
    accept: Option<&'a str>,
    actor_override: Option<&'a str>,
    body: &'a [u8],
}

fn beam_curl_exchange(
    hub_base: &str,
    request: &BeamRequest<'_>,
    identity: &IdentityConfig,
    _use_tailnet_resolve: bool,
) -> Option<BeamResponse> {
    use std::process::Stdio;
    let BeamRequest {
        method,
        path_and_query,
        content_type: req_content_type,
        accept: req_accept,
        actor_override: req_actor_override,
        body: req_body,
    } = *request;
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
    if !identity.api_key.is_empty() {
        cmd.args(["-H", &format!("Authorization: Bearer {}", identity.api_key)]);
    }
    let ascii_actor = req_actor_override
        .filter(|s| !s.is_empty() && s.is_ascii())
        .unwrap_or(if !identity.actor_id.is_empty() {
            identity.actor_id.as_str()
        } else {
            "actor-nic"
        });
    cmd.args(["-H", &format!("X-Chinwag-Actor: {ascii_actor}")]);
    if !identity.actor_id.is_empty() {
        cmd.args(["-H", &format!("X-Chinwag-Actor-Id: {}", identity.actor_id)]);
    }
    if !identity.machine_name.is_empty() {
        cmd.args([
            "-H",
            &format!("X-Chinwag-Machine: {}", identity.machine_name),
        ]);
    }
    if let Some(ct) = req_content_type
        && !ct.is_empty()
    {
        cmd.args(["-H", &format!("Content-Type: {ct}")]);
    }
    if let Some(acc) = req_accept
        && !acc.is_empty()
    {
        cmd.args(["-H", &format!("Accept: {acc}")]);
    }
    if !req_body.is_empty() && !method.eq_ignore_ascii_case("HEAD") {
        cmd.args(["--data-binary", "@-"]);
    }
    cmd.arg(&url);
    cmd.stdin(
        if req_body.is_empty() || method.eq_ignore_ascii_case("HEAD") {
            Stdio::null()
        } else {
            Stdio::piped()
        },
    );
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());

    let mut child = cmd.spawn().ok()?;
    if !req_body.is_empty()
        && !method.eq_ignore_ascii_case("HEAD")
        && let Some(mut stdin) = child.stdin.take()
    {
        let _ = stdin.write_all(req_body);
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
    request: &BeamRequest<'_>,
    identity: &IdentityConfig,
) -> (String, BeamHeaders, Vec<u8>, String) {
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

    push_candidate(&mut candidates, hub_url, false);
    if !fallback_hub_url.is_empty() {
        push_candidate(&mut candidates, fallback_hub_url, false);
    }

    for (cand, use_resolve) in candidates {
        if let Some((status_line, headers, body)) =
            beam_curl_exchange(&cand, request, identity, use_resolve)
        {
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
        &BeamRequest {
            method,
            path_and_query: &path_and_query,
            content_type: req_content_type.as_deref(),
            accept: req_accept.as_deref(),
            actor_override: req_actor_override.as_deref(),
            body: req_body,
        },
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
    if args
        .iter()
        .any(|a| a == "--help" || a == "-h" || a == "help")
    {
        let _ = writeln!(
            stdout,
            "Usage: chinwag beam [--listen 127.0.0.1:5487] [--hub <mission-control-url>] [--status | --once]"
        );
        return 0;
    }

    let identity = resolve_identity_config();
    let mut listen_addr = "127.0.0.1:5487".to_string();
    let mut explicit_listen = false;
    let mut hub_url = identity.mission_control_url.clone();
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
            &BeamRequest {
                method: "GET",
                path_and_query: "/api/auth/whoami",
                content_type: None,
                accept: Some("application/json"),
                actor_override: None,
                body: &[],
            },
            &identity,
        );
        let hub_ok = status_line.contains(" 200 ");
        let whoami_json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
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
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_default()
        );
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
                    serde_json::from_slice(&o.stdout).unwrap_or(serde_json::Value::Null);
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
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_default()
        );
        return if probe_ok { 0 } else { 1 };
    }

    let listener = match std::net::TcpListener::bind(&listen_addr) {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AddrInUse
                && identity.machine_name.to_ascii_lowercase().is_empty()
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

    if listen_addr == "127.0.0.1:5487"
        && let Ok(v6_listener) = std::net::TcpListener::bind("[::1]:5487")
    {
        let hub_v6 = hub_url.clone();
        let fb_v6 = identity.fallback_hub_url.clone();
        let id_v6 = identity.clone();
        std::thread::spawn(move || {
            for stream in v6_listener.incoming().flatten() {
                let hc = hub_v6.clone();
                let fc = fb_v6.clone();
                let ic = id_v6.clone();
                std::thread::spawn(move || {
                    handle_beam_stream(stream, &hc, &fc, &ic);
                });
            }
        });
    }

    for stream in listener.incoming().flatten() {
        let hub_clone = hub_url.clone();
        let fb_clone = identity.fallback_hub_url.clone();
        let id_clone = identity.clone();
        std::thread::spawn(move || {
            handle_beam_stream(stream, &hub_clone, &fb_clone, &id_clone);
        });
    }
    0
}

pub fn run_relay_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if args
        .iter()
        .any(|a| a == "--help" || a == "-h" || a == "help")
    {
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

    let relay = match relay_policy() {
        Ok(policy) => policy,
        Err(error) => {
            let _ = writeln!(stderr, "chinwag relay: {error}");
            return 2;
        }
    };
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "beam" => run_beam_cli(&args[1..], stdout, stderr),
        "status" => {
            let seats: Vec<_> = relay
                .seats
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
                "binary": "chinwag",
                "legacy_python_bridge_retired": true,
                "mgmt_group_channel": {
                    "name": "MGMT",
                    "uuid": relay.management_channel,
                    "member_count": relay.seats.len(),
                    "member_uuids": relay.seats.iter().map(|s| s.grokbot_uuid.as_str()).collect::<Vec<_>>()
                },
                "seats": seats
            });
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            0
        }
        "brief-mgmt" => {
            let _ = writeln!(
                stderr,
                "chinwag relay: use an explicit configured recipient and message with relay send"
            );
            2
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
                    from_seat
                        .trim_matches(|c| c == '[' || c == ']')
                        .to_uppercase()
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

            let effective_identity = if sender_cast == "■" {
                resolve_agent_relay_identity(&from_seat, &identity)
            } else {
                identity.clone()
            };
            let auth_key_scope = if sender_cast == "■" {
                "agent-relay.key (non-human seat credential)"
            } else if effective_identity.actor_id == "actor-nic" {
                "nic-api.key (co-founder credential)"
            } else {
                "delivery-api.key (founder credential)"
            };

            let payload_str = post_payload.to_string();
            let (mut http_ok, mut http_code, mut effective_endpoint) =
                post_mission_control_with_fallback(
                    &mission_control_url,
                    "/api/comms/channel",
                    &payload_str,
                    &effective_identity,
                );
            if !http_ok {
                let (ok2, code2, ep2) = post_mission_control_with_fallback(
                    &mission_control_url,
                    "/api/comms/channels",
                    &payload_str,
                    &effective_identity,
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
                "actor": effective_identity.handle,
                "actor_id": effective_identity.actor_id,
                "auth_key_scope": auth_key_scope,
                "machine_name": effective_identity.machine_name,
                "run_id": run_id,
                "item_key": item_key,
                "mission_control_url": mission_control_url,
                "effective_endpoint": effective_endpoint,
                "http_status": http_code,
                "delivered_to_mission_control_5487": http_ok,
                "ui_url": mission_control_url
            });
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&out).unwrap_or_default()
            );
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
            for seat in &relay.seats {
                let seat_upper = seat.seat.to_uppercase();
                let matches = target_seat == "ALL"
                    || target_seat == "#MGMT"
                    || target_seat == "MGMT"
                    || target_seat == seat_upper;
                if !matches {
                    continue;
                }
                let listener_prefix = seat.seat.as_str();
                let run_id = format!(
                    "chinwag-ui-{}-{}-{}",
                    seat.seat.to_lowercase(),
                    ticket.to_lowercase(),
                    run_ts
                );
                let subj = format!("[Paperclip] {} | {}: {}", listener_prefix, ticket, title);
                let msg = format!(
                    "{subj}\nRun: {run_id}\nTask: {ticket}\n{message}\n\nReply with: chinwag reply --channel \"{reply_channel}\" --from \"{}\" --run \"{run_id}\" --ticket \"{ticket}\" --message \"<your reply>\"",
                    seat.seat
                );

                let (slack_delivered, slack_http_code) =
                    if let Some(url) = read_webhook_url(&seat.webhook_env) {
                        post_slack_webhook(&url, &msg)
                    } else {
                        (false, 0)
                    };

                let (email_delivered, email_http_code) =
                    if seat.agentmail_inbox.contains("@agentmail.to")
                        || seat.agentmail_inbox.contains("@mail.grokbot.com")
                    {
                        send_agentmail(&seat.agentmail_inbox, &subj, &msg)
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
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&out).unwrap_or_default()
            );
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

    #[test]
    fn agent_relay_identity_never_impersonates_brian() {
        let base = IdentityConfig {
            actor_id: "actor-brian".to_string(),
            handle: "● Brian".to_string(),
            display_name: "Brian Spector".to_string(),
            machine_name: "unconfigured".to_string(),
            mission_control_url: "http://127.0.0.1:5487".to_string(),
            fallback_hub_url: "http://127.0.0.1:5488".to_string(),
            api_key: "fallback-test-key".to_string(),
        };
        let infra_id = resolve_agent_relay_identity("INFRA", &base);
        assert_eq!(infra_id.actor_id, "agent-infra");
        assert_eq!(infra_id.handle, "[INFRA]");
        assert!(!infra_id.actor_id.contains("brian"));
        assert!(!infra_id.handle.contains("Brian"));
    }
}
