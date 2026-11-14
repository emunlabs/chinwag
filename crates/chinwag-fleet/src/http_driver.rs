// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Topology-independent HTTP & manifest-declared auxiliary seat drivers.
//! Uses `/usr/bin/curl -q -K -` with stdin config/header piping so secrets never touch argv.
#![forbid(unsafe_code)]

use crate::{
    CredentialIsolation, DriverSpec, EgressPolicy, ExecutionContext, ExecutionOutcome,
    FleetManifest, FleetPolicyError, FleetResult, HttpUsageSummary, ResolvedDispatchPlan,
    WriteMode, compose_prompt, resolve_binary, resolve_dispatch_plan,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
#[cfg(test)]
use tempfile::TempDir;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpAuthFetchRule {
    pub host: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    pub header_name: String,
    #[serde(default)]
    pub header_prefix: Option<String>,
    pub secret_env_file: PathBuf,
    pub secret_key: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpToolEnvInjection {
    pub env_var: String,
    #[serde(default)]
    pub literal: Option<String>,
    #[serde(default)]
    pub secret_env_file: Option<PathBuf>,
    #[serde(default)]
    pub secret_key: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpToolConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_write_roots: Vec<PathBuf>,
    #[serde(default)]
    pub auth_fetches: Vec<HttpAuthFetchRule>,
    #[serde(default)]
    pub env_injections: Vec<HttpToolEnvInjection>,
    #[serde(default)]
    pub max_turns: Option<usize>,
    #[serde(default)]
    pub max_tool_calls: Option<usize>,
    #[serde(default)]
    pub max_output_tokens: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTransportPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_backoff_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_backoff_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_time_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stall_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_http1_1: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenAiStreamMode {
    None,
    Sse,
}

impl OpenAiStreamMode {
    pub(crate) fn parse(raw: &str) -> FleetResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
            Ok(Self::None)
        } else if trimmed.eq_ignore_ascii_case("sse") {
            Ok(Self::Sse)
        } else {
            Err(FleetPolicyError::InvalidManifest(format!(
                "unsupported OpenAI stream_mode: {raw}"
            )))
        }
    }

    pub(crate) fn is_sse(self) -> bool {
        matches!(self, Self::Sse)
    }
}

pub(crate) fn validate_transport_policy(policy: Option<&HttpTransportPolicy>) -> FleetResult<()> {
    let Some(policy) = policy else {
        return Ok(());
    };
    if policy.connect_timeout_secs == Some(0) {
        return Err(FleetPolicyError::InvalidManifest(
            "transport.connect_timeout_secs must be positive".into(),
        ));
    }
    if policy.keepalive_time_secs == Some(0) {
        return Err(FleetPolicyError::InvalidManifest(
            "transport.keepalive_time_secs must be positive".into(),
        ));
    }
    if policy.stall_timeout_secs == Some(0) {
        return Err(FleetPolicyError::InvalidManifest(
            "transport.stall_timeout_secs must be positive".into(),
        ));
    }
    Ok(())
}

/// Validates that the configured credential isolation path/binary is ready without leaking keys.
pub fn verify_credential_readiness(
    manifest: &FleetManifest,
    cwd: &Path,
    isolation: &CredentialIsolation,
    required_key: Option<&str>,
) -> FleetResult<bool> {
    match isolation {
        CredentialIsolation::NoneLocal => Ok(true),
        CredentialIsolation::FirstPartyCliOauth { preflight_cmd, .. } => {
            if let Some((bin, args)) = preflight_cmd.split_first() {
                let Ok(binary) = resolve_binary(bin) else {
                    return Ok(false);
                };
                let status = Command::new(binary)
                    .args(args)
                    .current_dir(cwd)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                Ok(status.is_ok_and(|s| s.success()))
            } else {
                Ok(true)
            }
        }
        CredentialIsolation::SecretEnvFile { path, key_map } => {
            let resolved = manifest.resolve_path(path, cwd);
            crate::keys::validate_private_key_path(&resolved)?;
            let target_key = required_key.unwrap_or_default();
            if target_key.is_empty() && key_map.is_empty() {
                return Ok(true);
            }
            let val = read_secret_from_env_file(&resolved, key_map, target_key)?;
            Ok(!val.is_empty())
        }
    }
}

pub fn read_secret_from_env_file(
    path: &Path,
    key_map: &BTreeMap<String, String>,
    target_key: &str,
) -> FleetResult<String> {
    crate::keys::validate_private_key_path(path)?;
    let content = read_0600_regular_file(path)?;
    let mut parsed: BTreeMap<String, String> = BTreeMap::new();
    for raw_line in content.lines() {
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(stripped) = line.strip_prefix("export ") {
            line = stripped.trim();
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_owned();
        let mut val = v.trim();
        if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
            || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
        {
            val = &val[1..val.len() - 1];
        }
        if !key.is_empty() && !val.is_empty() {
            parsed.insert(key, val.to_owned());
        }
    }

    if let Some(direct) = parsed.get(target_key) {
        return Ok(direct.clone());
    }
    for (file_key, mapped_env) in key_map {
        if mapped_env == target_key
            && let Some(val) = parsed.get(file_key)
        {
            return Ok(val.clone());
        }
    }
    if let Some((_, val)) = key_map.iter().find_map(|(k, _)| parsed.get_key_value(k)) {
        return Ok(val.clone());
    }
    Err(FleetPolicyError::DriverExecutionFailed(format!(
        "missing key {target_key} in credential file {}",
        path.display()
    )))
}

fn read_0600_regular_file(path: &Path) -> FleetResult<String> {
    #[cfg(unix)]
    const O_NOFOLLOW: i32 = 0x0100;
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(O_NOFOLLOW);
    let mut file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(FleetPolicyError::KeyBijectionFailed(
            "credential file must be regular".into(),
        ));
    }
    #[cfg(unix)]
    if meta.permissions().mode() & 0o7777 != 0o600 {
        return Err(FleetPolicyError::KeyBijectionFailed(
            "credential file permissions must be 0600".into(),
        ));
    }
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    Ok(buf)
}

fn resolve_driver_api_key(
    isolation: &CredentialIsolation,
    api_key_env: &str,
) -> FleetResult<Option<String>> {
    match isolation {
        CredentialIsolation::SecretEnvFile { path, key_map } => {
            Ok(Some(read_secret_from_env_file(path, key_map, api_key_env)?))
        }
        CredentialIsolation::NoneLocal => {
            if api_key_env.is_empty() {
                Ok(None)
            } else if let Ok(v) = std::env::var(api_key_env)
                && !v.trim().is_empty()
            {
                Ok(Some(v.trim().to_owned()))
            } else {
                Ok(None)
            }
        }
        CredentialIsolation::FirstPartyCliOauth { .. } => Err(FleetPolicyError::InvalidManifest(
            "HTTP drivers cannot use FirstPartyCliOauth".into(),
        )),
    }
}

struct CurlHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

#[derive(Debug)]
enum CurlCallError {
    Transport {
        exit_code: Option<i32>,
        stderr: String,
    },
    TruncatedStream {
        detail: String,
    },
    MissingStatusLine,
    InvalidStatusCode(String),
    IoOrPolicy(FleetPolicyError),
}

impl CurlCallError {
    fn into_policy_error(self) -> FleetPolicyError {
        match self {
            Self::Transport { exit_code, stderr } => {
                let trimmed = stderr.trim();
                let msg = if trimmed.is_empty() {
                    format!("HTTP transport failure: curl exited with {exit_code:?}")
                } else {
                    format!("HTTP transport failure: {trimmed}")
                };
                FleetPolicyError::DriverExecutionFailed(msg)
            }
            Self::TruncatedStream { detail } => FleetPolicyError::DriverExecutionFailed(format!(
                "HTTP transport failure: truncated SSE stream ({detail})"
            )),
            Self::MissingStatusLine => FleetPolicyError::DriverExecutionFailed(
                "curl output missing HTTP status line".into(),
            ),
            Self::InvalidStatusCode(code) => FleetPolicyError::DriverExecutionFailed(format!(
                "unparseable HTTP status code: {code}"
            )),
            Self::IoOrPolicy(err) => err,
        }
    }
}

#[derive(Clone, Debug)]
struct CurlRequestOptions<'a> {
    accept_header: &'a str,
    no_buffer: bool,
    timeout_secs: u64,
    connect_timeout_secs: u64,
    keepalive_time_secs: u64,
    stall_timeout_secs: Option<u64>,
    force_http1_1: bool,
}

impl<'a> CurlRequestOptions<'a> {
    fn default_json(timeout_secs: u64) -> Self {
        Self::from_policy(timeout_secs, None, false)
    }

    fn from_policy(timeout_secs: u64, policy: Option<&HttpTransportPolicy>, sse: bool) -> Self {
        let max_time = timeout_secs.max(1);
        let connect = policy
            .and_then(|p| p.connect_timeout_secs)
            .unwrap_or(30)
            .max(1)
            .min(max_time);
        let keepalive = policy
            .and_then(|p| p.keepalive_time_secs)
            .unwrap_or(15)
            .max(1);
        let stall = policy
            .and_then(|p| p.stall_timeout_secs)
            .map(|s| s.max(1).min(max_time));
        let force_http1_1 = policy.and_then(|p| p.force_http1_1).unwrap_or(false);
        Self {
            accept_header: if sse {
                "text/event-stream"
            } else {
                "application/json"
            },
            no_buffer: sse,
            timeout_secs: max_time,
            connect_timeout_secs: connect,
            keepalive_time_secs: keepalive,
            stall_timeout_secs: stall,
            force_http1_1,
        }
    }
}

trait CurlInvoker {
    fn invoke(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
        opts: CurlRequestOptions<'_>,
    ) -> Result<CurlHttpResponse, CurlCallError>;
}

struct SystemCurlInvoker;

impl CurlInvoker for SystemCurlInvoker {
    fn invoke(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
        opts: CurlRequestOptions<'_>,
    ) -> Result<CurlHttpResponse, CurlCallError> {
        curl_request_raw(method, url, headers, body, opts)
    }
}

fn parse_dump_headers(raw: &str) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.starts_with("HTTP/") {
            headers.clear();
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    headers
}

fn curl_request_raw(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    opts: CurlRequestOptions<'_>,
) -> Result<CurlHttpResponse, CurlCallError> {
    if url.contains(['\0', '\r', '\n']) {
        return Err(CurlCallError::IoOrPolicy(
            FleetPolicyError::EgressViolation("invalid characters in URL".into()),
        ));
    }
    if opts.accept_header.contains(['\0', '\r', '\n']) {
        return Err(CurlCallError::IoOrPolicy(
            FleetPolicyError::InvalidManifest("control character in Accept header".into()),
        ));
    }
    let curl_bin = if Path::new("/usr/bin/curl").is_file() {
        PathBuf::from("/usr/bin/curl")
    } else {
        resolve_binary("curl").map_err(CurlCallError::IoOrPolicy)?
    };
    let temp_dir = tempfile::Builder::new()
        .prefix("cw-http-")
        .tempdir_in(std::env::temp_dir())
        .map_err(|e| CurlCallError::IoOrPolicy(FleetPolicyError::Io(e)))?;
    #[cfg(unix)]
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700))
        .map_err(|e| CurlCallError::IoOrPolicy(FleetPolicyError::Io(e)))?;

    let dump_headers_path = temp_dir.path().join("resp.hdr");
    let mut cfg = String::new();
    cfg.push_str(&format!("url = \"{}\"\n", escape_curl_cfg(url)));
    cfg.push_str(&format!("request = \"{}\"\n", escape_curl_cfg(method)));
    cfg.push_str(&format!(
        "header = \"Accept: {}\"\n",
        escape_curl_cfg(opts.accept_header)
    ));
    for (k, v) in headers {
        if k.contains(['\0', '\r', '\n']) || v.contains(['\0', '\r', '\n']) {
            return Err(CurlCallError::IoOrPolicy(
                FleetPolicyError::InvalidManifest("control character in HTTP header".into()),
            ));
        }
        cfg.push_str(&format!(
            "header = \"{}: {}\"\n",
            escape_curl_cfg(k),
            escape_curl_cfg(v)
        ));
    }
    if let Some(payload) = body {
        let body_path = temp_dir.path().join("req.json");
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&body_path)
            .map_err(|e| CurlCallError::IoOrPolicy(FleetPolicyError::Io(e)))?;
        f.write_all(payload.as_bytes())
            .map_err(|e| CurlCallError::IoOrPolicy(FleetPolicyError::Io(e)))?;
        cfg.push_str("header = \"Content-Type: application/json\"\n");
        cfg.push_str(&format!(
            "data-binary = \"@{}\"\n",
            escape_curl_cfg(&body_path.to_string_lossy())
        ));
    }

    let timeout_str = opts.timeout_secs.max(1).to_string();
    let connect_str = opts
        .connect_timeout_secs
        .max(1)
        .min(opts.timeout_secs.max(1))
        .to_string();
    let keepalive_str = opts.keepalive_time_secs.max(1).to_string();
    let mut cmd = Command::new(curl_bin);
    cmd.args(["-q", "-g", "--silent", "--show-error", "--location"]);
    if opts.no_buffer {
        cmd.arg("-N");
    }
    if opts.force_http1_1 {
        cmd.arg("--http1.1");
    }
    cmd.args([
        "--connect-timeout",
        &connect_str,
        "--keepalive-time",
        &keepalive_str,
    ]);
    if let Some(stall) = opts.stall_timeout_secs {
        let stall_str = stall.max(1).min(opts.timeout_secs.max(1)).to_string();
        cmd.args(["--speed-limit", "1", "--speed-time", &stall_str]);
    }
    cmd.args(["--max-time", &timeout_str, "--dump-header"])
        .arg(&dump_headers_path)
        .args(["-w", "\n%{http_code}", "-K", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| CurlCallError::IoOrPolicy(FleetPolicyError::Io(e)))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(cfg.as_bytes())
            .map_err(|e| CurlCallError::IoOrPolicy(FleetPolicyError::Io(e)))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| CurlCallError::IoOrPolicy(FleetPolicyError::Io(e)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(CurlCallError::Transport {
            exit_code: output.status.code(),
            stderr,
        });
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let (resp_body, code_str) = raw
        .rsplit_once('\n')
        .ok_or(CurlCallError::MissingStatusLine)?;
    let status = code_str
        .trim()
        .parse::<u16>()
        .map_err(|_| CurlCallError::InvalidStatusCode(code_str.trim().to_owned()))?;
    let resp_headers = fs::read_to_string(&dump_headers_path)
        .map(|raw_hdrs| parse_dump_headers(&raw_hdrs))
        .unwrap_or_default();
    Ok(CurlHttpResponse {
        status,
        headers: resp_headers,
        body: resp_body.to_owned(),
    })
}

fn curl_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    timeout_secs: u64,
) -> FleetResult<CurlHttpResponse> {
    curl_request_raw(
        method,
        url,
        headers,
        body,
        CurlRequestOptions::default_json(timeout_secs),
    )
    .map_err(CurlCallError::into_policy_error)
}

fn escape_curl_cfg(val: &str) -> String {
    let mut out = String::with_capacity(val.len());
    for ch in val.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out
}

thread_local! {
    static LAST_FAILED_HTTP_USAGE: std::cell::RefCell<Option<HttpUsageSummary>> =
        const { std::cell::RefCell::new(None) };
}

/// Returns and clears the HTTP usage summary captured before an HTTP driver error.
pub fn take_last_failed_http_usage() -> Option<HttpUsageSummary> {
    LAST_FAILED_HTTP_USAGE.with(|cell| cell.borrow_mut().take())
}

#[derive(Default)]
struct UsageAccumulator {
    turns: u32,
    transport_retries: u32,
    unknown: bool,
    any_prompt: bool,
    any_completion: bool,
    prompt_sum: u64,
    completion_sum: u64,
    cached_sum: u64,
    reasoning_sum: u64,
    gross_sum: u64,
}

impl UsageAccumulator {
    fn mark_egress_failed(&mut self) {
        self.turns = self.turns.saturating_add(1);
        self.unknown = true;
    }

    fn record_openai_turn(&mut self, parsed: &Value) {
        self.turns = self.turns.saturating_add(1);
        let Some(usage) = parsed.get("usage").and_then(Value::as_object) else {
            self.unknown = true;
            return;
        };
        let prompt = usage.get("prompt_tokens").and_then(Value::as_u64);
        let completion = usage.get("completion_tokens").and_then(Value::as_u64);
        let total = usage
            .get("total_tokens")
            .and_then(Value::as_u64)
            .or_else(|| prompt.and_then(|p| completion.map(|c| p.saturating_add(c))));
        if usage.get("prompt_tokens").is_some() && prompt.is_none()
            || usage.get("completion_tokens").is_some() && completion.is_none()
            || usage.get("total_tokens").is_some()
                && usage.get("total_tokens").and_then(Value::as_u64).is_none()
        {
            self.unknown = true;
            return;
        }
        let Some(gross) = total else {
            self.unknown = true;
            return;
        };
        if let Some(p) = prompt {
            self.any_prompt = true;
            self.prompt_sum = self.prompt_sum.saturating_add(p);
        }
        if let Some(c) = completion {
            self.any_completion = true;
            self.completion_sum = self.completion_sum.saturating_add(c);
        }
        let cached = usage
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(Value::as_u64)
            .or_else(|| usage.get("cached_tokens").and_then(Value::as_u64))
            .unwrap_or(0);
        let reasoning = usage
            .get("completion_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(Value::as_u64)
            .or_else(|| usage.get("reasoning_tokens").and_then(Value::as_u64))
            .unwrap_or(0);
        self.cached_sum = self.cached_sum.saturating_add(cached);
        self.reasoning_sum = self.reasoning_sum.saturating_add(reasoning);
        self.gross_sum = self.gross_sum.saturating_add(gross);
    }

    fn record_gemini_turn(&mut self, parsed: &Value) {
        self.turns = self.turns.saturating_add(1);
        let Some(meta) = parsed.get("usageMetadata").and_then(Value::as_object) else {
            self.unknown = true;
            return;
        };
        let prompt = meta.get("promptTokenCount").and_then(Value::as_u64);
        let candidates = meta.get("candidatesTokenCount").and_then(Value::as_u64);
        let Some(total) = meta.get("totalTokenCount").and_then(Value::as_u64) else {
            self.unknown = true;
            return;
        };
        if let Some(p) = prompt {
            self.any_prompt = true;
            self.prompt_sum = self.prompt_sum.saturating_add(p);
        }
        if let Some(c) = candidates {
            self.any_completion = true;
            self.completion_sum = self.completion_sum.saturating_add(c);
        }
        let cached = meta
            .get("cachedContentTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let reasoning = meta
            .get("thoughtsTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        self.cached_sum = self.cached_sum.saturating_add(cached);
        self.reasoning_sum = self.reasoning_sum.saturating_add(reasoning);
        self.gross_sum = self.gross_sum.saturating_add(total);
    }

    fn record_anthropic_turn(&mut self, parsed: &Value) {
        self.turns = self.turns.saturating_add(1);
        let Some(usage) = parsed.get("usage").and_then(Value::as_object) else {
            self.unknown = true;
            return;
        };
        let (Some(input), Some(output)) = (
            usage.get("input_tokens").and_then(Value::as_u64),
            usage.get("output_tokens").and_then(Value::as_u64),
        ) else {
            self.unknown = true;
            return;
        };
        let cache_create = usage
            .get("cache_creation_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let cache_read = usage
            .get("cache_read_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let cached = cache_create.saturating_add(cache_read);
        let gross = input.saturating_add(cached).saturating_add(output);
        self.any_prompt = true;
        self.any_completion = true;
        self.prompt_sum = self.prompt_sum.saturating_add(input);
        self.completion_sum = self.completion_sum.saturating_add(output);
        self.cached_sum = self.cached_sum.saturating_add(cached);
        self.gross_sum = self.gross_sum.saturating_add(gross);
    }

    fn finish(&self, tool_calls: u32, force_unknown: bool) -> HttpUsageSummary {
        let counted = !self.unknown && !force_unknown && self.turns > 0;
        if counted {
            HttpUsageSummary {
                usage_status: "COUNTED".into(),
                turns: self.turns,
                tool_calls,
                prompt_tokens: self.any_prompt.then_some(self.prompt_sum),
                completion_tokens: self.any_completion.then_some(self.completion_sum),
                cached_tokens: Some(self.cached_sum),
                reasoning_tokens: Some(self.reasoning_sum),
                gross_tokens: Some(self.gross_sum),
                observed_partial_gross_tokens: self.gross_sum,
                transport_retries: self.transport_retries,
            }
        } else {
            HttpUsageSummary {
                usage_status: "UNKNOWN".into(),
                turns: self.turns,
                tool_calls,
                prompt_tokens: None,
                completion_tokens: None,
                cached_tokens: None,
                reasoning_tokens: None,
                gross_tokens: None,
                observed_partial_gross_tokens: self.gross_sum,
                transport_retries: self.transport_retries,
            }
        }
    }
}

fn resolve_usage_receipt_path(context: &ExecutionContext) -> Option<PathBuf> {
    context
        .env
        .get("CHINWAG_USAGE_RECEIPT_PATH")
        .cloned()
        .or_else(|| std::env::var("CHINWAG_USAGE_RECEIPT_PATH").ok())
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
}

fn write_usage_receipt(context: &ExecutionContext, summary: &HttpUsageSummary) {
    let Some(path) = resolve_usage_receipt_path(context) else {
        return;
    };
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(summary) {
        let _ = fs::write(path, bytes);
    }
}

fn record_http_failure(context: &ExecutionContext, acc: &UsageAccumulator, tool_calls: usize) {
    if acc.turns == 0 {
        return;
    }
    let summary = acc.finish(tool_calls as u32, true);
    write_usage_receipt(context, &summary);
    LAST_FAILED_HTTP_USAGE.with(|cell| {
        *cell.borrow_mut() = Some(summary);
    });
}

fn effort_override_from_context(context: &ExecutionContext) -> Option<String> {
    context
        .env
        .get("CHINWAG_EFFORT_OVERRIDE")
        .cloned()
        .or_else(|| std::env::var("CHINWAG_EFFORT_OVERRIDE").ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn is_effort_locked(plan: &ResolvedDispatchPlan) -> bool {
    plan.model
        .params
        .get("lock_effort")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(crate) fn execute_http_driver(
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    on_started: impl FnOnce(u32),
) -> FleetResult<ExecutionOutcome> {
    let mut invoker = SystemCurlInvoker;
    execute_http_driver_with_invoker(plan, context, on_started, &mut invoker)
}

fn execute_http_driver_with_invoker(
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    on_started: impl FnOnce(u32),
    invoker: &mut dyn CurlInvoker,
) -> FleetResult<ExecutionOutcome> {
    on_started(std::process::id());
    LAST_FAILED_HTTP_USAGE.with(|cell| {
        *cell.borrow_mut() = None;
    });
    let system_prompt = compose_system_instruction(plan, context)?;
    let user_prompt = context.prompt.as_deref().unwrap_or("").trim();
    if user_prompt.is_empty() {
        return Err(FleetPolicyError::InvalidManifest(
            "non-empty prompt required for HTTP driver".into(),
        ));
    }

    let outcome = match &plan.driver {
        DriverSpec::OpenAiCompatibleHttp {
            base_url,
            api_key_env,
            stream_mode,
            wire_mode: _,
            timeout_secs,
            auth_isolation,
            tools,
            transport,
        } => {
            let parsed_stream_mode = OpenAiStreamMode::parse(stream_mode)?;
            validate_transport_policy(transport.as_ref())?;
            let eff_timeout = context.timeout_override_secs.unwrap_or(*timeout_secs);
            let api_key = resolve_driver_api_key(auth_isolation, api_key_env)?;
            let endpoint = if base_url
                .trim_end_matches('/')
                .ends_with("/chat/completions")
            {
                base_url.trim_end_matches('/').to_owned()
            } else {
                format!("{}/chat/completions", base_url.trim_end_matches('/'))
            };
            run_openai_loop(
                plan,
                context,
                &endpoint,
                api_key.as_deref(),
                parsed_stream_mode,
                &system_prompt,
                user_prompt,
                eff_timeout,
                tools,
                transport.as_ref(),
                invoker,
            )
        }
        DriverSpec::GoogleGenAiHttp {
            endpoint_mode: _,
            base_url_or_region,
            auth_env,
            stream_mode: _,
            timeout_secs,
            auth_isolation,
            tools,
            transport,
        } => {
            validate_transport_policy(transport.as_ref())?;
            let eff_timeout = context.timeout_override_secs.unwrap_or(*timeout_secs);
            let api_key = resolve_driver_api_key(auth_isolation, auth_env)?.ok_or_else(|| {
                FleetPolicyError::DriverExecutionFailed("missing Gemini API key".into())
            })?;
            let url = format!(
                "{}/models/{}:generateContent",
                base_url_or_region.trim_end_matches('/'),
                plan.model.model_id
            );
            run_gemini_loop(
                plan,
                context,
                &url,
                &api_key,
                &system_prompt,
                user_prompt,
                eff_timeout,
                tools,
                transport.as_ref(),
                invoker,
            )
        }
        DriverSpec::AnthropicMessagesHttp {
            base_url,
            auth_env,
            beta_headers,
            stream_mode: _,
            timeout_secs,
            auth_isolation,
            tools,
            transport,
        } => {
            validate_transport_policy(transport.as_ref())?;
            let eff_timeout = context.timeout_override_secs.unwrap_or(*timeout_secs);
            let api_key = resolve_driver_api_key(auth_isolation, auth_env)?.ok_or_else(|| {
                FleetPolicyError::DriverExecutionFailed("missing Anthropic API key".into())
            })?;
            let endpoint = if base_url.trim_end_matches('/').ends_with("/messages") {
                base_url.trim_end_matches('/').to_owned()
            } else {
                format!("{}/messages", base_url.trim_end_matches('/'))
            };
            run_anthropic_loop(
                plan,
                context,
                &endpoint,
                &api_key,
                beta_headers,
                &system_prompt,
                user_prompt,
                eff_timeout,
                tools,
                transport.as_ref(),
                invoker,
            )
        }
        DriverSpec::CliSubprocess { .. } => unreachable!(),
    }?;
    if let Some(usage) = &outcome.usage {
        write_usage_receipt(context, usage);
    }
    Ok(outcome)
}

fn compose_system_instruction(
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
) -> FleetResult<String> {
    let mut prompt_less = context.clone();
    prompt_less.prompt = None;
    let mut text = compose_prompt(plan, &prompt_less)?;
    text.push_str("\nExecute rigorously and never fail over to another model or provider.");
    Ok(text)
}

#[derive(Default)]
struct SseToolCallAccum {
    id: Option<String>,
    call_type: Option<String>,
    name: String,
    arguments: String,
}

fn parse_openai_sse_transcript(body: &str) -> Result<Value, CurlCallError> {
    let lines: Vec<&str> = body.lines().collect();
    let mut role: Option<String> = None;
    let mut content_buf = String::new();
    let mut saw_nonempty_content = false;
    let mut tool_calls: BTreeMap<usize, SseToolCallAccum> = BTreeMap::new();
    let mut finish_reason: Option<String> = None;
    let mut usage: Option<Value> = None;
    let mut saw_done = false;
    let mut saw_data_line = false;
    let mut current_event: Option<String> = None;

    for (line_idx, raw_line) in lines.iter().enumerate() {
        let line = raw_line.trim_end_matches('\r');
        if line.trim().is_empty() {
            if current_event
                .as_deref()
                .is_some_and(|ev| ev.eq_ignore_ascii_case("error"))
            {
                return Err(CurlCallError::IoOrPolicy(
                    FleetPolicyError::DriverExecutionFailed("OpenAI SSE error event".into()),
                ));
            }
            current_event = None;
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        if let Some(ev) = line.strip_prefix("event:") {
            current_event = Some(ev.trim().to_owned());
            continue;
        }
        if line.starts_with("id:") || line.starts_with("retry:") {
            continue;
        }
        let Some(raw_data) = line.strip_prefix("data:") else {
            continue;
        };
        saw_data_line = true;
        let payload = raw_data.strip_prefix(' ').unwrap_or(raw_data).trim();
        if current_event
            .as_deref()
            .is_some_and(|ev| ev.eq_ignore_ascii_case("error"))
        {
            return Err(CurlCallError::IoOrPolicy(
                FleetPolicyError::DriverExecutionFailed(format!(
                    "OpenAI SSE error event: {}",
                    payload.chars().take(400).collect::<String>()
                )),
            ));
        }
        if payload.is_empty() {
            continue;
        }
        if payload == "[DONE]" {
            saw_done = true;
            break;
        }
        if current_event
            .as_deref()
            .is_some_and(|ev| ev.eq_ignore_ascii_case("ping"))
        {
            continue;
        }
        let chunk: Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(err) => {
                let has_later_data = lines[line_idx + 1..]
                    .iter()
                    .any(|later| later.trim_end_matches('\r').starts_with("data:"));
                if !has_later_data {
                    return Err(CurlCallError::TruncatedStream {
                        detail: format!("incomplete SSE JSON frame at EOF: {err}"),
                    });
                }
                return Err(CurlCallError::IoOrPolicy(
                    FleetPolicyError::DriverExecutionFailed(format!(
                        "invalid OpenAI SSE JSON chunk: {err}"
                    )),
                ));
            }
        };
        if let Some(err_val) = chunk.get("error").filter(|v| !v.is_null()) {
            return Err(CurlCallError::IoOrPolicy(
                FleetPolicyError::DriverExecutionFailed(format!("OpenAI SSE error: {err_val}")),
            ));
        }
        if let Some(u) = chunk.get("usage").filter(|v| v.is_object()) {
            usage = Some(u.clone());
        }
        if let Some(choice0) = chunk.pointer("/choices/0") {
            if let Some(fr) = choice0
                .get("finish_reason")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                finish_reason = Some(fr.to_owned());
            }
            if let Some(delta) = choice0
                .get("delta")
                .or_else(|| choice0.get("message"))
                .and_then(Value::as_object)
            {
                if let Some(r) = delta
                    .get("role")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    role = Some(r.to_owned());
                }
                if let Some(text) = delta.get("content").and_then(Value::as_str) {
                    content_buf.push_str(text);
                    if !text.is_empty() {
                        saw_nonempty_content = true;
                    }
                }
                if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
                    for (pos, tc) in calls.iter().enumerate() {
                        let idx = tc
                            .get("index")
                            .and_then(Value::as_u64)
                            .map(|n| n as usize)
                            .unwrap_or(pos);
                        let acc = tool_calls.entry(idx).or_default();
                        if acc.id.is_none()
                            && let Some(id) = tc
                                .get("id")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                        {
                            acc.id = Some(id.to_owned());
                        }
                        if acc.call_type.is_none()
                            && let Some(kind) = tc
                                .get("type")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                        {
                            acc.call_type = Some(kind.to_owned());
                        }
                        if let Some(func) = tc.get("function").and_then(Value::as_object) {
                            if let Some(name) = func
                                .get("name")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                            {
                                if acc.name.is_empty() {
                                    acc.name = name.to_owned();
                                } else if acc.name != name {
                                    acc.name.push_str(name);
                                }
                            }
                            if let Some(args) = func.get("arguments").and_then(Value::as_str) {
                                acc.arguments.push_str(args);
                            }
                        }
                    }
                }
            }
        }
    }

    if current_event
        .as_deref()
        .is_some_and(|ev| ev.eq_ignore_ascii_case("error"))
    {
        return Err(CurlCallError::IoOrPolicy(
            FleetPolicyError::DriverExecutionFailed("OpenAI SSE error event".into()),
        ));
    }

    if !saw_data_line {
        if body.trim_start().starts_with('{') {
            let parsed: Value = serde_json::from_str(body).map_err(|err| {
                CurlCallError::IoOrPolicy(FleetPolicyError::DriverExecutionFailed(format!(
                    "invalid OpenAI JSON: {err}"
                )))
            })?;
            if let Some(err_val) = parsed.get("error").filter(|v| !v.is_null()) {
                return Err(CurlCallError::IoOrPolicy(
                    FleetPolicyError::DriverExecutionFailed(format!(
                        "OpenAI error response: {err_val}"
                    )),
                ));
            }
            return Ok(parsed);
        }
        return Err(CurlCallError::TruncatedStream {
            detail: "empty SSE stream without data frames".into(),
        });
    }

    if !saw_done && finish_reason.is_none() {
        return Err(CurlCallError::TruncatedStream {
            detail: "SSE stream closed at EOF without [DONE] or finish_reason".into(),
        });
    }

    let mut message = Map::new();
    message.insert(
        "role".into(),
        Value::String(role.unwrap_or_else(|| "assistant".into())),
    );
    if tool_calls.is_empty() || saw_nonempty_content {
        message.insert("content".into(), Value::String(content_buf));
    } else {
        message.insert("content".into(), Value::Null);
    }
    if !tool_calls.is_empty() {
        let assembled_calls: Vec<Value> = tool_calls
            .into_iter()
            .map(|(idx, acc)| {
                let id = acc.id.unwrap_or_else(|| format!("call_{idx}"));
                let call_type = acc.call_type.unwrap_or_else(|| "function".into());
                let arguments = if acc.arguments.is_empty() {
                    "{}".to_owned()
                } else {
                    acc.arguments
                };
                json!({
                    "id": id,
                    "type": call_type,
                    "function": {
                        "name": acc.name,
                        "arguments": arguments,
                    }
                })
            })
            .collect();
        message.insert("tool_calls".into(), Value::Array(assembled_calls));
    }

    let mut choice = Map::new();
    choice.insert("index".into(), json!(0));
    choice.insert("message".into(), Value::Object(message));
    if let Some(fr) = finish_reason {
        choice.insert("finish_reason".into(), Value::String(fr));
    }

    let mut out = Map::new();
    out.insert("choices".into(), Value::Array(vec![Value::Object(choice)]));
    if let Some(u) = usage {
        out.insert("usage".into(), u);
    }
    Ok(Value::Object(out))
}

#[derive(Clone, Copy)]
enum ResponseParseMode {
    OpenAiSse,
    Json { provider_label: &'static str },
}

enum TurnHttpResult {
    ParsedJson(Value),
    NonSuccessStatus { status: u16, body: String },
}

fn is_pre_send_retryable_curl_exit(code: Option<i32>) -> bool {
    matches!(code, Some(6 | 7 | 35))
}

fn is_post_send_retryable_curl_exit(code: Option<i32>) -> bool {
    matches!(code, Some(16 | 18 | 28 | 52 | 55 | 56 | 92))
}

fn is_retryable_http_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 502 | 503 | 504)
}

fn parse_retry_after_ms(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, v)| v.trim().parse::<u64>().ok())
        .filter(|secs| *secs <= 15)
        .map(|secs| secs.saturating_mul(1_000))
}

fn try_schedule_retry(
    attempt: u32,
    max_retries: u32,
    turn_deadline: Instant,
    sleep_ms: u64,
    min_retry_budget: Duration,
    usage_acc: &mut UsageAccumulator,
) -> bool {
    if attempt >= max_retries {
        return false;
    }
    let sleep_dur = Duration::from_millis(sleep_ms);
    let remaining = turn_deadline.saturating_duration_since(Instant::now());
    if remaining <= sleep_dur || remaining.saturating_sub(sleep_dur) < min_retry_budget {
        return false;
    }
    std::thread::sleep(sleep_dur);
    usage_acc.transport_retries = usage_acc.transport_retries.saturating_add(1);
    true
}

#[allow(clippy::too_many_arguments)]
fn send_turn_with_retry(
    invoker: &mut dyn CurlInvoker,
    endpoint: &str,
    headers: &[(String, String)],
    payload: &str,
    timeout_secs: u64,
    policy: Option<&HttpTransportPolicy>,
    parse_mode: ResponseParseMode,
    usage_acc: &mut UsageAccumulator,
) -> FleetResult<TurnHttpResult> {
    let total_timeout = timeout_secs.max(1);
    let max_retries = policy.and_then(|p| p.max_retries).unwrap_or(2);
    let initial_backoff_ms = policy.and_then(|p| p.initial_backoff_ms).unwrap_or(1_000);
    let max_backoff_ms = policy
        .and_then(|p| p.max_backoff_ms)
        .unwrap_or(8_000)
        .max(initial_backoff_ms);
    let raw_connect_secs = policy
        .and_then(|p| p.connect_timeout_secs)
        .unwrap_or(30)
        .max(1);
    let min_retry_budget = if total_timeout > raw_connect_secs {
        Duration::from_secs(raw_connect_secs)
    } else {
        Duration::from_secs(1)
    };
    let turn_deadline = Instant::now() + Duration::from_secs(total_timeout);
    let sse = matches!(parse_mode, ResponseParseMode::OpenAiSse);

    let mut attempt: u32 = 0;
    loop {
        let remaining = turn_deadline.saturating_duration_since(Instant::now());
        let attempt_timeout_secs = if attempt == 0 {
            total_timeout
        } else {
            total_timeout.min(remaining.as_secs().max(1))
        };
        let opts = CurlRequestOptions::from_policy(attempt_timeout_secs, policy, sse);
        let backoff_ms = initial_backoff_ms
            .saturating_mul(1u64 << attempt.min(16))
            .min(max_backoff_ms);

        match invoker.invoke("POST", endpoint, headers, Some(payload), opts) {
            Err(err) => {
                let (retryable, post_send_ambiguous) = match &err {
                    CurlCallError::Transport { exit_code, .. } => {
                        if is_pre_send_retryable_curl_exit(*exit_code) {
                            (true, false)
                        } else if is_post_send_retryable_curl_exit(*exit_code) {
                            (true, true)
                        } else {
                            (false, true)
                        }
                    }
                    CurlCallError::TruncatedStream { .. } => (true, true),
                    CurlCallError::MissingStatusLine
                    | CurlCallError::InvalidStatusCode(_)
                    | CurlCallError::IoOrPolicy(_) => (false, true),
                };
                if post_send_ambiguous {
                    usage_acc.unknown = true;
                }
                if !retryable
                    || !try_schedule_retry(
                        attempt,
                        max_retries,
                        turn_deadline,
                        backoff_ms,
                        min_retry_budget,
                        usage_acc,
                    )
                {
                    return Err(err.into_policy_error());
                }
                attempt += 1;
            }
            Ok(resp) if !(200..300).contains(&resp.status) => {
                if !is_retryable_http_status(resp.status) {
                    return Ok(TurnHttpResult::NonSuccessStatus {
                        status: resp.status,
                        body: resp.body,
                    });
                }
                if resp.status != 429 {
                    usage_acc.unknown = true;
                }
                let sleep_ms = if resp.status == 429 {
                    parse_retry_after_ms(&resp.headers).unwrap_or(backoff_ms)
                } else {
                    backoff_ms
                };
                if !try_schedule_retry(
                    attempt,
                    max_retries,
                    turn_deadline,
                    sleep_ms,
                    min_retry_budget,
                    usage_acc,
                ) {
                    return Ok(TurnHttpResult::NonSuccessStatus {
                        status: resp.status,
                        body: resp.body,
                    });
                }
                attempt += 1;
            }
            Ok(resp) => match parse_mode {
                ResponseParseMode::OpenAiSse => match parse_openai_sse_transcript(&resp.body) {
                    Ok(parsed) => return Ok(TurnHttpResult::ParsedJson(parsed)),
                    Err(CurlCallError::TruncatedStream { detail }) => {
                        usage_acc.unknown = true;
                        let err = CurlCallError::TruncatedStream { detail };
                        if !try_schedule_retry(
                            attempt,
                            max_retries,
                            turn_deadline,
                            backoff_ms,
                            min_retry_budget,
                            usage_acc,
                        ) {
                            return Err(err.into_policy_error());
                        }
                        attempt += 1;
                    }
                    Err(other) => return Err(other.into_policy_error()),
                },
                ResponseParseMode::Json { provider_label } => {
                    let parsed: Value = serde_json::from_str(&resp.body).map_err(|e| {
                        FleetPolicyError::DriverExecutionFailed(format!(
                            "invalid {provider_label} JSON: {e}"
                        ))
                    })?;
                    return Ok(TurnHttpResult::ParsedJson(parsed));
                }
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_openai_loop(
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    endpoint: &str,
    api_key: Option<&str>,
    stream_mode: OpenAiStreamMode,
    system_prompt: &str,
    user_prompt: &str,
    timeout_secs: u64,
    tools: &HttpToolConfig,
    transport_policy: Option<&HttpTransportPolicy>,
    invoker: &mut dyn CurlInvoker,
) -> FleetResult<ExecutionOutcome> {
    let max_turns = context
        .max_turns_override
        .unwrap_or(tools.max_turns.unwrap_or(30));
    let max_calls = tools.max_tool_calls.unwrap_or(64);
    let max_tokens = context
        .max_output_tokens_override
        .unwrap_or(tools.max_output_tokens.unwrap_or(32_768));
    let tools_active = tools.enabled && !context.tools_disabled;
    let allow_writes = plan.write_mode != WriteMode::ReadOnly;
    let lock_effort = is_effort_locked(plan);
    let configured_effort = plan
        .model
        .params
        .get("reasoning_effort")
        .or_else(|| plan.model.params.get("effort"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let override_effort = effort_override_from_context(context);
    if lock_effort
        && let Some(ov) = &override_effort
        && configured_effort
            .as_deref()
            .is_some_and(|exp| !exp.eq_ignore_ascii_case(ov))
    {
        return Err(FleetPolicyError::DriverExecutionFailed(format!(
            "EffortSwitchDenied: effort '{ov}' rejected; seat {} is locked to '{}'",
            plan.seat,
            configured_effort.as_deref().unwrap_or("<unset>")
        )));
    }
    let effort = override_effort.or(configured_effort);

    let mut messages = vec![
        json!({"role": "system", "content": system_prompt}),
        json!({"role": "user", "content": user_prompt}),
    ];
    let mut headers = Vec::new();
    if let Some(key) = api_key {
        headers.push(("Authorization".to_owned(), format!("Bearer {key}")));
    }
    let mut tool_calls_used = 0usize;
    let mut usage_acc = UsageAccumulator::default();
    let mut send_reasoning_effort = matches!(effort.as_deref(), Some("low" | "medium" | "high"));
    let mut send_stream_options = stream_mode.is_sse();

    for _turn in 0..max_turns {
        let parsed = loop {
            let mut payload = json!({
                "model": plan.model.model_id,
                "messages": messages,
                "max_tokens": max_tokens,
            });
            if stream_mode.is_sse() {
                payload["stream"] = Value::Bool(true);
                if send_stream_options {
                    payload["stream_options"] = json!({"include_usage": true});
                }
            }
            if send_reasoning_effort && let Some(eff) = &effort {
                payload["reasoning_effort"] = Value::String(eff.clone());
            }
            if tools_active {
                payload["tools"] = openai_tool_declarations(allow_writes);
            }
            let parse_mode = if stream_mode.is_sse() {
                ResponseParseMode::OpenAiSse
            } else {
                ResponseParseMode::Json {
                    provider_label: "OpenAI",
                }
            };
            let turn_res = match send_turn_with_retry(
                invoker,
                endpoint,
                &headers,
                &payload.to_string(),
                timeout_secs,
                transport_policy,
                parse_mode,
                &mut usage_acc,
            ) {
                Ok(r) => r,
                Err(err) => {
                    usage_acc.mark_egress_failed();
                    record_http_failure(context, &usage_acc, tool_calls_used);
                    return Err(err);
                }
            };
            match turn_res {
                TurnHttpResult::ParsedJson(parsed) => break parsed,
                TurnHttpResult::NonSuccessStatus { status: 400, body }
                    if !lock_effort
                        && send_reasoning_effort
                        && body.contains("reasoning_effort") =>
                {
                    send_reasoning_effort = false;
                }
                TurnHttpResult::NonSuccessStatus { status: 400, body }
                    if !lock_effort
                        && stream_mode.is_sse()
                        && send_stream_options
                        && body.contains("stream_options") =>
                {
                    send_stream_options = false;
                }
                TurnHttpResult::NonSuccessStatus { status, body } => {
                    usage_acc.mark_egress_failed();
                    record_http_failure(context, &usage_acc, tool_calls_used);
                    return Err(FleetPolicyError::DriverExecutionFailed(format!(
                        "OpenAI-compatible HTTP {status} from {endpoint} (zero failover): {}",
                        body.chars().take(400).collect::<String>()
                    )));
                }
            }
        };
        usage_acc.record_openai_turn(&parsed);
        let Some(msg) = parsed.pointer("/choices/0/message") else {
            record_http_failure(context, &usage_acc, tool_calls_used);
            return Err(FleetPolicyError::DriverExecutionFailed(
                "response missing choices[0].message".into(),
            ));
        };
        messages.push(msg.clone());

        if let Some(calls) = msg.get("tool_calls").and_then(Value::as_array)
            && !calls.is_empty()
        {
            for tc in calls {
                tool_calls_used += 1;
                if tool_calls_used > max_calls {
                    record_http_failure(context, &usage_acc, tool_calls_used);
                    return Err(FleetPolicyError::DriverExecutionFailed(format!(
                        "exceeded max_tool_calls ({max_calls})"
                    )));
                }
                let call_id = tc
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("call_0")
                    .to_owned();
                let Some(name) = tc.pointer("/function/name").and_then(Value::as_str) else {
                    record_http_failure(context, &usage_acc, tool_calls_used);
                    return Err(FleetPolicyError::DriverExecutionFailed(
                        "tool_call missing name".into(),
                    ));
                };
                let raw_args = tc
                    .pointer("/function/arguments")
                    .and_then(Value::as_str)
                    .unwrap_or("{}");
                let args: Value = serde_json::from_str(raw_args).unwrap_or_else(|_| json!({}));
                let result = execute_tool_call(name, &args, plan, context, tools);
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": result.to_string(),
                }));
            }
            continue;
        }

        let content = msg
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned();
        if content.is_empty() {
            record_http_failure(context, &usage_acc, tool_calls_used);
            return Err(FleetPolicyError::DriverExecutionFailed(
                "model returned empty completion".into(),
            ));
        }
        return Ok(ExecutionOutcome {
            exit_code: Some(0),
            success: true,
            stdout: content,
            stderr: String::new(),
            timed_out: false,
            termination_signal: None,
            output_limit_exceeded: false,
            usage: Some(usage_acc.finish(tool_calls_used as u32, false)),
        });
    }

    record_http_failure(context, &usage_acc, tool_calls_used);
    Err(FleetPolicyError::DriverExecutionFailed(format!(
        "exceeded max_turns ({max_turns})"
    )))
}

#[allow(clippy::too_many_arguments)]
fn run_gemini_loop(
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    endpoint: &str,
    api_key: &str,
    system_prompt: &str,
    user_prompt: &str,
    timeout_secs: u64,
    tools: &HttpToolConfig,
    transport_policy: Option<&HttpTransportPolicy>,
    invoker: &mut dyn CurlInvoker,
) -> FleetResult<ExecutionOutcome> {
    let max_turns = context
        .max_turns_override
        .unwrap_or(tools.max_turns.unwrap_or(32));
    let max_calls = tools.max_tool_calls.unwrap_or(64);
    let max_tokens = context
        .max_output_tokens_override
        .unwrap_or(tools.max_output_tokens.unwrap_or(32_768));
    let tools_active = tools.enabled && !context.tools_disabled;
    let allow_writes = plan.write_mode != WriteMode::ReadOnly;
    let lock_effort = is_effort_locked(plan);
    let configured_thinking = plan
        .model
        .params
        .get("thinking_level")
        .or_else(|| plan.model.params.get("effort"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_uppercase());
    let override_thinking = effort_override_from_context(context).map(|s| s.to_ascii_uppercase());
    if lock_effort
        && let Some(ov) = &override_thinking
        && configured_thinking
            .as_deref()
            .is_some_and(|exp| !exp.eq_ignore_ascii_case(ov))
    {
        return Err(FleetPolicyError::DriverExecutionFailed(format!(
            "EffortSwitchDenied: effort '{ov}' rejected; seat {} is locked to '{}'",
            plan.seat,
            configured_thinking.as_deref().unwrap_or("<unset>")
        )));
    }
    let thinking_level = override_thinking.or(configured_thinking);

    let mut contents = vec![json!({
        "role": "user",
        "parts": [{"text": user_prompt}]
    })];
    let headers = vec![("x-goog-api-key".to_owned(), api_key.to_owned())];
    let mut tool_calls_used = 0usize;
    let mut usage_acc = UsageAccumulator::default();

    for _turn in 0..max_turns {
        let mut gen_cfg = json!({
            "temperature": 0.4,
            "maxOutputTokens": max_tokens,
        });
        if let Some(level) = &thinking_level
            && matches!(level.as_str(), "LOW" | "MEDIUM" | "HIGH")
        {
            gen_cfg["thinkingConfig"] = json!({"thinkingLevel": level});
        }
        let mut payload = json!({
            "systemInstruction": {
                "parts": [{"text": system_prompt}]
            },
            "contents": contents,
            "generationConfig": gen_cfg,
        });
        if tools_active {
            payload["tools"] = gemini_tool_declarations(allow_writes);
        }
        let parsed = match send_turn_with_retry(
            invoker,
            endpoint,
            &headers,
            &payload.to_string(),
            timeout_secs,
            transport_policy,
            ResponseParseMode::Json {
                provider_label: "Gemini",
            },
            &mut usage_acc,
        ) {
            Ok(TurnHttpResult::ParsedJson(v)) => v,
            Ok(TurnHttpResult::NonSuccessStatus { status, body }) => {
                usage_acc.mark_egress_failed();
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(FleetPolicyError::DriverExecutionFailed(format!(
                    "Gemini HTTP {status} from {endpoint} (zero failover): {}",
                    body.chars().take(400).collect::<String>()
                )));
            }
            Err(err) => {
                usage_acc.mark_egress_failed();
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(err);
            }
        };
        usage_acc.record_gemini_turn(&parsed);
        let Some(parts) = parsed
            .pointer("/candidates/0/content/parts")
            .and_then(Value::as_array)
        else {
            record_http_failure(context, &usage_acc, tool_calls_used);
            return Err(FleetPolicyError::DriverExecutionFailed(
                "Gemini missing candidates[0].content.parts".into(),
            ));
        };
        contents.push(json!({
            "role": "model",
            "parts": parts,
        }));

        let mut calls = Vec::new();
        for part in parts {
            if let Some(fc) = part.get("functionCall") {
                let Some(name) = fc.get("name").and_then(Value::as_str) else {
                    record_http_failure(context, &usage_acc, tool_calls_used);
                    return Err(FleetPolicyError::DriverExecutionFailed(
                        "functionCall missing name".into(),
                    ));
                };
                let args = fc.get("args").cloned().unwrap_or_else(|| json!({}));
                let id = fc.get("id").and_then(Value::as_str).map(str::to_owned);
                calls.push((id, name.to_owned(), args));
            }
        }
        if calls.is_empty() {
            let text: String = parts
                .iter()
                .filter(|p| !p.get("thought").and_then(Value::as_bool).unwrap_or(false))
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("");
            let trimmed = text.trim().to_owned();
            if trimmed.is_empty() {
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(FleetPolicyError::DriverExecutionFailed(
                    "Gemini returned empty completion".into(),
                ));
            }
            return Ok(ExecutionOutcome {
                exit_code: Some(0),
                success: true,
                stdout: trimmed,
                stderr: String::new(),
                timed_out: false,
                termination_signal: None,
                output_limit_exceeded: false,
                usage: Some(usage_acc.finish(tool_calls_used as u32, false)),
            });
        }

        let mut response_parts = Vec::new();
        for (id, name, args) in calls {
            tool_calls_used += 1;
            if tool_calls_used > max_calls {
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(FleetPolicyError::DriverExecutionFailed(format!(
                    "exceeded max_tool_calls ({max_calls})"
                )));
            }
            let result = execute_tool_call(&name, &args, plan, context, tools);
            let mut fr = Map::new();
            if let Some(id) = id {
                fr.insert("id".into(), Value::String(id));
            }
            fr.insert("name".into(), Value::String(name));
            fr.insert("response".into(), result);
            let mut wrapper = Map::new();
            wrapper.insert("functionResponse".into(), Value::Object(fr));
            response_parts.push(Value::Object(wrapper));
        }
        contents.push(json!({
            "role": "user",
            "parts": response_parts,
        }));
    }

    record_http_failure(context, &usage_acc, tool_calls_used);
    Err(FleetPolicyError::DriverExecutionFailed(format!(
        "exceeded max_turns ({max_turns})"
    )))
}

#[allow(clippy::too_many_arguments)]
fn run_anthropic_loop(
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    endpoint: &str,
    api_key: &str,
    beta_headers: &[String],
    system_prompt: &str,
    user_prompt: &str,
    timeout_secs: u64,
    tools: &HttpToolConfig,
    transport_policy: Option<&HttpTransportPolicy>,
    invoker: &mut dyn CurlInvoker,
) -> FleetResult<ExecutionOutcome> {
    let max_turns = context
        .max_turns_override
        .unwrap_or(tools.max_turns.unwrap_or(24));
    let max_calls = tools.max_tool_calls.unwrap_or(64);
    let max_tokens = context
        .max_output_tokens_override
        .unwrap_or(tools.max_output_tokens.unwrap_or(16_384));
    let tools_active = tools.enabled && !context.tools_disabled;
    let allow_writes = plan.write_mode != WriteMode::ReadOnly;

    let mut headers = vec![
        ("x-api-key".to_owned(), api_key.to_owned()),
        ("anthropic-version".to_owned(), "2023-06-01".to_owned()),
    ];
    if !beta_headers.is_empty() {
        headers.push(("anthropic-beta".to_owned(), beta_headers.join(",")));
    }
    let mut messages = vec![json!({"role": "user", "content": user_prompt})];
    let mut tool_calls_used = 0usize;
    let mut usage_acc = UsageAccumulator::default();

    for _turn in 0..max_turns {
        let mut payload = json!({
            "model": plan.model.model_id,
            "system": system_prompt,
            "messages": messages,
            "max_tokens": max_tokens,
        });
        if tools_active {
            payload["tools"] = anthropic_tool_declarations(allow_writes);
        }
        let parsed = match send_turn_with_retry(
            invoker,
            endpoint,
            &headers,
            &payload.to_string(),
            timeout_secs,
            transport_policy,
            ResponseParseMode::Json {
                provider_label: "Anthropic",
            },
            &mut usage_acc,
        ) {
            Ok(TurnHttpResult::ParsedJson(v)) => v,
            Ok(TurnHttpResult::NonSuccessStatus { status, body }) => {
                usage_acc.mark_egress_failed();
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(FleetPolicyError::DriverExecutionFailed(format!(
                    "Anthropic HTTP {status} from {endpoint} (zero failover): {}",
                    body.chars().take(400).collect::<String>()
                )));
            }
            Err(err) => {
                usage_acc.mark_egress_failed();
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(err);
            }
        };
        usage_acc.record_anthropic_turn(&parsed);
        let Some(blocks) = parsed.get("content").and_then(Value::as_array) else {
            record_http_failure(context, &usage_acc, tool_calls_used);
            return Err(FleetPolicyError::DriverExecutionFailed(
                "Anthropic missing content array".into(),
            ));
        };
        messages.push(json!({"role": "assistant", "content": blocks}));

        let mut tool_uses = Vec::new();
        for b in blocks {
            if b.get("type").and_then(Value::as_str) == Some("tool_use") {
                let id = b
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("toolu_0")
                    .to_owned();
                let Some(name) = b.get("name").and_then(Value::as_str) else {
                    record_http_failure(context, &usage_acc, tool_calls_used);
                    return Err(FleetPolicyError::DriverExecutionFailed(
                        "tool_use missing name".into(),
                    ));
                };
                let input = b.get("input").cloned().unwrap_or_else(|| json!({}));
                tool_uses.push((id, name.to_owned(), input));
            }
        }
        if tool_uses.is_empty() {
            let text: String = blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("");
            let trimmed = text.trim().to_owned();
            if trimmed.is_empty() {
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(FleetPolicyError::DriverExecutionFailed(
                    "Anthropic returned empty completion".into(),
                ));
            }
            return Ok(ExecutionOutcome {
                exit_code: Some(0),
                success: true,
                stdout: trimmed,
                stderr: String::new(),
                timed_out: false,
                termination_signal: None,
                output_limit_exceeded: false,
                usage: Some(usage_acc.finish(tool_calls_used as u32, false)),
            });
        }

        let mut results = Vec::new();
        for (id, name, input) in tool_uses {
            tool_calls_used += 1;
            if tool_calls_used > max_calls {
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(FleetPolicyError::DriverExecutionFailed(format!(
                    "exceeded max_tool_calls ({max_calls})"
                )));
            }
            let result = execute_tool_call(&name, &input, plan, context, tools);
            results.push(json!({
                "type": "tool_result",
                "tool_use_id": id,
                "content": result.to_string(),
            }));
        }
        messages.push(json!({"role": "user", "content": results}));
    }

    record_http_failure(context, &usage_acc, tool_calls_used);
    Err(FleetPolicyError::DriverExecutionFailed(format!(
        "exceeded max_turns ({max_turns})"
    )))
}

fn openai_tool_declarations(allow_writes: bool) -> Value {
    let mut decls = vec![json!({
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a UTF-8 text file or inspect media metadata on disk.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "max_chars": {"type": "integer"}
                },
                "required": ["path"]
            }
        }
    })];
    if allow_writes {
        decls.push(json!({
            "type": "function",
            "function": {
                "name": "write_file",
                "description": "Write UTF-8 text content inside allowed workspace roots.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"}
                    },
                    "required": ["path", "content"]
                }
            }
        }));
    }
    decls.extend([
        json!({
            "type": "function",
            "function": {
                "name": "fetch_url",
                "description": "Fetch an HTTPS resource subject to fleet egress policy.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "max_chars": {"type": "integer"}
                    },
                    "required": ["url"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "run_command",
                "description": "Run a bounded non-interactive command in the task cwd.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "program": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}},
                        "command": {"type": "string"}
                    }
                }
            }
        }),
    ]);
    Value::Array(decls)
}

fn gemini_tool_declarations(allow_writes: bool) -> Value {
    let mut decls = vec![json!({
        "name": "read_file",
        "description": "Read a UTF-8 text file from disk.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "path": {"type": "STRING"},
                "max_chars": {"type": "INTEGER"}
            },
            "required": ["path"]
        }
    })];
    if allow_writes {
        decls.push(json!({
            "name": "write_file",
            "description": "Write UTF-8 text content inside allowed workspace roots.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "path": {"type": "STRING"},
                    "content": {"type": "STRING"}
                },
                "required": ["path", "content"]
            }
        }));
    }
    decls.extend([
        json!({
            "name": "fetch_url",
            "description": "Fetch an HTTPS resource subject to fleet egress policy.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "url": {"type": "STRING"},
                    "max_chars": {"type": "INTEGER"}
                },
                "required": ["url"]
            }
        }),
        json!({
            "name": "run_command",
            "description": "Run a bounded non-interactive command in the task cwd.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "program": {"type": "STRING"},
                    "args": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "command": {"type": "STRING"}
                }
            }
        }),
    ]);
    json!([{ "functionDeclarations": decls }])
}

fn anthropic_tool_declarations(allow_writes: bool) -> Value {
    let mut decls = vec![json!({
        "name": "read_file",
        "description": "Read a UTF-8 text file from disk.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "max_chars": {"type": "integer"}
            },
            "required": ["path"]
        }
    })];
    if allow_writes {
        decls.push(json!({
            "name": "write_file",
            "description": "Write UTF-8 text content inside allowed workspace roots.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"}
                },
                "required": ["path", "content"]
            }
        }));
    }
    decls.extend([
        json!({
            "name": "fetch_url",
            "description": "Fetch an HTTPS resource subject to fleet egress policy.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "max_chars": {"type": "integer"}
                },
                "required": ["url"]
            }
        }),
        json!({
            "name": "run_command",
            "description": "Run a bounded non-interactive command in the task cwd.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "program": {"type": "string"},
                    "args": {"type": "array", "items": {"type": "string"}},
                    "command": {"type": "string"}
                }
            }
        }),
    ]);
    Value::Array(decls)
}

fn execute_tool_call(
    name: &str,
    args: &Value,
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    tools: &HttpToolConfig,
) -> Value {
    match name {
        "read_file" => tool_read_file(args, &plan.cwd),
        "write_file" => tool_write_file(args, plan, tools),
        "fetch_url" => tool_fetch_url(args, tools),
        "run_command" => tool_run_command(args, plan, context, tools),
        other => json!({"ok": false, "error": format!("unknown tool: {other}")}),
    }
}

fn resolve_input_path(raw_path: &str, cwd: &Path) -> PathBuf {
    let p = Path::new(raw_path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

fn tool_read_file(args: &Value, cwd: &Path) -> Value {
    let Some(raw_path) = args.get("path").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "missing path"});
    };
    let max_chars = args
        .get("max_chars")
        .and_then(Value::as_u64)
        .unwrap_or(32_000)
        .min(196_608) as usize;
    let target = resolve_input_path(raw_path, cwd);
    let canon = match target.canonicalize() {
        Ok(p) => p,
        Err(e) => return json!({"ok": false, "error": format!("cannot resolve path: {e}")}),
    };
    if !canon.is_file() {
        return json!({"ok": false, "error": "target is not a regular file"});
    }
    let ext = canon
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if matches!(
        ext.as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "webp"
            | "gif"
            | "wav"
            | "mp3"
            | "ogg"
            | "flac"
            | "mp4"
            | "mov"
            | "pdf"
    ) {
        let len = fs::metadata(&canon).map(|m| m.len()).unwrap_or(0);
        return json!({
            "ok": true,
            "path": canon.display().to_string(),
            "binary_media": true,
            "extension": ext,
            "bytes": len,
        });
    }
    let content = match fs::read_to_string(&canon) {
        Ok(text) => text,
        Err(e) => return json!({"ok": false, "error": format!("read failed: {e}")}),
    };
    let clipped: String = content.chars().take(max_chars).collect();
    let truncated = content.chars().count() > max_chars;
    json!({
        "ok": true,
        "path": canon.display().to_string(),
        "truncated": truncated,
        "content": clipped,
    })
}

fn tool_write_file(args: &Value, plan: &ResolvedDispatchPlan, tools: &HttpToolConfig) -> Value {
    if plan.write_mode == WriteMode::ReadOnly {
        return json!({"ok": false, "error": "read-only seat cannot write files"});
    }
    let Some(raw_path) = args.get("path").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "missing path"});
    };
    let Some(content) = args.get("content").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "missing content"});
    };
    let candidate = resolve_input_path(raw_path, &plan.cwd);
    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return json!({"ok": false, "error": "parent directory traversal (..) is forbidden"});
    }
    let Some(file_name) = candidate.file_name() else {
        return json!({"ok": false, "error": "invalid destination filename"});
    };
    let Some(parent) = candidate.parent() else {
        return json!({"ok": false, "error": "missing parent directory"});
    };

    let mut roots: Vec<PathBuf> = if !tools.allowed_write_roots.is_empty() {
        tools
            .allowed_write_roots
            .iter()
            .filter_map(|r| fs::canonicalize(r).ok())
            .collect()
    } else if plan.write_mode == WriteMode::Isolated {
        fs::canonicalize(&plan.cwd).into_iter().collect()
    } else {
        Vec::new()
    };
    roots.sort();
    roots.dedup();
    if roots.is_empty() {
        return json!({"ok": false, "error": "no allowed write roots exist on disk"});
    }

    let mut existing = parent.to_path_buf();
    let mut missing_tail = Vec::new();
    while !existing.exists() {
        let Some(seg) = existing.file_name() else {
            return json!({"ok": false, "error": "cannot resolve existing ancestor"});
        };
        missing_tail.push(seg.to_os_string());
        let Some(next) = existing.parent() else {
            return json!({"ok": false, "error": "cannot resolve existing ancestor"});
        };
        existing = next.to_path_buf();
    }
    let Ok(mut canon_dir) = fs::canonicalize(&existing) else {
        return json!({"ok": false, "error": "cannot canonicalize ancestor"});
    };
    for seg in missing_tail.iter().rev() {
        canon_dir.push(seg);
    }
    let final_path = canon_dir.join(file_name);
    if !roots.iter().any(|root| final_path.starts_with(root)) {
        return json!({
            "ok": false,
            "error": format!("destination {} is outside allowed write roots", final_path.display())
        });
    }
    if let Some(p) = final_path.parent()
        && let Err(e) = fs::create_dir_all(p)
    {
        return json!({"ok": false, "error": format!("mkdir failed: {e}")});
    }
    #[cfg(unix)]
    const O_NOFOLLOW: i32 = 0x0100;
    let mut opts = OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    opts.custom_flags(O_NOFOLLOW);
    let mut file = match opts.open(&final_path) {
        Ok(f) => f,
        Err(e) => return json!({"ok": false, "error": format!("open failed: {e}")}),
    };
    if let Err(e) = file.write_all(content.as_bytes()) {
        return json!({"ok": false, "error": format!("write failed: {e}")});
    }
    json!({
        "ok": true,
        "path": final_path.display().to_string(),
        "bytes_written": content.len(),
    })
}

fn parse_https_origin_and_path(url: &str) -> Result<(String, String), String> {
    let trimmed = url.trim();
    let Some(rest) = trimmed.strip_prefix("https://") else {
        return Err("only https:// URLs are permitted".into());
    };
    if rest
        .chars()
        .any(|c| c.is_control() || matches!(c, ' ' | '@' | '\\' | '#' | '[' | ']' | '{' | '}'))
    {
        return Err("URL contains forbidden characters".into());
    }
    let lower = rest.to_ascii_lowercase();
    for bad in ["%2e", "%2f", "%5c", "%00"] {
        if lower.contains(bad) {
            return Err("URL contains forbidden percent-encoded sequence".into());
        }
    }
    let (authority, raw_pq) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains(['?', '#']) {
        return Err("invalid URL authority".into());
    }
    let (raw_path, query) = match raw_pq.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw_pq, None),
    };
    let trailing = raw_path.ends_with('/');
    let mut segs = Vec::new();
    for seg in raw_path.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut norm = if segs.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}{}", segs.join("/"), if trailing { "/" } else { "" })
    };
    if let Some(q) = query {
        norm.push('?');
        norm.push_str(q);
    }
    Ok((authority.to_ascii_lowercase(), norm))
}

fn path_matches_prefix(normalized_pq: &str, prefix: &str) -> bool {
    let path_only = normalized_pq
        .split_once('?')
        .map_or(normalized_pq, |(p, _)| p);
    if !path_only.starts_with(prefix) {
        return false;
    }
    prefix.ends_with('/')
        || path_only.len() == prefix.len()
        || path_only[prefix.len()..].starts_with('/')
}

fn tool_fetch_url(args: &Value, tools: &HttpToolConfig) -> Value {
    let Some(url) = args.get("url").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "missing url"});
    };
    let max_chars = args
        .get("max_chars")
        .and_then(Value::as_u64)
        .unwrap_or(16_000)
        .min(64_000) as usize;
    let (host, norm_path) = match parse_https_origin_and_path(url) {
        Ok(pair) => pair,
        Err(e) => return json!({"ok": false, "error": e}),
    };
    let norm_url = format!("https://{host}{norm_path}");
    let mut headers = vec![("User-Agent".to_owned(), "chinwag-fleet/1.0".to_owned())];
    for rule in &tools.auth_fetches {
        if rule.host.eq_ignore_ascii_case(&host)
            && rule
                .path_prefix
                .as_deref()
                .is_none_or(|p| path_matches_prefix(&norm_path, p))
            && let Ok(secret) =
                read_secret_from_env_file(&rule.secret_env_file, &BTreeMap::new(), &rule.secret_key)
        {
            let val = match &rule.header_prefix {
                Some(prefix) => format!("{prefix}{secret}"),
                None => secret,
            };
            headers.push((rule.header_name.clone(), val));
        }
    }
    match curl_request("GET", &norm_url, &headers, None, 25) {
        Ok(resp) => json!({
            "ok": (200..300).contains(&resp.status),
            "status": resp.status,
            "url": norm_url,
            "body": resp.body.chars().take(max_chars).collect::<String>(),
        }),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

fn tool_run_command(
    args: &Value,
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    tools: &HttpToolConfig,
) -> Value {
    let mut cmd = if let Some(program) = args.get("program").and_then(Value::as_str) {
        if program.trim().is_empty() || program.contains('\0') {
            return json!({"ok": false, "error": "invalid program"});
        }
        let prog_args: Vec<String> = args
            .get("args")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let mut c = Command::new(program);
        c.args(&prog_args);
        c
    } else if let Some(shell_cmd) = args.get("command").and_then(Value::as_str) {
        if shell_cmd.trim().is_empty() || shell_cmd.contains('\0') {
            return json!({"ok": false, "error": "empty or invalid command"});
        }
        let mut c = Command::new("/bin/sh");
        c.args(["-c", shell_cmd]);
        c
    } else {
        return json!({"ok": false, "error": "missing program or command"});
    };

    cmd.current_dir(&plan.cwd);
    cmd.env_clear();
    for key in [
        "HOME", "PATH", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "TERM",
    ] {
        if let Some(val) = std::env::var_os(key) {
            cmd.env(key, val);
        }
    }
    for (k, v) in &context.env {
        cmd.env(k, v);
    }
    for inj in &tools.env_injections {
        if let Some(lit) = &inj.literal {
            cmd.env(&inj.env_var, lit);
        } else if let (Some(path), Some(key)) = (&inj.secret_env_file, &inj.secret_key)
            && let Ok(val) = read_secret_from_env_file(path, &BTreeMap::new(), key)
        {
            cmd.env(&inj.env_var, val);
        }
    }

    let Ok(mut stdout_f) = tempfile::tempfile() else {
        return json!({"ok": false, "error": "tempfile failed"});
    };
    let Ok(mut stderr_f) = tempfile::tempfile() else {
        return json!({"ok": false, "error": "tempfile failed"});
    };
    let (Ok(out_dup), Ok(err_dup)) = (stdout_f.try_clone(), stderr_f.try_clone()) else {
        return json!({"ok": false, "error": "fd clone failed"});
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(out_dup))
        .stderr(Stdio::from(err_dup));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return json!({"ok": false, "error": format!("spawn failed: {e}")}),
    };
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if start.elapsed() >= Duration::from_secs(120) => {
                #[cfg(unix)]
                if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => break None,
        }
    };
    let mut out_s = String::new();
    let mut err_s = String::new();
    let _ = std::io::Seek::seek(&mut stdout_f, std::io::SeekFrom::Start(0));
    let _ = std::io::Seek::seek(&mut stderr_f, std::io::SeekFrom::Start(0));
    let _ = stdout_f.take(12_000).read_to_string(&mut out_s);
    let _ = stderr_f.take(4_000).read_to_string(&mut err_s);
    match status {
        Some(st) => json!({
            "ok": st.success(),
            "exit_code": st.code().unwrap_or(-1),
            "stdout": out_s,
            "stderr": err_s,
        }),
        None => json!({
            "ok": false,
            "timed_out": true,
            "stdout": out_s,
            "stderr": err_s,
        }),
    }
}

#[derive(Clone, Debug, Default)]
pub struct SeatActionOptions {
    pub input_text: String,
    pub commit_boundary: bool,
    pub ambiguity_threshold: f64,
    pub cwcard: Option<String>,
    pub timeout_secs: Option<u64>,
}

/// Executes a manifest-declared seat auxiliary action (e.g. `clef`, `clairic`, `telemetry-gate`,
/// or `scrutinize-omp`) purely from `manifest.extensions.seat_actions.<SEAT>.<ACTION>`.
pub fn execute_manifest_seat_action(
    manifest: &FleetManifest,
    seat_id: &str,
    action_name: &str,
    cwd: &Path,
    options: &SeatActionOptions,
    context: &ExecutionContext,
) -> FleetResult<Value> {
    let spec = manifest
        .extensions
        .get("seat_actions")
        .and_then(|v| v.get(seat_id))
        .and_then(|v| v.get(action_name))
        .ok_or_else(|| {
            FleetPolicyError::UnsupportedDriver(format!(
                "undeclared seat action {seat_id}.{action_name}"
            ))
        })?;
    let kind = spec
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| FleetPolicyError::InvalidManifest("seat action missing kind".into()))?;

    match kind {
        "workers_ai_structured" => run_workers_ai_structured(manifest, spec, cwd, options),
        "openai_json_scrutinizer" => {
            run_openai_json_scrutinizer(manifest, seat_id, spec, cwd, options, context)
        }
        "composite_telemetry_gate" => {
            run_composite_telemetry_gate(manifest, seat_id, spec, cwd, options, context)
        }
        other => Err(FleetPolicyError::InvalidManifest(format!(
            "unsupported seat action kind: {other}"
        ))),
    }
}

fn check_egress_policy(policy: &EgressPolicy, endpoint: &str) -> FleetResult<()> {
    let allowed = match policy {
        EgressPolicy::Unrestricted => true,
        EgressPolicy::DenyAll => false,
        EgressPolicy::AllowList { endpoints } => endpoints.iter().any(|e| {
            endpoint == e
                || endpoint
                    .strip_prefix(e)
                    .is_some_and(|tail| tail.starts_with('/'))
        }),
    };
    if allowed {
        Ok(())
    } else {
        Err(FleetPolicyError::EgressViolation(endpoint.to_owned()))
    }
}

fn run_workers_ai_structured(
    manifest: &FleetManifest,
    spec: &Value,
    cwd: &Path,
    options: &SeatActionOptions,
) -> FleetResult<Value> {
    let base_url = spec
        .get("base_url")
        .and_then(Value::as_str)
        .ok_or_else(|| FleetPolicyError::InvalidManifest("action missing base_url".into()))?;
    check_egress_policy(&manifest.policy.egress_policy, base_url)?;
    let account_id = spec
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| FleetPolicyError::InvalidManifest("action missing account_id".into()))?;
    let env_file = spec
        .get("secret_env_file")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            FleetPolicyError::InvalidManifest("action missing secret_env_file".into())
        })?;
    let resolved_env = manifest.resolve_path(Path::new(env_file), cwd);
    let secret_key = spec
        .get("secret_key")
        .and_then(Value::as_str)
        .ok_or_else(|| FleetPolicyError::InvalidManifest("action missing secret_key".into()))?;
    let token = read_secret_from_env_file(&resolved_env, &BTreeMap::new(), secret_key)?;

    let model = if options.commit_boundary {
        spec.get("commit_boundary_model")
            .or_else(|| spec.get("model"))
            .and_then(Value::as_str)
    } else {
        spec.get("model").and_then(Value::as_str)
    }
    .ok_or_else(|| FleetPolicyError::InvalidManifest("action missing model".into()))?;
    let selector = if options.commit_boundary {
        spec.get("commit_boundary_selector")
            .or_else(|| spec.get("selector"))
            .and_then(Value::as_str)
    } else {
        spec.get("selector").and_then(Value::as_str)
    };

    let mode = spec
        .get("payload_mode")
        .and_then(Value::as_str)
        .unwrap_or("clef_state");
    let mut payload = Map::new();
    if let Some(sel) = selector {
        payload.insert("model".into(), Value::String(sel.to_owned()));
    }
    if mode == "clairic_text" {
        payload.insert(
            "state".into(),
            Value::String(options.input_text.chars().take(32_000).collect()),
        );
        let fields = spec.get("fields").cloned().ok_or_else(|| {
            FleetPolicyError::InvalidManifest("clairic_text missing fields".into())
        })?;
        payload.insert("fields".into(), fields);
    } else {
        let state_val: Value = if options.input_text.trim().starts_with('{') {
            serde_json::from_str(&options.input_text)
                .unwrap_or_else(|_| json!({"text": options.input_text}))
        } else {
            json!({"text": options.input_text})
        };
        payload.insert("state".into(), state_val);
        let questions = spec.get("questions").cloned().ok_or_else(|| {
            FleetPolicyError::InvalidManifest("clef_state missing questions".into())
        })?;
        payload.insert("questions".into(), questions);
    }

    let url = format!(
        "{}/accounts/{}/ai/run/{}",
        base_url.trim_end_matches('/'),
        account_id,
        model
    );
    let headers = vec![("Authorization".to_owned(), format!("Bearer {token}"))];
    let resp = curl_request(
        "POST",
        &url,
        &headers,
        Some(&Value::Object(payload).to_string()),
        options.timeout_secs.unwrap_or(45),
    )?;
    if !(200..300).contains(&resp.status) {
        return Err(FleetPolicyError::DriverExecutionFailed(format!(
            "Workers AI HTTP {} for {}: {}",
            resp.status,
            model,
            resp.body.chars().take(300).collect::<String>()
        )));
    }
    serde_json::from_str(&resp.body).map_err(|e| {
        FleetPolicyError::DriverExecutionFailed(format!("invalid Workers AI JSON: {e}"))
    })
}

fn run_openai_json_scrutinizer(
    manifest: &FleetManifest,
    seat_id: &str,
    spec: &Value,
    cwd: &Path,
    options: &SeatActionOptions,
    context: &ExecutionContext,
) -> FleetResult<Value> {
    let seat_def = manifest
        .seat(seat_id)
        .ok_or_else(|| FleetPolicyError::UnknownSeat(seat_id.to_owned()))?;
    let system_prompt = spec
        .get("system_prompt")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            FleetPolicyError::InvalidManifest("scrutinizer missing system_prompt".into())
        })?;
    let raw_cwcard = options.cwcard.as_deref().unwrap_or(&options.input_text);
    let card_text = if !raw_cwcard.trim().starts_with('{') && Path::new(raw_cwcard).is_file() {
        fs::read_to_string(raw_cwcard)?
    } else {
        raw_cwcard.to_owned()
    };

    let DriverSpec::OpenAiCompatibleHttp {
        base_url,
        api_key_env,
        timeout_secs,
        auth_isolation,
        transport,
        ..
    } = &seat_def.driver
    else {
        return Err(FleetPolicyError::UnsupportedDriver(
            "openai_json_scrutinizer requires OpenAiCompatibleHttp seat driver".into(),
        ));
    };
    validate_transport_policy(transport.as_ref())?;
    check_egress_policy(&manifest.policy.egress_policy, base_url)?;
    let mut iso = auth_isolation.clone();
    let mut dummy_tools = HttpToolConfig::default();
    crate::resolve_driver_credentials(manifest, cwd, &mut iso, &mut dummy_tools)?;
    let api_key = resolve_driver_api_key(&iso, api_key_env)?;
    let endpoint = if base_url
        .trim_end_matches('/')
        .ends_with("/chat/completions")
    {
        base_url.trim_end_matches('/').to_owned()
    } else {
        format!("{}/chat/completions", base_url.trim_end_matches('/'))
    };
    let mut headers = Vec::new();
    if let Some(key) = api_key {
        headers.push(("Authorization".to_owned(), format!("Bearer {key}")));
    }
    let max_tokens = spec
        .get("max_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(2048);
    let payload = json!({
        "model": seat_def.model.model_id,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": card_text}
        ],
        "max_tokens": max_tokens,
        "temperature": 0.0
    });
    let eff_timeout = context
        .timeout_override_secs
        .or(options.timeout_secs)
        .unwrap_or(*timeout_secs);
    let resp = curl_request_raw(
        "POST",
        &endpoint,
        &headers,
        Some(&payload.to_string()),
        CurlRequestOptions::from_policy(eff_timeout, transport.as_ref(), false),
    )
    .map_err(CurlCallError::into_policy_error)?;
    if !(200..300).contains(&resp.status) {
        return Err(FleetPolicyError::DriverExecutionFailed(format!(
            "scrutinizer HTTP {}: {}",
            resp.status,
            resp.body.chars().take(300).collect::<String>()
        )));
    }
    let parsed: Value = serde_json::from_str(&resp.body).map_err(|e| {
        FleetPolicyError::DriverExecutionFailed(format!("invalid scrutinizer envelope: {e}"))
    })?;
    let raw_content = parsed
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let cleaned = raw_content
        .strip_prefix("```json")
        .or_else(|| raw_content.strip_prefix("```"))
        .map(|s| s.trim().strip_suffix("```").unwrap_or(s).trim())
        .unwrap_or(raw_content);
    let out: Value = serde_json::from_str(cleaned).map_err(|e| {
        FleetPolicyError::DriverExecutionFailed(format!("scrutinizer returned non-JSON: {e}"))
    })?;
    if !out.is_object() {
        return Err(FleetPolicyError::DriverExecutionFailed(
            "scrutinizer JSON output must be an object".into(),
        ));
    }
    Ok(out)
}

fn run_composite_telemetry_gate(
    manifest: &FleetManifest,
    seat_id: &str,
    spec: &Value,
    cwd: &Path,
    options: &SeatActionOptions,
    context: &ExecutionContext,
) -> FleetResult<Value> {
    let clef_action = spec
        .get("clef_action")
        .and_then(Value::as_str)
        .unwrap_or("clef");
    let clairic_action = spec
        .get("clairic_action")
        .and_then(Value::as_str)
        .unwrap_or("clairic");
    let redaction_key = spec
        .get("redaction_clean_key")
        .and_then(Value::as_str)
        .unwrap_or("public_board_redaction_clean");
    let loc_p90_threshold = spec
        .get("loc_p90_threshold")
        .and_then(Value::as_f64)
        .unwrap_or(150.0);

    let clef_res =
        execute_manifest_seat_action(manifest, seat_id, clef_action, cwd, options, context)?;
    let clairic_res =
        execute_manifest_seat_action(manifest, seat_id, clairic_action, cwd, options, context)?;
    let res_body = clef_res.get("result").unwrap_or(&clef_res);
    let answers_map = res_body
        .get("answers")
        .or_else(|| res_body.get("questions"))
        .unwrap_or(res_body)
        .as_object();

    let mut max_trigger = 0.0f64;
    let mut scores = Map::new();
    if let Some(map) = answers_map {
        for (k, v) in map {
            if k == redaction_key {
                continue;
            }
            if let Some(score) = v
                .as_f64()
                .or_else(|| v.get("noul").and_then(Value::as_f64))
                .or_else(|| v.get("probability").and_then(Value::as_f64))
            {
                scores.insert(k.clone(), json!(score));
                if score > max_trigger {
                    max_trigger = score;
                }
            }
        }
    }
    let clairic_body = clairic_res.get("result").unwrap_or(&clairic_res);
    let loc_p90 = clairic_body
        .pointer("/answers/estimated_loc_diff/p90")
        .or_else(|| clairic_body.pointer("/fields/estimated_loc_diff/p90"))
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let clef_ok = clef_res
        .get("success")
        .or_else(|| clef_res.get("ok"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let needs_escalation =
        !clef_ok || max_trigger >= options.ambiguity_threshold || loc_p90 > loc_p90_threshold;
    if !needs_escalation {
        return Ok(json!({
            "ok": true,
            "routed_to": "system1_clef_clairic_only",
            "system2_woken": false,
            "max_ambiguity_score": (max_trigger * 10_000.0).round() / 10_000.0,
            "clairic_loc_p90": loc_p90,
            "clef": clef_res,
            "clairic": clairic_res,
        }));
    }

    let escalated_prompt = format!(
        "[SYSTEM 1 AMBIGUITY ESCALATION]\nScores: {}\nClairic: {}\n\nTelemetry Event:\n{}",
        Value::Object(scores),
        clairic_body,
        options.input_text
    );
    let seat_def = manifest
        .seat(seat_id)
        .ok_or_else(|| FleetPolicyError::UnknownSeat(seat_id.to_owned()))?;
    let plan = resolve_dispatch_plan(
        manifest,
        &crate::DispatchRequest {
            seat: seat_id.to_owned(),
            cwd: cwd.to_path_buf(),
            requested_write_globs: seat_def.allowed_write_roots.clone(),
            ..Default::default()
        },
    )?;
    let mut esc_ctx = context.clone();
    esc_ctx.prompt = Some(escalated_prompt);
    let outcome = execute_http_driver(&plan, &esc_ctx, |_| {})?;
    Ok(json!({
        "ok": outcome.success,
        "routed_to": "system2_escalated",
        "system2_woken": true,
        "max_ambiguity_score": (max_trigger * 10_000.0).round() / 10_000.0,
        "clairic_loc_p90": loc_p90,
        "reply": outcome.stdout,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ExecutionTarget, ModelBinding, OrgFleetPolicy, SeatDefinition, SeatId, SeatLifecycle,
        SkillConfig, SkillPolicyRef,
    };
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::thread;

    fn mock_http_server(responses: Vec<&'static str>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for body in responses {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut content_len = 0usize;
                    loop {
                        let mut line = String::new();
                        let _ = reader.read_line(&mut line);
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = trimmed.split_once(':')
                            && k.eq_ignore_ascii_case("content-length")
                        {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                    if content_len > 0 {
                        let mut discard = vec![0u8; content_len];
                        let _ = std::io::Read::read_exact(&mut reader, &mut discard);
                    }
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(reply.as_bytes());
                }
            }
        });
        format!("http://{addr}")
    }

    fn write_0600_secret(path: &Path, text: &str) {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn openai_http_driver_executes_tool_turn_and_final_reply_against_local_server() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        fs::write(root.join("sample.txt"), "hello-from-tool").unwrap();
        let env_path = root.join("gateway.env");
        write_0600_secret(&env_path, "GATEWAY_KEY=secret-test-123\n");

        let turn1 = r#"{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"sample.txt\"}"}}]}}]}"#;
        let turn2 =
            r#"{"choices":[{"message":{"role":"assistant","content":"VERIFIED_TOOL_LOOP"}}]}"#;
        let base_url = mock_http_server(vec![turn1, turn2]);

        let manifest = FleetManifest {
            schema_version: 1,
            nodes: vec![],
            seats: vec![SeatDefinition {
                id: SeatId::new("CUSTOM-HTTP").unwrap(),
                display_name: None,
                lifecycle: SeatLifecycle::ActiveStanding,
                target_selector: ExecutionTarget::LocalProcess,
                driver: DriverSpec::OpenAiCompatibleHttp {
                    base_url,
                    api_key_env: "GATEWAY_KEY".into(),
                    wire_mode: "chat_completions".into(),
                    stream_mode: "none".into(),
                    timeout_secs: 10,
                    auth_isolation: CredentialIsolation::SecretEnvFile {
                        path: env_path,
                        key_map: BTreeMap::new(),
                    },
                    tools: HttpToolConfig {
                        enabled: true,
                        ..Default::default()
                    },
                    transport: None,
                },
                model: ModelBinding {
                    provider: "custom-gw".into(),
                    model_id: "vendor/custom-model".into(),
                    params: BTreeMap::new(),
                    failover_policy: None,
                },
                write_mode: WriteMode::ReadOnly,
                isolation: crate::IsolationSpec::ReadOnly,
                allowed_write_roots: vec![],
                allowed_rooms: None,
                skills: SkillPolicyRef::default(),
                boot_files: vec![],
                profile_dir: None,
            }],
            policy: OrgFleetPolicy::default(),
            skills: SkillConfig::default(),
            pubkey_map: BTreeMap::new(),
            allowed_signers: BTreeMap::new(),
            private_key_paths: BTreeMap::new(),
            pin: None,
            extensions: BTreeMap::new(),
            task_profiles: BTreeMap::new(),
            source_dir: None,
        };

        let plan = resolve_dispatch_plan(
            &manifest,
            &crate::DispatchRequest {
                seat: "CUSTOM-HTTP".into(),
                cwd: root,
                ..Default::default()
            },
        )
        .unwrap();
        let outcome = execute_http_driver(
            &plan,
            &ExecutionContext {
                prompt: Some("Read sample.txt".into()),
                ..Default::default()
            },
            |_| {},
        )
        .unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.stdout, "VERIFIED_TOOL_LOOP");
    }

    #[test]
    fn google_genai_http_driver_preserves_thought_signature_and_replies() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let env_path = root.join("gemini.env");
        write_0600_secret(&env_path, "export GEMINI_API_KEY=\"test-gemini-key\"\n");
        let reply = r#"{"candidates":[{"content":{"role":"model","parts":[{"thought":true,"text":"thinking"},{"text":"GEMINI_OK","thoughtSignature":"sig123"}]}}]}"#;
        let base_url = mock_http_server(vec![reply]);

        let manifest = FleetManifest {
            schema_version: 1,
            nodes: vec![],
            seats: vec![SeatDefinition {
                id: SeatId::new("MEDIA-SEAT").unwrap(),
                display_name: None,
                lifecycle: SeatLifecycle::ActiveStanding,
                target_selector: ExecutionTarget::LocalProcess,
                driver: DriverSpec::GoogleGenAiHttp {
                    endpoint_mode: "ai_studio".into(),
                    base_url_or_region: base_url,
                    auth_env: "GEMINI_API_KEY".into(),
                    stream_mode: "none".into(),
                    timeout_secs: 10,
                    auth_isolation: CredentialIsolation::SecretEnvFile {
                        path: env_path,
                        key_map: BTreeMap::new(),
                    },
                    tools: HttpToolConfig::default(),
                    transport: None,
                },
                model: ModelBinding {
                    provider: "google-gemini".into(),
                    model_id: "gemini-4-carbon".into(),
                    params: BTreeMap::from([(
                        "thinking_level".into(),
                        Value::String("HIGH".into()),
                    )]),
                    failover_policy: None,
                },
                write_mode: WriteMode::ReadOnly,
                isolation: crate::IsolationSpec::ReadOnly,
                allowed_write_roots: vec![],
                allowed_rooms: None,
                skills: SkillPolicyRef::default(),
                boot_files: vec![],
                profile_dir: None,
            }],
            policy: OrgFleetPolicy::default(),
            skills: SkillConfig::default(),
            pubkey_map: BTreeMap::new(),
            allowed_signers: BTreeMap::new(),
            private_key_paths: BTreeMap::new(),
            pin: None,
            extensions: BTreeMap::new(),
            task_profiles: BTreeMap::new(),
            source_dir: None,
        };

        let plan = resolve_dispatch_plan(
            &manifest,
            &crate::DispatchRequest {
                seat: "MEDIA-SEAT".into(),
                cwd: root,
                ..Default::default()
            },
        )
        .unwrap();
        let outcome = execute_http_driver(
            &plan,
            &ExecutionContext {
                prompt: Some("Ping".into()),
                ..Default::default()
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(outcome.stdout, "GEMINI_OK");
    }

    #[test]
    fn manifest_seat_action_workers_ai_executes_without_hardcoding() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let env_path = root.join("cf.env");
        write_0600_secret(&env_path, "CF_TOKEN=tok-123\n");
        let base_url = mock_http_server(vec![
            r#"{"success":true,"result":{"answers":{"flag":0.1}}}"#,
        ]);

        let mut manifest = FleetManifest::starter_profile("solo").unwrap();
        manifest.extensions.insert(
            "seat_actions".into(),
            json!({
                "default": {
                    "triage": {
                        "kind": "workers_ai_structured",
                        "base_url": base_url,
                        "account_id": "0123456789abcdef0123456789abcdef",
                        "secret_env_file": env_path,
                        "secret_key": "CF_TOKEN",
                        "model": "@cf/example/classifier",
                        "payload_mode": "clef_state",
                        "questions": {"flag": {"type": "noul"}}
                    }
                }
            }),
        );
        let out = execute_manifest_seat_action(
            &manifest,
            "default",
            "triage",
            &root,
            &SeatActionOptions {
                input_text: "{\"task\":\"T-1\"}".into(),
                ..Default::default()
            },
            &ExecutionContext::default(),
        )
        .unwrap();
        assert_eq!(out["success"], true);
        assert_eq!(out["result"]["answers"]["flag"], 0.1);
    }

    #[derive(Clone)]
    struct RecordedCurlCall {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<String>,
        accept_header: String,
        no_buffer: bool,
        timeout_secs: u64,
        connect_timeout_secs: u64,
        keepalive_time_secs: u64,
        stall_timeout_secs: Option<u64>,
        force_http1_1: bool,
    }

    struct MockCurlInvoker {
        scripts: std::collections::VecDeque<Result<CurlHttpResponse, CurlCallError>>,
        calls: Vec<RecordedCurlCall>,
    }

    impl MockCurlInvoker {
        fn new(scripts: Vec<Result<CurlHttpResponse, CurlCallError>>) -> Self {
            Self {
                scripts: scripts.into_iter().collect(),
                calls: Vec::new(),
            }
        }
    }

    impl CurlInvoker for MockCurlInvoker {
        fn invoke(
            &mut self,
            method: &str,
            url: &str,
            headers: &[(String, String)],
            body: Option<&str>,
            opts: CurlRequestOptions<'_>,
        ) -> Result<CurlHttpResponse, CurlCallError> {
            self.calls.push(RecordedCurlCall {
                method: method.to_string(),
                url: url.to_string(),
                headers: headers.to_vec(),
                body: body.map(ToOwned::to_owned),
                accept_header: opts.accept_header.to_string(),
                no_buffer: opts.no_buffer,
                timeout_secs: opts.timeout_secs,
                connect_timeout_secs: opts.connect_timeout_secs,
                keepalive_time_secs: opts.keepalive_time_secs,
                stall_timeout_secs: opts.stall_timeout_secs,
                force_http1_1: opts.force_http1_1,
            });
            self.scripts
                .pop_front()
                .expect("MockCurlInvoker exhausted scripted responses")
        }
    }

    #[derive(Clone)]
    struct CapturedHttpRequest {
        headers_raw: String,
        body_raw: String,
    }

    impl CapturedHttpRequest {
        fn has_header_ci(&self, name: &str, expected_value: &str) -> bool {
            let needle_name = name.to_ascii_lowercase();
            let needle_val = expected_value.to_ascii_lowercase();
            self.headers_raw.lines().skip(1).any(|line| {
                let Some((k, v)) = line.split_once(':') else {
                    return false;
                };
                k.trim().eq_ignore_ascii_case(&needle_name)
                    && v.trim().to_ascii_lowercase().contains(&needle_val)
            })
        }

        fn body_json(&self) -> serde_json::Value {
            serde_json::from_str(&self.body_raw).expect("captured HTTP body should be JSON")
        }
    }

    enum MockTcpScript {
        Http {
            status_line: String,
            headers: Vec<(String, String)>,
            chunks: Vec<Vec<u8>>,
            drop_without_closing_gracefully: bool,
        },
        RawBytes(Vec<u8>),
    }

    fn read_http_request_from_stream(stream: &mut std::net::TcpStream) -> CapturedHttpRequest {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut temp = [0u8; 4096];
        let mut header_end = None;
        let mut content_length = 0usize;

        loop {
            let n = stream.read(&mut temp).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&temp[..n]);
            if header_end.is_none()
                && let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
            {
                header_end = Some(pos + 4);
                let header_str = String::from_utf8_lossy(&buf[..pos]);
                for line in header_str.lines() {
                    if let Some((k, v)) = line.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_length = v.trim().parse::<usize>().unwrap_or(0);
                    }
                }
            }
            if let Some(end) = header_end
                && buf.len() >= end + content_length
            {
                break;
            }
        }

        let end = header_end.unwrap_or(buf.len());
        let headers_raw = String::from_utf8_lossy(&buf[..end]).into_owned();
        let body_slice = &buf[end..buf.len().min(end + content_length)];
        let body_raw = String::from_utf8_lossy(body_slice).into_owned();
        CapturedHttpRequest {
            headers_raw,
            body_raw,
        }
    }

    fn spawn_mock_script_server(
        scripts: Vec<MockTcpScript>,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<CapturedHttpRequest>>>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_clone = std::sync::Arc::clone(&captured);

        let handle = std::thread::spawn(move || {
            for script in scripts {
                let (mut stream, _) = listener.accept().unwrap();
                let req = read_http_request_from_stream(&mut stream);
                captured_clone.lock().unwrap().push(req);

                match script {
                    MockTcpScript::RawBytes(bytes) => {
                        let _ = stream.write_all(&bytes);
                        let _ = stream.flush();
                    }
                    MockTcpScript::Http {
                        status_line,
                        headers,
                        chunks,
                        drop_without_closing_gracefully,
                    } => {
                        let mut head = format!("HTTP/1.1 {status_line}\r\nConnection: close\r\n");
                        for (k, v) in headers {
                            head.push_str(&format!("{k}: {v}\r\n"));
                        }
                        head.push_str("\r\n");
                        let _ = stream.write_all(head.as_bytes());
                        for chunk in chunks {
                            let _ = stream.write_all(&chunk);
                            let _ = stream.flush();
                        }
                        if !drop_without_closing_gracefully {
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                        }
                    }
                }
            }
        });

        (format!("http://{addr}"), captured, handle)
    }

    fn zero_backoff_transport_policy(max_retries: u32) -> HttpTransportPolicy {
        HttpTransportPolicy {
            max_retries: Some(max_retries),
            initial_backoff_ms: Some(0),
            max_backoff_ms: Some(0),
            connect_timeout_secs: Some(30),
            keepalive_time_secs: Some(15),
            stall_timeout_secs: None,
            force_http1_1: Some(false),
        }
    }

    fn build_openai_test_plan(
        root: &std::path::Path,
        base_url: &str,
        stream_mode: &str,
        lock_effort: bool,
        reasoning_effort: Option<&str>,
        transport: Option<HttpTransportPolicy>,
    ) -> ResolvedDispatchPlan {
        let env_path = root.join("openai.env");
        write_0600_secret(&env_path, "OPENAI_KEY=test-secret-123\n");
        let mut params = BTreeMap::new();
        params.insert("lock_effort".into(), json!(lock_effort));
        if let Some(effort) = reasoning_effort {
            params.insert("reasoning_effort".into(), json!(effort));
        }

        let manifest = FleetManifest {
            schema_version: 1,
            nodes: vec![],
            seats: vec![SeatDefinition {
                id: SeatId::new("TEST-QA").unwrap(),
                display_name: None,
                lifecycle: SeatLifecycle::ActiveStanding,
                target_selector: ExecutionTarget::LocalProcess,
                driver: DriverSpec::OpenAiCompatibleHttp {
                    base_url: base_url.to_string(),
                    api_key_env: "OPENAI_KEY".into(),
                    wire_mode: "chat_completions".into(),
                    stream_mode: stream_mode.to_string(),
                    timeout_secs: 60,
                    auth_isolation: crate::CredentialIsolation::SecretEnvFile {
                        path: env_path,
                        key_map: BTreeMap::new(),
                    },
                    tools: HttpToolConfig {
                        enabled: true,
                        ..Default::default()
                    },
                    transport,
                },
                model: ModelBinding {
                    provider: "custom-gw".into(),
                    model_id: "vendor/custom-model".into(),
                    params,
                    failover_policy: None,
                },
                write_mode: crate::WriteMode::ReadOnly,
                isolation: crate::IsolationSpec::ReadOnly,
                allowed_write_roots: vec![],
                allowed_rooms: None,
                skills: SkillPolicyRef::default(),
                boot_files: vec![],
                profile_dir: None,
            }],
            policy: OrgFleetPolicy::default(),
            skills: SkillConfig::default(),
            pubkey_map: BTreeMap::new(),
            allowed_signers: BTreeMap::new(),
            private_key_paths: BTreeMap::new(),
            pin: None,
            extensions: BTreeMap::new(),
            task_profiles: BTreeMap::new(),
            source_dir: None,
        };
        manifest.validate().unwrap();
        resolve_dispatch_plan(
            &manifest,
            &crate::DispatchRequest {
                seat: "TEST-QA".into(),
                cwd: root.to_path_buf(),
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn openai_sse_reassembles_chunked_tool_calls_heartbeat_comments_and_final_usage() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::write(root.join("note.txt"), "hello from sse note\n").unwrap();

        let turn1_chunks = vec![
            b": ping\n\n: keepalive\n\nevent: ping\ndata: {\"type\":\"ping\"}\n\n".to_vec(),
            br#"data: {"id":"cmpl-1","choices":[{"index":0,"delta":{"role":"assistant","content":"","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\""}}]},"finish_reason":null}]}"#.to_vec(),
            b"\n\n: mid-stream heartbeat\n\n".to_vec(),
            br#"data: {"id":"cmpl-1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"note.txt\"}"}}]},"finish_reason":null}]}"#.to_vec(),
            b"\n\n".to_vec(),
            br#"data: {"id":"cmpl-1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#.to_vec(),
            b"\n\n".to_vec(),
            br#"data: {"id":"cmpl-1","choices":[],"usage":{"prompt_tokens":40,"completion_tokens":20,"total_tokens":60}}"#.to_vec(),
            b"\n\ndata: [DONE]\n\n".to_vec(),
        ];

        let turn2_chunks = vec![
            b": keepalive before final answer\n\n".to_vec(),
            br#"data: {"id":"cmpl-2","choices":[{"index":0,"delta":{"content":"Read "},"finish_reason":null}]}"#.to_vec(),
            b"\n\n".to_vec(),
            br#"data: {"id":"cmpl-2","choices":[{"index":0,"delta":{"content":"done."},"finish_reason":"stop"}],"usage":{"prompt_tokens":50,"completion_tokens":10,"total_tokens":60}}"#.to_vec(),
            b"\n\ndata: [DONE]\n\n".to_vec(),
        ];

        let (base_url, captured, handle) = spawn_mock_script_server(vec![
            MockTcpScript::Http {
                status_line: "200 OK".to_string(),
                headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
                chunks: turn1_chunks,
                drop_without_closing_gracefully: false,
            },
            MockTcpScript::Http {
                status_line: "200 OK".to_string(),
                headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
                chunks: turn2_chunks,
                drop_without_closing_gracefully: false,
            },
        ]);

        let plan = build_openai_test_plan(&root, &base_url, "sse", true, Some("high"), None);
        let ctx = ExecutionContext {
            prompt: Some("Read note.txt and confirm.".to_string()),
            ..Default::default()
        };

        let outcome = execute_http_driver(&plan, &ctx, |_| {}).unwrap();
        handle.join().unwrap();

        assert!(outcome.stdout.contains("Read done."));
        let usage = outcome.usage.expect("http usage summary recorded");
        assert_eq!(usage.usage_status, "COUNTED");
        assert_eq!(usage.turns, 2);
        assert_eq!(usage.tool_calls, 1);
        assert_eq!(usage.transport_retries, 0);
        assert_eq!(usage.prompt_tokens, Some(90));
        assert_eq!(usage.completion_tokens, Some(30));
        assert_eq!(usage.gross_tokens, Some(120));
        assert_eq!(usage.observed_partial_gross_tokens, 120);

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        assert!(reqs[0].has_header_ci("accept", "text/event-stream"));
        let b0 = reqs[0].body_json();
        assert_eq!(b0["stream"], json!(true));
        assert_eq!(b0["stream_options"], json!({"include_usage": true}));
        let b1 = reqs[1].body_json();
        assert!(
            b1["messages"].to_string().contains("hello from sse note"),
            "Turn 2 should receive the Turn 1 read_file tool result: {b1}"
        );
    }

    #[test]
    fn openai_sse_truncated_without_done_retries_same_route_and_recovers() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::write(root.join("note.txt"), "note payload\n").unwrap();

        let turn1 = MockTcpScript::Http {
            status_line: "200 OK".to_string(),
            headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
            chunks: vec![
                br#"data: {"id":"t1","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_t1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"note.txt\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":70,"completion_tokens":30,"total_tokens":100}}"#.to_vec(),
                b"\n\ndata: [DONE]\n\n".to_vec(),
            ],
            drop_without_closing_gracefully: false,
        };

        // Turn 2 Attempt 1: 200 SSE with partial delta.tool_calls and immediate EOF (no [DONE], no finish_reason)
        let turn2_attempt1_truncated = MockTcpScript::Http {
            status_line: "200 OK".to_string(),
            headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
            chunks: vec![
                br#"data: {"id":"t2_bad","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_partial","type":"function","function":{"name":"read_file","arguments":"{\"path\":"}}]},"finish_reason":null}]}"#.to_vec(),
                b"\n\n".to_vec(),
            ],
            drop_without_closing_gracefully: true,
        };

        // Turn 2 Attempt 2: Complete SSE reply + [DONE]
        let turn2_attempt2_ok = MockTcpScript::Http {
            status_line: "200 OK".to_string(),
            headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
            chunks: vec![
                br#"data: {"id":"t2_ok","choices":[{"index":0,"delta":{"content":"Recovered after stream drop"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}"#.to_vec(),
                b"\n\ndata: [DONE]\n\n".to_vec(),
            ],
            drop_without_closing_gracefully: false,
        };

        let (base_url, captured, handle) =
            spawn_mock_script_server(vec![turn1, turn2_attempt1_truncated, turn2_attempt2_ok]);

        let plan = build_openai_test_plan(
            &root,
            &base_url,
            "sse",
            true,
            Some("high"),
            Some(zero_backoff_transport_policy(2)),
        );
        let ctx = ExecutionContext {
            prompt: Some("Inspect note.txt".to_string()),
            ..Default::default()
        };

        let outcome = execute_http_driver(&plan, &ctx, |_| {}).unwrap();
        handle.join().unwrap();

        assert!(outcome.stdout.contains("Recovered after stream drop"));
        let usage = outcome.usage.expect("http usage summary recorded");
        assert_eq!(usage.usage_status, "UNKNOWN");
        assert_eq!(usage.turns, 2);
        assert_eq!(usage.tool_calls, 1);
        assert_eq!(usage.transport_retries, 1);
        assert_eq!(usage.gross_tokens, None);
        assert_eq!(usage.observed_partial_gross_tokens, 250);

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 3);
        assert_eq!(
            reqs[1].body_raw, reqs[2].body_raw,
            "Turn 2 retry must re-send identical JSON payload without partial Turn 2 tool state"
        );
        assert!(!reqs[2].body_raw.contains("call_partial"));
    }

    #[test]
    fn curl_exit_56_retries_bounded_same_endpoint_preserves_prior_turns_and_marks_unknown_usage() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::write(root.join("note.txt"), "data for curl 56 test\n").unwrap();

        let turn1_json = serde_json::json!({
            "id": "r1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": "{\"path\":\"note.txt\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 70, "completion_tokens": 30, "total_tokens": 100}
        })
        .to_string();

        let turn2_ok_json = serde_json::json!({
            "id": "r2",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Recovered from 56"
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
        })
        .to_string();

        // (a) MockCurlInvoker curl exit 56 on Turn 2 Attempt 1 -> recovers on Turn 2 Attempt 2
        let plan_mock = build_openai_test_plan(
            &root,
            "https://gateway.example.invalid/v1",
            "none",
            true,
            Some("high"),
            Some(zero_backoff_transport_policy(2)),
        );
        let ctx_mock = ExecutionContext {
            prompt: Some("Read note.txt".to_string()),
            ..Default::default()
        };
        let mut invoker_ok = MockCurlInvoker::new(vec![
            Ok(CurlHttpResponse {
                status: 200,
                headers: vec![],
                body: turn1_json.clone(),
            }),
            Err(CurlCallError::Transport {
                exit_code: Some(56),
                stderr: "curl: (56) Recv failure: Operation timed out".to_string(),
            }),
            Ok(CurlHttpResponse {
                status: 200,
                headers: vec![],
                body: turn2_ok_json.clone(),
            }),
        ]);

        let outcome =
            execute_http_driver_with_invoker(&plan_mock, &ctx_mock, |_| {}, &mut invoker_ok)
                .unwrap();
        assert!(outcome.stdout.contains("Recovered from 56"));
        let usage = outcome.usage.unwrap();
        assert_eq!(usage.turns, 2);
        assert_eq!(usage.tool_calls, 1);
        assert_eq!(usage.transport_retries, 1);
        assert_eq!(usage.usage_status, "UNKNOWN");
        assert_eq!(usage.gross_tokens, None);
        assert_eq!(usage.observed_partial_gross_tokens, 250);

        assert_eq!(invoker_ok.calls.len(), 3);
        for c in &invoker_ok.calls {
            assert_eq!(c.method, "POST");
            assert_eq!(c.accept_header, "application/json");
            assert!(!c.no_buffer);
            assert!((55..=60).contains(&c.timeout_secs));
            assert_eq!(c.connect_timeout_secs, 30);
            assert_eq!(c.keepalive_time_secs, 15);
            assert_eq!(c.stall_timeout_secs, None);
            assert!(!c.force_http1_1);
        }
        assert_eq!(invoker_ok.calls[1].url, invoker_ok.calls[2].url);
        assert_eq!(invoker_ok.calls[1].headers, invoker_ok.calls[2].headers);
        assert_eq!(invoker_ok.calls[1].body, invoker_ok.calls[2].body);

        // (b) Bounded exhaustion: max_retries = 2 -> 3 Turn-2 attempts fail closed preserving Turn 1
        let _ = take_last_failed_http_usage();
        let mut invoker_exhaust = MockCurlInvoker::new(vec![
            Ok(CurlHttpResponse {
                status: 200,
                headers: vec![],
                body: turn1_json.clone(),
            }),
            Err(CurlCallError::Transport {
                exit_code: Some(56),
                stderr: "curl: (56) Recv failure: Operation timed out".to_string(),
            }),
            Err(CurlCallError::Transport {
                exit_code: Some(56),
                stderr: "curl: (56) Recv failure: Operation timed out".to_string(),
            }),
            Err(CurlCallError::Transport {
                exit_code: Some(56),
                stderr: "curl: (56) Recv failure: Operation timed out".to_string(),
            }),
        ]);

        let err =
            execute_http_driver_with_invoker(&plan_mock, &ctx_mock, |_| {}, &mut invoker_exhaust)
                .unwrap_err();
        assert_eq!(invoker_exhaust.calls.len(), 4);
        assert!(
            err.to_string()
                .starts_with("DriverExecutionFailed: HTTP transport failure: curl: (56) Recv failure: Operation timed out"),
            "unexpected error format: {err}"
        );
        let failed_usage = take_last_failed_http_usage().expect("failed usage summary captured");
        assert_eq!(failed_usage.turns, 2);
        assert_eq!(failed_usage.tool_calls, 1);
        assert_eq!(failed_usage.transport_retries, 2);
        assert_eq!(failed_usage.usage_status, "UNKNOWN");
        assert_eq!(failed_usage.gross_tokens, None);
        assert_eq!(failed_usage.observed_partial_gross_tokens, 100);

        // (c) Real /usr/bin/curl premature TCP EOF mid-body on Turn 2 Attempt 1 -> recovers on Attempt 2
        let (base_url, captured, handle) = spawn_mock_script_server(vec![
            MockTcpScript::Http {
                status_line: "200 OK".to_string(),
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    (
                        "Content-Length".to_string(),
                        turn1_json.len().to_string(),
                    ),
                ],
                chunks: vec![turn1_json.into_bytes()],
                drop_without_closing_gracefully: false,
            },
            MockTcpScript::RawBytes(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\nConnection: close\r\n\r\n{\"id\":\"partial\",\"ch".to_vec(),
            ),
            MockTcpScript::Http {
                status_line: "200 OK".to_string(),
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    (
                        "Content-Length".to_string(),
                        turn2_ok_json.len().to_string(),
                    ),
                ],
                chunks: vec![turn2_ok_json.into_bytes()],
                drop_without_closing_gracefully: false,
            },
        ]);

        let plan_real = build_openai_test_plan(
            &root,
            &base_url,
            "none",
            true,
            Some("high"),
            Some(zero_backoff_transport_policy(2)),
        );
        let outcome_real = execute_http_driver(&plan_real, &ctx_mock, |_| {}).unwrap();
        handle.join().unwrap();

        assert_eq!(captured.lock().unwrap().len(), 3);
        let usage_real = outcome_real.usage.unwrap();
        assert_eq!(usage_real.turns, 2);
        assert_eq!(usage_real.tool_calls, 1);
        assert_eq!(usage_real.transport_retries, 1);
        assert_eq!(usage_real.usage_status, "UNKNOWN");
        assert_eq!(usage_real.gross_tokens, None);
        assert_eq!(usage_real.observed_partial_gross_tokens, 250);
    }

    #[test]
    fn non_retryable_http_401_400_and_locked_effort_never_retry_or_failover() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();

        // 1. HTTP 401 never retries even with max_retries = 3
        let _ = take_last_failed_http_usage();
        let err_401 = r#"{"error":{"message":"bad api key"}}"#;
        let (url_401, cap_401, h_401) = spawn_mock_script_server(vec![MockTcpScript::Http {
            status_line: "401 Unauthorized".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Length".to_string(), err_401.len().to_string()),
            ],
            chunks: vec![err_401.as_bytes().to_vec()],
            drop_without_closing_gracefully: false,
        }]);
        let plan_401 = build_openai_test_plan(
            &root,
            &url_401,
            "none",
            true,
            Some("high"),
            Some(zero_backoff_transport_policy(3)),
        );
        let ctx = ExecutionContext {
            prompt: Some("hello".to_string()),
            ..Default::default()
        };
        let res_401 = execute_http_driver(&plan_401, &ctx, |_| {});
        h_401.join().unwrap();
        assert!(res_401.is_err());
        assert_eq!(cap_401.lock().unwrap().len(), 1);
        let u_401 = take_last_failed_http_usage().unwrap();
        assert_eq!(u_401.turns, 1);
        assert_eq!(u_401.transport_retries, 0);
        assert_eq!(u_401.usage_status, "UNKNOWN");

        // 2. Locked effort HTTP 400 fails closed in 1 attempt (never strips/downgrades effort or retries)
        let _ = take_last_failed_http_usage();
        let err_400 = r#"{"error":{"message":"unsupported parameter: reasoning_effort"}}"#;
        let (url_400, cap_400, h_400) = spawn_mock_script_server(vec![MockTcpScript::Http {
            status_line: "400 Bad Request".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Length".to_string(), err_400.len().to_string()),
            ],
            chunks: vec![err_400.as_bytes().to_vec()],
            drop_without_closing_gracefully: false,
        }]);
        let plan_400 = build_openai_test_plan(
            &root,
            &url_400,
            "sse",
            true,
            Some("high"),
            Some(zero_backoff_transport_policy(3)),
        );
        let res_400 = execute_http_driver(&plan_400, &ctx, |_| {});
        h_400.join().unwrap();
        assert!(res_400.is_err());
        assert_eq!(cap_400.lock().unwrap().len(), 1);
        let u_400 = take_last_failed_http_usage().unwrap();
        assert_eq!(u_400.turns, 1);
        assert_eq!(u_400.transport_retries, 0);
        assert_eq!(u_400.usage_status, "UNKNOWN");

        // 3. CHINWAG_EFFORT_OVERRIDE fails pre-egress with EffortSwitchDenied (0 HTTP requests)
        let mut override_env = BTreeMap::new();
        override_env.insert("CHINWAG_EFFORT_OVERRIDE".to_string(), "low".to_string());
        let ctx_override = ExecutionContext {
            prompt: Some("hello".to_string()),
            env: override_env,
            ..Default::default()
        };
        let err_override = execute_http_driver(&plan_400, &ctx_override, |_| {}).unwrap_err();
        assert!(
            err_override.to_string().contains("EffortSwitchDenied"),
            "expected EffortSwitchDenied, got {err_override}"
        );

        // 4. Invalid stream_mode scoped to OpenAiCompatibleHttp fails validate() and resolve_dispatch_plan
        let env_path = root.join("openai.env");
        let bad_manifest = FleetManifest {
            schema_version: 1,
            nodes: vec![],
            seats: vec![SeatDefinition {
                id: SeatId::new("BAD-OPENAI").unwrap(),
                display_name: None,
                lifecycle: SeatLifecycle::ActiveStanding,
                target_selector: ExecutionTarget::LocalProcess,
                driver: DriverSpec::OpenAiCompatibleHttp {
                    base_url: "https://gateway.example.invalid/v1".to_string(),
                    api_key_env: "OPENAI_KEY".to_string(),
                    wire_mode: "chat_completions".to_string(),
                    stream_mode: "websocket".to_string(),
                    timeout_secs: 30,
                    auth_isolation: crate::CredentialIsolation::SecretEnvFile {
                        path: env_path.clone(),
                        key_map: BTreeMap::new(),
                    },
                    tools: HttpToolConfig::default(),
                    transport: None,
                },
                model: ModelBinding {
                    provider: "custom-gw".into(),
                    model_id: "gpt-test".into(),
                    params: BTreeMap::new(),
                    failover_policy: None,
                },
                write_mode: crate::WriteMode::ReadOnly,
                isolation: crate::IsolationSpec::ReadOnly,
                allowed_write_roots: vec![],
                allowed_rooms: None,
                skills: SkillPolicyRef::default(),
                boot_files: vec![],
                profile_dir: None,
            }],
            policy: OrgFleetPolicy::default(),
            skills: SkillConfig::default(),
            pubkey_map: BTreeMap::new(),
            allowed_signers: BTreeMap::new(),
            private_key_paths: BTreeMap::new(),
            pin: None,
            extensions: BTreeMap::new(),
            task_profiles: BTreeMap::new(),
            source_dir: None,
        };
        assert!(matches!(
            bad_manifest.validate(),
            Err(FleetPolicyError::InvalidManifest(_))
        ));
        assert!(matches!(
            resolve_dispatch_plan(
                &bad_manifest,
                &crate::DispatchRequest {
                    seat: "BAD-OPENAI".into(),
                    cwd: root.clone(),
                    ..Default::default()
                },
            ),
            Err(FleetPolicyError::InvalidManifest(_))
        ));

        // GoogleGenAiHttp & AnthropicMessagesHttp remain unaffected and validate cleanly
        let multi_manifest = FleetManifest {
            schema_version: 1,
            nodes: vec![],
            seats: vec![
                SeatDefinition {
                    id: SeatId::new("GEM-SEAT").unwrap(),
                    display_name: None,
                    lifecycle: SeatLifecycle::ActiveStanding,
                    target_selector: ExecutionTarget::LocalProcess,
                    driver: DriverSpec::GoogleGenAiHttp {
                        endpoint_mode: "gemini_api".to_string(),
                        base_url_or_region: "https://generativelanguage.googleapis.com".to_string(),
                        auth_env: "OPENAI_KEY".to_string(),
                        stream_mode: "none".to_string(),
                        timeout_secs: 30,
                        auth_isolation: crate::CredentialIsolation::SecretEnvFile {
                            path: env_path.clone(),
                            key_map: BTreeMap::new(),
                        },
                        tools: HttpToolConfig::default(),
                        transport: None,
                    },
                    model: ModelBinding {
                        provider: "google".into(),
                        model_id: "gemini-test".into(),
                        params: BTreeMap::new(),
                        failover_policy: None,
                    },
                    write_mode: crate::WriteMode::ReadOnly,
                    isolation: crate::IsolationSpec::ReadOnly,
                    allowed_write_roots: vec![],
                    allowed_rooms: None,
                    skills: SkillPolicyRef::default(),
                    boot_files: vec![],
                    profile_dir: None,
                },
                SeatDefinition {
                    id: SeatId::new("ANT-SEAT").unwrap(),
                    display_name: None,
                    lifecycle: SeatLifecycle::ActiveStanding,
                    target_selector: ExecutionTarget::LocalProcess,
                    driver: DriverSpec::AnthropicMessagesHttp {
                        base_url: "https://api.anthropic.com".to_string(),
                        auth_env: "OPENAI_KEY".to_string(),
                        beta_headers: vec![],
                        stream_mode: "none".to_string(),
                        timeout_secs: 30,
                        auth_isolation: crate::CredentialIsolation::SecretEnvFile {
                            path: env_path,
                            key_map: BTreeMap::new(),
                        },
                        tools: HttpToolConfig::default(),
                        transport: None,
                    },
                    model: ModelBinding {
                        provider: "anthropic".into(),
                        model_id: "claude-test".into(),
                        params: BTreeMap::new(),
                        failover_policy: None,
                    },
                    write_mode: crate::WriteMode::ReadOnly,
                    isolation: crate::IsolationSpec::ReadOnly,
                    allowed_write_roots: vec![],
                    allowed_rooms: None,
                    skills: SkillPolicyRef::default(),
                    boot_files: vec![],
                    profile_dir: None,
                },
            ],
            policy: OrgFleetPolicy::default(),
            skills: SkillConfig::default(),
            pubkey_map: BTreeMap::new(),
            allowed_signers: BTreeMap::new(),
            private_key_paths: BTreeMap::new(),
            pin: None,
            extensions: BTreeMap::new(),
            task_profiles: BTreeMap::new(),
            source_dir: None,
        };
        multi_manifest.validate().unwrap();

        // 5. Pre-send HTTP 429 with Retry-After: 0 retries cleanly and counts usage
        let ok_429_json = serde_json::json!({
            "id": "r429",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "ok after 429"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 25, "completion_tokens": 15, "total_tokens": 40}
        })
        .to_string();
        let mut invoker_429 = MockCurlInvoker::new(vec![
            Ok(CurlHttpResponse {
                status: 429,
                headers: vec![("retry-after".to_string(), "0".to_string())],
                body: r#"{"error":{"message":"rate limited"}}"#.to_string(),
            }),
            Ok(CurlHttpResponse {
                status: 200,
                headers: vec![],
                body: ok_429_json,
            }),
        ]);
        let outcome_429 =
            execute_http_driver_with_invoker(&plan_401, &ctx, |_| {}, &mut invoker_429).unwrap();
        assert!(outcome_429.stdout.contains("ok after 429"));
        let usage_429 = outcome_429.usage.unwrap();
        assert_eq!(usage_429.turns, 1);
        assert_eq!(usage_429.transport_retries, 1);
        assert_eq!(usage_429.usage_status, "COUNTED");
        assert_eq!(usage_429.gross_tokens, Some(40));
    }

    #[test]
    fn manifest_digest_unchanged_when_optional_transport_policy_omitted() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let env_path = root.join("secret.env");
        write_0600_secret(&env_path, "API_KEY=secret\n");

        let mut manifest = FleetManifest {
            schema_version: 1,
            nodes: vec![],
            seats: vec![
                SeatDefinition {
                    id: SeatId::new("CLI-SEAT").unwrap(),
                    display_name: None,
                    lifecycle: SeatLifecycle::ActiveStanding,
                    target_selector: ExecutionTarget::LocalProcess,
                    driver: DriverSpec::CliSubprocess {
                        executable: "/usr/bin/true".into(),
                        argv_template: vec![],
                        auth_isolation: crate::CredentialIsolation::default(),
                        env_allowlist: vec![],
                        env_overrides: BTreeMap::new(),
                        framing: "stdin".into(),
                        timeout_secs: 30,
                    },
                    model: ModelBinding {
                        provider: "local".into(),
                        model_id: "local-cli".into(),
                        params: BTreeMap::new(),
                        failover_policy: None,
                    },
                    write_mode: crate::WriteMode::ReadOnly,
                    isolation: crate::IsolationSpec::ReadOnly,
                    allowed_write_roots: vec![],
                    allowed_rooms: None,
                    skills: SkillPolicyRef::default(),
                    boot_files: vec![],
                    profile_dir: None,
                },
                SeatDefinition {
                    id: SeatId::new("OAI-SEAT").unwrap(),
                    display_name: None,
                    lifecycle: SeatLifecycle::ActiveStanding,
                    target_selector: ExecutionTarget::LocalProcess,
                    driver: DriverSpec::OpenAiCompatibleHttp {
                        base_url: "https://gateway.example.invalid/v1".to_string(),
                        api_key_env: "API_KEY".to_string(),
                        wire_mode: "chat_completions".to_string(),
                        stream_mode: String::new(),
                        timeout_secs: 60,
                        auth_isolation: crate::CredentialIsolation::SecretEnvFile {
                            path: env_path.clone(),
                            key_map: BTreeMap::new(),
                        },
                        tools: HttpToolConfig::default(),
                        transport: None,
                    },
                    model: ModelBinding {
                        provider: "openai".into(),
                        model_id: "model-o".into(),
                        params: BTreeMap::new(),
                        failover_policy: None,
                    },
                    write_mode: crate::WriteMode::ReadOnly,
                    isolation: crate::IsolationSpec::ReadOnly,
                    allowed_write_roots: vec![],
                    allowed_rooms: None,
                    skills: SkillPolicyRef::default(),
                    boot_files: vec![],
                    profile_dir: None,
                },
                SeatDefinition {
                    id: SeatId::new("GEM-SEAT").unwrap(),
                    display_name: None,
                    lifecycle: SeatLifecycle::ActiveStanding,
                    target_selector: ExecutionTarget::LocalProcess,
                    driver: DriverSpec::GoogleGenAiHttp {
                        endpoint_mode: "gemini_api".to_string(),
                        base_url_or_region: "https://generativelanguage.googleapis.com".to_string(),
                        auth_env: "API_KEY".to_string(),
                        stream_mode: String::new(),
                        timeout_secs: 60,
                        auth_isolation: crate::CredentialIsolation::SecretEnvFile {
                            path: env_path.clone(),
                            key_map: BTreeMap::new(),
                        },
                        tools: HttpToolConfig::default(),
                        transport: None,
                    },
                    model: ModelBinding {
                        provider: "google".into(),
                        model_id: "model-g".into(),
                        params: BTreeMap::new(),
                        failover_policy: None,
                    },
                    write_mode: crate::WriteMode::ReadOnly,
                    isolation: crate::IsolationSpec::ReadOnly,
                    allowed_write_roots: vec![],
                    allowed_rooms: None,
                    skills: SkillPolicyRef::default(),
                    boot_files: vec![],
                    profile_dir: None,
                },
                SeatDefinition {
                    id: SeatId::new("ANT-SEAT").unwrap(),
                    display_name: None,
                    lifecycle: SeatLifecycle::ActiveStanding,
                    target_selector: ExecutionTarget::LocalProcess,
                    driver: DriverSpec::AnthropicMessagesHttp {
                        base_url: "https://api.anthropic.com".to_string(),
                        auth_env: "API_KEY".to_string(),
                        beta_headers: vec![],
                        stream_mode: String::new(),
                        timeout_secs: 60,
                        auth_isolation: crate::CredentialIsolation::SecretEnvFile {
                            path: env_path,
                            key_map: BTreeMap::new(),
                        },
                        tools: HttpToolConfig::default(),
                        transport: None,
                    },
                    model: ModelBinding {
                        provider: "anthropic".into(),
                        model_id: "model-a".into(),
                        params: BTreeMap::new(),
                        failover_policy: None,
                    },
                    write_mode: crate::WriteMode::ReadOnly,
                    isolation: crate::IsolationSpec::ReadOnly,
                    allowed_write_roots: vec![],
                    allowed_rooms: None,
                    skills: SkillPolicyRef::default(),
                    boot_files: vec![],
                    profile_dir: None,
                },
            ],
            policy: OrgFleetPolicy::default(),
            skills: SkillConfig::default(),
            pubkey_map: BTreeMap::new(),
            allowed_signers: BTreeMap::new(),
            private_key_paths: BTreeMap::new(),
            pin: None,
            extensions: BTreeMap::new(),
            task_profiles: BTreeMap::new(),
            source_dir: None,
        };
        manifest.validate().unwrap();

        let serialized_json = serde_json::to_string(&manifest).unwrap();
        assert!(
            !serialized_json.contains("\"transport\""),
            "omitted transport policy must not appear in serialized JSON: {serialized_json}"
        );
        let baseline_digest = manifest.digest().unwrap();

        let toml_text = toml::to_string(&manifest).unwrap();
        assert!(
            !toml_text.contains("transport"),
            "omitted transport policy must not appear in TOML: {toml_text}"
        );
        let parsed_from_toml: FleetManifest = toml::from_str(&toml_text).unwrap();
        assert_eq!(parsed_from_toml.digest().unwrap(), baseline_digest);

        let parsed_from_json: FleetManifest = serde_json::from_str(&serialized_json).unwrap();
        assert_eq!(parsed_from_json.digest().unwrap(), baseline_digest);

        if let Some(seat) = manifest
            .seats
            .iter_mut()
            .find(|s| s.id.as_str() == "OAI-SEAT")
            && let DriverSpec::OpenAiCompatibleHttp { transport, .. } = &mut seat.driver
        {
            *transport = Some(zero_backoff_transport_policy(2));
        }
        manifest.validate().unwrap();
        let with_transport_digest = manifest.digest().unwrap();
        assert_ne!(with_transport_digest, baseline_digest);
        assert!(
            serde_json::to_string(&manifest)
                .unwrap()
                .contains("\"transport\"")
        );
    }
}
