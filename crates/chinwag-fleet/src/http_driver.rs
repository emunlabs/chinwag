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
    body: String,
}

fn curl_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    timeout_secs: u64,
) -> FleetResult<CurlHttpResponse> {
    if url.contains(['\0', '\r', '\n']) {
        return Err(FleetPolicyError::EgressViolation(
            "invalid characters in URL".into(),
        ));
    }
    let curl_bin = if Path::new("/usr/bin/curl").is_file() {
        PathBuf::from("/usr/bin/curl")
    } else {
        resolve_binary("curl")?
    };
    let mut dir_builder = tempfile::Builder::new();
    dir_builder.prefix("cw-http-");
    let temp_dir = TempDir::new_in(std::env::temp_dir())?;
    #[cfg(unix)]
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700))?;

    let mut cfg = String::new();
    cfg.push_str(&format!("url = \"{}\"\n", escape_curl_cfg(url)));
    cfg.push_str(&format!("request = \"{}\"\n", escape_curl_cfg(method)));
    cfg.push_str("header = \"Accept: application/json\"\n");
    for (k, v) in headers {
        if k.contains(['\0', '\r', '\n']) || v.contains(['\0', '\r', '\n']) {
            return Err(FleetPolicyError::InvalidManifest(
                "control character in HTTP header".into(),
            ));
        }
        cfg.push_str(&format!("header = \"{}: {}\"\n", escape_curl_cfg(k), escape_curl_cfg(v)));
    }
    if let Some(payload) = body {
        let body_path = temp_dir.path().join("req.json");
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&body_path)?;
        f.write_all(payload.as_bytes())?;
        cfg.push_str("header = \"Content-Type: application/json\"\n");
        cfg.push_str(&format!(
            "data-binary = \"@{}\"\n",
            escape_curl_cfg(&body_path.to_string_lossy())
        ));
    }

    let timeout_str = timeout_secs.max(1).to_string();
    let mut cmd = Command::new(curl_bin);
    cmd.arg("-q")
        .args([
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            &timeout_str,
            "-w",
            "\n%{http_code}",
            "-K",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(cfg.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FleetPolicyError::DriverExecutionFailed(format!(
            "HTTP transport failure: {}",
            stderr.trim()
        )));
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let (resp_body, code_str) = raw.rsplit_once('\n').ok_or_else(|| {
        FleetPolicyError::DriverExecutionFailed("curl output missing HTTP status line".into())
    })?;
    let status = code_str.trim().parse::<u16>().map_err(|_| {
        FleetPolicyError::DriverExecutionFailed(format!(
            "unparseable HTTP status code: {}",
            code_str.trim()
        ))
    })?;
    Ok(CurlHttpResponse {
        status,
        body: resp_body.to_owned(),
    })
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
            || usage.get("total_tokens").is_some() && usage.get("total_tokens").and_then(Value::as_u64).is_none()
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

fn record_http_failure(
    context: &ExecutionContext,
    acc: &UsageAccumulator,
    tool_calls: usize,
) {
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
            stream_mode: _,
            wire_mode: _,
            timeout_secs,
            auth_isolation,
            tools,
        } => {
            let eff_timeout = context.timeout_override_secs.unwrap_or(*timeout_secs);
            let api_key = resolve_driver_api_key(auth_isolation, api_key_env)?;
            let endpoint = if base_url.trim_end_matches('/').ends_with("/chat/completions") {
                base_url.trim_end_matches('/').to_owned()
            } else {
                format!("{}/chat/completions", base_url.trim_end_matches('/'))
            };
            run_openai_loop(
                plan,
                context,
                &endpoint,
                api_key.as_deref(),
                &system_prompt,
                user_prompt,
                eff_timeout,
                tools,
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
        } => {
            let eff_timeout = context.timeout_override_secs.unwrap_or(*timeout_secs);
            let api_key = resolve_driver_api_key(auth_isolation, auth_env)?
                .ok_or_else(|| FleetPolicyError::DriverExecutionFailed("missing Gemini API key".into()))?;
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
        } => {
            let eff_timeout = context.timeout_override_secs.unwrap_or(*timeout_secs);
            let api_key = resolve_driver_api_key(auth_isolation, auth_env)?
                .ok_or_else(|| FleetPolicyError::DriverExecutionFailed("missing Anthropic API key".into()))?;
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

#[allow(clippy::too_many_arguments)]
fn run_openai_loop(
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    endpoint: &str,
    api_key: Option<&str>,
    system_prompt: &str,
    user_prompt: &str,
    timeout_secs: u64,
    tools: &HttpToolConfig,
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
    let mut send_reasoning_effort = matches!(
        effort.as_deref(),
        Some("low" | "medium" | "high")
    );

    for _turn in 0..max_turns {
        let mut resp = {
            let mut payload = json!({
                "model": plan.model.model_id,
                "messages": messages,
                "max_tokens": max_tokens,
            });
            if send_reasoning_effort && let Some(eff) = &effort {
                payload["reasoning_effort"] = Value::String(eff.clone());
            }
            if tools_active {
                payload["tools"] = openai_tool_declarations(allow_writes);
            }
            match curl_request("POST", endpoint, &headers, Some(&payload.to_string()), timeout_secs) {
                Ok(r) => r,
                Err(err) => {
                    usage_acc.mark_egress_failed();
                    record_http_failure(context, &usage_acc, tool_calls_used);
                    return Err(err);
                }
            }
        };

        if resp.status == 400
            && send_reasoning_effort
            && !lock_effort
            && resp.body.contains("reasoning_effort")
        {
            send_reasoning_effort = false;
            let mut payload = json!({
                "model": plan.model.model_id,
                "messages": messages,
                "max_tokens": max_tokens,
            });
            if tools_active {
                payload["tools"] = openai_tool_declarations(allow_writes);
            }
            resp = match curl_request(
                "POST",
                endpoint,
                &headers,
                Some(&payload.to_string()),
                timeout_secs,
            ) {
                Ok(r) => r,
                Err(err) => {
                    usage_acc.mark_egress_failed();
                    record_http_failure(context, &usage_acc, tool_calls_used);
                    return Err(err);
                }
            };
        }

        if !(200..300).contains(&resp.status) {
            usage_acc.mark_egress_failed();
            record_http_failure(context, &usage_acc, tool_calls_used);
            return Err(FleetPolicyError::DriverExecutionFailed(format!(
                "OpenAI-compatible HTTP {} from {} (zero failover): {}",
                resp.status,
                endpoint,
                resp.body.chars().take(400).collect::<String>()
            )));
        }
        let parsed: Value = match serde_json::from_str(&resp.body) {
            Ok(v) => v,
            Err(e) => {
                usage_acc.mark_egress_failed();
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(FleetPolicyError::DriverExecutionFailed(format!(
                    "invalid OpenAI JSON: {e}"
                )));
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
        let resp = match curl_request("POST", endpoint, &headers, Some(&payload.to_string()), timeout_secs) {
            Ok(r) => r,
            Err(err) => {
                usage_acc.mark_egress_failed();
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(err);
            }
        };
        if !(200..300).contains(&resp.status) {
            usage_acc.mark_egress_failed();
            record_http_failure(context, &usage_acc, tool_calls_used);
            return Err(FleetPolicyError::DriverExecutionFailed(format!(
                "Gemini HTTP {} from {} (zero failover): {}",
                resp.status,
                endpoint,
                resp.body.chars().take(400).collect::<String>()
            )));
        }
        let parsed: Value = match serde_json::from_str(&resp.body) {
            Ok(v) => v,
            Err(e) => {
                usage_acc.mark_egress_failed();
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(FleetPolicyError::DriverExecutionFailed(format!(
                    "invalid Gemini JSON: {e}"
                )));
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
        let resp = match curl_request("POST", endpoint, &headers, Some(&payload.to_string()), timeout_secs) {
            Ok(r) => r,
            Err(err) => {
                usage_acc.mark_egress_failed();
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(err);
            }
        };
        if !(200..300).contains(&resp.status) {
            usage_acc.mark_egress_failed();
            record_http_failure(context, &usage_acc, tool_calls_used);
            return Err(FleetPolicyError::DriverExecutionFailed(format!(
                "Anthropic HTTP {} from {} (zero failover): {}",
                resp.status,
                endpoint,
                resp.body.chars().take(400).collect::<String>()
            )));
        }
        let parsed: Value = match serde_json::from_str(&resp.body) {
            Ok(v) => v,
            Err(e) => {
                usage_acc.mark_egress_failed();
                record_http_failure(context, &usage_acc, tool_calls_used);
                return Err(FleetPolicyError::DriverExecutionFailed(format!(
                    "invalid Anthropic JSON: {e}"
                )));
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
    let mut decls = vec![
        json!({
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
        }),
    ];
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
    let mut decls = vec![
        json!({
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
        }),
    ];
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
    let mut decls = vec![
        json!({
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
        }),
    ];
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
        "png" | "jpg" | "jpeg" | "webp" | "gif" | "wav" | "mp3" | "ogg" | "flac" | "mp4" | "mov" | "pdf"
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
    prefix.ends_with('/') || path_only.len() == prefix.len() || path_only[prefix.len()..].starts_with('/')
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
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
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
    cmd.stdin(Stdio::null()).stdout(Stdio::from(out_dup)).stderr(Stdio::from(err_dup));
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
        "openai_json_scrutinizer" => run_openai_json_scrutinizer(manifest, seat_id, spec, cwd, options, context),
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
        .ok_or_else(|| FleetPolicyError::InvalidManifest("action missing secret_env_file".into()))?;
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
        let fields = spec
            .get("fields")
            .cloned()
            .ok_or_else(|| FleetPolicyError::InvalidManifest("clairic_text missing fields".into()))?;
        payload.insert("fields".into(), fields);
    } else {
        let state_val: Value = if options.input_text.trim().starts_with('{') {
            serde_json::from_str(&options.input_text)
                .unwrap_or_else(|_| json!({"text": options.input_text}))
        } else {
            json!({"text": options.input_text})
        };
        payload.insert("state".into(), state_val);
        let questions = spec
            .get("questions")
            .cloned()
            .ok_or_else(|| FleetPolicyError::InvalidManifest("clef_state missing questions".into()))?;
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
        .ok_or_else(|| FleetPolicyError::InvalidManifest("scrutinizer missing system_prompt".into()))?;
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
        ..
    } = &seat_def.driver
    else {
        return Err(FleetPolicyError::UnsupportedDriver(
            "openai_json_scrutinizer requires OpenAiCompatibleHttp seat driver".into(),
        ));
    };
    check_egress_policy(&manifest.policy.egress_policy, base_url)?;
    let mut iso = auth_isolation.clone();
    let mut dummy_tools = HttpToolConfig::default();
    crate::resolve_driver_credentials(manifest, cwd, &mut iso, &mut dummy_tools)?;
    let api_key = resolve_driver_api_key(&iso, api_key_env)?;
    let endpoint = if base_url.trim_end_matches('/').ends_with("/chat/completions") {
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
    let resp = curl_request(
        "POST",
        &endpoint,
        &headers,
        Some(&payload.to_string()),
        context.timeout_override_secs.or(options.timeout_secs).unwrap_or(*timeout_secs),
    )?;
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

    let clef_res = execute_manifest_seat_action(manifest, seat_id, clef_action, cwd, options, context)?;
    let clairic_res = execute_manifest_seat_action(manifest, seat_id, clairic_action, cwd, options, context)?;
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
    let needs_escalation = !clef_ok || max_trigger >= options.ambiguity_threshold || loc_p90 > loc_p90_threshold;
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
    use crate::{ExecutionTarget, ModelBinding, OrgFleetPolicy, SeatDefinition, SeatId, SeatLifecycle, SkillConfig, SkillPolicyRef};
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
        let turn2 = r#"{"choices":[{"message":{"role":"assistant","content":"VERIFIED_TOOL_LOOP"}}]}"#;
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
                },
                model: ModelBinding {
                    provider: "google-gemini".into(),
                    model_id: "gemini-4-carbon".into(),
                    params: BTreeMap::from([("thinking_level".into(), Value::String("HIGH".into()))]),
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
        let base_url = mock_http_server(vec![r#"{"success":true,"result":{"answers":{"flag":0.1}}}"#]);

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
}
