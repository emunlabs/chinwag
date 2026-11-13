// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Configurable Hosted-Model & AI-Service Agent Runner (`CHWG-PERSONA-LOADER-FIX-01`).
//!
//! Generalizes standalone hosted API agent execution across:
//! 1. `gemini_generate_content` — Google Gemini REST API (`POST {base_url}/models/{model}:generateContent`)
//! 2. `open_ai_chat_completions` — OpenAI / xAI Grok / OpenRouter / Cloudflare AI Gateway
//!    OpenAI-compatible Chat Completions (`POST {endpoint}`)
//! 3. `cloudflare_workers_ai` — Cloudflare Workers AI REST API
//!    (`POST {base_url}/accounts/{account_id}/ai/run/{model}`)
//!
//! Security & Boundary Invariants:
//! - All credentials are resolved from local mode-`0600` regular files opened with `O_NOFOLLOW`
//!   (zero Infisical SaaS calls, zero inherited-environment fallback for provider keys).
//! - `/usr/bin/curl` is invoked with `-q` as the first argument (suppressing `~/.curlrc`) and
//!   `-K -` so authentication headers are piped exclusively via `stdin` and never appear in `argv`.
//! - Request bodies are written to mode-`0600` temporary files inside a `0700` directory and
//!   removed immediately after each call.
//! - Multi-turn tool execution (`read_file`, `write_file`, `fetch_url`, `run_command`) enforces
//!   component-wise canonical root checks for writes and exact HTTPS host/path matching for
//!   authenticated documentation/catalog fetches.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_GEMINI_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta";
pub const DEFAULT_CF_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
#[cfg(test)]
const DEFAULT_CF_ACCOUNT_ID: &str = "0123456789abcdef0123456789abcdef";

const O_NOFOLLOW: i32 = 0x0100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedAgentError {
    UnboundSeat(String),
    ConfigError(String),
    SecretError(String),
    TransportError(String),
    ProtocolError(String),
    TurnLimitExceeded(usize),
    ToolCallLimitExceeded(usize),
}

impl std::fmt::Display for HostedAgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnboundSeat(seat) => write!(f, "seat {seat} is not bound to a hosted provider"),
            Self::ConfigError(msg) => write!(f, "provider config error: {msg}"),
            Self::SecretError(msg) => write!(f, "credential error: {msg}"),
            Self::TransportError(msg) => write!(f, "transport error: {msg}"),
            Self::ProtocolError(msg) => write!(f, "protocol error: {msg}"),
            Self::TurnLimitExceeded(max) => write!(f, "exceeded max model turns ({max})"),
            Self::ToolCallLimitExceeded(max) => write!(f, "exceeded max tool calls ({max})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidersConfig {
    pub version: u32,
    pub providers: BTreeMap<String, ProviderConfig>,
    pub agents: BTreeMap<String, AgentBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderConfig {
    GeminiGenerateContent {
        base_url: String,
        credential: SecretRef,
    },
    OpenAiChatCompletions {
        endpoint: String,
        #[serde(default)]
        credential: Option<SecretRef>,
    },
    CloudflareWorkersAi {
        #[serde(default = "default_cf_base_url")]
        base_url: String,
        account_id: String,
        credential: SecretRef,
    },
}

fn default_cf_base_url() -> String {
    DEFAULT_CF_BASE_URL.to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretRef {
    EnvFile { path: PathBuf, key: String },
    TokenFile { path: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBinding {
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub limits: RunLimits,
    #[serde(default)]
    pub tools: ToolPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunLimits {
    #[serde(default = "default_max_turns")]
    pub max_turns: usize,
    #[serde(default = "default_max_tool_calls")]
    pub max_tool_calls: usize,
    #[serde(default = "default_max_output_tokens")]
    pub max_output_tokens: u32,
    #[serde(default = "default_timeout_secs")]
    pub request_timeout_secs: u64,
}

fn default_max_turns() -> usize {
    24
}
fn default_max_tool_calls() -> usize {
    48
}
fn default_max_output_tokens() -> u32 {
    8192
}
fn default_timeout_secs() -> u64 {
    180
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            max_turns: default_max_turns(),
            max_tool_calls: default_max_tool_calls(),
            max_output_tokens: default_max_output_tokens(),
            request_timeout_secs: default_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_write_roots: Vec<PathBuf>,
    #[serde(default)]
    pub auth_fetches: Vec<AuthFetchRule>,
    #[serde(default)]
    pub env_injections: Vec<EnvInjectionRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthFetchRule {
    pub host: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    pub header_name: String,
    #[serde(default)]
    pub header_prefix: Option<String>,
    pub credential: SecretRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvInjectionRule {
    pub env_var: String,
    pub source: EnvValueSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvValueSource {
    Literal { value: String },
    Secret { credential: SecretRef },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedReply {
    pub text: String,
    pub engine_label: String,
    pub turns_used: usize,
    pub tool_calls_used: usize,
}

impl ProvidersConfig {
    /// An unconfigured provider registry has no dispatchable seats.
    pub fn default_for_home(_home_dir: &Path, _workspace_dir: &Path) -> Self {
        Self {
            version: 1,
            providers: BTreeMap::new(),
            agents: BTreeMap::new(),
        }
    }

    pub fn load_or_default(
        config_path: Option<&Path>,
        home_dir: &Path,
        workspace_dir: &Path,
    ) -> Result<Self, HostedAgentError> {
        let candidate = match config_path {
            Some(explicit) => explicit.to_path_buf(),
            None => {
                let default_path = home_dir.join(".chinwag/providers.json");
                if default_path.symlink_metadata().is_err() {
                    let cfg = Self::default_for_home(home_dir, workspace_dir);
                    cfg.validate()?;
                    return Ok(cfg);
                }
                default_path
            }
        };
        let raw = read_regular_file_nofollow(&candidate, false)
            .map_err(|e| HostedAgentError::ConfigError(format!("{}: {e}", candidate.display())))?;
        let cfg: Self = serde_json::from_str(&raw)
            .map_err(|e| HostedAgentError::ConfigError(format!("invalid JSON: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), HostedAgentError> {
        if self.version != 1 {
            return Err(HostedAgentError::ConfigError(format!(
                "unsupported providers config version {}",
                self.version
            )));
        }
        for (name, provider) in &self.providers {
            if name.trim().is_empty() {
                return Err(HostedAgentError::ConfigError(
                    "provider name cannot be empty".to_owned(),
                ));
            }
            match provider {
                ProviderConfig::GeminiGenerateContent { base_url, .. } => {
                    validate_endpoint_url(base_url, false)?;
                }
                ProviderConfig::OpenAiChatCompletions { endpoint, .. } => {
                    validate_endpoint_url(endpoint, true)?;
                }
                ProviderConfig::CloudflareWorkersAi {
                    base_url,
                    account_id,
                    ..
                } => {
                    validate_endpoint_url(base_url, false)?;
                    if account_id.len() != 32 || !account_id.chars().all(|c| c.is_ascii_hexdigit())
                    {
                        return Err(HostedAgentError::ConfigError(format!(
                            "provider {name} has invalid 32-hex Cloudflare account_id"
                        )));
                    }
                }
            }
        }
        for (seat, binding) in &self.agents {
            if !self.providers.contains_key(&binding.provider) {
                return Err(HostedAgentError::ConfigError(format!(
                    "agent {seat} references unknown provider {}",
                    binding.provider
                )));
            }
            if binding.model.trim().is_empty() || binding.model.contains(['\0', '\r', '\n', ' ']) {
                return Err(HostedAgentError::ConfigError(format!(
                    "agent {seat} has invalid model identifier"
                )));
            }
            if binding.limits.max_turns == 0 || binding.limits.max_turns > 32 {
                return Err(HostedAgentError::ConfigError(format!(
                    "agent {seat} max_turns must be in 1..=32"
                )));
            }
            if binding.limits.max_tool_calls > 64 {
                return Err(HostedAgentError::ConfigError(format!(
                    "agent {seat} max_tool_calls must be <= 64"
                )));
            }
            if binding.limits.request_timeout_secs == 0 || binding.limits.request_timeout_secs > 600
            {
                return Err(HostedAgentError::ConfigError(format!(
                    "agent {seat} request_timeout_secs must be in 1..=600"
                )));
            }
        }
        Ok(())
    }
}

fn validate_endpoint_url(url: &str, allow_http: bool) -> Result<(), HostedAgentError> {
    let trimmed = url.trim();
    let ok_scheme =
        trimmed.starts_with("https://") || (allow_http && trimmed.starts_with("http://"));
    if !ok_scheme || trimmed.contains(['\0', '\r', '\n', ' ']) {
        return Err(HostedAgentError::ConfigError(format!(
            "invalid endpoint URL: {url}"
        )));
    }
    Ok(())
}

/// Opens a file with `O_NOFOLLOW`, verifies that the opened descriptor is a regular
/// file owned by the current effective UID, and when `require_0600` is true enforces
/// `mode & 0o077 == 0`.
fn read_regular_file_nofollow(path: &Path, require_0600: bool) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| "file unreadable or symlink rejected".to_owned())?;
    let meta = file
        .metadata()
        .map_err(|_| "file metadata unreadable".to_owned())?;
    if !meta.file_type().is_file() {
        return Err("target must be a regular file".to_owned());
    }
    let euid = rustix::process::geteuid().as_raw();
    if meta.uid() != euid {
        return Err("file owner mismatch".to_owned());
    }
    if require_0600 && (meta.mode() & 0o077 != 0) {
        return Err("secret file must be mode 0600".to_owned());
    }
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|_| "invalid UTF-8 content".to_owned())?;
    Ok(content)
}

pub fn resolve_secret(secret_ref: &SecretRef) -> Result<String, HostedAgentError> {
    let raw_value = match secret_ref {
        SecretRef::TokenFile { path } => {
            let content = read_regular_file_nofollow(path, true)
                .map_err(|e| HostedAgentError::SecretError(format!("{}: {e}", path.display())))?;
            content.trim().to_owned()
        }
        SecretRef::EnvFile { path, key } => {
            let content = read_regular_file_nofollow(path, true)
                .map_err(|e| HostedAgentError::SecretError(format!("{}: {e}", path.display())))?;
            parse_dotenv_key(&content, key).ok_or_else(|| {
                HostedAgentError::SecretError(format!("key {key} missing in {}", path.display()))
            })?
        }
    };
    validate_secret_material(&raw_value)?;
    Ok(raw_value)
}

fn parse_dotenv_key(content: &str, target_key: &str) -> Option<String> {
    for line in content.lines() {
        let mut s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        if let Some(rest) = s.strip_prefix("export ") {
            s = rest.trim();
        }
        let Some((k, v)) = s.split_once('=') else {
            continue;
        };
        if k.trim() != target_key {
            continue;
        }
        let mut val = v.trim();
        if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
            || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
        {
            val = &val[1..val.len() - 1];
        }
        if !val.is_empty() {
            return Some(val.to_owned());
        }
    }
    None
}

fn validate_secret_material(secret: &str) -> Result<(), HostedAgentError> {
    if secret.len() < 8 || secret.len() > 512 {
        return Err(HostedAgentError::SecretError(
            "secret length out of bounds (8..=512)".to_owned(),
        ));
    }
    if secret
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\\'))
    {
        return Err(HostedAgentError::SecretError(
            "secret contains forbidden control or quote characters".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

pub trait HostedTransport {
    fn send(&mut self, req: &HttpRequest) -> Result<HttpResponse, HostedAgentError>;
}

pub struct CurlTransport {
    curl_bin: PathBuf,
    scratch_root: PathBuf,
}

impl CurlTransport {
    pub fn new(curl_bin: PathBuf, scratch_root: PathBuf) -> Self {
        Self {
            curl_bin,
            scratch_root,
        }
    }

    pub fn system_default(home_dir: &Path) -> Self {
        Self::new(
            PathBuf::from("/usr/bin/curl"),
            home_dir.join(".chinwag/tmp-hosted"),
        )
    }
}

impl HostedTransport for CurlTransport {
    fn send(&mut self, req: &HttpRequest) -> Result<HttpResponse, HostedAgentError> {
        for (h_name, h_val) in &req.headers {
            if h_name
                .chars()
                .any(|c| c.is_control() || matches!(c, ':' | '"' | '\\'))
                || h_val
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '"' | '\\'))
            {
                return Err(HostedAgentError::TransportError(
                    "rejected unsafe header characters".to_owned(),
                ));
            }
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let run_dir = self
            .scratch_root
            .join(format!("req-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&run_dir)
            .map_err(|e| HostedAgentError::TransportError(format!("scratch dir: {e}")))?;
        let _ = fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700));

        let body_path = run_dir.join("body.json");
        let result = (|| -> Result<HttpResponse, HostedAgentError> {
            let mut cmd = Command::new(&self.curl_bin);
            // `-q` MUST be the first argument so curl ignores ~/.curlrc;
            // `-g` (`--globoff`) disables curl `[]{}` URL glob expansion.
            cmd.args([
                "-q",
                "-g",
                "-sS",
                "--max-time",
                &req.timeout_secs.to_string(),
                "-K",
                "-",
                "-X",
                &req.method,
            ]);
            if let Some(body) = &req.body {
                let mut f = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .custom_flags(O_NOFOLLOW)
                    .open(&body_path)
                    .map_err(|e| HostedAgentError::TransportError(format!("body file: {e}")))?;
                f.write_all(body.as_bytes())
                    .map_err(|e| HostedAgentError::TransportError(format!("body write: {e}")))?;
                drop(f);
                cmd.args([
                    "-H",
                    "Content-Type: application/json",
                    "--data-binary",
                    &format!("@{}", body_path.display()),
                ]);
            }
            cmd.args(["-w", "\n%{http_code}", &req.url]);
            let mut child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| HostedAgentError::TransportError(format!("curl spawn: {e}")))?;

            if let Some(mut stdin) = child.stdin.take() {
                for (name, value) in &req.headers {
                    let line = format!("header = \"{name}: {value}\"\n");
                    stdin.write_all(line.as_bytes()).map_err(|e| {
                        HostedAgentError::TransportError(format!("curl stdin: {e}"))
                    })?;
                }
            }
            let out = child
                .wait_with_output()
                .map_err(|e| HostedAgentError::TransportError(format!("curl wait: {e}")))?;
            if !out.status.success() {
                return Err(HostedAgentError::TransportError(format!(
                    "curl exited with {:?}",
                    out.status.code()
                )));
            }
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let (payload, status_str) = stdout.rsplit_once('\n').unwrap_or((stdout.as_str(), ""));
            let status: u16 = status_str.trim().parse().map_err(|_| {
                HostedAgentError::TransportError("invalid HTTP status code from curl".to_owned())
            })?;
            Ok(HttpResponse {
                status,
                body: payload.to_owned(),
            })
        })();

        let _ = fs::remove_dir_all(&run_dir);
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub id: Option<String>,
    pub name: String,
    pub args: Value,
}

pub trait ToolExecutor {
    fn execute(
        &mut self,
        call: &ToolCall,
        policy: &ToolPolicy,
        transport: &mut dyn HostedTransport,
    ) -> Value;
}

pub struct StandardToolExecutor {
    pub cwd: PathBuf,
    pub base_env: Vec<(String, String)>,
}

impl StandardToolExecutor {
    pub fn new(cwd: PathBuf, base_env: Vec<(String, String)>) -> Self {
        Self { cwd, base_env }
    }
}

impl ToolExecutor for StandardToolExecutor {
    fn execute(
        &mut self,
        call: &ToolCall,
        policy: &ToolPolicy,
        transport: &mut dyn HostedTransport,
    ) -> Value {
        if !policy.enabled {
            return json!({
                "ok": false,
                "error": "tool execution disabled by seat policy"
            });
        }
        match call.name.as_str() {
            "read_file" => execute_read_file(&call.args, &self.cwd),
            "write_file" => execute_write_file(&call.args, &self.cwd, &policy.allowed_write_roots),
            "fetch_url" => execute_fetch_url(&call.args, &policy.auth_fetches, transport),
            "run_command" => execute_run_command(
                &call.args,
                &self.cwd,
                &self.base_env,
                &policy.env_injections,
            ),
            other => json!({
                "ok": false,
                "error": format!("unknown tool: {other}")
            }),
        }
    }
}

fn execute_read_file(args: &Value, cwd: &Path) -> Value {
    let Some(raw_path) = args.get("path").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "missing path"});
    };
    let max_chars = args
        .get("max_chars")
        .and_then(Value::as_u64)
        .unwrap_or(16_000)
        .min(64_000) as usize;
    let resolved = resolve_input_path(raw_path, cwd);
    match read_regular_file_nofollow(&resolved, false) {
        Ok(content) => {
            let clipped: String = content.chars().take(max_chars).collect();
            json!({
                "ok": true,
                "path": resolved.display().to_string(),
                "content": clipped
            })
        }
        Err(e) => json!({
            "ok": false,
            "error": format!("{}: {e}", resolved.display())
        }),
    }
}

fn resolve_input_path(raw_path: &str, cwd: &Path) -> PathBuf {
    if let Some(stripped) = raw_path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(stripped);
    }
    let p = Path::new(raw_path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

/// Validates that `candidate` resolves inside one of `allowed_roots` using
/// component-wise `Path::starts_with` on canonicalized paths (rejecting `..`
/// traversal, sibling-prefix tricks like `/WORKSPACE-evil`, and symlinks).
pub fn resolve_confined_write_path(
    raw_path: &str,
    cwd: &Path,
    allowed_roots: &[PathBuf],
) -> Result<PathBuf, String> {
    let candidate = resolve_input_path(raw_path, cwd);
    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("parent directory traversal (..) is forbidden".to_owned());
    }
    let file_name = candidate
        .file_name()
        .ok_or_else(|| "invalid destination file name".to_owned())?;
    let parent = candidate
        .parent()
        .ok_or_else(|| "missing parent directory".to_owned())?;

    let mut canonical_roots = Vec::new();
    for root in allowed_roots {
        if let Ok(canon) = fs::canonicalize(root) {
            canonical_roots.push(canon);
        }
    }
    if canonical_roots.is_empty() {
        return Err("no allowed write roots exist on disk".to_owned());
    }

    // Find the deepest existing ancestor of `parent`, canonicalize it, and verify
    // none of the remaining relative components are symlinks.
    let mut existing = parent.to_path_buf();
    let mut missing_tail = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name() else {
            return Err("cannot resolve existing ancestor directory".to_owned());
        };
        missing_tail.push(name.to_os_string());
        let Some(next_parent) = existing.parent() else {
            return Err("cannot resolve existing ancestor directory".to_owned());
        };
        existing = next_parent.to_path_buf();
    }
    let mut canon_dir =
        fs::canonicalize(&existing).map_err(|_| "cannot canonicalize ancestor".to_owned())?;
    for seg in missing_tail.iter().rev() {
        canon_dir.push(seg);
    }
    let final_path = canon_dir.join(file_name);
    if !canonical_roots
        .iter()
        .any(|root| final_path.starts_with(root))
    {
        return Err(format!(
            "destination {} is outside allowed write roots",
            final_path.display()
        ));
    }
    Ok(final_path)
}

fn execute_write_file(args: &Value, cwd: &Path, allowed_roots: &[PathBuf]) -> Value {
    let Some(raw_path) = args.get("path").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "missing path"});
    };
    let Some(content) = args.get("content").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "missing content"});
    };
    let target = match resolve_confined_write_path(raw_path, cwd, allowed_roots) {
        Ok(p) => p,
        Err(e) => return json!({"ok": false, "error": e}),
    };
    if let Some(parent) = target.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        return json!({"ok": false, "error": format!("mkdir failed: {e}")});
    }
    let mut file = match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .custom_flags(O_NOFOLLOW)
        .open(&target)
    {
        Ok(f) => f,
        Err(e) => return json!({"ok": false, "error": format!("open failed: {e}")}),
    };
    if let Err(e) = file.write_all(content.as_bytes()) {
        return json!({"ok": false, "error": format!("write failed: {e}")});
    }
    json!({
        "ok": true,
        "path": target.display().to_string(),
        "bytes_written": content.len()
    })
}

/// Parses and normalizes an `https://` URL into `(host_lowercase, normalized_path_and_query)`.
/// Rejects userinfo (`@`), fragments (`#`), backslashes (`\`), curl glob chars (`[`, `]`, `{`, `}`),
/// percent-encoded dot/slash/control sequences (`%2e`, `%2f`, `%5c`, `%00`), and resolves `.`/`..`
/// path segments before any `AuthFetchRule` path-prefix comparison.
pub fn parse_https_origin_and_path(url: &str) -> Result<(String, String), String> {
    let trimmed = url.trim();
    let Some(rest) = trimmed.strip_prefix("https://") else {
        return Err("only https:// URLs are permitted".to_owned());
    };
    if rest
        .chars()
        .any(|c| c.is_control() || matches!(c, ' ' | '@' | '\\' | '#' | '[' | ']' | '{' | '}'))
    {
        return Err("URL contains forbidden characters, userinfo, fragment, or glob".to_owned());
    }
    let lower_rest = rest.to_ascii_lowercase();
    for forbidden_pct in ["%2e", "%2f", "%5c", "%00"] {
        if lower_rest.contains(forbidden_pct) {
            return Err("URL contains forbidden percent-encoded path sequence".to_owned());
        }
    }
    let (authority, raw_path_and_query) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains(['?', '#']) {
        return Err("invalid URL authority".to_owned());
    }
    let (raw_path, query_opt) = match raw_path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw_path_and_query, None),
    };
    let trailing_slash = raw_path.ends_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for seg in raw_path.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut normalized_path = if segments.is_empty() {
        "/".to_owned()
    } else {
        format!(
            "/{}{}",
            segments.join("/"),
            if trailing_slash { "/" } else { "" }
        )
    };
    if let Some(q) = query_opt {
        normalized_path.push('?');
        normalized_path.push_str(q);
    }
    Ok((authority.to_ascii_lowercase(), normalized_path))
}

fn path_matches_prefix(normalized_path_and_query: &str, prefix: &str) -> bool {
    let path_only = normalized_path_and_query
        .split_once('?')
        .map_or(normalized_path_and_query, |(p, _)| p);
    if !path_only.starts_with(prefix) {
        return false;
    }
    prefix.ends_with('/')
        || path_only.len() == prefix.len()
        || path_only[prefix.len()..].starts_with('/')
}

fn execute_fetch_url(
    args: &Value,
    auth_rules: &[AuthFetchRule],
    transport: &mut dyn HostedTransport,
) -> Value {
    let Some(url) = args.get("url").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "missing url"});
    };
    let max_chars = args
        .get("max_chars")
        .and_then(Value::as_u64)
        .unwrap_or(16_000)
        .min(64_000) as usize;
    let (host, normalized_path) = match parse_https_origin_and_path(url) {
        Ok(pair) => pair,
        Err(e) => return json!({"ok": false, "error": e}),
    };
    let normalized_url = format!("https://{host}{normalized_path}");

    let mut headers = vec![(
        "User-Agent".to_owned(),
        "chinwag-hosted-agent/1.0".to_owned(),
    )];
    for rule in auth_rules {
        if rule.host.eq_ignore_ascii_case(&host) {
            let prefix_ok = rule
                .path_prefix
                .as_deref()
                .is_none_or(|prefix| path_matches_prefix(&normalized_path, prefix));
            if prefix_ok && let Ok(secret) = resolve_secret(&rule.credential) {
                let value = match &rule.header_prefix {
                    Some(prefix) => format!("{prefix}{secret}"),
                    None => secret,
                };
                headers.push((rule.header_name.clone(), value));
            }
        }
    }

    let req = HttpRequest {
        method: "GET".to_owned(),
        url: normalized_url.clone(),
        headers,
        body: None,
        timeout_secs: 25,
    };
    match transport.send(&req) {
        Ok(resp) => {
            let clipped: String = resp.body.chars().take(max_chars).collect();
            json!({
                "ok": (200..300).contains(&resp.status),
                "status": resp.status,
                "url": normalized_url,
                "body": clipped
            })
        }
        Err(e) => json!({
            "ok": false,
            "error": e.to_string()
        }),
    }
}

fn execute_run_command(
    args: &Value,
    cwd: &Path,
    base_env: &[(String, String)],
    injections: &[EnvInjectionRule],
) -> Value {
    let mut env_pairs = base_env.to_vec();
    for rule in injections {
        match &rule.source {
            EnvValueSource::Literal { value } => {
                env_pairs.push((rule.env_var.clone(), value.clone()));
            }
            EnvValueSource::Secret { credential } => {
                if let Ok(secret) = resolve_secret(credential) {
                    env_pairs.push((rule.env_var.clone(), secret));
                }
            }
        }
    }

    let output = if let Some(program) = args.get("program").and_then(Value::as_str) {
        if program.trim().is_empty() || program.contains('\0') {
            return json!({"ok": false, "error": "invalid program"});
        }
        let prog_args: Vec<String> = args
            .get("args")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Command::new(program)
            .args(&prog_args)
            .current_dir(cwd)
            .envs(env_pairs.iter().cloned())
            .output()
    } else if let Some(cmd) = args.get("command").and_then(Value::as_str) {
        if cmd.trim().is_empty() || cmd.contains('\0') {
            return json!({"ok": false, "error": "empty or invalid command"});
        }
        Command::new("/bin/sh")
            .args(["-c", cmd])
            .current_dir(cwd)
            .envs(env_pairs.iter().cloned())
            .output()
    } else {
        return json!({"ok": false, "error": "missing program or command"});
    };

    match output {
        Ok(out) => {
            let stdout: String = String::from_utf8_lossy(&out.stdout)
                .chars()
                .take(12_000)
                .collect();
            let stderr: String = String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(4_000)
                .collect();
            json!({
                "ok": out.status.success(),
                "exit_code": out.status.code().unwrap_or(-1),
                "stdout": stdout,
                "stderr": stderr
            })
        }
        Err(e) => json!({
            "ok": false,
            "error": format!("spawn error: {e}")
        }),
    }
}

fn gemini_tool_declarations() -> Value {
    json!([{
        "functionDeclarations": [
            {
                "name": "read_file",
                "description": "Read a UTF-8 text file from disk.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "path": {"type": "STRING", "description": "Absolute or relative file path."},
                        "max_chars": {"type": "INTEGER", "description": "Maximum characters to return (default 16000)."}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "write_file",
                "description": "Write UTF-8 text content to a file inside an allowed workspace directory.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "path": {"type": "STRING", "description": "Destination file path."},
                        "content": {"type": "STRING", "description": "Full UTF-8 content to write."}
                    },
                    "required": ["path", "content"]
                }
            },
            {
                "name": "fetch_url",
                "description": "Fetch live HTTPS documentation or JSON model catalogs with domain-scoped local credential headers.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "url": {"type": "STRING", "description": "HTTPS URL to GET."},
                        "max_chars": {"type": "INTEGER", "description": "Maximum characters to return (default 16000)."}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "run_command",
                "description": "Run a bounded non-interactive command (e.g. chinwag memory recall/retain/tombstone, chinwag bus send, earshot, ffmpeg).",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "program": {"type": "STRING", "description": "Executable name or path."},
                        "args": {"type": "ARRAY", "items": {"type": "STRING"}, "description": "Argument list."},
                        "command": {"type": "STRING", "description": "Shell command string when program/args are not used."}
                    }
                }
            }
        ]
    }])
}

fn openai_tool_declarations() -> Value {
    json!([
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a UTF-8 text file from disk.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "max_chars": {"type": "integer"}
                    },
                    "required": ["path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "write_file",
                "description": "Write UTF-8 text content to a file inside an allowed workspace root.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"}
                    },
                    "required": ["path", "content"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "fetch_url",
                "description": "Fetch live HTTPS documentation or JSON model catalogs.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "max_chars": {"type": "integer"}
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "run_command",
                "description": "Run a bounded non-interactive command.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "program": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}},
                        "command": {"type": "string"}
                    }
                }
            }
        }
    ])
}

/// Runs a configured hosted agent seat through its bound provider and multi-turn tool loop.
pub fn run_hosted_seat(
    config: &ProvidersConfig,
    seat_upper: &str,
    system_instruction: &str,
    user_prompt: &str,
    transport: &mut dyn HostedTransport,
    executor: &mut dyn ToolExecutor,
) -> Result<HostedReply, HostedAgentError> {
    let Some(binding) = config.agents.get(seat_upper) else {
        return Err(HostedAgentError::UnboundSeat(seat_upper.to_owned()));
    };
    let Some(provider) = config.providers.get(&binding.provider) else {
        return Err(HostedAgentError::ConfigError(format!(
            "missing provider {}",
            binding.provider
        )));
    };

    match provider {
        ProviderConfig::GeminiGenerateContent {
            base_url,
            credential,
        } => run_gemini_loop(
            base_url,
            credential,
            binding,
            system_instruction,
            user_prompt,
            transport,
            executor,
        ),
        ProviderConfig::OpenAiChatCompletions {
            endpoint,
            credential,
        } => run_openai_loop(
            endpoint,
            credential.as_ref(),
            binding,
            system_instruction,
            user_prompt,
            transport,
            executor,
        ),
        ProviderConfig::CloudflareWorkersAi {
            base_url,
            account_id,
            credential,
        } => run_workers_ai_loop(
            base_url,
            account_id,
            credential,
            binding,
            system_instruction,
            user_prompt,
            transport,
            executor,
        ),
    }
}

fn run_gemini_loop(
    base_url: &str,
    credential: &SecretRef,
    binding: &AgentBinding,
    system_instruction: &str,
    user_prompt: &str,
    transport: &mut dyn HostedTransport,
    executor: &mut dyn ToolExecutor,
) -> Result<HostedReply, HostedAgentError> {
    let api_key = resolve_secret(credential)?;
    let url = format!(
        "{}/models/{}:generateContent",
        base_url.trim_end_matches('/'),
        binding.model
    );
    let mut contents = vec![json!({
        "role": "user",
        "parts": [{"text": user_prompt}]
    })];
    let mut total_tool_calls = 0usize;

    for turn in 1..=binding.limits.max_turns {
        let mut payload = json!({
            "systemInstruction": {
                "parts": [{"text": system_instruction}]
            },
            "contents": contents,
            "generationConfig": {
                "temperature": 0.4,
                "maxOutputTokens": binding.limits.max_output_tokens
            }
        });
        if binding.tools.enabled {
            payload["tools"] = gemini_tool_declarations();
        }
        let req = HttpRequest {
            method: "POST".to_owned(),
            url: url.clone(),
            headers: vec![("x-goog-api-key".to_owned(), api_key.clone())],
            body: Some(payload.to_string()),
            timeout_secs: binding.limits.request_timeout_secs,
        };
        let resp = transport.send(&req)?;
        if resp.status != 200 {
            return Err(HostedAgentError::ProtocolError(format!(
                "Gemini HTTP {}",
                resp.status
            )));
        }
        let parsed: Value = serde_json::from_str(&resp.body)
            .map_err(|_| HostedAgentError::ProtocolError("invalid Gemini JSON".to_owned()))?;
        let Some(candidate) = parsed.pointer("/candidates/0") else {
            return Err(HostedAgentError::ProtocolError(
                "Gemini response missing candidates[0]".to_owned(),
            ));
        };
        let Some(parts) = candidate
            .pointer("/content/parts")
            .and_then(Value::as_array)
        else {
            return Err(HostedAgentError::ProtocolError(
                "Gemini candidate missing content.parts".to_owned(),
            ));
        };

        // Preserve original model parts (including thought signatures and IDs) intact.
        contents.push(json!({
            "role": "model",
            "parts": parts
        }));

        let mut fn_calls = Vec::new();
        for part in parts {
            if let Some(fc) = part.get("functionCall") {
                let name = fc
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        HostedAgentError::ProtocolError(
                            "Gemini functionCall missing name".to_owned(),
                        )
                    })?
                    .to_owned();
                let args = fc.get("args").cloned().unwrap_or_else(|| json!({}));
                let id = fc.get("id").and_then(Value::as_str).map(str::to_owned);
                fn_calls.push(ToolCall { id, name, args });
            }
        }

        if fn_calls.is_empty() {
            let text: String = parts
                .iter()
                .filter(|p| !p.get("thought").and_then(Value::as_bool).unwrap_or(false))
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("");
            let trimmed = text.trim().to_owned();
            if trimmed.is_empty() {
                return Err(HostedAgentError::ProtocolError(
                    "Gemini returned empty text completion".to_owned(),
                ));
            }
            return Ok(HostedReply {
                text: trimmed,
                engine_label: format!("{}:{}", binding.provider, binding.model),
                turns_used: turn,
                tool_calls_used: total_tool_calls,
            });
        }

        let mut response_parts = Vec::new();
        for call in fn_calls {
            total_tool_calls += 1;
            if total_tool_calls > binding.limits.max_tool_calls {
                return Err(HostedAgentError::ToolCallLimitExceeded(
                    binding.limits.max_tool_calls,
                ));
            }
            let result = executor.execute(&call, &binding.tools, transport);
            let mut fr = Map::new();
            if let Some(id) = call.id {
                fr.insert("id".to_owned(), Value::String(id));
            }
            fr.insert("name".to_owned(), Value::String(call.name));
            fr.insert("response".to_owned(), result);
            response_parts.push(Value::Object({
                let mut wrapper = Map::new();
                wrapper.insert("functionResponse".to_owned(), Value::Object(fr));
                wrapper
            }));
        }
        contents.push(json!({
            "role": "user",
            "parts": response_parts
        }));
    }

    Err(HostedAgentError::TurnLimitExceeded(
        binding.limits.max_turns,
    ))
}

fn run_openai_loop(
    endpoint: &str,
    credential: Option<&SecretRef>,
    binding: &AgentBinding,
    system_instruction: &str,
    user_prompt: &str,
    transport: &mut dyn HostedTransport,
    executor: &mut dyn ToolExecutor,
) -> Result<HostedReply, HostedAgentError> {
    let bearer = match credential {
        Some(secret_ref) => Some(resolve_secret(secret_ref)?),
        None => None,
    };
    let mut messages = vec![
        json!({"role": "system", "content": system_instruction}),
        json!({"role": "user", "content": user_prompt}),
    ];
    let mut total_tool_calls = 0usize;

    for turn in 1..=binding.limits.max_turns {
        let mut payload = json!({
            "model": binding.model,
            "messages": messages,
            "max_tokens": binding.limits.max_output_tokens
        });
        if binding.tools.enabled {
            payload["tools"] = openai_tool_declarations();
        }
        let mut headers = Vec::new();
        if let Some(token) = &bearer {
            headers.push(("Authorization".to_owned(), format!("Bearer {token}")));
        }
        let req = HttpRequest {
            method: "POST".to_owned(),
            url: endpoint.to_owned(),
            headers,
            body: Some(payload.to_string()),
            timeout_secs: binding.limits.request_timeout_secs,
        };
        let resp = transport.send(&req)?;
        if resp.status != 200 {
            return Err(HostedAgentError::ProtocolError(format!(
                "OpenAI-compatible HTTP {}",
                resp.status
            )));
        }
        let parsed: Value = serde_json::from_str(&resp.body).map_err(|_| {
            HostedAgentError::ProtocolError("invalid OpenAI-compatible JSON".to_owned())
        })?;
        let Some(msg) = parsed.pointer("/choices/0/message") else {
            return Err(HostedAgentError::ProtocolError(
                "missing choices[0].message".to_owned(),
            ));
        };
        messages.push(msg.clone());

        if let Some(tool_calls) = msg.get("tool_calls").and_then(Value::as_array)
            && !tool_calls.is_empty()
        {
            for tc in tool_calls {
                total_tool_calls += 1;
                if total_tool_calls > binding.limits.max_tool_calls {
                    return Err(HostedAgentError::ToolCallLimitExceeded(
                        binding.limits.max_tool_calls,
                    ));
                }
                let call_id = tc
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        HostedAgentError::ProtocolError("tool_call missing id".to_owned())
                    })?
                    .to_owned();
                let name = tc
                    .pointer("/function/name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        HostedAgentError::ProtocolError(
                            "tool_call missing function.name".to_owned(),
                        )
                    })?
                    .to_owned();
                let raw_args = tc
                    .pointer("/function/arguments")
                    .and_then(Value::as_str)
                    .unwrap_or("{}");
                let args: Value = serde_json::from_str(raw_args).map_err(|_| {
                    HostedAgentError::ProtocolError("invalid tool_call arguments JSON".to_owned())
                })?;
                let call = ToolCall {
                    id: Some(call_id.clone()),
                    name,
                    args,
                };
                let result = executor.execute(&call, &binding.tools, transport);
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": result.to_string()
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
            return Err(HostedAgentError::ProtocolError(
                "empty assistant content".to_owned(),
            ));
        }
        return Ok(HostedReply {
            text: content,
            engine_label: format!("{}:{}", binding.provider, binding.model),
            turns_used: turn,
            tool_calls_used: total_tool_calls,
        });
    }

    Err(HostedAgentError::TurnLimitExceeded(
        binding.limits.max_turns,
    ))
}

#[allow(clippy::too_many_arguments)]
fn run_workers_ai_loop(
    base_url: &str,
    account_id: &str,
    credential: &SecretRef,
    binding: &AgentBinding,
    system_instruction: &str,
    user_prompt: &str,
    transport: &mut dyn HostedTransport,
    executor: &mut dyn ToolExecutor,
) -> Result<HostedReply, HostedAgentError> {
    let token = resolve_secret(credential)?;
    let url = format!(
        "{}/accounts/{account_id}/ai/run/{}",
        base_url.trim_end_matches('/'),
        binding.model
    );
    let mut messages = vec![
        json!({"role": "system", "content": system_instruction}),
        json!({"role": "user", "content": user_prompt}),
    ];
    let mut total_tool_calls = 0usize;

    for turn in 1..=binding.limits.max_turns {
        let mut payload = json!({
            "messages": messages,
            "max_tokens": binding.limits.max_output_tokens
        });
        if binding.tools.enabled {
            payload["tools"] = openai_tool_declarations();
        }
        let req = HttpRequest {
            method: "POST".to_owned(),
            url: url.clone(),
            headers: vec![("Authorization".to_owned(), format!("Bearer {token}"))],
            body: Some(payload.to_string()),
            timeout_secs: binding.limits.request_timeout_secs,
        };
        let resp = transport.send(&req)?;
        if resp.status != 200 {
            return Err(HostedAgentError::ProtocolError(format!(
                "Workers AI HTTP {}",
                resp.status
            )));
        }
        let parsed: Value = serde_json::from_str(&resp.body)
            .map_err(|_| HostedAgentError::ProtocolError("invalid Workers AI JSON".to_owned()))?;
        if parsed.get("success").and_then(Value::as_bool) == Some(false) {
            return Err(HostedAgentError::ProtocolError(
                "Workers AI returned success:false".to_owned(),
            ));
        }
        let root = parsed.get("result").unwrap_or(&parsed);

        let choice_msg = root.pointer("/choices/0/message");
        let raw_tool_calls = choice_msg
            .and_then(|m| m.get("tool_calls"))
            .or_else(|| root.get("tool_calls"))
            .and_then(Value::as_array);

        if let Some(tool_calls) = raw_tool_calls
            && !tool_calls.is_empty()
        {
            let mut normalized_calls = Vec::with_capacity(tool_calls.len());
            let mut parsed_invocations = Vec::with_capacity(tool_calls.len());
            for (idx, tc) in tool_calls.iter().enumerate() {
                total_tool_calls += 1;
                if total_tool_calls > binding.limits.max_tool_calls {
                    return Err(HostedAgentError::ToolCallLimitExceeded(
                        binding.limits.max_tool_calls,
                    ));
                }
                let call_id = tc
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("cf-call-{turn}-{idx}"));
                let name = tc
                    .get("name")
                    .or_else(|| tc.pointer("/function/name"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        HostedAgentError::ProtocolError(
                            "Workers AI tool_call missing name".to_owned(),
                        )
                    })?
                    .to_owned();
                let args = if let Some(obj) = tc.get("arguments") {
                    if let Some(s) = obj.as_str() {
                        serde_json::from_str(s).map_err(|_| {
                            HostedAgentError::ProtocolError("invalid arguments JSON".to_owned())
                        })?
                    } else {
                        obj.clone()
                    }
                } else if let Some(s) = tc.pointer("/function/arguments").and_then(Value::as_str) {
                    serde_json::from_str(s).map_err(|_| {
                        HostedAgentError::ProtocolError(
                            "invalid function.arguments JSON".to_owned(),
                        )
                    })?
                } else {
                    json!({})
                };
                let mut tc_obj = tc.clone();
                if let Some(map) = tc_obj.as_object_mut() {
                    map.entry("id".to_owned())
                        .or_insert_with(|| Value::String(call_id.clone()));
                }
                normalized_calls.push(tc_obj);
                parsed_invocations.push((
                    call_id.clone(),
                    name.clone(),
                    ToolCall {
                        id: Some(call_id),
                        name,
                        args,
                    },
                ));
            }

            if let Some(msg) = choice_msg {
                let mut preserved = msg.clone();
                if let Some(map) = preserved.as_object_mut() {
                    map.insert("tool_calls".to_owned(), Value::Array(normalized_calls));
                }
                messages.push(preserved);
            } else {
                messages.push(json!({
                    "role": "assistant",
                    "tool_calls": normalized_calls
                }));
            }

            for (call_id, name, call) in parsed_invocations {
                let result = executor.execute(&call, &binding.tools, transport);
                messages.push(json!({
                    "role": "tool",
                    "name": name,
                    "tool_call_id": call_id,
                    "content": result.to_string()
                }));
            }
            continue;
        }

        let text = root
            .get("response")
            .and_then(Value::as_str)
            .or_else(|| {
                root.pointer("/choices/0/message/content")
                    .and_then(Value::as_str)
            })
            .unwrap_or("")
            .trim()
            .to_owned();
        if text.is_empty() {
            return Err(HostedAgentError::ProtocolError(
                "Workers AI returned empty response".to_owned(),
            ));
        }
        return Ok(HostedReply {
            text,
            engine_label: format!("{}:{}", binding.provider, binding.model),
            turns_used: turn,
            tool_calls_used: total_tool_calls,
        });
    }

    Err(HostedAgentError::TurnLimitExceeded(
        binding.limits.max_turns,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tempfile::TempDir;

    struct MockTransport {
        requests: Vec<HttpRequest>,
        responses: VecDeque<Result<HttpResponse, HostedAgentError>>,
    }

    impl MockTransport {
        fn new(responses: Vec<Result<HttpResponse, HostedAgentError>>) -> Self {
            Self {
                requests: Vec::new(),
                responses: responses.into(),
            }
        }
    }

    impl HostedTransport for MockTransport {
        fn send(&mut self, req: &HttpRequest) -> Result<HttpResponse, HostedAgentError> {
            self.requests.push(req.clone());
            self.responses
                .pop_front()
                .unwrap_or_else(|| Err(HostedAgentError::TransportError("no mock response".into())))
        }
    }

    fn write_0600(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        f.write_all(content.as_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn secret_resolver_enforces_0600_and_rejects_symlinks() {
        let tmp = TempDir::new().unwrap();
        let env_path = tmp.path().join("gemini.env");
        write_0600(
            &env_path,
            "export GEMINI_API_KEY=\"AIzaTestSecretKey123456\"\n",
        );

        let secret = resolve_secret(&SecretRef::EnvFile {
            path: env_path.clone(),
            key: "GEMINI_API_KEY".to_owned(),
        })
        .unwrap();
        assert_eq!(secret, "AIzaTestSecretKey123456");

        // Group/world-readable file must fail closed.
        fs::set_permissions(&env_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            resolve_secret(&SecretRef::EnvFile {
                path: env_path.clone(),
                key: "GEMINI_API_KEY".to_owned(),
            }),
            Err(HostedAgentError::SecretError(_))
        ));
        fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600)).unwrap();

        // Symlink to a valid 0600 file must also fail closed via O_NOFOLLOW.
        let link_path = tmp.path().join("symlink.env");
        std::os::unix::fs::symlink(&env_path, &link_path).unwrap();
        assert!(matches!(
            resolve_secret(&SecretRef::EnvFile {
                path: link_path,
                key: "GEMINI_API_KEY".to_owned(),
            }),
            Err(HostedAgentError::SecretError(_))
        ));
    }

    #[test]
    fn curl_transport_passes_secret_headers_only_on_stdin_never_argv() {
        let tmp = TempDir::new().unwrap();
        let fake_curl = tmp.path().join("fake-curl.sh");
        let argv_dump = tmp.path().join("argv.txt");
        let stdin_dump = tmp.path().join("stdin.txt");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\ncat > \"{}\"\nprintf '{{\"ok\":true}}\\n200'",
            argv_dump.display(),
            stdin_dump.display()
        );
        write_0600(&fake_curl, &script);
        fs::set_permissions(&fake_curl, fs::Permissions::from_mode(0o700)).unwrap();

        let mut transport = CurlTransport::new(fake_curl, tmp.path().join("scratch"));
        let resp = transport
            .send(&HttpRequest {
                method: "POST".to_owned(),
                url: "https://generativelanguage.googleapis.com/v1beta/models/fixture-model:generateContent".to_owned(),
                headers: vec![("x-goog-api-key".to_owned(), "SUPER_SECRET_SENTINEL_999".to_owned())],
                body: Some("{\"hello\":\"world\"}".to_owned()),
                timeout_secs: 30,
            })
            .unwrap();
        assert_eq!(resp.status, 200);

        let argv_text = fs::read_to_string(&argv_dump).unwrap();
        let stdin_text = fs::read_to_string(&stdin_dump).unwrap();
        assert!(
            argv_text.starts_with("-q\n"),
            "first curl argument must be -q: {argv_text}"
        );
        assert!(
            !argv_text.contains("SUPER_SECRET_SENTINEL_999"),
            "secret must never appear in curl argv"
        );
        assert!(
            stdin_text.contains("header = \"x-goog-api-key: SUPER_SECRET_SENTINEL_999\""),
            "secret header must arrive on curl stdin"
        );
    }

    #[test]
    fn gemini_adapter_preserves_model_parts_and_completes_tool_loop() {
        let tmp = TempDir::new().unwrap();
        let gem_env = tmp.path().join("gemini.env");
        let el_env = tmp.path().join("eleven.env");
        write_0600(&gem_env, "GEMINI_API_KEY=AIzaGeminiKey1234567890\n");
        write_0600(&el_env, "ELEVENLABS_API_KEY=el_live_secret_token_12345\n");

        let mut providers = BTreeMap::new();
        providers.insert(
            "google-gemini".to_owned(),
            ProviderConfig::GeminiGenerateContent {
                base_url: DEFAULT_GEMINI_BASE_URL.to_owned(),
                credential: SecretRef::EnvFile {
                    path: gem_env,
                    key: "GEMINI_API_KEY".to_owned(),
                },
            },
        );
        let mut agents = BTreeMap::new();
        agents.insert(
            "FIXTURE-F".to_owned(),
            AgentBinding {
                provider: "google-gemini".to_owned(),
                model: "fixture-model".to_owned(),
                limits: RunLimits::default(),
                tools: ToolPolicy {
                    enabled: true,
                    allowed_write_roots: vec![tmp.path().to_path_buf()],
                    auth_fetches: vec![AuthFetchRule {
                        host: "api.elevenlabs.io".to_owned(),
                        path_prefix: Some("/v1/".to_owned()),
                        header_name: "xi-api-key".to_owned(),
                        header_prefix: None,
                        credential: SecretRef::EnvFile {
                            path: el_env,
                            key: "ELEVENLABS_API_KEY".to_owned(),
                        },
                    }],
                    env_injections: Vec::new(),
                },
            },
        );
        let cfg = ProvidersConfig {
            version: 1,
            providers,
            agents,
        };

        let mut transport = MockTransport::new(vec![
            // Turn 1: Gemini requests fetch_url on api.elevenlabs.io with a thoughtSignature
            Ok(HttpResponse {
                status: 200,
                body: json!({
                    "candidates": [{
                        "content": {
                            "parts": [
                                {"text": "checking models", "thought": true, "thoughtSignature": "sig-abc-123"},
                                {"functionCall": {"id": "call-1", "name": "fetch_url", "args": {"url": "https://api.elevenlabs.io/v1/models"}}}
                            ]
                        }
                    }]
                })
                .to_string(),
            }),
            // Tool execution: fetch_url response from api.elevenlabs.io
            Ok(HttpResponse {
                status: 200,
                body: "[{\"model_id\":\"eleven_v3\"}]".to_owned(),
            }),
            // Turn 2: Gemini returns final text
            Ok(HttpResponse {
                status: 200,
                body: json!({
                    "candidates": [{
                        "content": {
                            "parts": [
                                {"text": "Ingested eleven_v3 from live API."}
                            ]
                        }
                    }]
                })
                .to_string(),
            }),
        ]);
        let mut executor = StandardToolExecutor::new(tmp.path().to_path_buf(), Vec::new());

        let reply = run_hosted_seat(
            &cfg,
            "FIXTURE-F",
            "System instructions",
            "Check ElevenLabs models",
            &mut transport,
            &mut executor,
        )
        .unwrap();

        assert_eq!(reply.text, "Ingested eleven_v3 from live API.");
        assert_eq!(reply.turns_used, 2);
        assert_eq!(reply.tool_calls_used, 1);

        // Verify the fetch_url call injected xi-api-key for api.elevenlabs.io
        assert_eq!(
            transport.requests[1].headers,
            vec![
                (
                    "User-Agent".to_owned(),
                    "chinwag-hosted-agent/1.0".to_owned()
                ),
                (
                    "xi-api-key".to_owned(),
                    "el_live_secret_token_12345".to_owned()
                )
            ]
        );

        // Verify Turn 2 preserved the original model thoughtSignature and functionCall id
        let turn2_body: Value =
            serde_json::from_str(transport.requests[2].body.as_ref().unwrap()).unwrap();
        assert_eq!(
            turn2_body.pointer("/contents/1/parts/0/thoughtSignature"),
            Some(&Value::String("sig-abc-123".to_owned()))
        );
        assert_eq!(
            turn2_body.pointer("/contents/2/parts/0/functionResponse/id"),
            Some(&Value::String("call-1".to_owned()))
        );
    }

    #[test]
    fn auth_fetch_never_leaks_credentials_to_spoofed_subdomain_or_wrong_path() {
        let tmp = TempDir::new().unwrap();
        let el_env = tmp.path().join("eleven.env");
        write_0600(&el_env, "ELEVENLABS_API_KEY=el_live_secret_token_12345\n");
        let rules = vec![AuthFetchRule {
            host: "api.elevenlabs.io".to_owned(),
            path_prefix: Some("/v1/".to_owned()),
            header_name: "xi-api-key".to_owned(),
            header_prefix: None,
            credential: SecretRef::EnvFile {
                path: el_env,
                key: "ELEVENLABS_API_KEY".to_owned(),
            },
        }];

        let mut transport = MockTransport::new(vec![Ok(HttpResponse {
            status: 200,
            body: "ok".to_owned(),
        })]);
        let res = execute_fetch_url(
            &json!({"url": "https://api.elevenlabs.io.attacker.example/v1/models"}),
            &rules,
            &mut transport,
        );
        assert_eq!(res["ok"], Value::Bool(true));
        assert_eq!(
            transport.requests[0].headers,
            vec![(
                "User-Agent".to_owned(),
                "chinwag-hosted-agent/1.0".to_owned()
            )]
        );
    }

    #[test]
    fn write_file_confines_paths_and_rejects_sibling_prefix_and_traversal() {
        let tmp = TempDir::new().unwrap();
        let allowed = tmp.path().join("WORKSPACE");
        let sibling = tmp.path().join("WORKSPACE-evil");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&sibling).unwrap();

        let roots = vec![allowed.clone()];
        let ok_path = resolve_confined_write_path(
            allowed.join("sub/out.txt").to_str().unwrap(),
            &allowed,
            &roots,
        );
        assert!(ok_path.is_ok());

        let sibling_attempt = resolve_confined_write_path(
            sibling.join("out.txt").to_str().unwrap(),
            &allowed,
            &roots,
        );
        assert!(sibling_attempt.is_err());

        let traversal_attempt =
            resolve_confined_write_path("../WORKSPACE-evil/out.txt", &allowed, &roots);
        assert!(traversal_attempt.is_err());
    }

    #[test]
    fn openai_and_workers_ai_adapters_complete_tool_turns_and_reject_errors() {
        let tmp = TempDir::new().unwrap();
        let tok_path = tmp.path().join("cf.token");
        write_0600(&tok_path, "cf_workers_ai_token_1234567890");

        let mut providers = BTreeMap::new();
        providers.insert(
            "cf".to_owned(),
            ProviderConfig::CloudflareWorkersAi {
                base_url: DEFAULT_CF_BASE_URL.to_owned(),
                account_id: DEFAULT_CF_ACCOUNT_ID.to_owned(),
                credential: SecretRef::TokenFile { path: tok_path },
            },
        );
        providers.insert(
            "oai".to_owned(),
            ProviderConfig::OpenAiChatCompletions {
                endpoint: "https://api.openai.example/v1/chat/completions".to_owned(),
                credential: None,
            },
        );
        let mut agents = BTreeMap::new();
        agents.insert(
            "CF-AGENT".to_owned(),
            AgentBinding {
                provider: "cf".to_owned(),
                model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017".to_owned(),
                limits: RunLimits::default(),
                tools: ToolPolicy {
                    enabled: false,
                    ..ToolPolicy::default()
                },
            },
        );
        agents.insert(
            "OAI-AGENT".to_owned(),
            AgentBinding {
                provider: "oai".to_owned(),
                model: "gpt-6.1-sol".to_owned(),
                limits: RunLimits::default(),
                tools: ToolPolicy {
                    enabled: true,
                    allowed_write_roots: vec![tmp.path().to_path_buf()],
                    auth_fetches: Vec::new(),
                    env_injections: Vec::new(),
                },
            },
        );
        let cfg = ProvidersConfig {
            version: 1,
            providers,
            agents,
        };

        // 1. Workers AI success:false must fail closed.
        let mut bad_cf = MockTransport::new(vec![Ok(HttpResponse {
            status: 200,
            body: json!({"success": false, "errors": [{"code": 1000, "message": "boom"}]})
                .to_string(),
        })]);
        let mut exec = StandardToolExecutor::new(tmp.path().to_path_buf(), Vec::new());
        assert!(matches!(
            run_hosted_seat(&cfg, "CF-AGENT", "sys", "hi", &mut bad_cf, &mut exec),
            Err(HostedAgentError::ProtocolError(_))
        ));

        // 2. OpenAI tool call + completion turn succeeds and preserves tool_call_id.
        let sample_file = tmp.path().join("note.txt");
        fs::write(&sample_file, "hello from disk").unwrap();
        let mut oai_transport = MockTransport::new(vec![
            Ok(HttpResponse {
                status: 200,
                body: json!({
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "tool_calls": [{
                                "id": "call-oai-99",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": json!({"path": sample_file.display().to_string()}).to_string()
                                }
                            }]
                        }
                    }]
                })
                .to_string(),
            }),
            Ok(HttpResponse {
                status: 200,
                body: json!({
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": "Read: hello from disk"
                        }
                    }]
                })
                .to_string(),
            }),
        ]);
        let reply = run_hosted_seat(
            &cfg,
            "OAI-AGENT",
            "sys",
            "read note",
            &mut oai_transport,
            &mut exec,
        )
        .unwrap();
        assert_eq!(reply.text, "Read: hello from disk");
        assert_eq!(reply.tool_calls_used, 1);
    }

    #[test]
    fn explicit_missing_config_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("does-not-exist-providers.json");
        let res = ProvidersConfig::load_or_default(Some(&missing), tmp.path(), tmp.path());
        assert!(
            matches!(res, Err(HostedAgentError::ConfigError(_))),
            "explicit missing CHINWAG_PROVIDERS_CONFIG must fail closed with ConfigError: {res:?}"
        );
    }

    #[test]
    fn authenticated_dot_segments_and_encoded_separators_do_not_receive_credentials() {
        let tmp = TempDir::new().unwrap();
        let el_env = tmp.path().join("eleven.env");
        write_0600(&el_env, "ELEVENLABS_API_KEY=el_live_secret_token_12345\n");
        let rules = vec![AuthFetchRule {
            host: "api.elevenlabs.io".to_owned(),
            path_prefix: Some("/v1/".to_owned()),
            header_name: "xi-api-key".to_owned(),
            header_prefix: None,
            credential: SecretRef::EnvFile {
                path: el_env,
                key: "ELEVENLABS_API_KEY".to_owned(),
            },
        }];

        // 1. Dot-segment escape /v1/../public must normalize to /public and NOT receive xi-api-key.
        let mut transport = MockTransport::new(vec![Ok(HttpResponse {
            status: 200,
            body: "ok".to_owned(),
        })]);
        let res = execute_fetch_url(
            &json!({"url": "https://api.elevenlabs.io/v1/../public"}),
            &rules,
            &mut transport,
        );
        assert_eq!(res["ok"], Value::Bool(true));
        assert_eq!(
            transport.requests[0].url,
            "https://api.elevenlabs.io/public"
        );
        assert!(
            !transport.requests[0]
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("xi-api-key")),
            "dot-segment traversal outside /v1/ must not receive xi-api-key"
        );

        // 2. Percent-encoded dot/slash (%2e%2e / %2f) must be rejected outright.
        let mut transport2 = MockTransport::new(vec![]);
        let bad_encoded = execute_fetch_url(
            &json!({"url": "https://api.elevenlabs.io/v1/%2e%2e/public"}),
            &rules,
            &mut transport2,
        );
        assert_eq!(bad_encoded["ok"], Value::Bool(false));
        assert!(transport2.requests.is_empty());
    }

    #[test]
    fn workers_ai_preserves_assistant_continuation_and_flat_tool_call_ids() {
        let tmp = TempDir::new().unwrap();
        let tok_path = tmp.path().join("cf.token");
        write_0600(&tok_path, "cf_workers_ai_token_1234567890");
        let sample_file = tmp.path().join("cf_note.txt");
        fs::write(&sample_file, "workers ai payload").unwrap();

        let mut providers = BTreeMap::new();
        providers.insert(
            "cf".to_owned(),
            ProviderConfig::CloudflareWorkersAi {
                base_url: DEFAULT_CF_BASE_URL.to_owned(),
                account_id: DEFAULT_CF_ACCOUNT_ID.to_owned(),
                credential: SecretRef::TokenFile { path: tok_path },
            },
        );
        let mut agents = BTreeMap::new();
        agents.insert(
            "CF-AGENT".to_owned(),
            AgentBinding {
                provider: "cf".to_owned(),
                model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017".to_owned(),
                limits: RunLimits::default(),
                tools: ToolPolicy {
                    enabled: true,
                    allowed_write_roots: vec![tmp.path().to_path_buf()],
                    auth_fetches: Vec::new(),
                    env_injections: Vec::new(),
                },
            },
        );
        let cfg = ProvidersConfig {
            version: 1,
            providers,
            agents,
        };

        let mut transport = MockTransport::new(vec![
            Ok(HttpResponse {
                status: 200,
                body: json!({
                    "success": true,
                    "result": {
                        "choices": [{
                            "message": {
                                "role": "assistant",
                                "content": null,
                                "reasoning_content": "need to inspect cf_note.txt first",
                                "tool_calls": [{
                                    "name": "read_file",
                                    "arguments": {
                                        "path": sample_file.display().to_string()
                                    }
                                }]
                            }
                        }]
                    }
                })
                .to_string(),
            }),
            Ok(HttpResponse {
                status: 200,
                body: json!({
                    "success": true,
                    "result": {
                        "response": "Workers AI finished reading"
                    }
                })
                .to_string(),
            }),
        ]);
        let mut exec = StandardToolExecutor::new(tmp.path().to_path_buf(), Vec::new());
        let reply =
            run_hosted_seat(&cfg, "CF-AGENT", "sys", "go", &mut transport, &mut exec).unwrap();
        assert_eq!(reply.text, "Workers AI finished reading");
        assert_eq!(reply.turns_used, 2);

        let turn2_body: Value =
            serde_json::from_str(transport.requests[1].body.as_ref().unwrap()).unwrap();
        assert_eq!(
            turn2_body.pointer("/messages/2/reasoning_content"),
            Some(&Value::String(
                "need to inspect cf_note.txt first".to_owned()
            ))
        );
        assert_eq!(
            turn2_body.pointer("/messages/2/tool_calls/0/id"),
            Some(&Value::String("cf-call-1-0".to_owned()))
        );
        assert_eq!(
            turn2_body.pointer("/messages/3/tool_call_id"),
            Some(&Value::String("cf-call-1-0".to_owned()))
        );
    }
}
