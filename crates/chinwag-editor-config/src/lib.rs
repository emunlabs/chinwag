//! Pure 6-editor proposals and descriptor-anchored atomic installation (`INV-NO-ENV-INTERPOLATION-01`).
#![deny(unsafe_code)]
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod install;
mod json_config;

use std::{
    path::{Component, Path},
    str::FromStr,
};
use toml_edit::{DocumentMut, Item};

pub const MAX_BYTES: usize = 1_048_576;

const FORBIDDEN_SHELL_WRAPPERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "env",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "osascript",
];

const FORBIDDEN_SHELL_FLAGS: &[&str] = &["-c", "-lc", "/c", "/C"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Editor {
    ClaudeCode,
    Cursor,
    Codex,
    Gemini,
    Grok,
    VsCode,
}

impl Editor {
    pub const ALL: [Self; 6] = [
        Self::ClaudeCode,
        Self::Cursor,
        Self::Codex,
        Self::Gemini,
        Self::Grok,
        Self::VsCode,
    ];

    pub const fn relative_path(self) -> &'static str {
        match self {
            Self::ClaudeCode => ".mcp.json",
            Self::Cursor => ".cursor/mcp.json",
            Self::Codex => ".codex/config.toml",
            Self::Gemini => ".gemini/settings.json",
            Self::Grok => ".grok/config.toml",
            Self::VsCode => ".vscode/mcp.json",
        }
    }

    pub const fn json_container_key(self) -> Option<&'static str> {
        match self {
            Self::ClaudeCode | Self::Cursor | Self::Gemini => Some("mcpServers"),
            Self::VsCode => Some("servers"),
            Self::Codex | Self::Grok => None,
        }
    }

    pub const fn is_toml(self) -> bool {
        matches!(self, Self::Codex | Self::Grok)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    InvalidDocument,
    UnsupportedLayout,
    Conflict,
    InvalidLaunch,
    Limit,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    Unchanged,
    Proposed {
        relative_path: &'static str,
        bytes: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Launch<'a> {
    pub command: &'a str,
    pub args: &'a [String],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Remote<'a> {
    pub url: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerProfile<'a> {
    Local(Launch<'a>),
    Remote(Remote<'a>),
}

pub fn plan(editor: Editor, existing: Option<&[u8]>, launch: Launch<'_>) -> Result<Plan, Refusal> {
    plan_profile(editor, existing, ServerProfile::Local(launch))
}

pub fn plan_remote(
    editor: Editor,
    existing: Option<&[u8]>,
    remote: Remote<'_>,
) -> Result<Plan, Refusal> {
    plan_profile(editor, existing, ServerProfile::Remote(remote))
}

pub fn plan_profile(
    editor: Editor,
    existing: Option<&[u8]>,
    profile: ServerProfile<'_>,
) -> Result<Plan, Refusal> {
    match &profile {
        ServerProfile::Local(launch) => validate_launch(launch)?,
        ServerProfile::Remote(remote) => validate_remote(remote)?,
    }
    let source = match existing {
        Some(bytes) => {
            if bytes.len() > MAX_BYTES {
                return Err(Refusal::Limit);
            }
            std::str::from_utf8(bytes).map_err(|_| Refusal::InvalidDocument)?
        }
        None => {
            if editor.is_toml() {
                ""
            } else {
                "{}"
            }
        }
    };
    let proposed = if editor.is_toml() {
        toml_proposal(source, profile)?
    } else {
        json_config::proposal(editor, source, profile)?
    };
    match proposed {
        None => Ok(Plan::Unchanged),
        Some(proposed) if proposed.len() <= MAX_BYTES => Ok(Plan::Proposed {
            relative_path: editor.relative_path(),
            bytes: proposed.into_bytes(),
        }),
        Some(_) => Err(Refusal::Limit),
    }
}

pub fn contains_env_interpolation(text: &str) -> bool {
    if text.contains("${") || text.contains("$(") {
        return true;
    }
    let bytes = text.as_bytes();
    for idx in 0..bytes.len() {
        if bytes[idx] == b'$'
            && let Some(next) = bytes.get(idx + 1)
            && (next.is_ascii_alphabetic() || *next == b'_')
        {
            return true;
        }
        if bytes[idx] == b'%'
            && let Some(first) = bytes.get(idx + 1)
            && (first.is_ascii_alphabetic() || *first == b'_')
        {
            let mut end = idx + 2;
            while let Some(ch) = bytes.get(end) {
                if *ch == b'%' {
                    return true;
                }
                if ch.is_ascii_alphanumeric() || *ch == b'_' {
                    end += 1;
                } else {
                    break;
                }
            }
        }
    }
    false
}

fn validate_launch(launch: &Launch<'_>) -> Result<(), Refusal> {
    if !launch.command.starts_with('/')
        || launch.command.ends_with('/')
        || launch.command.len() > 4096
        || launch.args.len() > 64
        || launch.command.contains(['\r', '\n'])
    {
        return Err(Refusal::InvalidLaunch);
    }
    let cmd_path = Path::new(launch.command);
    if cmd_path.components().count() < 2
        || cmd_path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(Refusal::InvalidLaunch);
    }
    let basename = cmd_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(Refusal::InvalidLaunch)?;
    if FORBIDDEN_SHELL_WRAPPERS
        .iter()
        .any(|shell| basename.eq_ignore_ascii_case(shell))
    {
        return Err(Refusal::InvalidLaunch);
    }
    if let Some(first_arg) = launch.args.first()
        && FORBIDDEN_SHELL_FLAGS.contains(&first_arg.as_str())
    {
        return Err(Refusal::InvalidLaunch);
    }
    for text in std::iter::once(launch.command).chain(launch.args.iter().map(String::as_str)) {
        if text.len() > 16_384 || text.contains('\0') || contains_env_interpolation(text) {
            return Err(Refusal::InvalidLaunch);
        }
    }
    Ok(())
}

fn validate_remote(remote: &Remote<'_>) -> Result<(), Refusal> {
    let url = remote.url;
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(Refusal::InvalidLaunch);
    };
    if url.len() > 2048
        || rest.is_empty()
        || rest.starts_with('/')
        || url.contains("..")
        || contains_env_interpolation(url)
        || url.bytes().any(|b| {
            b <= 0x20 || b == 0x7f || matches!(b, b'@' | b'?' | b'#' | b'\\' | b'"' | b'\'')
        })
    {
        return Err(Refusal::InvalidLaunch);
    }
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() || !host.contains('.') {
        return Err(Refusal::InvalidLaunch);
    }
    Ok(())
}

fn toml_proposal(source: &str, profile: ServerProfile<'_>) -> Result<Option<String>, Refusal> {
    let doc = DocumentMut::from_str(source).map_err(|_| Refusal::InvalidDocument)?;
    if let Some(parent) = doc.get("mcp_servers") {
        let table = parent.as_table_like().ok_or(Refusal::UnsupportedLayout)?;
        if let Some(existing) = table.get("chinwag") {
            let entry = existing.as_table_like().ok_or(Refusal::Conflict)?;
            let matches = match profile {
                ServerProfile::Local(launch) => {
                    entry.len() == 2
                        && entry.get("command").and_then(Item::as_str) == Some(launch.command)
                        && entry.get("args").and_then(Item::as_array).is_some_and(|a| {
                            a.len() == launch.args.len()
                                && a.iter()
                                    .zip(launch.args)
                                    .all(|(a, b)| a.as_str() == Some(b.as_str()))
                        })
                }
                ServerProfile::Remote(remote) => {
                    entry.len() == 1 && entry.get("url").and_then(Item::as_str) == Some(remote.url)
                }
            };
            return if matches {
                Ok(None)
            } else {
                Err(Refusal::Conflict)
            };
        }
        // TOML inline tables cannot be reopened by appending a child table.
        if !parent.is_table() {
            return Err(Refusal::UnsupportedLayout);
        }
    }
    let body = match profile {
        ServerProfile::Local(launch) => {
            let command =
                serde_json::to_string(launch.command).map_err(|_| Refusal::InvalidLaunch)?;
            let args = serde_json::to_string(launch.args).map_err(|_| Refusal::InvalidLaunch)?;
            format!("command = {command}\nargs = {args}\n")
        }
        ServerProfile::Remote(remote) => {
            let url = serde_json::to_string(remote.url).map_err(|_| Refusal::InvalidLaunch)?;
            format!("url = {url}\n")
        }
    };
    let separator = if source.is_empty() || source.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let prefix = if source.is_empty() { "" } else { "\n" };
    let proposed = format!("{source}{separator}{prefix}[mcp_servers.chinwag]\n{body}");
    if proposed.len() > MAX_BYTES {
        return Err(Refusal::Limit);
    }
    DocumentMut::from_str(&proposed).map_err(|_| Refusal::UnsupportedLayout)?;
    Ok(Some(proposed))
}
