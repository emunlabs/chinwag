//! Pure proposals and separately owned macOS repository installation.
#![deny(unsafe_code)]
#[cfg(target_os = "macos")]
pub mod install;
mod json_config;

use std::str::FromStr;
use toml_edit::{DocumentMut, Item};

pub const MAX_BYTES: usize = 1_048_576;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Editor {
    ClaudeCode,
    Cursor,
    Codex,
}
impl Editor {
    pub fn relative_path(self) -> &'static str {
        match self {
            Self::ClaudeCode => ".mcp.json",
            Self::Cursor => ".cursor/mcp.json",
            Self::Codex => ".codex/config.toml",
        }
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
pub struct Launch<'a> {
    pub command: &'a str,
    pub args: &'a [String],
}

pub fn plan(editor: Editor, existing: Option<&[u8]>, launch: Launch<'_>) -> Result<Plan, Refusal> {
    if !launch.command.starts_with('/') || launch.command.len() > 4096 || launch.args.len() > 64 {
        return Err(Refusal::InvalidLaunch);
    }
    for text in std::iter::once(launch.command).chain(launch.args.iter().map(String::as_str)) {
        if text.len() > 16_384 || text.contains('\0') || text.contains("${") {
            return Err(Refusal::InvalidLaunch);
        }
    }
    let source = match existing {
        Some(bytes) => {
            if bytes.len() > MAX_BYTES {
                return Err(Refusal::Limit);
            }
            std::str::from_utf8(bytes).map_err(|_| Refusal::InvalidDocument)?
        }
        None => match editor {
            Editor::Codex => "",
            _ => "{}",
        },
    };
    let proposed = match editor {
        Editor::Codex => toml_proposal(source, &launch)?,
        _ => json_config::proposal(source, &launch)?,
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

fn toml_proposal(source: &str, launch: &Launch<'_>) -> Result<Option<String>, Refusal> {
    let doc = DocumentMut::from_str(source).map_err(|_| Refusal::InvalidDocument)?;
    if let Some(parent) = doc.get("mcp_servers") {
        let table = parent.as_table_like().ok_or(Refusal::UnsupportedLayout)?;
        if let Some(existing) = table.get("chinwag") {
            let entry = existing.as_table_like().ok_or(Refusal::Conflict)?;
            let matches = entry.len() == 2
                && entry.get("command").and_then(Item::as_str) == Some(launch.command)
                && entry.get("args").and_then(Item::as_array).is_some_and(|a| {
                    a.len() == launch.args.len()
                        && a.iter()
                            .zip(launch.args)
                            .all(|(a, b)| a.as_str() == Some(b.as_str()))
                });
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
    // JSON string/array spelling is checked again by the TOML parser below.
    let command = serde_json::to_string(launch.command).map_err(|_| Refusal::InvalidLaunch)?;
    let args = serde_json::to_string(launch.args).map_err(|_| Refusal::InvalidLaunch)?;
    let proposed = format!("{source}\n[mcp_servers.chinwag]\ncommand = {command}\nargs = {args}\n");
    if proposed.len() > MAX_BYTES {
        return Err(Refusal::Limit);
    }
    DocumentMut::from_str(&proposed).map_err(|_| Refusal::UnsupportedLayout)?;
    Ok(Some(proposed))
}
