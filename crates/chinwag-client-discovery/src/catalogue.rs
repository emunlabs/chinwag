//! Built-in family hints from public bundle metadata and exact CLI filenames.
//! These matches are not vendor signatures, launch approval, or connector proof.

use crate::ClientFamily;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationMatch {
    PublicBundleIdentity,
    NameAndExecutableHint,
    ExactCliFilenameHint,
    LauncherOnly,
}

struct AppRule {
    family: ClientFamily,
    name: &'static str,
    executable: &'static str,
    bundle: Option<&'static str>,
}

const APPS: &[AppRule] = &[
    AppRule {
        family: ClientFamily::GrokBot,
        name: "Grok Bot",
        executable: "Grok Bot",
        bundle: Some("com.anysphere.sand"),
    },
    AppRule {
        family: ClientFamily::ChatgptDesktop,
        name: "ChatGPT",
        executable: "ChatGPT",
        bundle: Some("com.openai.codex"),
    },
    AppRule {
        family: ClientFamily::CodexDesktop,
        name: "Codex",
        executable: "Codex",
        bundle: Some("com.openai.codex"),
    },
    AppRule {
        family: ClientFamily::ClaudeDesktop,
        name: "Claude",
        executable: "Claude",
        bundle: Some("com.anthropic.claudefordesktop"),
    },
    AppRule {
        family: ClientFamily::GeminiDesktop,
        name: "Gemini",
        executable: "Gemini",
        bundle: Some("com.google.GeminiMacOS"),
    },
    AppRule {
        family: ClientFamily::GoogleAntigravity,
        name: "Antigravity",
        executable: "Antigravity",
        bundle: Some("com.google.antigravity"),
    },
    AppRule {
        family: ClientFamily::Cursor,
        name: "Cursor",
        executable: "Cursor",
        bundle: Some("com.todesktop.230313mzl4w4u92"),
    },
    AppRule {
        family: ClientFamily::Windsurf,
        name: "Windsurf",
        executable: "Electron",
        bundle: Some("com.exafunction.windsurf"),
    },
    AppRule {
        family: ClientFamily::VisualStudioCode,
        name: "Code",
        executable: "Code",
        bundle: Some("com.microsoft.VSCode"),
    },
    AppRule {
        family: ClientFamily::Warp,
        name: "Warp",
        executable: "stable",
        bundle: Some("dev.warp.Warp-Stable"),
    },
    AppRule {
        family: ClientFamily::LmStudio,
        name: "LM Studio",
        executable: "LM Studio",
        bundle: Some("ai.elementlabs.lmstudio"),
    },
    AppRule {
        family: ClientFamily::AnythingLlm,
        name: "AnythingLLM",
        executable: "AnythingLLM",
        bundle: Some("com.anythingllm"),
    },
    AppRule {
        family: ClientFamily::Zed,
        name: "Zed",
        executable: "zed",
        bundle: None,
    },
    AppRule {
        family: ClientFamily::Kiro,
        name: "Kiro",
        executable: "Kiro",
        bundle: None,
    },
    AppRule {
        family: ClientFamily::Ollama,
        name: "Ollama",
        executable: "Ollama",
        bundle: None,
    },
    AppRule {
        family: ClientFamily::Goose,
        name: "Goose",
        executable: "Goose",
        bundle: None,
    },
    AppRule {
        family: ClientFamily::Jan,
        name: "Jan",
        executable: "Jan",
        bundle: None,
    },
    AppRule {
        family: ClientFamily::Msty,
        name: "Msty",
        executable: "Msty",
        bundle: None,
    },
    AppRule {
        family: ClientFamily::CherryStudio,
        name: "Cherry Studio",
        executable: "Cherry Studio",
        bundle: None,
    },
    AppRule {
        family: ClientFamily::Boltai,
        name: "BoltAI",
        executable: "BoltAI",
        bundle: None,
    },
    AppRule {
        family: ClientFamily::Chatbox,
        name: "Chatbox",
        executable: "Chatbox",
        bundle: None,
    },
    AppRule {
        family: ClientFamily::Gpt4all,
        name: "GPT4All",
        executable: "GPT4All",
        bundle: None,
    },
    AppRule {
        family: ClientFamily::Perplexity,
        name: "Perplexity",
        executable: "Perplexity",
        bundle: None,
    },
];

pub const CLI_NAMES: &[&str] = &[
    "codex",
    "claude",
    "gemini",
    "opencode",
    "aider",
    "copilot",
    "kiro",
    "q",
    "cursor",
    "windsurf",
    "ollama",
    "lms",
    "goose",
    "amp",
    "droid",
    "continue",
    "cn",
    "cline",
    "roo",
    "mistral-vibe",
    "vibe",
    "warp",
    "zed",
];

pub(crate) fn app_family(
    bundle_name: &str,
    bundle_id: &str,
    executable: &str,
) -> Option<(ClientFamily, InstallationMatch)> {
    if bundle_id == "com.anthropic.claude-code-url-handler" && executable == "claude" {
        return Some((ClientFamily::ClaudeCode, InstallationMatch::LauncherOnly));
    }
    APPS.iter().find_map(|rule| {
        if executable != rule.executable {
            return None;
        }
        match rule.bundle {
            Some(expected) if bundle_id == expected => {
                Some((rule.family, InstallationMatch::PublicBundleIdentity))
            }
            None if bundle_name == rule.name => {
                Some((rule.family, InstallationMatch::NameAndExecutableHint))
            }
            _ => None,
        }
    })
}

pub(crate) fn cli_family(name: &str) -> Option<ClientFamily> {
    Some(match name {
        "codex" => ClientFamily::CodexCli,
        "claude" => ClientFamily::ClaudeCode,
        "gemini" => ClientFamily::GeminiCli,
        "opencode" => ClientFamily::Opencode,
        "aider" => ClientFamily::Aider,
        "copilot" => ClientFamily::GithubCopilot,
        "kiro" => ClientFamily::Kiro,
        "q" => ClientFamily::AmazonQ,
        "cursor" => ClientFamily::Cursor,
        "windsurf" => ClientFamily::Windsurf,
        "ollama" => ClientFamily::Ollama,
        "lms" => ClientFamily::LmStudio,
        "goose" => ClientFamily::Goose,
        "amp" => ClientFamily::Amp,
        "droid" => ClientFamily::Droid,
        "continue" | "cn" => ClientFamily::Continue,
        "cline" => ClientFamily::Cline,
        "roo" => ClientFamily::RooCode,
        "mistral-vibe" | "vibe" => ClientFamily::MistralVibe,
        "warp" => ClientFamily::Warp,
        "zed" => ClientFamily::Zed,
        _ => return None,
    })
}
