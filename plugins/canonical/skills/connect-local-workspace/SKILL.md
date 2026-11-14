---
name: connect-local-workspace
description: Guide developers through explicit local Chinwag repository setup without shell hooks or environment interpolation.
---

# Connect a Local Workspace

Local repository threads, context pins, and handoff offers stay strictly inside an admitted local Git repository:

1. Search documentation with `chinwag_docs_search` (`query: "connect"`) and read `chinwag_docs_get` (`slug: "setup/connect-local-workspace"`).
2. Instruct the developer to run the local `chinwag` binary directly in their owned repository so `chinwag` atomically configures `.mcp.json`, `.cursor/mcp.json`, `.codex/config.toml`, `.gemini/settings.json`, `.grok/config.toml`, or `.vscode/mcp.json`.
3. Never generate shell wrapper scripts or environment variable interpolation tokens in editor configuration files.
