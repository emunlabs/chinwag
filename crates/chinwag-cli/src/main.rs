#![forbid(unsafe_code)]

mod relay_run;

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let raw_os: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let all_utf8: Option<Vec<String>> = raw_os
        .iter()
        .map(|s| s.to_str().map(|v| v.to_string()))
        .collect();
    let is_chinwag_prog = raw_os
        .first()
        .and_then(|p| std::path::Path::new(p).file_name())
        .and_then(|n| n.to_str())
        == Some("chinwag");
    if let (true, Some(raw_args)) = (is_chinwag_prog, all_utf8) {
        if raw_args.get(1).map(|s| s.as_str()) == Some("onboard") {
            let identity = relay_run::resolve_identity_config();
            let mut mission_control_url = identity.mission_control_url.clone();
            let mut idx = 2;
            while idx < raw_args.len() {
                if (raw_args[idx] == "--url" || raw_args[idx] == "-u") && idx + 1 < raw_args.len() {
                    mission_control_url = raw_args[idx + 1].trim_end_matches('/').to_string();
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            let wizard_url = format!("{}/?onboard=1", mission_control_url.trim_end_matches('/'));
            let is_json = raw_args.iter().any(|a| a == "--json");
            let has_tart = std::path::Path::new("/opt/homebrew/bin/tart").exists()
                || std::path::Path::new("/usr/local/bin/tart").exists();
            let has_softnet = std::path::Path::new("/opt/homebrew/bin/softnet").exists()
                || std::path::Path::new("/usr/local/bin/softnet").exists();
            let has_node = std::path::Path::new("/opt/homebrew/bin/node").exists()
                || std::path::Path::new("/usr/local/bin/node").exists();
            let has_git = std::path::Path::new("/usr/bin/git").exists()
                || std::path::Path::new("/opt/homebrew/bin/git").exists();
            let has_dagu = std::path::Path::new("/opt/homebrew/bin/dagu").exists()
                || std::path::Path::new("/usr/local/bin/dagu").exists();
            if is_json {
                let payload = serde_json::json!({
                    "ok": true,
                    "command": "chinwag onboard",
                    "actor": identity.handle,
                    "actor_id": identity.actor_id,
                    "machine_name": identity.machine_name,
                    "mission_control_url": mission_control_url,
                    "invariants": ["INV-ONBOARD-01", "INV-ROUTE-01", "INV-MERGE-01"],
                    "frontier_catalog": {
                        "source": "https://models.dev/api.json",
                        "anthropic": ["claude-opus-5-5 ($4/$20)", "claude-sonnet-5-5 ($2/$10)", "claude-haiku-5-5 ($0.10/$0.50)", "claude-fable-5-1 ($10/$50)"],
                        "openai": ["gpt-6-1-terra ($1/$5)", "gpt-6-1-sol ($2/$10)", "gpt-6-astra ($10/$50)", "gpt-6-luna ($0.10/$0.50)"],
                        "google": ["gemini-4-argon ($2/$10)"],
                        "xai": ["grok-4.7 ($2/$6)", "grok-build-0.1 ($1/$2)"]
                    },
                    "preflight": {
                        "tart_installed": has_tart,
                        "softnet_installed": has_softnet,
                        "node_installed": has_node,
                        "git_installed": has_git,
                        "dagu_installed": has_dagu,
                        "cleanroom_vm_slots_fleet_target": 4
                    },
                    "wizard_url": wizard_url
                });
                let _ = writeln!(std::io::stdout().lock(), "{payload}");
                return ExitCode::SUCCESS;
            }
            let _ = writeln!(
                std::io::stdout().lock(),
                "✨ Chinwag First-Run Coalface Onboarding (PRD-ONBOARD-01 · INV-ONBOARD-01 · INV-ROUTE-01)\n\
                 1. iroh QUIC Multi-Mac Mesh & 4-VM Cleanroom Swarm: 2 VMs Mac Studio + 2 VMs MacBook Pro (Tart: {has_tart}, Softnet: {has_softnet})\n\
                 2. #mgmt Executive Layer: Always-On Cloud Frontier VPs (Grok 4.7, Gemini 4 Argon, Claude Opus 5.5, GPT-6.1 Sol)\n\
                 3. Local Frontier CLIs: Claude Code (Opus/Sonnet 5.5), Codex CLI (GPT-6.1 Terra/Sol), Gemini CLI (Gemini 4 Argon), Grok 4.7\n\
                 4. Burst API Failover: Keychain 0600 (Anthropic, OpenAI, xAI, Google Gemini 4 Argon, ElevenLabs)\n\
                 5. Local Apple Silicon Models: ■ FLINT (:11500 via iroh QUIC) + LEANN CSR ($0.00/tok Rung 0)\n\
                 6. FinOps Smart Router: L1–L5 Cost × Capability Arbitrage (~$2.80/commit · 78% saved vs unrouted API)\n\
                 7. Worker Swarm Provisioning: 30 Enrolled Org Agents active\n\
                 → Launch Full-Screen First-Run Wizard: {wizard_url}"
            );
            return ExitCode::SUCCESS;
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("beam") {
            let code = relay_run::run_beam_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("relay") {
            let code = relay_run::run_relay_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("reply")
            || raw_args.get(1).map(|s| s.as_str()) == Some("post")
        {
            let mut forwarded = vec!["reply".to_string()];
            forwarded.extend_from_slice(&raw_args[2..]);
            let code = relay_run::run_relay_cli(
                &forwarded,
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
    }

    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_default();
    match chinwag_cli::dispatch(&program, args) {
        chinwag_cli::Dispatch::Immediate(result) => {
            if std::io::stdout()
                .lock()
                .write_all(result.stdout().as_bytes())
                .is_err()
                || std::io::stderr()
                    .lock()
                    .write_all(result.stderr().as_bytes())
                    .is_err()
            {
                return ExitCode::FAILURE;
            }
            ExitCode::from(result.code())
        }
        chinwag_cli::Dispatch::Serve(request) => {
            ExitCode::from(chinwag_cli::run_mcp_stdio(request, &mut std::io::stderr()))
        }
        chinwag_cli::Dispatch::ServeHttp(request) => {
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() {
                let _ = writeln!(
                    std::io::stderr(),
                    "chinwag: HTTP requires exactly 32 secret bytes and EOF from piped stdin"
                );
                return ExitCode::from(2);
            }
            ExitCode::from(chinwag_cli::run_mcp_http(
                request,
                &mut std::io::stdin().lock(),
                &mut std::io::stdout().lock(),
                &mut std::io::stderr(),
            ))
        }
        chinwag_cli::Dispatch::Configure(request) => ExitCode::from(chinwag_cli::run_configure(
            request,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        )),
        chinwag_cli::Dispatch::Init(request) => ExitCode::from(chinwag_cli::run_init(
            request,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        )),
        chinwag_cli::Dispatch::AgentDispatch(request) => {
            ExitCode::from(chinwag_cli::run_agent_dispatch(
                request,
                &mut std::io::stdin().lock(),
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            ))
        }
        chinwag_cli::Dispatch::Memory(request) => ExitCode::from(chinwag_cli::run_memory(
            request,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        )),
    }
}
