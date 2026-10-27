#![forbid(unsafe_code)]

mod relay_run;

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.get(1).map(|s| s.as_str()) == Some("onboard") {
        let _ = writeln!(
            std::io::stdout().lock(),
            "✨ Chinwag First-Run Coalface Onboarding (PRD-ONBOARD-01 · INV-ONBOARD-01 · INV-ROUTE-01)\n\
             1. iroh QUIC Multi-Mac Mesh: Zero-Config Ed25519 NodeId Pairing (No Tailscale/Cables required)\n\
             2. #mgmt Executive Layer: Enforced Always-On Cloud Frontier VPs ([PA], [PRODUCT], [ENG], [INFRA], [BIZFIN], [S-AND-M])\n\
             3. Local Frontier CLIs: Claude Code, Codex CLI, Gemini CLI, Grok Desktop (Rung 1 Subscription Drain)\n\
             4. Burst API Failover: Keychain 0600 (Anthropic, OpenAI, xAI, Gemini, ElevenLabs)\n\
             5. Local Apple Silicon Models: ■ FLINT (:11500 via iroh QUIC) + LEANN CSR ($0.00/tok Rung 0)\n\
             6. FinOps Smart Router: Cost × Capability Arbitrage (~$3.20/commit · 74% saved vs unrouted API)\n\
             7. Worker Swarm Provisioning: 30 Enrolled Org Agents active\n\
             → Launch Full-Screen First-Run Wizard: http://127.0.0.1:5487/?onboard=1"
        );
        return ExitCode::SUCCESS;
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
