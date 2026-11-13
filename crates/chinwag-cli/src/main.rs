#![forbid(unsafe_code)]

mod bus_run;
mod feature_cli_run;
mod relay_run;
mod ui_auth;
mod ui_gate_run;
mod ui_sse;
mod ui_workbench_run;

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
            let fleet = std::env::current_dir()
                .ok()
                .and_then(|cwd| chinwag_cli::fleet_cmd::load_manifest(None, &cwd).ok());
            let payload = serde_json::json!({
                "ok": true,
                "command": "chinwag onboard",
                "actor": identity.handle,
                "actor_id": identity.actor_id,
                "machine_name": identity.machine_name,
                "mission_control_url": mission_control_url,
                "fleet_manifest": fleet.as_ref().map(|(path, _)| path),
                "fleet_seats": fleet.as_ref().map(|(_, manifest)| &manifest.seats),
                "fleet_status": if fleet.is_some() { "configured" } else { "unconfigured (no fleet manifest)" },
                "wizard_url": wizard_url,
            });
            if is_json {
                let _ = writeln!(std::io::stdout().lock(), "{payload}");
            } else {
                let _ = writeln!(
                    std::io::stdout().lock(),
                    "Chinwag onboarding\nFleet: {}\nOpen: {wizard_url}",
                    payload["fleet_status"].as_str().unwrap_or_default()
                );
            }
            return ExitCode::SUCCESS;
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("bus") {
            // The daemon's async handlers also write diagnostics. Holding a
            // process-wide stdio lock across its runtime blocks those workers
            // before they can acknowledge a persisted remote original.
            let code = bus_run::run_bus_cli(
                &raw_args[2..],
                &mut std::io::stdout(),
                &mut std::io::stderr(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("release") {
            let code = bus_run::run_release_cli(
                &raw_args[2..],
                &mut std::io::stdout(),
                &mut std::io::stderr(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("history") {
            return ExitCode::from(chinwag_history_archive::run_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            ));
        }
        if matches!(raw_args.get(1).map(|s| s.as_str()), Some("tasks" | "task")) {
            let code = chinwag_cli::board::run_tasks_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("board") {
            let code = chinwag_cli::board::run_board_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("ci-report") {
            let code = chinwag_cli::board::run_ci_report_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("openspec") {
            let code = feature_cli_run::run_openspec_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("plugin") {
            let code = feature_cli_run::run_plugin_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("cwcard") {
            let code = feature_cli_run::run_cwcard_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("bond") {
            let code = feature_cli_run::run_bond_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if matches!(
            raw_args.get(1).map(|s| s.as_str()),
            Some("ui" | "workbench")
        ) {
            let code = ui_workbench_run::run_ui_workbench_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("a509") {
            let code = feature_cli_run::run_a509_cli(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
        }
        if raw_args.get(1).map(|s| s.as_str()) == Some("ui-gate") {
            let code = ui_gate_run::run_ui_gate(
                &raw_args[2..],
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            );
            return ExitCode::from(code);
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
        chinwag_cli::Dispatch::Fleet(args) => {
            ExitCode::from(chinwag_cli::fleet_cmd::run_fleet_cli(
                &args,
                &mut std::io::stdout(),
                &mut std::io::stderr(),
            ))
        }
        chinwag_cli::Dispatch::AgentDispatchStatus(repo) => {
            ExitCode::from(chinwag_cli::run_agent_dispatch_status(
                repo,
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            ))
        }
        chinwag_cli::Dispatch::AgentDispatchNetwork(request) => {
            ExitCode::from(chinwag_cli::run_agent_dispatch_network(
                request,
                &mut std::io::stdin().lock(),
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            ))
        }
        chinwag_cli::Dispatch::AgentDispatch(request) => {
            chinwag_cli::board::emit_active_crisis_alert_from_cwd(&mut std::io::stderr());
            ExitCode::from(chinwag_cli::run_agent_dispatch(
                request,
                &mut std::io::stdin().lock(),
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            ))
        }
        chinwag_cli::Dispatch::Memory(request) => {
            chinwag_cli::board::emit_active_crisis_alert_from_cwd(&mut std::io::stderr());
            ExitCode::from(chinwag_cli::run_memory(
                request,
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            ))
        }
    }
}
