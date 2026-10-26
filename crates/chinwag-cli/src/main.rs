#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
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
    }
}
