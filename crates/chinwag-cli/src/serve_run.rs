use crate::ServeRequest;
use std::io::Write;

pub fn run_mcp_stdio(request: ServeRequest, err: &mut dyn Write) -> u8 {
    match chinwag_mcp_private_anchored::run_repository_stdio(request.repo) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(err, "chinwag: context_failed: {error}");
            1
        }
    }
}
